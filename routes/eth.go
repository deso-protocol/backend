package routes

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"io"
	"io/ioutil"
	"math"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"golang.org/x/crypto/sha3"

	"encoding/hex"

	"github.com/davecgh/go-spew/spew"
	"github.com/deso-protocol/core/lib"
	"github.com/golang/glog"
	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
)

func (fes *APIServer) IsConfiguredForETH() bool {
	return fes.Config.BuyDESOETHAddress != "" && fes.Config.InfuraProjectID != ""
}

type ETHTx struct {
	Nonce   string `json:"nonce"`
	Value   string `json:"value"`
	ChainId string `json:"chainId"`
	To      string `json:"to"`
	R       string `json:"r"`
	S       string `json:"s"`
}

type SubmitETHTxRequest struct {
	PublicKeyBase58Check string
	Tx                   ETHTx
	TxBytes              string
	ToSign               []string
	SignedHashes         []string
}

type SubmitETHTxResponse struct {
	DESOTxHash string
}

// ETHTxLog is used by admins to reprocess stuck transactions
type ETHTxLog struct {
	PublicKey  []byte
	DESOTxHash string
}

// We assume that there are valid signatures if the transaction mines.
func (fes *APIServer) validateETHDepositAddress(depositAddress string) error {
	// Verify the deposit address is correct
	configDepositAddress := strings.ToLower(fes.Config.BuyDESOETHAddress)
	txDepositAddress := strings.ToLower(depositAddress)
	if configDepositAddress != txDepositAddress {
		return errors.Errorf("Invalid deposit address: %s != %s", txDepositAddress, configDepositAddress)
	}
	return nil
}

func (fes *APIServer) SubmitETHTx(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := SubmitETHTxRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: Problem parsing request body: %v", err))
		return
	}

	if !fes.IsConfiguredForETH() {
		_AddBadRequestError(ww, "SubmitETHTx: Not configured for ETH")
		return
	}

	if err := fes.validateETHDepositAddress(requestData.Tx.To); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: Failed to validate transaction: %v", err))
		return
	}

	nanosPurchased, err := fes.CalculateNanosPurchasedFromWei(requestData.Tx.Value)

	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: Unable to calculate nanos purchasd from eth tx: %v", err))
		return
	}

	var balanceInsufficient bool
	balanceInsufficient, err = fes.ExceedsDeSoBalance(nanosPurchased, fes.Config.BuyDESOSeed)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: Error checking if send deso balance is sufficient: %v", err))
		return
	}
	if balanceInsufficient {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: SendDeSo wallet balance is below nanos purchased"))
		return
	}

	// Parse the public key
	pkBytes, _, err := lib.Base58CheckDecode(requestData.PublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: Invalid public key: %v", err))
		return
	}

	// Submit the transaction. Note that the SignedHashes is actually the whole transaction serialized with signature.
	params := []interface{}{fmt.Sprintf("0x%v", requestData.SignedHashes[0])}
	response, err := fes.ExecuteETHRPCRequest("eth_sendRawTransaction", params, nil)

	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: Error sending raw transaction: %v", err))
		return
	}

	// Record the valid transaction in global state
	ethTxLog := &ETHTxLog{
		PublicKey: pkBytes,
	}

	// Convert the result from interface to string.
	hash := response.Result.(string)

	globalStateKey := GlobalStateKeyETHPurchases(hash)
	globalStateVal := bytes.NewBuffer([]byte{})
	if err = gob.NewEncoder(globalStateVal).Encode(ethTxLog); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: Failed to encode ETH transaction: %v", err))
		return
	}
	if err = fes.GlobalState.Put(globalStateKey, globalStateVal.Bytes()); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: Error processing Put: %v", err))
		return
	}

	// Wait up to 10 minutes
	// TODO: Long running requests are bad. Replace this with polling (or websockets etc)
	var ethTx *InfuraTx
	for i := 0; i < 60; i++ {
		// Check if the transaction was mined every 10 seconds
		time.Sleep(10 * time.Second)

		ethTx, err = fes.GetETHTransactionByHash(hash)
		if err != nil {
			glog.Errorf("GetETHTransactionByHash: %v", err)
			continue
		}
		if ethTx == nil {
			// Sometimes these requests can fail. Ignore the failure and keep polling
			continue
		}

		// A block height means the transaction mined
		if ethTx.BlockNumber != nil {
			break
		}
	}
	// The transaction has mined or we've waited for 10 minutes so we finish by validating the transaction and paying the user.
	desoTxHash, err := fes.finishETHTx(ethTx, ethTxLog)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: Failed: %v", err))
		return
	}

	res := SubmitETHTxResponse{
		DESOTxHash: desoTxHash.String(),
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: Problem encoding response: %v", err))
		return
	}
}

// 1. Validate the transaction mined and sends money to the correct address
// 2. Calculate the nanos to send
// 3. Send the nanos
// 4. Record the successful send
func (fes *APIServer) finishETHTx(ethTx *InfuraTx, ethTxLog *ETHTxLog) (desoTxHash *lib.BlockHash, _err error) {
	if ethTx == nil {
		return nil, errors.New("ETHTx provided is nil")
	}

	glog.Info("finishETHTx - ETH tx provided: ", spew.Sdump(ethTx))

	if ethTx.BlockNumber == nil {
		return nil, errors.New(fmt.Sprintf("Transaction failed to mine: %v", ethTx.Hash))
	}

	if err := fes.validateETHDepositAddress(*ethTx.To); err != nil {
		return nil, errors.New(fmt.Sprintf("Error validating Infura ETH Tx: %v", err))
	}

	nanosPurchased, err := fes.CalculateNanosPurchasedFromWei(ethTx.Value)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("finishETHTx: Error calculating NanosPurchasedFromWei: %v", err))
	}

	var balanceInsufficient bool
	balanceInsufficient, err = fes.ExceedsDeSoBalance(nanosPurchased, fes.Config.BuyDESOSeed)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("finishETHTx: Error checking if send deso balance is sufficient: %v", err))
	}
	if balanceInsufficient {
		return nil, errors.New("finishETHTx: SendDeSo wallet balance is below nanos purchased")
	}

	// Send the DESO and get the hash of that transaction
	desoTxHash, err = fes.SendSeedDeSo(ethTxLog.PublicKey, nanosPurchased, true)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error sending DESO: %v", err))
	}

	// Record successful transaction in global state
	ethTxLog.DESOTxHash = desoTxHash.String()
	globalStateKey := GlobalStateKeyETHPurchases(ethTx.Hash)
	globalStateVal := bytes.NewBuffer([]byte{})

	// Save the ethTxLog in global state
	if err = gob.NewEncoder(globalStateVal).Encode(ethTxLog); err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to encode ETH transaction: %v", err))
	}

	if err = fes.GlobalState.Put(globalStateKey, globalStateVal.Bytes()); err != nil {
		return nil, errors.New(fmt.Sprintf("Error processing Put: %v", err))
	}

	return desoTxHash, nil
}

func (fes *APIServer) CalculateNanosPurchasedFromWei(value string) (_nanosPurchased uint64, _err error) {
	// Calculate nanos purchased
	// Strip the 0x prefix from the value attribute and parse hex string to uint64
	hexValueString := strings.Replace(value, "0x", "", -1)
	weiSentBigint, success := big.NewInt(0).SetString(hexValueString, 16)
	if !success {
		return 0, errors.New(fmt.Sprintf("Failed to convert wei hex to uint64"))
	}

	// Use big number math to convert wei to eth and then compute DESO nanos purchased.
	totalWei := big.NewFloat(0).SetInt(weiSentBigint)
	totalEth := big.NewFloat(0).Quo(totalWei, big.NewFloat(1e18))
	return fes.GetNanosFromETH(totalEth, fes.BuyDESOFeeBasisPoints), nil
}

type AdminProcessETHTxRequest struct {
	ETHTxHash string
}

type AdminProcessETHTxResponse struct {
	DESOTxHash string
}

func (fes *APIServer) AdminProcessETHTx(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminProcessETHTxRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminProcessETHTx: Problem parsing request body: %v", err))
		return
	}

	if !fes.IsConfiguredForETH() {
		_AddBadRequestError(ww, "AdminProcessETHTx: Not configured for ETH")
		return
	}

	// Fetch the log data from global state
	globalStateKey := GlobalStateKeyETHPurchases(requestData.ETHTxHash)
	globalStateLog, err := fes.GlobalState.Get(globalStateKey)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminProcessETHTx: Error processing Get: %v", err))
		return
	}

	ethTxLog := &ETHTxLog{}
	err = gob.NewDecoder(bytes.NewReader(globalStateLog)).Decode(ethTxLog)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminProcessETHTx: Error decoding global state data: %v", err))
		return
	}

	// Transaction must be unsuccessful
	if len(ethTxLog.DESOTxHash) > 0 {
		_AddBadRequestError(ww, fmt.Sprintf("AdminProcessETHTx: DESO was sent: %s", ethTxLog.DESOTxHash))
		return
	}

	// Fetch the transaction
	ethTx, err := fes.GetETHTransactionByHash(requestData.ETHTxHash)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminProcessETHTx: Failed to get transaction: %v", err))
		return
	}

	desoTxHash, err := fes.finishETHTx(ethTx, ethTxLog)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminProcessETHTx: Failed: %v", err))
		return
	}

	res := AdminProcessETHTxResponse{
		DESOTxHash: desoTxHash.String(),
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminProcessETHTx: Problem encoding response: %v", err))
		return
	}
}

// JSON RPC with Infura

type InfuraRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	Id      uint64        `json:"id"`
}

type InfuraResponse struct {
	Id      uint64      `json:"id"`
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result"`
	Error   struct {
		Code    float64 `json:"code"`
		Message string  `json:"message"`
	} `json:"error"`
}

type InfuraTx struct {
	BlockHash            *string `json:"blockHash"`
	BlockNumber          *string `json:"blockNumber"`
	From                 string  `json:"from"`
	Gas                  string  `json:"gas"`
	GasPrice             string  `json:"gasPrice"`
	Hash                 string  `json:"hash"`
	Input                string  `json:"input"`
	Nonce                string  `json:"nonce"`
	To                   *string `json:"to"`
	TransactionIndex     *string `json:"transactionIndex"`
	Value                string  `json:"value"`
	V                    string  `json:"v"`
	R                    string  `json:"r"`
	S                    string  `json:"s"`
	Type                 string  `json:"type"`
	MaxPriorityFeePerGas *string `json:"maxPriorityFeePerGas"`
	MaxFeePerGas         *string `json:"maxFeePerGas"`
	ChainId              *string `json:"chainId"`
}

type QueryETHRPCRequest struct {
	Method     string
	Params     []interface{}
	UseNetwork *string
}

// QueryETHRPC is an endpoint used to execute queries through Infura
func (fes *APIServer) QueryETHRPC(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := QueryETHRPCRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("QueryETHRPC: Problem parsing request body: %v", err))
		return
	}
	res, err := fes.ExecuteETHRPCRequest(requestData.Method, requestData.Params, requestData.UseNetwork)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("QueryETHRPC: Error executing request: %v", err))
		return
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("QueryETHRPC: Problem encoding response: %v", err))
		return
	}
}

type MetamaskSignInRequest struct {
	AmountNanos uint64
	Signer      []byte
	Message     []byte
	Signature   []byte
}
type MetamaskSignInResponse struct {
	TxnHash *lib.BlockHash
}

func (fes *APIServer) MetamaskSignIn(ww http.ResponseWriter, req *http.Request) {
	// Give the user starter deso if this is their first time signing in with through metamask and if they don't have Deso
	DEFAULT_ERROR := "MetamaskSignin: something went wrong with processing your airdrop: %v"
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	// Validate the  request object
	requestData := MetamaskSignInRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("MetamaskSignin: Problem parsing request body: %v", err))
		return
	}
	// get the deso public address of the user
	recipientPublicKey := lib.Base58CheckEncode(requestData.Signer, false, fes.Params)
	recipientBytePK, _, err := lib.Base58CheckDecode(recipientPublicKey)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(DEFAULT_ERROR, err))
		return
	}
	// get the public eth address of the user
	recipientEthAddress, err := publicKeyToEthAddress(requestData.Signer)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(DEFAULT_ERROR, err))
		return
	}

	// Validate that the user doesn't have Deso already
	desoBalance, desoBalanceErr := fes.getBalanceForPubKey(recipientBytePK)
	if desoBalanceErr != nil {
		_AddBadRequestError(ww, fmt.Sprintf("MetamaskSignin: Error checking balance for public key: %v", desoBalanceErr))
		return
	}
	// balance check TESTED
	if desoBalance != 0 {
		_AddBadRequestError(ww, fmt.Sprint("MetamaskSignin: Account already has a balance"))
		return
	}
	metamaskAirdropMetadata, err := fes.GetMetamaskAirdropMetadata(recipientBytePK)
	// If there are no bytes from global state, we know that they haven't received an airdrop.
	if metamaskAirdropMetadata != nil && metamaskAirdropMetadata.HasReceivedAirdrop {
		_AddBadRequestError(ww, fmt.Sprintf("MetamaskSignin: Account has already received airdrop"))
		return
	}

	if fes.Config.MetamaskAirdropDESONanosAmount == 0 {
		res := MetamaskSignInResponse{TxnHash: nil}
		// Issue constructing response
		if err = json.NewEncoder(ww).Encode(res); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(DEFAULT_ERROR, err))
			return
		}
		return
	}
	// validate the user's eth balance
	params := []interface{}{recipientEthAddress, "latest"}
	infuraResponse, err := fes.ExecuteETHRPCRequest("eth_getBalance", params, nil)
	// infura did something funky when getting the user balance
	if infuraResponse == nil || err != nil {
		balanceRequestErr := fmt.Sprintf("Infura balance request: %v", err)
		_AddBadRequestError(ww, fmt.Sprintf(DEFAULT_ERROR, balanceRequestErr))
		return
	}
	ethBalance := strings.Split(infuraResponse.Result.(string), "x")[1]
	numberStr := strings.Replace(ethBalance, "0x", "", -1)
	ethBalanceBigint, ok := big.NewInt(0).SetString(numberStr, 16)
	if !ok {
		_AddBadRequestError(ww, fmt.Sprintf(DEFAULT_ERROR, fmt.Sprintf(
			"could not parse ETH balance %v into bigint", numberStr)))
		return
	}
	// To prevent bots we only allow accounts with .0001 eth or greater to qualify
	if ethBalanceBigint.Cmp(fes.Config.MetamaskAirdropEthMinimum.ToBig()) < 0 {
		// Ceil to 4 decimal places
		minEthAmountRequired := math.Ceil(float64(fes.Config.MetamaskAirdropEthMinimum.Uint64())*10000) / 1e18 * 10000
		_AddBadRequestError(ww, fmt.Sprintf("MetamaskSignin: To be eligible for "+
			"airdrop your account needs to have more than %v eth", minEthAmountRequired))
		return
	}
	//Verify that they signed a signature from their account
	verifyEthError := lib.VerifyEthPersonalSignature(requestData.Signer, requestData.Message, requestData.Signature)
	if verifyEthError != nil {
		_AddBadRequestError(ww, fmt.Sprintf(DEFAULT_ERROR, verifyEthError))
		return
	}
	// Converting to public key failed
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(DEFAULT_ERROR, err))
		return

	}
	addressToAirdrop, _, err := lib.Base58CheckDecode(recipientPublicKey)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(DEFAULT_ERROR, err))
		return
	}
	// add them to the received airdrop list with ShouldCompProfileCreation set to true
	newMetamaskAirdropMetadata := MetamaskAirdropMetadata{
		PublicKey:                 recipientBytePK,
		HasReceivedAirdrop:        true,
		ShouldCompProfileCreation: true,
	}
	if err = fes.PutMetamaskAirdropMetadata(&newMetamaskAirdropMetadata); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(DEFAULT_ERROR, err))
		return
	}

	txnHash, err := fes.SendSeedDeSo(addressToAirdrop, fes.Config.MetamaskAirdropDESONanosAmount, false)
	// attempted to send the deso but something went wrong
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(DEFAULT_ERROR, err))
		return
	}
	res := MetamaskSignInResponse{TxnHash: txnHash}
	// Issue constructing response
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(DEFAULT_ERROR, err))
		return
	}
}

func (fes *APIServer) PutMetamaskAirdropMetadata(metamaskAirdropMetadata *MetamaskAirdropMetadata) error {
	if metamaskAirdropMetadata == nil {
		return fmt.Errorf("PutMetamaskAirdropMetadata called with nil metadata struct")
	}
	globalStateVal := bytes.NewBuffer([]byte{})
	if err := gob.NewEncoder(globalStateVal).Encode(metamaskAirdropMetadata); err != nil {
		return fmt.Errorf("Failed to encode metamaskAirdropMetadata: %v", err)
	}
	if err := fes.GlobalState.Put(GlobalStateKeyMetamaskAirdrop(metamaskAirdropMetadata.PublicKey), globalStateVal.Bytes()); err != nil {
		return fmt.Errorf("GlobalState update failed: %v", err)
	}
	return nil
}

func (fes *APIServer) GetMetamaskAirdropMetadata(publicKey []byte) (*MetamaskAirdropMetadata, error) {
	// Check to see if they've received this airdrop
	existingMetamaskAirdropMetadataBytes, err := fes.GlobalState.Get(GlobalStateKeyMetamaskAirdrop(publicKey))
	if err != nil {
		return nil, fmt.Errorf("Error getting metamask airdrop from global state: %v", err)
	}
	if len(existingMetamaskAirdropMetadataBytes) == 0 {
		return nil, nil
	}
	existingMetamaskAirdropMetadata := MetamaskAirdropMetadata{}
	if err = gob.NewDecoder(bytes.NewReader(existingMetamaskAirdropMetadataBytes)).Decode(&existingMetamaskAirdropMetadata); err != nil {
		return nil, fmt.Errorf("Problem decoding bytes for metamask airdrop: %v", err)
	}
	return &existingMetamaskAirdropMetadata, nil
}

// ExecuteETHRPCRequest makes a request to Infura to fetch information about the Ethereum blockchain
func (fes *APIServer) ExecuteETHRPCRequest(method string, params []interface{}, useNetwork *string) (response *InfuraResponse, _err error) {
	projectId := fes.Config.InfuraProjectID
	if projectId == "" {
		return nil, fmt.Errorf("ExecuteETHRPCRequest: Project ID not set. Airdrop can only be " +
			"given if project ID is set via commandline flags when node is started")
	}
	var networkString string
	if useNetwork == nil {
		networkString = "mainnet"
		if fes.Params.NetworkType == lib.NetworkType_TESTNET {
			networkString = "goerli"
		}
	} else {
		if *useNetwork != "mainnet" && *useNetwork != "goerli" {
			return nil, fmt.Errorf("ExecuteETHRPCRequest: Invalid network type. Must be mainnet or goerli")
		}
		networkString = *useNetwork
	}
	URL := fmt.Sprintf("https://%v.infura.io/v3/%v", networkString, projectId)
	jsonData, err := json.Marshal(InfuraRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		Id:      1,
	})

	if err != nil {
		return nil, err
	}

	req, _ := http.NewRequest("POST", URL, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ExecuteETHRPCRequest: Problem with HTTP request %s: %v", URL, err)
	}
	defer resp.Body.Close()

	// Decode the response into the appropriate struct.
	body, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ExecuteETHRPCRequest: Infura returned an error: %v", string(body))
	}

	var responseData *InfuraResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err = decoder.Decode(&responseData); err != nil {
		return nil, fmt.Errorf("BlockCypherCreateETHTx: Problem decoding response JSON: %v, response: %v, error: %v", responseData, resp, err)
	}
	if len(responseData.Error.Message) > 0 {
		return nil, fmt.Errorf("ExecuteETHRPCRequest: RPC Error: %v", responseData.Error.Message)
	}
	return responseData, nil
}

// GetETHTransactionByHash is a helper function to fetch transaction details and parse it into an InfuraTx struct
func (fes *APIServer) GetETHTransactionByHash(hash string) (_tx *InfuraTx, _err error) {
	params := []interface{}{hash}
	txRes, err := fes.ExecuteETHRPCRequest("eth_getTransactionByHash", params, nil)
	if err != nil {
		return nil, err
	}
	var response *InfuraTx
	if err = mapstructure.Decode(txRes.Result, &response); err != nil {
		return nil, err
	}
	return response, nil
}
func publicKeyToEthAddress(address []byte) (str string, err error) {
	addressPubKey, err := btcutil.NewAddressPubKey(address, &chaincfg.MainNetParams)
	if err != nil {
		return "", errors.Wrapf(err,
			"publicKeyToEthAddress: problem getting eth public key, address: (%v)", err)
	}
	hash := sha3.NewLegacyKeccak256()
	hash.Write(addressPubKey.PubKey().SerializeUncompressed()[1:])
	sum := hash.Sum(nil)
	str = "0x" + hex.EncodeToString(sum[12:])
	return str, nil
}

type ETHNetwork string

const (
	UNDEFINED   ETHNetwork = ""
	ETH_MAINNET ETHNetwork = "mainnet"
	ETH_GOERLI  ETHNetwork = "goerli"
)

type EtherscanTransaction struct {
	BlockNumber       string `json:"blockNumber"`
	Timestamp         string `json:"timeStamp"`
	Hash              string `json:"hash"`
	Nonce             string `json:"nonce"`
	BlockHash         string `json:"blockHash"`
	TransactionIndex  string `json:"transactionIndex"`
	From              string `json:"from"`
	To                string `json:"to"`
	Value             string `json:"value"`
	Gas               string `json:"gas"`
	GasPrice          string `json:"gasPrice"`
	IsError           string `json:"isError"`
	TxreceiptStatus   string `json:"txreceipt_status"`
	Input             string `json:"input"`
	ContractAddress   string `json:"contractAddress"`
	CumulativeGasUsed string `json:"cumulativeGasUsed"`
	GasUsed           string `json:"gasUsed"`
	Confirmations     string `json:"confirmations"`
	MethodId          string `json:"methodId"`
	FunctionName      string `json:"functionName"`
}

type EtherscanTransactionsByAddressResponse struct {
	Status  string                 `json:"status"`
	Message string                 `json:"message"`
	Result  []EtherscanTransaction `json:"result"`
}

func (fes *APIServer) GetETHTransactionsForETHAddress(ww http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)

	ethAddress := vars["ethAddress"]

	ethNetworkString := req.URL.Query().Get("eth_network")
	if ethNetworkString != "" && ethNetworkString != string(ETH_MAINNET) && ethNetworkString != string(ETH_GOERLI) {
		_AddBadRequestError(ww, fmt.Sprintf("GetETHTransactionsForETHAddress: Invalid network type. Must be mainnet or goerli"))
		return
	}
	ethNetwork := ETHNetwork(ethNetworkString)
	if ethNetwork == UNDEFINED {
		ethNetwork = ETH_MAINNET
		if fes.Params.NetworkType == lib.NetworkType_TESTNET {
			ethNetwork = ETH_GOERLI
		}
	}
	ethTransactions, err := fes.GetETHTransactionsForETHAddressHandler(ethAddress, ethNetwork)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetETHTransactionsForETHAddress: Problem getting transactions for ETH address: %v", err))
		return
	}
	if err = json.NewEncoder(ww).Encode(ethTransactions); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetETHTransactionsForETHAddress: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) GetETHTransactionsForETHAddressHandler(
	ethAddress string,
	ethereumNetwork ETHNetwork,
) (*EtherscanTransactionsByAddressResponse, error) {
	etherscanAPIKey := fes.Config.EtherscanAPIKey
	if etherscanAPIKey == "" {
		return nil, fmt.Errorf("GetETHTransactionsForETHAddress: Etherscan API key not set")
	}
	var apiSuffix string
	if ethereumNetwork != ETH_MAINNET {
		apiSuffix = "-" + string(ethereumNetwork)
	}
	url := fmt.Sprintf(
		"https://api%v.etherscan.io/api?module=account&action=txlist&address=%v&apikey=%v",
		apiSuffix,
		ethAddress,
		etherscanAPIKey,
	)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GetETHTransactionsForETHAddress: Etherscan returned an error: %v", resp)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	responseData := &EtherscanTransactionsByAddressResponse{}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err = decoder.Decode(&responseData); err != nil {
		return nil, fmt.Errorf("GetETHTransactionsForETHAddress: Problem decoding response JSON: %v, response: %v, error: %v", responseData, resp, err)
	}
	return responseData, nil
}
