package routes

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"github.com/deso-protocol/core/lib"
	"github.com/golang/glog"
	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
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

type TempRes struct {
	Result interface{}
}

func (fes *APIServer) validateETHTx(ethTx ETHTx, publicKey string) error {
	// Verify the deposit address is correct
	configDepositAddress := strings.ToLower(fes.Config.BuyDESOETHAddress)
	txDepositAddress := strings.ToLower(ethTx.To)
	if configDepositAddress != txDepositAddress {
		return errors.Errorf("Invalid deposit address: %s != %s", txDepositAddress, configDepositAddress)
	}

	return nil
}

func (fes *APIServer) validateInfuraETHTx(ethTx *InfuraTx) error {
	// Verify the deposit address is correct
	configDepositAddress := strings.ToLower(fes.Config.BuyDESOETHAddress)
	txDepositAddress := strings.ToLower(*ethTx.To)
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

	// Parse the public key
	pkBytes, _, err := lib.Base58CheckDecode(requestData.PublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: Invalid public key: %v", err))
		return
	}

	if err = fes.validateETHTx(requestData.Tx, requestData.PublicKeyBase58Check); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: Failed to validate transaction: %v", err))
		return
	}

	// Submit the transaction
	params := []interface{}{fmt.Sprintf("0x%v", requestData.SignedHashes[0])}
	response, err := fes.ExecuteETHRPCRequest("eth_sendRawTransaction", params)

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

	// what is my hash? Can I just use the signed hash?
	globalStateKey := GlobalStateKeyETHPurchases(hash)
	globalStateVal := bytes.NewBuffer([]byte{})
	if err = gob.NewEncoder(globalStateVal).Encode(ethTxLog); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: Failed to encode ETH transaction: %v", err))
		return
	}
	if err = fes.GlobalStatePut(globalStateKey, globalStateVal.Bytes()); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: Error processing GlobalStatePut: %v", err))
		return
	}


	// Wait up to 10 minutes
	// TODO: Long running requests are bad. Replace this with polling (or websockets etc)
	var ethTx *InfuraTx
	for i := 0; i < 60; i++ {
		// Check if the transaction was mined every 10 seconds
		time.Sleep(10 * time.Second)

		ethTx, err = fes.GetETHTransactionByHash(hash)
		if err != nil  {
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
	// The transaction has mined so we finish by validating the transaction again and paying the user.
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

// 1. Validate the transaction mined
// 2. Calculate the nanos to send
// 3. Send the nanos
// 4. Record the successful send
func (fes *APIServer) finishETHTx(ethTxIn *InfuraTx, ethTxLog *ETHTxLog) (desoTxHash *lib.BlockHash, _err error) {
	ethTx, err := fes.GetETHTransactionByHash(ethTxIn.Hash)
	if err != nil  {
		return nil, errors.New(fmt.Sprintf("Failed to get eth transaction: %v", err))
	}

	// Ensure the transaction mined
	if ethTx.BlockNumber == nil {
		return nil, errors.New("Transaction failed to mine")
	}

	if err = fes.validateInfuraETHTx(ethTx); err != nil {
		return nil, errors.New(fmt.Sprintf("Error validating Infura ETH Tx: %v", err))

	}

	// Fetch buy DESO basis points fee
	feeBasisPoints, err := fes.GetBuyDeSoFeeBasisPointsResponseFromGlobalState()
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error getting buy fee basis points: %v", err))
	}

	// Calculate nanos purchased
	var weiSent uint64
	// Strip the 0x prefix from the value attribute and parse hex string to uint64
	hexValueString := strings.Replace(ethTx.Value, "0x", "", -1)
	weiSent, err = strconv.ParseUint(hexValueString, 16, 64)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to convert wei hex to uint64: %v", err))
	}

	// Use big number math to convert wei to eth and then compute DESO nanos purchased.
	totalWei := big.NewFloat(0).SetInt64(int64(weiSent))
	totalEth := big.NewFloat(0).Quo(totalWei, big.NewFloat(1e18))
	nanosPurchased := fes.GetNanosFromETH(totalEth, feeBasisPoints)

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

	if err = fes.GlobalStatePut(globalStateKey, globalStateVal.Bytes()); err != nil {
		return nil, errors.New(fmt.Sprintf("Error processing GlobalStatePut: %v", err))
	}

	return desoTxHash, nil
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
	globalStateLog, err := fes.GlobalStateGet(globalStateKey)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminProcessETHTx: Error processing GlobalStateGet: %v", err))
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
	Id      uint64 `json:"id"`
	JSONRPC string `json:"jsonrpc"`
	Result  interface{} `json:"result"`
	Error   struct {
		Code float64 `json:"code"`
		Message string `json:"message"`
	}`json:"error"`
}

type InfuraTx struct {
	BlockHash        *string `json:"blockHash"`
	BlockNumber      *string `json:"blockNumber"`
	From             string `json:"from"`
	Gas              string `json:"gas"`
	GasPrice         string `json:"gasPrice"`
	Hash             string `json:"hash"`
	Input            string `json:"input"`
	Nonce            string `json:"nonce"`
	To               *string `json:"to"`
	TransactionIndex *string `json:"transactionIndex"`
	Value            string `json:"value"`
	V                string `json:"v"`
	R                string `json:"r"`
	S                string `json:"s"`
}

type QueryETHRPCRequest struct {
	Method               string
	Params               []interface{}
	JWT                  string
	PublicKeyBase58Check string
}

func (fes *APIServer) QueryETHRPC(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := QueryETHRPCRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("QueryETHRPC: Problem parsing request body: %v", err))
		return
	}
	isValid, err := fes.ValidateJWT(requestData.PublicKeyBase58Check, requestData.JWT)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("QueryETHRPC: error validating JWT: %v", err))
		return
	}
	if !isValid {
		_AddBadRequestError(ww, fmt.Sprintf("QueryETHRPC: Invalid token: %v", err))
		return
	}
	res, err := fes.ExecuteETHRPCRequest(requestData.Method, requestData.Params)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("QueryETHRPC: Error executing request: %v", err))
		return
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("QueryETHRPC: Problem encoding response: %v", err))
		return
	}
}

func (fes *APIServer) ExecuteETHRPCRequest(method string, params []interface{}) (response *InfuraResponse, _err error) {
	projectId := fes.Config.InfuraProjectID
	URL := fmt.Sprintf("https://mainnet.infura.io/v3/%v", projectId)
	if fes.Params.NetworkType == lib.NetworkType_TESTNET {
		URL = fmt.Sprintf("https://ropsten.infura.io/v3/%v", projectId)
	}

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
	var responseData *InfuraResponse //make(map[string]interface{})
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err = decoder.Decode(&responseData); err != nil {
		return nil, fmt.Errorf("BlockCypherCreateETHTx: Problem decoding response JSON: %v, response: %v, error: %v", responseData, resp, err)
	}
	if len(responseData.Error.Message) > 0 {
		return nil, fmt.Errorf("ExecuteETHRPCRequest: RPC Error: %v", responseData.Error.Message)
	}
	return responseData, nil
}

func (fes *APIServer) GetETHTransactionByHash(hash string) (_tx *InfuraTx, _err error) {
	params := []interface{}{hash}
	txRes, err := fes.ExecuteETHRPCRequest("eth_getTransactionByHash", params)
	if err != nil {
		return nil, err
	}
	var response *InfuraTx
	if err = mapstructure.Decode(txRes.Result, &response); err != nil {
		return nil, err
	}
	return response, nil
}

//
// BlockCypher API
//

type BlockCypherTx struct {
	BlockHeight int64                 `json:"block_height"`
	BlockIndex  uint64                `json:"block_index"`
	Hash        string                `json:"hash"`
	Hex         string                `json:"hex"`
	Addresses   []string              `json:"addresses"`
	Total       *big.Int              `json:"total"`
	Fees        *big.Int              `json:"fees"`
	Size        uint64                `json:"size"`
	GasUsed     *big.Int              `json:"gas_used"`
	GasPrice    *big.Int              `json:"gas_price"`
	RelayedBy   string                `json:"relayed_by"`
	Received    string                `json:"received"`
	Ver         uint64                `json:"ver"`
	DoubleSpend bool                  `json:"double_spend"`
	VinSz       uint64                `json:"vin_sz"`
	VoutSz      uint64                `json:"vout_sz"`
	Inputs      []BlockCypherTxInput  `json:"inputs"`
	Outputs     []BlockCypherTxOutput `json:"outputs"`
}

type BlockCypherTxInput struct {
	Addresses []string `json:"addresses"`
	Sequence  uint64   `json:"sequence"`
}

type BlockCypherTxOutput struct {
	Addresses []string `json:"addresses"`
	Value     *big.Int `json:"value"`
}

type BlockCypherCreateETHTxRequest struct {
	Inputs  []BlockCypherTxInput  `json:"inputs"`
	Outputs []BlockCypherTxOutput `json:"outputs"`
}

type BlockCypherCreateETHTxResponse struct {
	Tx     BlockCypherTx `json:"tx"`
	ToSign []string      `json:"tosign"`
}

func (fes *APIServer) BlockCypherCreateETHTx(ethAddress string, amount *big.Int) (*BlockCypherCreateETHTxResponse, error) {
	URL := "https://api.blockcypher.com/v1/eth/main/txs/new"
	if fes.Params.NetworkType == lib.NetworkType_TESTNET {
		URL = "https://api.blockcypher.com/v1/beth/test/txs/new"
	}

	jsonData, err := json.Marshal(BlockCypherCreateETHTxRequest{
		Inputs: []BlockCypherTxInput{
			{
				Addresses: []string{
					ethAddress[2:], // Remove the 0x prefix
				},
			},
		},
		Outputs: []BlockCypherTxOutput{
			{
				Addresses: []string{
					fes.Config.BuyDESOETHAddress[2:], // Remove the 0x prefix
				},
				Value: amount,
			},
		},
	})

	req, _ := http.NewRequest("POST", URL, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	q := req.URL.Query()
	q.Add("token", fes.BlockCypherAPIKey)
	req.URL.RawQuery = q.Encode()

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("BlockCypherCreateETHTx: Problem with HTTP request %s: %v", URL, err)
	}
	defer resp.Body.Close()

	// Decode the response into the appropriate struct.
	body, _ := ioutil.ReadAll(resp.Body)
	responseData := &BlockCypherCreateETHTxResponse{}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(responseData); err != nil {
		return nil, fmt.Errorf("BlockCypherCreateETHTx: Problem decoding response JSON: %v, response: %v, error: %v", responseData, resp, err)
	}

	// API returns a 201 for Created
	if resp.StatusCode != 201 {
		return responseData, fmt.Errorf("BlockCypherCreateETHTx: Error code returned from BlockCypher: %v %v", resp.StatusCode, string(body))
	}

	return responseData, nil
}

type BlockCypherSubmitETHTxRequest struct {
	Tx         BlockCypherTx `json:"tx"`
	ToSign     []string      `json:"tosign"`
	Signatures []string      `json:"signatures"`
}

type BlockCypherSubmitETHTxResponse struct {
	Tx BlockCypherTx `json:"tx"`
}

func (fes *APIServer) BlockCypherSubmitETHTx(tx BlockCypherTx, toSign []string, signatures []string) (*BlockCypherSubmitETHTxResponse, error) {
	URL := "https://api.blockcypher.com/v1/eth/main/txs/send"
	if fes.Params.NetworkType == lib.NetworkType_TESTNET {
		URL = "https://api.blockcypher.com/v1/beth/test/txs/send"
	}

	jsonData, err := json.Marshal(BlockCypherSubmitETHTxRequest{
		Tx:         tx,
		ToSign:     toSign,
		Signatures: signatures,
	})

	req, _ := http.NewRequest("POST", URL, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	q := req.URL.Query()
	q.Add("token", fes.BlockCypherAPIKey)
	req.URL.RawQuery = q.Encode()

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("BlockCypherCreateETHTx: Problem with HTTP request %s: %v", URL, err)
	}
	defer resp.Body.Close()

	// API returns a 201 for Created
	if resp.StatusCode != 201 {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("BlockCypherSubmitETHTx: Error code returned from BlockCypher: %v %v", resp.StatusCode, string(body))
	}

	// Decode the response into the appropriate struct.
	body, _ := ioutil.ReadAll(resp.Body)
	responseData := &BlockCypherSubmitETHTxResponse{}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(responseData); err != nil {
		return nil, fmt.Errorf("BlockCypherSubmitETHTx: Problem decoding response JSON: %v, response: %v, error: %v", responseData, resp, err)
	}

	return responseData, nil
}

type BlockCypherBalanceResponse struct {
	Address            string   `json:"address"`
	TotalReceived      *big.Int `json:"total_received"`
	TotalSent          *big.Int `json:"total_sent"`
	Balance            *big.Int `json:"balance"`
	UnconfirmedBalance *big.Int `json:"unconfirmed_balance"`
	FinalBalance       *big.Int `json:"final_balance"`
	NTx                uint64   `json:"n_tx"`
	UnconfirmedNTx     uint64   `json:"unconfirmed_n_tx"`
	FinalNTx           uint64   `json:"final_n_tx"`
}

func (fes *APIServer) BlockCypherBalance(address string) (*BlockCypherBalanceResponse, error) {
	URL := fmt.Sprintf("https://api.blockcypher.com/v1/eth/main/addrs/%s/balance", address)
	if fes.Params.NetworkType == lib.NetworkType_TESTNET {
		URL = fmt.Sprintf("https://api.blockcypher.com/v1/beth/test/addrs/%s/balance", address)
	}

	req, _ := http.NewRequest("GET", URL, nil)
	q := req.URL.Query()
	q.Add("token", fes.BlockCypherAPIKey)
	req.URL.RawQuery = q.Encode()

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("BlockCypherBalance: Problem with HTTP request %s: %v", URL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("BlockCypherBalance: Error code returned from BlockCypher: %v %v", resp.StatusCode, string(body))
	}

	// Decode the response into the appropriate struct.
	body, _ := ioutil.ReadAll(resp.Body)
	responseData := &BlockCypherBalanceResponse{}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(responseData); err != nil {
		return nil, fmt.Errorf("BlockCypherBalance: Problem decoding response JSON: %v, response: %v, error: %v", responseData, resp, err)
	}

	return responseData, nil
}

type BlockCypherBlockchainResponse struct {
	Name             string    `json:"name"`
	Height           int       `json:"height"`
	Hash             string    `json:"hash"`
	Time             time.Time `json:"time"`
	LatestUrl        string    `json:"latest_url"`
	PreviousHash     string    `json:"previous_hash"`
	PreviousUrl      string    `json:"previous_url"`
	PeerCount        int       `json:"peer_count"`
	UnconfirmedCount int       `json:"unconfirmed_count"`
	HighGasPrice     *big.Int  `json:"high_gas_price"`
	MediumGasPrice   *big.Int  `json:"medium_gas_price"`
	LowGasPrice      *big.Int  `json:"low_gas_price"`
	LastForkHeight   int       `json:"last_fork_height"`
	LastForkHash     string    `json:"last_fork_hash"`
}

func (fes *APIServer) BlockCypherBlockchain() (*BlockCypherBlockchainResponse, error) {
	URL := "https://api.blockcypher.com/v1/eth/main"
	//if fes.Params.NetworkType == lib.NetworkType_TESTNET {
	//	URL = "https://api.blockcypher.com/v1/beth/test"
	//}

	req, _ := http.NewRequest("GET", URL, nil)
	q := req.URL.Query()
	q.Add("token", fes.BlockCypherAPIKey)
	req.URL.RawQuery = q.Encode()

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("BlockCypherBalance: Problem with HTTP request %s: %v", URL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("BlockCypherBalance: Error code returned from BlockCypher: %v %v", resp.StatusCode, string(body))
	}

	// Decode the response into the appropriate struct.
	body, _ := ioutil.ReadAll(resp.Body)
	responseData := &BlockCypherBlockchainResponse{}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(responseData); err != nil {
		return nil, fmt.Errorf("BlockCypherBalance: Problem decoding response JSON: %v, response: %v, error: %v", responseData, resp, err)
	}

	return responseData, nil
}

func (fes *APIServer) BlockCypherGetETHTx(txnHash string) (*BlockCypherTx, error) {
	URL := fmt.Sprintf("https://api.blockcypher.com/v1/eth/main/txs/%s", txnHash)
	if fes.Params.NetworkType == lib.NetworkType_TESTNET {
		URL = fmt.Sprintf("https://api.blockcypher.com/v1/beth/test/txs/%s", txnHash)
	}

	req, _ := http.NewRequest("GET", URL, nil)
	q := req.URL.Query()
	q.Add("token", fes.BlockCypherAPIKey)
	q.Add("includeHex", "true")
	req.URL.RawQuery = q.Encode()

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("BlockCypherGetETHTx: Problem with HTTP request %s: %v", URL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("BlockCypherGetETHTx: Error code returned from BlockCypher: %v %v", resp.StatusCode, string(body))
	}

	// Decode the response into the appropriate struct.
	body, _ := ioutil.ReadAll(resp.Body)
	responseData := &BlockCypherTx{}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(responseData); err != nil {
		return nil, fmt.Errorf("BlockCypherGetETHTx: Problem decoding response JSON: %v, response: %v, error: %v", responseData, resp, err)
	}

	return responseData, nil
}

func (fes *APIServer) EtherscanSendRawTransaction(txHex string) {
	URL := "https://api.etherscan.io/api"

	req, _ := http.NewRequest("GET", URL, nil)
	q := req.URL.Query()
	q.Add("module", "proxy")
	q.Add("action", "eth_sendRawTransaction")
	q.Add("hex", txHex)
	// TODO: Make this a configuration value. This method is probably being deleted soon so we're leaving it for now
	q.Add("apikey", "21QBFB9E8JRCAY9G9N8FTJRSY9P9M6RTSR")
	req.URL.RawQuery = q.Encode()

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		glog.Errorf("EtherscanSendRawTransaction: Problem with HTTP request %s: %v", URL, err)
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		glog.Errorf("EtherscanSendRawTransaction: Error code returned from BlockCypher: %v %v", resp.StatusCode, string(body))
		return
	}

	glog.Infof("EtherscanSendRawTransaction: %s", string(body))
}
