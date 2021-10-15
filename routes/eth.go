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

	// Parse the public key
	pkBytes, _, err := lib.Base58CheckDecode(requestData.PublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: Invalid public key: %v", err))
		return
	}

	if err = fes.validateETHDepositAddress(requestData.Tx.To); err != nil {
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

	if err = fes.validateETHDepositAddress(*ethTx.To); err != nil {
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

// QueryETHRPC is an endpoint used to execute queries through Infura
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

// ExecuteETHRPCRequest makes a request to Infura to fetch information about the Ethereum blockchain
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
