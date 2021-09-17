package routes

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/bitclout/core/lib"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"time"
)

func (fes *APIServer) IsConfiguredForETH() bool {
	return fes.Config.BuyBitCloutETHAddress != "" && fes.BlockCypherAPIKey != ""
}

type GetETHBalanceRequest struct {
	Address string
}

type GetETHBalanceResponse struct {
	Balance *big.Int
	Fees    *big.Int
}

func (fes *APIServer) GetETHBalance(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetETHBalanceRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetETHBalance: Problem parsing request body: %v", err))
		return
	}

	if !fes.IsConfiguredForETH() {
		_AddBadRequestError(ww, "GetETHBalance: Not configured for ETH")
		return
	}

	balance, err := fes.BlockCypherBalance(requestData.Address)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetETHBalance: Failed to get ETH balance: %v", err))
		return
	}

	// The only way to determine the fee BlockCypher wants to use is to create a useless transaction
	// and extract the gas price. We care about no fee data (errors are ok because zero balance addresses can't
	// create transactions).
	fees, err := fes.BlockCypherCreateETHTx(requestData.Address, big.NewInt(0))
	if fees == nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetETHFees: Failed to create fee transaction: %v", err))
		return
	}

	res := GetETHBalanceResponse{
		Balance: balance.FinalBalance,
		Fees:    fees.Tx.Fees,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetETHBalance: Problem encoding response: %v", err))
		return
	}
}

type CreateETHTxRequest struct {
	Address string
	Amount  *big.Int
}

type CreateETHTxResponse struct {
	Tx     BlockCypherTx
	ToSign []string
}

func (fes *APIServer) CreateETHTx(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := CreateETHTxRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateETHTx: Problem parsing request body: %v", err))
		return
	}

	if !fes.IsConfiguredForETH() {
		_AddBadRequestError(ww, "CreateETHTx: Not configured for ETH")
		return
	}

	// See GetETHBalance for fees explanation
	fees, err := fes.BlockCypherCreateETHTx(requestData.Address, big.NewInt(0))
	if fees == nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetETHFees: Failed to create fee transaction: %v", err))
		return
	}

	amountMinusFees := big.NewInt(0).Sub(requestData.Amount, fees.Tx.Fees)
	ethTx, err := fes.BlockCypherCreateETHTx(requestData.Address, amountMinusFees)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateETHTx: Failed to create ETH transaction: %v", err))
		return
	}

	res := CreateETHTxResponse{
		Tx:     ethTx.Tx,
		ToSign: ethTx.ToSign,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateETHTx: Problem encoding response: %v", err))
		return
	}
}

type SubmitETHTxRequest struct {
	PublicKeyBase58Check string
	Tx                   BlockCypherTx
	ToSign               []string
	SignedHashes         []string
}

type SubmitETHTxResponse struct {
	BitCloutTxnHash string
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

	// Verify there's only one signature
	if len(requestData.ToSign) != 1 || len(requestData.SignedHashes) != 1 {
		_AddBadRequestError(ww, "SubmitETHTx: Invalid number of signatures")
		return
	}

	// Normalize the signature to use low-S values by decoding and re-encoding
	sig, err := hex.DecodeString(requestData.SignedHashes[0])
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: Failed to decode SignedHash: %v", err))
		return
	}

	parsedSig, err := btcec.ParseDERSignature(sig, btcec.S256())
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: Parsing signature failed: %v", err))
		return
	}

	normalizedSig := hex.EncodeToString(parsedSig.Serialize())

	// Parse the public key
	pkBytes, _, err := lib.Base58CheckDecode(requestData.PublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: Invalid public key: %v", err))
		return
	}
	addressPubKey, err := btcutil.NewAddressPubKey(pkBytes, fes.Params.BitcoinBtcdParams)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: Invalid public key: %v", err))
		return
	}
	pubKey := addressPubKey.PubKey()

	signedHash, err := hex.DecodeString(requestData.ToSign[0])
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: Failed to decode ToSign: %v", err))
		return
	}

	// Verify the signature was signed by the public key we're going to pay
	validSignature := parsedSig.Verify(signedHash, pubKey)
	if !validSignature {
		_AddBadRequestError(ww, "SubmitETHTx: Invalid signature")
		return
	}

	// Verify only one deposit address
	if len(requestData.Tx.Outputs) != 1 || len(requestData.Tx.Outputs[0].Addresses) != 1 {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: Can only have one output"))
		return
	}

	// Verify the deposit address is correct
	configDepositAddress := strings.ToLower(fes.Config.BuyBitCloutETHAddress[2:])
	txDepositAddress := strings.ToLower(requestData.Tx.Outputs[0].Addresses[0])
	if configDepositAddress != txDepositAddress {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: Invalid deposit address: %s", txDepositAddress))
		return
	}

	// Record pending transaction in global state
	globalStateKey := GlobalStateKeyETHPurchases(requestData.Tx.Hash)
	if err = fes.GlobalStatePut(globalStateKey, []byte{0}); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: Error processing GlobalStatePut: %v", err))
		return
	}

	// Submit the transaction
	submitTx, err := fes.BlockCypherSubmitETHTx(requestData.Tx, requestData.ToSign, []string{normalizedSig})
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: Failed to submit ETH transaction: %v", err))
		return
	}

	// Wait up to 10 minutes
	// TODO: Long running requests are bad. Replace this with polling (or websockets etc)
	var ethTx *BlockCypherTx
	for i := 0; i < 60; i++ {
		// Check if the transaction was mined every 10 seconds
		time.Sleep(10 * time.Second)

		ethTx, err = fes.BlockCypherGetETHTx(submitTx.Tx.Hash)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: Failed to get ETH transaction: %v", err))
			return
		}

		// A block height means the transaction mined
		if ethTx.BlockHeight > 0 {
			break
		}
	}

	// Ensure the transaction mined
	if ethTx.BlockHeight < 0 {
		_AddBadRequestError(ww, "SubmitETHTx: Transaction failed to mine")
		return
	}

	// Fetch buy bitclout basis points fee
	feeBasisPoints, err := fes.GetBuyBitCloutFeeBasisPointsResponseFromGlobalState()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: Error getting buy fee basis points: %v", err))
		return
	}

	// Calculate nanos purchased
	totalWei := big.NewFloat(0).SetInt(ethTx.Total)
	totalEth := big.NewFloat(0).Quo(totalWei, big.NewFloat(1e18))
	nanosPurchased := fes.GetNanosFromETH(totalEth, feeBasisPoints)

	bitcloutTxnHash, err := fes.SendSeedBitClout(pkBytes, nanosPurchased, true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: Error sending BitClout: %v", err))
		return
	}

	// Record transaction success in global state
	if err = fes.GlobalStatePut(globalStateKey, []byte{1}); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: Error processing GlobalStatePut: %v", err))
		return
	}

	res := SubmitETHTxResponse{
		BitCloutTxnHash: bitcloutTxnHash.String(),
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitETHTx: Problem encoding response: %v", err))
		return
	}
}

//
// BlockCypher API
//

type BlockCypherTx struct {
	BlockHeight int64                 `json:"block_height"`
	BlockIndex  uint64                `json:"block_index"`
	Hash        string                `json:"hash"`
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
					fes.Config.BuyBitCloutETHAddress[2:], // Remove the 0x prefix
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
	if fes.Params.NetworkType == lib.NetworkType_TESTNET {
		URL = "https://api.blockcypher.com/v1/beth/test"
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
