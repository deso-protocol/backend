package routes

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/bitclout/core/lib"
	"github.com/btcsuite/btcd/btcec"
	"github.com/dgraph-io/badger/v3"
	"io"
	"io/ioutil"
	"math"
	"net/http"
	"time"
)

type WyreWalletOrderWebhookPayload struct {
	// referenceId holds the public key of the user who made initiated the wallet order
	ReferenceId string `json:"referenceId"`
	AccountId string `json:"accountId"`
	OrderId string `json:"orderId"`
	OrderStatus string `json:"orderStatus"`
	TransferId string `json:"transferId"`
	FailedReason string `json:"failedReason"`
}

type WyreWalletOrderFullDetails struct {
	Id string `json:"id"`
	CreatedAt uint64 `json:"createdAt"`
	Owner string `json:"owner"`
	Status string `json:"status"`
	OrderType string `json:"orderType"`
	SourceAmount float64 `json:"sourceAmount"`
	PurchaseAmount float64 `json:"purchaseAmount"`
	SourceCurrency string `json:"sourceCurrency"`
	DestCurrency string `json:"destCurrency"`
	TransferId string `json:"transferId"`
	Dest string `json:"dest"`
	AuthCodesRequested bool `json:"authCodesRequested"`
	ErrorCategory string `json:"errorCategory"`
	ErrorCode string `json:"errorCode"`
	ErrorMessage string `json:"errorMessage"`
	FailureReason string `json:"failureReason"`
	AccountId string `json:"accountId"`
	PaymentNetworkErrorCode string `json:"paymentNetworkErrorCode"`
	InternalErrorCode string `json:"internalErrorCode"`
}

type WyreTransferDetails struct {
	Owner              string      `json:"owner"`
	ReversingSubStatus interface{} `json:"reversingSubStatus"`
	Source             string      `json:"source"`
	PendingSubStatus   interface{} `json:"pendingSubStatus"`
	Status             string      `json:"status"`
	ReversalReason     interface{} `json:"reversalReason"`
	CreatedAt          int64       `json:"createdAt"`
	SourceAmount       float64     `json:"sourceAmount"`
	DestCurrency       string      `json:"destCurrency"`
	SourceCurrency     string      `json:"sourceCurrency"`
	StatusHistories    []struct {
		Id           string      `json:"id"`
		TransferId   string      `json:"transferId"`
		CreatedAt    int64       `json:"createdAt"`
		Type         string      `json:"type"`
		StatusOrder  int         `json:"statusOrder"`
		StatusDetail string      `json:"statusDetail"`
		State        string      `json:"state"`
		FailedState  interface{} `json:"failedState"`
	} `json:"statusHistories"`
	BlockchainTx struct {
		Id            string      `json:"id"`
		NetworkTxId   string      `json:"networkTxId"`
		CreatedAt     int64       `json:"createdAt"`
		Confirmations int         `json:"confirmations"`
		TimeObserved  int64       `json:"timeObserved"`
		BlockTime     int64       `json:"blockTime"`
		Blockhash     string      `json:"blockhash"`
		Amount        float64     `json:"amount"`
		Direction     string      `json:"direction"`
		NetworkFee    float64     `json:"networkFee"`
		Address       string      `json:"address"`
		SourceAddress interface{} `json:"sourceAddress"`
		Currency      string      `json:"currency"`
		TwinTxId      interface{} `json:"twinTxId"`
	} `json:"blockchainTx"`
	ExpiresAt     int64       `json:"expiresAt"`
	CompletedAt   int64       `json:"completedAt"`
	CancelledAt   interface{} `json:"cancelledAt"`
	FailureReason interface{} `json:"failureReason"`
	UpdatedAt     int64       `json:"updatedAt"`
	ExchangeRate  float64     `json:"exchangeRate"`
	DestAmount    float64     `json:"destAmount"`
	Fees          struct {
		BTC int     `json:"BTC"`
		USD float64 `json:"USD"`
	} `json:"fees"`
	TotalFees float64     `json:"totalFees"`
	CustomId  string      `json:"customId"`
	Dest      string      `json:"dest"`
	Message   interface{} `json:"message"`
	Id        string      `json:"id"`
}

func (fes *APIServer) WyreWalletOrderSubscription(ww http.ResponseWriter, req *http.Request) {
	// If this node has not integrated with Wyre, bail immediately.
	if !fes.IsConfiguredForWyre() {
		_AddBadRequestError(ww, fmt.Sprintf("WyreWalletOrderSubscription: This node is not configured with Wyre"))
		return
	}

	// Decode the request body
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	wyreWalletOrderWebhookRequest := WyreWalletOrderWebhookPayload{}
	if err := decoder.Decode(&wyreWalletOrderWebhookRequest); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("WyreWalletOrderSubscription: Error parsing request body: %v", err))
		return
	}

	orderId := wyreWalletOrderWebhookRequest.OrderId
	publicKey := wyreWalletOrderWebhookRequest.ReferenceId
	publicKeyBytes, _, err := lib.Base58CheckDecode(publicKey)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("WyreWalletOrderSubscription: error decoding public key %v: %v", publicKey, err))
		return
	}
	// Get the current Wyre Order Metadata from global state
	currentWyreWalletOrderMetadata, err := fes.GetWyreWalletOrderMetadataFromGlobalState(publicKey, orderId)

	// Initialize the new Wyre Order Metadata object based on the current wallet order metadata (if it exists)
	// and the current payload.
	newMetadataObj := WyreWalletOrderMetadata{
		LatestWyreWalletOrderWebhookPayload: wyreWalletOrderWebhookRequest,
	}

	if currentWyreWalletOrderMetadata != nil {
		newMetadataObj.LatestWyreWalletOrderFullDetails = currentWyreWalletOrderMetadata.LatestWyreWalletOrderFullDetails
		newMetadataObj.BitCloutPurchasedNanos = currentWyreWalletOrderMetadata.BitCloutPurchasedNanos
		newMetadataObj.BasicTransferTxnBlockHash = currentWyreWalletOrderMetadata.BasicTransferTxnBlockHash
	}

	// Make a client
	client := &http.Client{}

	// Get the full wallet order details
	var wyreWalletOrderFullDetails *WyreWalletOrderFullDetails
	wyreWalletOrderFullDetails, err = fes.GetFullWalletOrderDetails(client, orderId)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("WyreWalletOrderSubscription: error gettin full order details: %v. Webhook Payload: %v", err, wyreWalletOrderWebhookRequest))
		return
	}

	// Set the latest wyre wallet order full details to the details we just fetched.
	newMetadataObj.LatestWyreWalletOrderFullDetails = wyreWalletOrderFullDetails

	transferId := wyreWalletOrderFullDetails.TransferId

	// If there is a transferId, we need to get the transfer details, update the new metadata object and pay out
	// bitclout if it has not been paid out yet.
	if transferId != "" {
		// Get the transfer details from Wyre
		var wyreTransferDetails *WyreTransferDetails
		wyreTransferDetails, err = fes.GetTransferDetails(client, transferId)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("WyreWalletOrderSubscription: error getting transfer details: %v", err))
			return
		}
		newMetadataObj.LatestWyreTransferDetails = wyreTransferDetails

		// Get utxoView to get the current amount of nanos purchased, so we can compute the current price of CLOUT in BTC
		var utxoView *lib.UtxoView
		utxoView, err = fes.backendServer.GetMempool().GetAugmentedUniversalView()
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("WyreWalletOrderSubscription: error getting utxoview: %v", err))
			return
		}

		// If the amount of BTC purchased is greater than 0, compute how much BitClout to pay out if it has not been
		// paid out yet.
		btcPurchased := wyreTransferDetails.BlockchainTx.Amount
		if btcPurchased > 0 {
			startNanos := utxoView.NanosPurchased
			// BTC Purchased is in whole bitcoins, so multiply it by 10^8 to convert to Satoshis
			satsPurchased := uint64(btcPurchased * math.Pow(10, 8))
			usdCentsPerBitcoin := utxoView.GetCurrentUSDCentsPerBitcoin()
			// Get the current Satoshis / CLOUT-nano exchange rate
			satoshisPerUnit := lib.GetSatoshisPerUnitExchangeRate(startNanos, usdCentsPerBitcoin)
			// Assess a 1% fee
			nodeFee := satoshisPerUnit / 100
			bitcloutToSend := satsPurchased / (satoshisPerUnit + nodeFee)
			// Make sure this order hasn't been paid out, then mark it as paid out.
			wyreOrderIdKey := GlobalStateKeyForWyreOrderIDProcessed([]byte(orderId))
			// We expect badger to return a key not found error if BitClout has been paid out for this order.
			// If it does not return an error, BitClout has already been paid out, so we skip ahead.
			_, err = fes.GlobalStateGet(wyreOrderIdKey)
			if err == badger.ErrKeyNotFound {
				// Mark this order as paid out
				if err = fes.GlobalStatePut(wyreOrderIdKey, []byte{}); err != nil {
					_AddBadRequestError(ww, fmt.Sprintf("WyreWalletOrderSubscription: error marking orderId %v as paid out: %v", orderId, err))
					return
				}
				// Pay out bitclout to send to the public key
				var txnHash *lib.BlockHash
				txnHash, err = fes.SendSeedBitClout(publicKeyBytes, bitcloutToSend)
				if err != nil {
					_AddBadRequestError(ww, fmt.Sprintf("WyreWalletOrderSubscription: error paying out bitclout: %v", err))
					// In the event that sending the bitclout to the public key fails for some reason, we will "unmark"
					// this order as paid in global state
					err = fes.GlobalStateDelete(wyreOrderIdKey)
					if err != nil {
						_AddBadRequestError(ww, fmt.Sprintf("WyreWalletOrderSubscription: error deleting order id key when failing to payout bitclout: %v", err))
					}
					return
				}
				// Set the basic transfer txn hash and bitclout purchased nanos of the metadata object
				newMetadataObj.BasicTransferTxnBlockHash = txnHash
				newMetadataObj.BitCloutPurchasedNanos = bitcloutToSend
			}
		}
	}
	// Update global state
	fes.UpdateWyreGlobalState(ww, publicKeyBytes, orderId, newMetadataObj)
}

func (fes *APIServer) GetFullWalletOrderDetails(client *http.Client, orderId string) (_wyreWalletOrderFullDetails *WyreWalletOrderFullDetails, _err error){
	// Make a request and set the headers
	getFullDetails, err := http.NewRequest("GET", fmt.Sprintf("%v/v3/orders/%v/full?timestamp=%v", fes.WyreUrl, orderId, uint64(time.Now().UnixNano())), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating get full order details request: %v", err)
	}
	getFullDetails = fes.SetWyreRequestHeaders(getFullDetails, nil)
	// Execute the request and handle errors
	orderDetailsResp, err := client.Do(getFullDetails)
	if err != nil {
		return nil, fmt.Errorf("error getting full order details: %v", err)
	}
	if orderDetailsResp == nil {
		return nil, fmt.Errorf("full order details response is nil")
	}
	// If the response is not a 200, raise an error.
	if orderDetailsResp.StatusCode != 200 {
		return nil, fmt.Errorf("get full order details returned non 200 response: %v", orderDetailsResp.StatusCode)
	}
	defer orderDetailsResp.Body.Close()

	// Read the order details body and unmarshal it
	orderDetailsBodyBytes, err := ioutil.ReadAll(orderDetailsResp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading body for full order details: %v", err)
	}

	var wyreWalletOrderFullDetails *WyreWalletOrderFullDetails
	err = json.Unmarshal(orderDetailsBodyBytes, &wyreWalletOrderFullDetails)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling JSON from full order details bytes: %v", err)
	}

	// If the wallet order's destination does not match the configured address, that is an error.
	if wyreWalletOrderFullDetails.Dest != fes.GetBTCAddress() {
		return nil, fmt.Errorf("wyre wallet order's btc address (%v) does not match node's configured btc address (%v)", wyreWalletOrderFullDetails.Dest, fes.GetBTCAddress())
	}
	return wyreWalletOrderFullDetails, nil
}

func (fes *APIServer) GetTransferDetails(client *http.Client, transferId string) (_wyreTransferDetails *WyreTransferDetails, _err error) {
	// Make the request and set the headers
	getTransferDetails, err := http.NewRequest("GET", fmt.Sprintf("%v/v3/transfers/%v?timestamp=%v", fes.WyreUrl, transferId, uint64(time.Now().UnixNano())), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating get wyre transfer request for transferId %v: %v", transferId, err)
	}
	getTransferDetails = fes.SetWyreRequestHeaders(getTransferDetails, nil)
	// Execute the request and handle errors
	transferDetailsResp, err := client.Do(getTransferDetails)
	if err != nil {
		return nil, fmt.Errorf("error getting wyre transfer details for transferId %v: %v", transferId, err)
	}

	if transferDetailsResp == nil {
		return nil, fmt.Errorf("transfer details response is nil")
	}
	// If the response is not a 200, raise an error.
	if transferDetailsResp.StatusCode != 200 {
		// what is the appropriate way to handle these errors.
		return nil, fmt.Errorf("transfer details responded with a non-200 status code of %v", transferDetailsResp.StatusCode)
	}
	defer transferDetailsResp.Body.Close()

	// Read the response body and unmarshal it
	transferDetailsBodyBytes, err := ioutil.ReadAll(transferDetailsResp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading body for transfer details: %v", err)
	}

	var wyreTransferDetails *WyreTransferDetails
	if err = json.Unmarshal(transferDetailsBodyBytes, &wyreTransferDetails); err != nil {
		return nil, fmt.Errorf("error unmarshaling JSON from transfer details bytes: %v", err)
	}
	return wyreTransferDetails, nil
}

func (fes *APIServer) UpdateWyreGlobalState(ww http.ResponseWriter, publicKeyBytes []byte, orderId string, wyreWalletOrderMetadata WyreWalletOrderMetadata) {
	// Construct the key for accessing the wyre order metadata
	globalStateKey := GlobalStateKeyForUserPublicKeyWyreOrderIDToWyreOrderMetadata(publicKeyBytes, []byte(orderId))
	// Encode the WyreWalletOrderMetadata
	wyreWalletOrderMetadataBuf := bytes.NewBuffer([]byte{})
	gob.NewEncoder(wyreWalletOrderMetadataBuf).Encode(wyreWalletOrderMetadata)
	// Put the metadata in GlobalState
	err := fes.GlobalStatePut(globalStateKey, wyreWalletOrderMetadataBuf.Bytes())
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("Update Wyre Global state failed: %v", err))
		return
	}
}

type WalletOrderQuotationRequest struct {
	SourceAmount float64
}

type WyreWalletOrderQuotationPayload struct {
	SourceCurrency string `json:"sourceCurrency"`
	Dest string `json:"dest"`
	DestCurrency string `json:"destCurrency"`
	AmountIncludeFees bool `json:"amountIncludeFees"`
	Country string `json:"country"`
	SourceAmount string `json:"sourceAmount"`
	WalletType string `json:"walletType"`
	AccountId string `json:"accountId"`
}

func (fes *APIServer) GetWyreWalletOrderQuotation(ww http.ResponseWriter, req *http.Request) {
	// Exit immediately if this node has not integrated with Wyre
	if !fes.IsConfiguredForWyre() {
		_AddBadRequestError(ww, fmt.Sprintf("HandleWyreWalletOrderWebhook: This node is not configured with Wyre"))
		return
	}
	// Decode the request body
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	wyreWalletOrderQuotationRequest := WalletOrderQuotationRequest{}
	if err := decoder.Decode(&wyreWalletOrderQuotationRequest); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetWyreWalletOrderQuotation: Error parsing request body: %v", err))
		return
	}
	// Make and marshal the payload
	body := WyreWalletOrderQuotationPayload{
		AccountId: fes.WyreAccountId,
		Dest: fmt.Sprintf("bitcoin:%v", fes.WyreBTCAddress),
		AmountIncludeFees: true,
		DestCurrency: "BTC",
		SourceCurrency: "USD",
		Country: "US",
		WalletType: "DEBIT_CARD",
		SourceAmount: fmt.Sprintf("%f", wyreWalletOrderQuotationRequest.SourceAmount),
	}

	payload, err := json.Marshal(body)
	if err != nil {
		// do something with this error
		return
	}

	// Construct the URL
	url := fmt.Sprintf("%v/v3/orders/quote/partner?timestamp=%v", fes.WyreUrl, uint64(time.Now().UnixNano()))

	// Make the request get an order reservation to Wyre
	fes.MakeWyreRequest(payload, url, ww)
}

type WalletOrderReservationRequest struct {
	SourceAmount float64
	ReferenceId string
}

type WyreWalletOrderReservationPayload struct {
	SourceCurrency string `json:"sourceCurrency"`
	Dest string `json:"dest"`
	DestCurrency string `json:"destCurrency"`
	AmountIncludeFees bool `json:"amountIncludeFees"`
	Country string `json:"country"`
	SourceAmount string `json:"sourceAmount"`
	PaymentMethod string `json:"paymentMethod"`
	ReferrerAccountId string `json:"referrerAccountId"`
	LockFields []string `json:"lockFields"`
	RedirectUrl string `json:"redirectUrl"`
	ReferenceId string `json:"referenceId"`
}

func (fes *APIServer) GetWyreWalletOrderReservation(ww http.ResponseWriter, req *http.Request) {
	// Exit immediately if this node has not integrated with Wyre
	if !fes.IsConfiguredForWyre() {
		_AddBadRequestError(ww, fmt.Sprintf("HandleWyreWalletOrderWebhook: This node is not configured with Wyre"))
		return
	}
	// Decode the request body
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	wyreWalletOrderReservationRequest := WalletOrderReservationRequest{}
	if err := decoder.Decode(&wyreWalletOrderReservationRequest); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetWyreWalletOrderReservation: Error parsing request body: %v", err))
		return
	}
	// Make and marshal the payload
	body := WyreWalletOrderReservationPayload{
		ReferrerAccountId: fes.WyreAccountId,
		Dest: fes.GetBTCAddress(),
		AmountIncludeFees: true,
		DestCurrency: "BTC",
		SourceCurrency: "USD",
		Country: "US",
		PaymentMethod: "debit-card",
		SourceAmount: fmt.Sprintf("%f", wyreWalletOrderReservationRequest.SourceAmount),
		LockFields: []string{"dest", "destCurrency"},
		RedirectUrl: fmt.Sprintf("%v/buy-bitclout", req.Host),
		ReferenceId: wyreWalletOrderReservationRequest.ReferenceId,
	}

	payload, err := json.Marshal(body)
	if err != nil {
		// do something with this error
		return
	}

	// Construct the URL
	url := fmt.Sprintf("%v/v3/orders/reserve?timestamp=%v", fes.WyreUrl, uint64(time.Now().UnixNano()))

	// Make the request get an order reservation to Wyre.
	fes.MakeWyreRequest(payload, url, ww)
}

func (fes *APIServer) MakeWyreRequest(payload []byte, url string, ww http.ResponseWriter) {
	// Create a new buffer and request
	payloadBytes := bytes.NewBuffer(payload)
	wyreReq, err := http.NewRequest("POST", url, payloadBytes)

	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("Problem creating new wyre request: %v", err))
		return
	}

	// Set the wyre headers appropriately
	wyreReq = fes.SetWyreRequestHeaders(wyreReq, payloadBytes.Bytes())

	// Perform the POST request
	client := &http.Client{}
	resp, err := client.Do(wyreReq)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("Problem executing wyre request: %v", err))
		return
	}
	defer resp.Body.Close()

	// Read the response body and write it to the response writer
	wyreResponseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("Problem reading wyre response: %v", err))
		return
	}

	if _, err = ww.Write(wyreResponseBody); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("Problem writing wyte response: %v", err))
		return
	}
}


func (fes *APIServer) GetWyreWalletOrderMetadataFromGlobalState(publicKey string, orderId string) (*WyreWalletOrderMetadata, error) {
	// Decode the public get and get the key to access the Wyre Order Metadata
	publicKeyBytes, _, err := lib.Base58CheckDecode(publicKey)
	if err != nil {
		return nil, err
	}
	globalStateKey := GlobalStateKeyForUserPublicKeyWyreOrderIDToWyreOrderMetadata(publicKeyBytes, []byte(orderId))

	// Get Wyre Order Metadata from global state and decode it
	currentWyreWalletOrderMetadataBytes, err := fes.GlobalStateGet(globalStateKey)
	if err != nil {
		return nil, err
	}
	currentWyreWalletOrderMetadata := &WyreWalletOrderMetadata{}
	err = gob.NewDecoder(bytes.NewReader(currentWyreWalletOrderMetadataBytes)).Decode(currentWyreWalletOrderMetadata)
	if err != nil {
		// do somethign with this error
		return nil, err
	}
	return currentWyreWalletOrderMetadata, err
}

func (fes *APIServer) SetWyreRequestHeaders(req *http.Request, dataBytes []byte) *http.Request {
	// Set the API Key and Content type headers
	req.Header.Set("X-Api-Key", fes.WyreApiKey)
	req.Header.Set("Content-Type", "application/json")

	// Wyre expects the signature to be HEX encoded HMAC with SHA-256 and the Wyre secret key
	// the message will be the URL + the data (if it is a GET request, data will be nil
	// For more details, see this link: https://docs.sendwyre.com/docs/authentication#secret-key-signature-auth
	h := hmac.New(sha256.New, []byte(fes.WyreSecretKey))
	h.Write([]byte(req.URL.String()))
	h.Write(dataBytes)
	req.Header.Set("X-Api-Signature", hex.EncodeToString(h.Sum(nil)))
	return req
}

func (fes *APIServer) GetBTCAddress() string {
	return fmt.Sprintf("bitcoin:%v", fes.WyreBTCAddress)
}

type GetWyreWalletOrderForPublicKeyRequest struct {
	PublicKeyBase58Check string
	Username string
}

type GetWyreWalletOrderForPublicKeyResponse struct {
	WyreWalletOrderMetadataResponses []*WyreWalletOrderMetadata
}

func (fes *APIServer) GetWyreWalletOrdersForPublicKey(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetWyreWalletOrderForPublicKeyRequest{}
	var err error
	if err = decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetWyreWalletOrdersForPublicKey: Error parsing request body: %v", err))
		return
	}

	var publicKeyBytes []byte
	if requestData.PublicKeyBase58Check != "" {
		publicKeyBytes, _, err = lib.Base58CheckDecode(requestData.PublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetWyreWalletOrdersForPublicKey: error decoding public key %v: %v", requestData.PublicKeyBase58Check, err))
			return
		}
	} else if requestData.Username != "" {
		var utxoView *lib.UtxoView
		utxoView, err = fes.backendServer.GetMempool().GetAugmentedUniversalView()
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetWyreWalletOrdersForPublicKey: error getting utxoview: %v", err))
			return
		}
		profileEntry := utxoView.GetProfileEntryForUsername([]byte(requestData.Username))
		if profileEntry == nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetWyreWalletOrdersForPublicKey: error getting profile entry for username %v", requestData.Username))
			return
		}
		publicKeyBytes = profileEntry.PublicKey
	} else {
		_AddBadRequestError(ww, "GetWyreWalletOrdersForPublicKey: must provide either a public key or username")
		return
	}
	var values [][]byte
	// 1 + max length of public key + max length of wyre order id
	maxKeyLen := 1 + btcec.PubKeyBytesLenCompressed + 15
	prefix := GlobalStateKeyForUserPublicKeyWyreOrderIDToWyreOrderMetadata(publicKeyBytes, []byte{})
	_, values, err = fes.GlobalStateSeek(prefix, prefix, maxKeyLen, 100, false, true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetWyreWalletOrdersForPublicKey: error getting wyre order metadata from global state"))
		return
	}

	res := &GetWyreWalletOrderForPublicKeyResponse{
		WyreWalletOrderMetadataResponses: []*WyreWalletOrderMetadata{},
	}
	for _, wyreOrderMetadataBytes := range values {
		var wyreOrderMetadata *WyreWalletOrderMetadata
		err = gob.NewDecoder(bytes.NewReader(wyreOrderMetadataBytes)).Decode(&wyreOrderMetadata)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetWyreWalletOrdersForPublicKey: error decoding order: %v", wyreOrderMetadataBytes))
			return
		}
		res.WyreWalletOrderMetadataResponses = append(res.WyreWalletOrderMetadataResponses, wyreOrderMetadata)
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetWyreWalletOrdersForPublicKey: Problem encoding response as JSON: #{err}"))
		return
	}
}

func (fes *APIServer) IsConfiguredForWyre() bool {
	return fes.WyreBTCAddress != "" &&
		fes.WyreUrl != "" &&
		fes.WyreAccountId != "" &&
		fes.WyreSecretKey != "" &&
		fes.WyreApiKey != ""
}
