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
	"github.com/fatih/structs"
	"github.com/golang/glog"
	"io"
	"io/ioutil"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type WyreWalletOrderWebhookPayload struct {
	// referenceId holds the public key of the user who made initiated the wallet order
	ReferenceId  string `json:"referenceId"`
	AccountId    string `json:"accountId"`
	OrderId      string `json:"orderId"`
	OrderStatus  string `json:"orderStatus"`
	TransferId   string `json:"transferId"`
	FailedReason string `json:"failedReason"`
}

type WyreWalletOrderFullDetails struct {
	Id                      string  `json:"id"`
	CreatedAt               uint64  `json:"createdAt"`
	Owner                   string  `json:"owner"`
	Status                  string  `json:"status"`
	OrderType               string  `json:"orderType"`
	SourceAmount            float64 `json:"sourceAmount"`
	PurchaseAmount          float64 `json:"purchaseAmount"`
	SourceCurrency          string  `json:"sourceCurrency"`
	DestCurrency            string  `json:"destCurrency"`
	TransferId              string  `json:"transferId"`
	Dest                    string  `json:"dest"`
	AuthCodesRequested      bool    `json:"authCodesRequested"`
	ErrorCategory           string  `json:"errorCategory"`
	ErrorCode               string  `json:"errorCode"`
	ErrorMessage            string  `json:"errorMessage"`
	FailureReason           string  `json:"failureReason"`
	AccountId               string  `json:"accountId"`
	PaymentNetworkErrorCode string  `json:"paymentNetworkErrorCode"`
	InternalErrorCode       string  `json:"internalErrorCode"`
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

// Make sure you only allow access to Wyre IPs for this endpoint, otherwise anybody can take all the funds from
// the public key that sends BitClout. WHITELIST WYRE IPs.
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
	orderIdBytes := []byte(orderId)
	if err := fes.GlobalStatePut(GlobalStateKeyForWyreOrderID(orderIdBytes), []byte{1}); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("WyreWalletOrderSubscription: Error saving orderId to global state"))
		return
	}
	referenceId := wyreWalletOrderWebhookRequest.ReferenceId
	referenceIdSplit := strings.Split(referenceId, ":")
	publicKey := referenceIdSplit[0]
	if err := fes.logAmplitudeEvent(publicKey, fmt.Sprintf("wyre : buy : subscription : %v", strings.ToLower(wyreWalletOrderWebhookRequest.OrderStatus)), structs.Map(wyreWalletOrderWebhookRequest)); err != nil {
		glog.Errorf("WyreWalletOrderSubscription: Error logging payload to amplitude: %v", err)
	}
	timestamp, err := strconv.ParseUint(referenceIdSplit[1], 10, 64)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("WyreWalletOrderSubscription: Error parsing timestamp as uint64 from referenceId: %v", err))
		return
	}
	transferId := wyreWalletOrderWebhookRequest.TransferId
	publicKeyBytes, _, err := lib.Base58CheckDecode(publicKey)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("WyreWalletOrderSubscription: error decoding public key %v: %v", publicKey, err))
		return
	}
	// Get the current Wyre Order Metadata from global state
	currentWyreWalletOrderMetadata, err := fes.GetWyreWalletOrderMetadataFromGlobalState(publicKey, timestamp)

	// Initialize the new Wyre Order Metadata object based on the current wallet order metadata (if it exists)
	// and the current payload.
	newMetadataObj := WyreWalletOrderMetadata{
		LatestWyreWalletOrderWebhookPayload: wyreWalletOrderWebhookRequest,
	}

	if currentWyreWalletOrderMetadata != nil {
		newMetadataObj.LatestWyreTrackWalletOrderResponse = currentWyreWalletOrderMetadata.LatestWyreTrackWalletOrderResponse
		newMetadataObj.BitCloutPurchasedNanos = currentWyreWalletOrderMetadata.BitCloutPurchasedNanos
		newMetadataObj.BasicTransferTxnBlockHash = currentWyreWalletOrderMetadata.BasicTransferTxnBlockHash
	}
	// Update global state before all transfer logic is completed so we have a record of the last webhook payload
	// received in the event of an error when paying out BitClout.
	fes.UpdateWyreGlobalState(ww, publicKeyBytes, timestamp, newMetadataObj)

	// If there is a transferId, we need to get the transfer details, update the new metadata object and pay out
	// bitclout if it has not been paid out yet.
	if transferId != "" {
		// Get the transfer details from Wyre
		client := &http.Client{}
		var wyreTrackOrderResponse *WyreTrackOrderResponse
		wyreTrackOrderResponse, err = fes.TrackWalletOrder(client, transferId)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("WyreWalletOrderSubscription: error getting track wallet order response: %v. Webhook payload: %v", err, wyreWalletOrderWebhookRequest))
		}
		newMetadataObj.LatestWyreTrackWalletOrderResponse = wyreTrackOrderResponse

		// If the amount of BTC purchased is greater than 0, compute how much BitClout to pay out if it has not been
		// paid out yet.
		btcPurchased := wyreTrackOrderResponse.DestAmount
		if btcPurchased > 0 {
			// BTC Purchased is in whole bitcoins, so multiply it by 10^8 to convert to Satoshis
			satsPurchased := uint64(btcPurchased * lib.SatoshisPerBitcoin)
			var feeBasisPoints uint64
			feeBasisPoints, err = fes.GetBuyBitCloutFeeBasisPointsResponseFromGlobalState()
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("WyreWalletOrderSubscription: error getting buy bitclout premium basis points from global state: %v", err))
				return
			}
			var nanosPurchased uint64
			nanosPurchased, err = fes.GetNanosFromSats(satsPurchased, feeBasisPoints)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("WyreWalletOrdersubscription: error calculating nanos purchased: %v", err))
				return
			}
			var balanceInsufficient bool
			balanceInsufficient, err = fes.ExceedsBitCloutBalance(nanosPurchased, fes.Config.BuyBitCloutSeed)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("WyreWalletOrdersubscription: Error checking if send bitclout balance is sufficient: %v", err))
				return
			}
			if balanceInsufficient {
				// TODO: THIS SHOULD TRIGGER ALERT
				_AddBadRequestError(ww, fmt.Sprintf("WyreWalletOrdersubscription: SendBitClout wallet balance is below nanos purchased"))
				return
			}

			// Make sure this order hasn't been paid out, then mark it as paid out.
			wyreOrderIdKey := GlobalStateKeyForWyreOrderIDProcessed(orderIdBytes)
			// We expect badger to return a key not found error if BitClout has been paid out for this order.
			// If it does not return an error, BitClout has already been paid out, so we skip ahead.
			if val, _ := fes.GlobalStateGet(wyreOrderIdKey); val == nil {
				// Mark this order as paid out
				if err = fes.GlobalStatePut(wyreOrderIdKey, []byte{1}); err != nil {
					_AddBadRequestError(ww, fmt.Sprintf("WyreWalletOrderSubscription: error marking orderId %v as paid out: %v", orderId, err))
					return
				}
				// Pay out bitclout to send to the public key
				var txnHash *lib.BlockHash
				txnHash, err = fes.SendSeedBitClout(publicKeyBytes, nanosPurchased, true)
				if err != nil {
					_AddBadRequestError(ww, fmt.Sprintf("WyreWalletOrderSubscription: error paying out bitclout: %v", err))
					// In the event that sending the bitclout to the public key fails for some reason, we will "unmark"
					// this order as paid in global state
					if err = fes.GlobalStateDelete(wyreOrderIdKey); err != nil {
						_AddBadRequestError(ww, fmt.Sprintf("WyreWalletOrderSubscription: error deleting order id key when failing to payout bitclout: %v", err))
					}
					return
				}
				// Set the basic transfer txn hash and bitclout purchased nanos of the metadata object
				newMetadataObj.BasicTransferTxnBlockHash = txnHash
				newMetadataObj.BitCloutPurchasedNanos = nanosPurchased
			}
		}
	}
	// Update global state after all transfer logic is completed.
	fes.UpdateWyreGlobalState(ww, publicKeyBytes, timestamp, newMetadataObj)
}

func (fes *APIServer) GetFullWalletOrderDetails(client *http.Client, orderId string) (_wyreWalletOrderFullDetails *WyreWalletOrderFullDetails, _err error) {
	bodyBytes, err := fes.MakeWyreGetRequest(client, fmt.Sprintf("%v/v3/orders/%v/full", fes.Config.WyreUrl, orderId))
	if err != nil {
		return nil, fmt.Errorf("error getting full order details for orderId %v: %v", orderId, err)
	}

	var wyreWalletOrderFullDetails *WyreWalletOrderFullDetails
	err = json.Unmarshal(bodyBytes, &wyreWalletOrderFullDetails)
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
	bodyBytes, err := fes.MakeWyreGetRequest(client, fmt.Sprintf("%v/v3/transfers/%v", fes.Config.WyreUrl, transferId))
	if err != nil {
		return nil, fmt.Errorf("error getting transfer details for transferId %v: %v", transferId, err)
	}

	var wyreTransferDetails *WyreTransferDetails
	if err = json.Unmarshal(bodyBytes, &wyreTransferDetails); err != nil {
		return nil, fmt.Errorf("error unmarshaling JSON from transfer details bytes: %v", err)
	}
	return wyreTransferDetails, nil
}

type WyreTrackOrderResponse struct {
	TransferId  string  `json:"transferId"`
	FeeCurrency string  `json:"feeCurrency"`
	Fee         float64 `json:"fee"`
	Fees        struct {
		BTC float64 `json:"BTC"`
		USD float64 `json:"USD"`
	} `json:"fees"`
	SourceCurrency           string      `json:"sourceCurrency"`
	DestCurrency             string      `json:"destCurrency"`
	SourceAmount             float64     `json:"sourceAmount"`
	DestAmount               float64     `json:"destAmount"`
	DestSrn                  string      `json:"destSrn"`
	From                     string      `json:"from"`
	To                       interface{} `json:"to"`
	Rate                     float64     `json:"rate"`
	CustomId                 interface{} `json:"customId"`
	Status                   interface{} `json:"status"`
	BlockchainNetworkTx      interface{} `json:"blockchainNetworkTx"`
	Message                  interface{} `json:"message"`
	TransferHistoryEntryType string      `json:"transferHistoryEntryType"`
	SuccessTimeline          []struct {
		StatusDetails string `json:"statusDetails"`
		State         string `json:"state"`
		CreatedAt     int64  `json:"createdAt"`
	} `json:"successTimeline"`
	FailedTimeline []interface{} `json:"failedTimeline"`
	FailureReason  interface{}   `json:"failureReason"`
	ReversalReason interface{}   `json:"reversalReason"`
}

func (fes *APIServer) TrackWalletOrder(client *http.Client, transferId string) (_wyreTrackOrderResponse *WyreTrackOrderResponse, _err error) {
	bodyBytes, err := fes.MakeWyreGetRequest(client, fmt.Sprintf("%v/v2/transfer/%v/track", fes.Config.WyreUrl, transferId))
	if err != nil {
		return nil, fmt.Errorf("error tracking transferId %v: %v", transferId, err)
	}
	var wyreTrackOrderResponse *WyreTrackOrderResponse
	if err = json.Unmarshal(bodyBytes, &wyreTrackOrderResponse); err != nil {
		return nil, fmt.Errorf("error unmarshaling JSON from transfer details bytes: %v", err)
	}

	// If the wallet order's destination does not match the configured address, that is an error.
	if wyreTrackOrderResponse.DestSrn != fes.GetBTCAddress() {
		return nil, fmt.Errorf("wyre wallet order's btc address (%v) does not match node's configured btc address (%v)", wyreTrackOrderResponse.DestSrn, fes.GetBTCAddress())
	}
	return wyreTrackOrderResponse, nil
}

func (fes *APIServer) UpdateWyreGlobalState(ww http.ResponseWriter, publicKeyBytes []byte, timestampNanos uint64, wyreWalletOrderMetadata WyreWalletOrderMetadata) {
	// Construct the key for accessing the wyre order metadata
	globalStateKey := GlobalStateKeyForUserPublicKeyTstampNanosToWyreOrderMetadata(publicKeyBytes, timestampNanos)
	// Encode the WyreWalletOrderMetadata
	wyreWalletOrderMetadataBuf := bytes.NewBuffer([]byte{})
	if err := gob.NewEncoder(wyreWalletOrderMetadataBuf).Encode(wyreWalletOrderMetadata); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("error encoding wyre wallet order metadata: %v", err))
		return
	}
	// Put the metadata in GlobalState
	if err := fes.GlobalStatePut(globalStateKey, wyreWalletOrderMetadataBuf.Bytes()); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("Update Wyre Global state failed: %v", err))
		return
	}
}

type WalletOrderQuotationRequest struct {
	SourceAmount   float64
	Country        string
	SourceCurrency string
}

type WyreWalletOrderQuotationPayload struct {
	SourceCurrency    string `json:"sourceCurrency"`
	Dest              string `json:"dest"`
	DestCurrency      string `json:"destCurrency"`
	AmountIncludeFees bool   `json:"amountIncludeFees"`
	Country           string `json:"country"`
	SourceAmount      string `json:"sourceAmount"`
	WalletType        string `json:"walletType"`
	AccountId         string `json:"accountId"`
}

func (fes *APIServer) GetWyreWalletOrderQuotation(ww http.ResponseWriter, req *http.Request) {
	// Exit immediately if this node has not integrated with Wyre
	if !fes.IsConfiguredForWyre() {
		_AddBadRequestError(ww, fmt.Sprintf("GetWyreWalletOrderQuotation: This node is not configured with Wyre"))
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
		AccountId:         fes.Config.WyreAccountId,
		Dest:              fmt.Sprintf("bitcoin:%v", fes.Config.BuyBitCloutBTCAddress),
		AmountIncludeFees: true,
		DestCurrency:      "BTC",
		SourceCurrency:    wyreWalletOrderQuotationRequest.SourceCurrency,
		Country:           wyreWalletOrderQuotationRequest.Country,
		WalletType:        "DEBIT_CARD",
		SourceAmount:      fmt.Sprintf("%f", wyreWalletOrderQuotationRequest.SourceAmount),
	}

	payload, err := json.Marshal(body)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetWyreWalletOrderQuotation: Error marshaling JSON body: %v", err))
		return
	}

	// Construct the URL
	url := fmt.Sprintf("%v/v3/orders/quote/partner?timestamp=%v", fes.Config.WyreUrl, uint64(time.Now().UnixNano()))

	// Make the request get an order reservation to Wyre
	fes.MakeWyrePostRequest(payload, url, ww)
}

type WalletOrderReservationRequest struct {
	SourceAmount   float64
	ReferenceId    string
	Country        string
	SourceCurrency string
}

type WyreWalletOrderReservationPayload struct {
	SourceCurrency    string   `json:"sourceCurrency"`
	Dest              string   `json:"dest"`
	DestCurrency      string   `json:"destCurrency"`
	Country           string   `json:"country"`
	Amount            string   `json:"amount"`
	ReferrerAccountId string   `json:"referrerAccountId"`
	LockFields        []string `json:"lockFields"`
	RedirectUrl       string   `json:"redirectUrl"`
	ReferenceId       string   `json:"referenceId"`
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
	currentTime := uint64(time.Now().UnixNano())
	// Make and marshal the payload
	body := WyreWalletOrderReservationPayload{
		ReferrerAccountId: fes.Config.WyreAccountId,
		Dest:              fes.GetBTCAddress(),
		DestCurrency:      "BTC",
		SourceCurrency:    wyreWalletOrderReservationRequest.SourceCurrency,
		Country:           wyreWalletOrderReservationRequest.Country,
		Amount:            fmt.Sprintf("%f", wyreWalletOrderReservationRequest.SourceAmount),
		LockFields:        []string{"dest", "destCurrency"},
		RedirectUrl:       fmt.Sprintf("https://%v/buy-bitclout", req.Host),
		ReferenceId:       fmt.Sprintf("%v:%v", wyreWalletOrderReservationRequest.ReferenceId, currentTime),
	}

	payload, err := json.Marshal(body)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetWyreWalletOrderReservation: Error marshaling JSON body: %v", err))
		return
	}

	// Construct the URL
	url := fmt.Sprintf("%v/v3/orders/reserve?timestamp=%v", fes.Config.WyreUrl, currentTime)

	// Make the request get an order reservation to Wyre.
	fes.MakeWyrePostRequest(payload, url, ww)
}

func (fes *APIServer) MakeWyrePostRequest(payload []byte, url string, ww http.ResponseWriter) {
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

func (fes *APIServer) MakeWyreGetRequest(client *http.Client, url string) (_bodyBytes []byte, _err error) {
	// Make the request and set the headers
	request, err := http.NewRequest("GET", fmt.Sprintf("%v?timestamp=%v", url, uint64(time.Now().UnixNano())), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating get request: %v", err)
	}
	request = fes.SetWyreRequestHeaders(request, nil)
	// Execute the request and handle errors
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("error performing wyre get request: %v", err)
	}

	if response == nil {
		return nil, fmt.Errorf("wyre response is nil")
	}
	// If the response is not a 200, raise an error.
	if response.StatusCode != 200 {
		// what is the appropriate way to handle these errors.
		return nil, fmt.Errorf("wyre responded with a non-200 status code of %v", response.StatusCode)
	}
	defer response.Body.Close()

	// Read the response body and unmarshal it
	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading body from wyre response: %v", err)
	}
	return bodyBytes, nil
}

func (fes *APIServer) GetWyreWalletOrderMetadataFromGlobalState(publicKey string, timestamp uint64) (*WyreWalletOrderMetadata, error) {
	// Decode the public get and get the key to access the Wyre Order Metadata
	publicKeyBytes, _, err := lib.Base58CheckDecode(publicKey)
	if err != nil {
		return nil, err
	}
	globalStateKey := GlobalStateKeyForUserPublicKeyTstampNanosToWyreOrderMetadata(publicKeyBytes, timestamp)

	// Get Wyre Order Metadata from global state and decode it
	currentWyreWalletOrderMetadataBytes, err := fes.GlobalStateGet(globalStateKey)
	if err != nil {
		return nil, err
	}
	currentWyreWalletOrderMetadata := &WyreWalletOrderMetadata{}
	if err = gob.NewDecoder(bytes.NewReader(currentWyreWalletOrderMetadataBytes)).Decode(currentWyreWalletOrderMetadata); err != nil {
		return nil, err
	}
	return currentWyreWalletOrderMetadata, err
}

func (fes *APIServer) SetWyreRequestHeaders(req *http.Request, dataBytes []byte) *http.Request {
	// Set the API Key and Content type headers
	req.Header.Set("X-Api-Key", fes.Config.WyreApiKey)
	req.Header.Set("Content-Type", "application/json")

	// Wyre expects the signature to be HEX encoded HMAC with SHA-256 and the Wyre secret key
	// the message will be the URL + the data (if it is a GET request, data will be nil
	// For more details, see this link: https://docs.sendwyre.com/docs/authentication#secret-key-signature-auth
	h := hmac.New(sha256.New, []byte(fes.Config.WyreSecretKey))
	h.Write([]byte(req.URL.String()))
	h.Write(dataBytes)
	req.Header.Set("X-Api-Signature", hex.EncodeToString(h.Sum(nil)))
	return req
}

func (fes *APIServer) GetBTCAddress() string {
	return fmt.Sprintf("bitcoin:%v", fes.Config.BuyBitCloutBTCAddress)
}

type GetWyreWalletOrderForPublicKeyRequest struct {
	PublicKeyBase58Check string
	Username             string

	AdminPublicKey string
}

type GetWyreWalletOrderForPublicKeyResponse struct {
	WyreWalletOrderMetadataResponses []*WyreWalletOrderMetadataResponse
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
	// 1 + max length of public key + max uint64 bytes length
	maxKeyLen := 1 + btcec.PubKeyBytesLenCompressed + 8
	prefix := GlobalStateKeyForUserPublicKeyTstampNanosToWyreOrderMetadata(publicKeyBytes, math.MaxUint64)
	validPrefix := append(_GlobalStatePrefixUserPublicKeyWyreOrderIdToWyreOrderMetadata, publicKeyBytes...)
	_, values, err = fes.GlobalStateSeek(prefix, validPrefix, maxKeyLen, 100, true, true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetWyreWalletOrdersForPublicKey: error getting wyre order metadata from global state"))
		return
	}

	res := &GetWyreWalletOrderForPublicKeyResponse{
		WyreWalletOrderMetadataResponses: []*WyreWalletOrderMetadataResponse{},
	}
	for _, wyreOrderMetadataBytes := range values {
		var wyreOrderMetadata *WyreWalletOrderMetadata
		err = gob.NewDecoder(bytes.NewReader(wyreOrderMetadataBytes)).Decode(&wyreOrderMetadata)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetWyreWalletOrdersForPublicKey: error decoding order: %v", wyreOrderMetadataBytes))
			return
		}
		res.WyreWalletOrderMetadataResponses = append(res.WyreWalletOrderMetadataResponses, fes.WyreWalletOrderMetadataToResponse(wyreOrderMetadata))
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetWyreWalletOrdersForPublicKey: Problem encoding response as JSON: #{err}"))
		return
	}
}

func (fes *APIServer) IsConfiguredForWyre() bool {
	return fes.Config.WyreUrl != ""
}

type WyreWalletOrderMetadataResponse struct {
	// Last payload received from Wyre webhook
	LatestWyreWalletOrderWebhookPayload WyreWalletOrderWebhookPayload

	// Track Wallet Order response received based on the last payload received from Wyre Webhook
	LatestWyreTrackWalletOrderResponse *WyreTrackOrderResponse

	// Amount of BitClout that was sent for this WyreWalletOrder
	BitCloutPurchasedNanos uint64

	// BlockHash of the transaction for sending the BitClout
	BasicTransferTxnHash string

	Timestamp *time.Time
}

func (fes *APIServer) WyreWalletOrderMetadataToResponse(metadata *WyreWalletOrderMetadata) *WyreWalletOrderMetadataResponse {
	orderMetadataResponse := WyreWalletOrderMetadataResponse{
		LatestWyreTrackWalletOrderResponse:  metadata.LatestWyreTrackWalletOrderResponse,
		LatestWyreWalletOrderWebhookPayload: metadata.LatestWyreWalletOrderWebhookPayload,
		BitCloutPurchasedNanos:              metadata.BitCloutPurchasedNanos,
		Timestamp:                           getTimestampFromReferenceId(metadata.LatestWyreWalletOrderWebhookPayload.ReferenceId),
	}
	basicTransferTxnHash := metadata.BasicTransferTxnBlockHash
	if basicTransferTxnHash != nil {
		orderMetadataResponse.BasicTransferTxnHash = lib.PkToString(basicTransferTxnHash[:], fes.Params)
	}
	return &orderMetadataResponse
}

func getTimestampFromReferenceId(referenceId string) *time.Time {
	splits := strings.Split(referenceId, ":")
	uint64Timestamp, err := strconv.ParseUint(splits[1], 10, 64)
	if err != nil {
		return nil
	}
	timestamp := time.Unix(0, int64(uint64Timestamp))
	return &timestamp
}
