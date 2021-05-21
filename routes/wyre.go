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
	"io"
	"io/ioutil"
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
	PurchaseAmount uint64 `json:"purchaseAmount"`
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

func (fes *APIServer) HandleWyreWalletOrderWebhook(ww http.ResponseWriter, req *http.Request) {
	// Verify that this is coming from wyre somehow.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	wyreWalletOrderWebhookRequest := WyreWalletOrderWebhookPayload{}
	if err := decoder.Decode(&wyreWalletOrderWebhookRequest); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetUsersStateless: Error parsing request body: %v", err))
		return
	}
	// Update the order in global state
	orderId := wyreWalletOrderWebhookRequest.OrderId
	publicKey := wyreWalletOrderWebhookRequest.ReferenceId
	publicKeyBytes, _, err := lib.Base58CheckDecode(publicKey)
	if err != nil {
		// do something here.
	}
	var wyreWalletOrderFullDetails *WyreWalletOrderFullDetails
	currentWyreWalletOrderMetadata, err := fes.GetWyreWalletOrderMetadataFromGlobalState(publicKey, orderId)

	newMetadataObj := WyreWalletOrderMetadata{
		LatestWyreWalletOrderWebhookPayload: wyreWalletOrderWebhookRequest,
	}
	if currentWyreWalletOrderMetadata != nil {
		newMetadataObj.LatestWyreWalletOrderFullDetails = currentWyreWalletOrderMetadata.LatestWyreWalletOrderFullDetails
		newMetadataObj.BitCloutPurchasedNanos = currentWyreWalletOrderMetadata.BitCloutPurchasedNanos
		newMetadataObj.BasicTransferTxnBlockHash = currentWyreWalletOrderMetadata.BasicTransferTxnBlockHash
	}

	if (wyreWalletOrderWebhookRequest.OrderStatus == "PROCESSING" || wyreWalletOrderWebhookRequest.OrderStatus == "COMPLETE") && newMetadataObj.BasicTransferTxnBlockHash == nil {
		// we fetch the full order details
		// Create a new HTTP Client, create the request, and perform the GET request.
		client := &http.Client{}
		getFullDetails, err := http.NewRequest("GET", fmt.Sprintf("https://api.sendwyre.com/v3/orders/%v/full", orderId), nil)
		if err != nil {
			// what is the appropriate way to handle these errors.
		}
		resp, err := client.Do(getFullDetails)
		if err != nil {
			// what is the appropriate way to handle these errors.
		}
		if resp == nil {
			// what is the appropriate way to handle these errors.
			return
		}
		// If the response is not a 200 or 302, raise an error.
		if resp.StatusCode != 200 && resp.StatusCode != 302 {
			// what is the appropriate way to handle these errors.
		}
		defer resp.Body.Close()

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			// do something with this error
		}

		err = json.Unmarshal(bodyBytes, &wyreWalletOrderFullDetails)
		if err != nil {
			// do something with this error
		}

		if wyreWalletOrderFullDetails.Dest != "MY ADDRESS" {
			// throw some error -- it must equal our address
		}

		newMetadataObj.LatestWyreWalletOrderFullDetails = wyreWalletOrderFullDetails
		btcPurchased := wyreWalletOrderFullDetails.PurchaseAmount
		utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
		if err != nil {
			// do something with this error
			return
		}
		startNanos := utxoView.NanosPurchased
		usdCentsPerBitcoin := utxoView.GetCurrentUSDCentsPerBitcoin()
		satoshisPerUnit := lib.GetSatoshisPerUnitExchangeRate(startNanos, usdCentsPerBitcoin)
		merlinFee := satoshisPerUnit / 100
		bitcloutToSend := btcPurchased / (satoshisPerUnit + merlinFee)
		txnHash, err := fes.SendSeedBitClout(publicKeyBytes, bitcloutToSend)
		if err != nil {
			// do something with this error
			return
		}
		newMetadataObj.BasicTransferTxnBlockHash = txnHash
		newMetadataObj.BitCloutPurchasedNanos = bitcloutToSend
	}


	globalStateKey := GlobalStateKeyForUserPublicKeyWyreOrderIDToWyreOrderMetadata(publicKeyBytes, []byte(orderId))
	wyreWalletOrderMetadataBuf := bytes.NewBuffer([]byte{})
	gob.NewEncoder(wyreWalletOrderMetadataBuf).Encode(newMetadataObj)
	err = fes.GlobalStatePut(globalStateKey, wyreWalletOrderMetadataBuf.Bytes())
	if err != nil {
		// what do we do if we hit this error
	}
}

type WalletOrderQuotationRequest struct {
	BtcAddress string
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

//type WalletOrderQuotationResponse struct {
//	destAmount float64
//	destCurrency string
//	equivalencies map[string]float64
//	fees map[string]float64
//	sourceAmount float64
//	sourceAmountWithoutFees float64
//	sourceCurrency string
//}

func (fes *APIServer) GetWyreWalletOrderQuotation(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	wyreWalletOrderQuotationRequest := WalletOrderQuotationRequest{}
	if err := decoder.Decode(&wyreWalletOrderQuotationRequest); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetWyreWalletOrderQuotation: Error parsing request body: %v", err))
		return
	}
	body := WyreWalletOrderQuotationPayload{
		AccountId: fes.WyreAccountId,
		Dest: fmt.Sprintf("bitcoin:%v", wyreWalletOrderQuotationRequest.BtcAddress),
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

	url := fmt.Sprintf("%v/v3/orders/quote/partner?timestamp=%v", fes.WyreUrl, uint64(time.Now().UnixNano()))

	fes.MakeWyreRequest(payload, url, ww)
}

type WalletOrderReservationRequest struct {
	BtcAddress string
	SourceAmount float64
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
}

func (fes *APIServer) GetWyreWalletOrderReservation(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	wyreWalletOrderReservationRequest := WalletOrderReservationRequest{}
	if err := decoder.Decode(&wyreWalletOrderReservationRequest); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetWyreWalletOrderReservation: Error parsing request body: %v", err))
		return
	}
	body := WyreWalletOrderReservationPayload{
		ReferrerAccountId: fes.WyreAccountId,
		Dest: fmt.Sprintf("bitcoin:%v", wyreWalletOrderReservationRequest.BtcAddress),
		AmountIncludeFees: true,
		DestCurrency: "BTC",
		SourceCurrency: "USD",
		Country: "US",
		PaymentMethod: "debit-card",
		SourceAmount: fmt.Sprintf("%f", wyreWalletOrderReservationRequest.SourceAmount),
		LockFields: []string{"dest", "destCurrency"},
		RedirectUrl: fmt.Sprintf("%v/buy-bitclout", req.Host),
	}


	payload, err := json.Marshal(body)
	if err != nil {
		// do something with this error
		return
	}
	url := fmt.Sprintf("%v/v3/orders/reserve?timestamp=%v", fes.WyreUrl, uint64(time.Now().UnixNano()))

	fes.MakeWyreRequest(payload, url, ww)
}

func (fes *APIServer) MakeWyreRequest(payload []byte, url string, ww http.ResponseWriter) {
	payloadBytes := bytes.NewBuffer(payload)
	wyreReq, err := http.NewRequest("POST", url, payloadBytes)

	if err != nil {
		// do sometihng
		return
	}

	wyreReq = fes.SetWyreRequestHeaders(wyreReq, payloadBytes.Bytes())

	client := &http.Client{}
	resp, err := client.Do(wyreReq)
	if err != nil {
		// do something
		return
	}
	defer resp.Body.Close()

	wyreResponseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		// do something
		return
	}

	if _, err = ww.Write(wyreResponseBody); err != nil {
		// do something with this error
		return
	}
}

//type GetWyreWalletOrderStatusRequest struct {
//	PublicKeyBase58Check string
//}
//
//func (fes *APIServer) GetWyreWalletOrderStatus(ww http.ResponseWriter, req *http.Request) {
//
//	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
//	wyreWalletOrderWebhookRequest := WyreWalletOrderWebhookPayload{}
//
//	publicKeyBytes, _, err := lib.Base58CheckDecode(publicKey)
//	if err != nil {
//		return nil, err
//	}
//
//}


func (fes *APIServer) GetWyreWalletOrderMetadataFromGlobalState(publicKey string, orderId string) (*WyreWalletOrderMetadata, error) {
	publicKeyBytes, _, err := lib.Base58CheckDecode(publicKey)
	if err != nil {
		return nil, err
	}
	globalStateKey := GlobalStateKeyForUserPublicKeyWyreOrderIDToWyreOrderMetadata(publicKeyBytes, []byte(orderId))

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
	req.Header.Set("X-Api-Key", fes.WyreApiKey)
	req.Header.Set("Content-Type", "application/json")
	h := hmac.New(sha256.New, []byte(fes.WyreSecretKey))
	h.Write([]byte(req.URL.String()))
	h.Write(dataBytes)
	req.Header.Set("X-Api-Signature", hex.EncodeToString(h.Sum(nil)))
	return req
}
