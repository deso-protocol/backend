package routes

import (
	"encoding/json"
	"fmt"
	"github.com/deso-protocol/core/lib"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"io"
	"math/big"
	"net/http"
)

type GetDAOCoinLimitOrdersRequest struct {
	DAOCoin1CreatorPublicKeyBase58CheckOrUsername string `safeForLogging:"true"`
	DAOCoin2CreatorPublicKeyBase58CheckOrUsername string `safeForLogging:"true"`
}

type GetDAOCoinLimitOrdersResponse struct {
	Orders []DAOCoinLimitOrderEntryResponse
}

type DAOCoinLimitOrderEntryResponse struct {
	TransactorPublicKeyBase58Check string `safeForLogging:"true"`

	BuyingDAOCoinCreatorPublicKeyBase58Check  string `safeForLogging:"true"`
	SellingDAOCoinCreatorPublicKeyBase58Check string `safeForLogging:"true"`

	ExchangeRateCoinsToSellPerCoinToBuy float64 `safeForLogging:"true"`
	QuantityToFill                      float64 `safeForLogging:"true"`

	OperationType DAOCoinLimitOrderOperationTypeString

	OrderID string
}

func (fes *APIServer) GetDAOCoinLimitOrders(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetDAOCoinLimitOrdersRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(
			ww,
			fmt.Sprintf("GetDAOCoinLimitOrders: Problem parsing request body: %v", err),
		)
		return
	}

	if requestData.DAOCoin1CreatorPublicKeyBase58CheckOrUsername == "" &&
		requestData.DAOCoin2CreatorPublicKeyBase58CheckOrUsername == "" {
		_AddBadRequestError(
			ww,
			fmt.Sprint("GetDAOCoinLimitOrders: Must provide either a "+
				"DAOCoin1CreatorPublicKeyBase58CheckOrUsername or DAOCoin2CreatorPublicKeyBase58CheckOrUsername "+
				"or both"),
		)
		return
	}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetDAOCoinLimitOrders: Problem fetching utxoView: %v", err))
		return
	}

	coin1PKID := &lib.ZeroPKID
	coin2PKID := &lib.ZeroPKID

	coin1ProfilePublicBase58Check := ""
	coin2ProfilePublicBase58Check := ""

	if requestData.DAOCoin1CreatorPublicKeyBase58CheckOrUsername != "" {
		coin1ProfilePublicBase58Check, coin1PKID, err = fes.getPublicKeyBase58CheckAndPKIDForPublicKeyBase58CheckOrUsername(
			utxoView,
			requestData.DAOCoin1CreatorPublicKeyBase58CheckOrUsername,
		)
		if err != nil {
			_AddBadRequestError(
				ww,
				fmt.Sprintf("GetDAOCoinLimitOrders: Invalid DAOCoin1CreatorPublicKeyBase58CheckOrUsername: %v", err),
			)
			return
		}
	}

	if requestData.DAOCoin2CreatorPublicKeyBase58CheckOrUsername != "" {
		coin2ProfilePublicBase58Check, coin2PKID, err = fes.getPublicKeyBase58CheckAndPKIDForPublicKeyBase58CheckOrUsername(
			utxoView,
			requestData.DAOCoin2CreatorPublicKeyBase58CheckOrUsername,
		)
		if err != nil {
			_AddBadRequestError(
				ww,
				fmt.Sprintf("GetDAOCoinLimitOrders: Invalid DAOCoin2CreatorPublicKeyBase58CheckOrUsername: %v", err),
			)
			return
		}
	}

	ordersBuyingCoin1, err := utxoView.GetAllDAOCoinLimitOrdersForThisDAOCoinPair(coin1PKID, coin2PKID)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetDAOCoinLimitOrders: Error getting limit orders: %v", err))
		return
	}

	ordersBuyingCoin2, err := utxoView.GetAllDAOCoinLimitOrdersForThisDAOCoinPair(coin2PKID, coin1PKID)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetDAOCoinLimitOrders: Error getting limit orders: %v", err))
		return
	}

	responses := append(
		fes.buildDAOCoinLimitOrderResponsesFromEntriesForCoinPair(
			utxoView,
			coin1ProfilePublicBase58Check,
			coin2ProfilePublicBase58Check,
			ordersBuyingCoin1,
		),
		fes.buildDAOCoinLimitOrderResponsesFromEntriesForCoinPair(
			utxoView,
			coin2ProfilePublicBase58Check,
			coin1ProfilePublicBase58Check,
			ordersBuyingCoin2,
		)...,
	)

	if err = json.NewEncoder(ww).Encode(GetDAOCoinLimitOrdersResponse{Orders: responses}); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDAOCoinLimitOrders: Problem encoding response as JSON: %v", err))
		return
	}
}

type GetTransactorDAOCoinLimitOrdersRequest struct {
	TransactorPublicKeyBase58CheckOrUsername string `safeForLogging:"true"`
}

func (fes *APIServer) GetTransactorDAOCoinLimitOrders(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetTransactorDAOCoinLimitOrdersRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(
			ww,
			fmt.Sprintf("GetTransactorDAOCoinLimitOrders: Problem parsing request body: %v", err),
		)
		return
	}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetTransactorDAOCoinLimitOrders: Problem fetching utxoView: %v", err))
		return
	}

	transactorPublicKeyBase58Check, transactorPKID, err := fes.getPublicKeyBase58CheckAndPKIDForPublicKeyBase58CheckOrUsername(
		utxoView,
		requestData.TransactorPublicKeyBase58CheckOrUsername,
	)
	if err != nil {
		_AddBadRequestError(
			ww,
			fmt.Sprintf("GetTransactorDAOCoinLimitOrders: Invalid TransactorPublicKeyBase58CheckOrUsername: %v", err),
		)
		return
	}

	orders, err := utxoView.GetAllDAOCoinLimitOrdersForThisTransactor(transactorPKID)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetTransactorDAOCoinLimitOrders: Error getting limit orders: %v", err))
		return
	}

	responses := fes.buildDAOCoinLimitOrderResponsesForTransactor(utxoView, transactorPublicKeyBase58Check, orders)

	if err = json.NewEncoder(ww).Encode(GetDAOCoinLimitOrdersResponse{Orders: responses}); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetTransactorDAOCoinLimitOrders: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) getPublicKeyBase58CheckAndPKIDForPublicKeyBase58CheckOrUsername(
	utxoView *lib.UtxoView,
	publicKeyBase58CheckOrUsername string,
) (string, *lib.PKID, error) {
	publicKeyBytes, _, err := fes.GetPubKeyAndProfileEntryForUsernameOrPublicKeyBase58Check(
		publicKeyBase58CheckOrUsername,
		utxoView,
	)
	if err != nil {
		return "", nil, err
	}

	pkid := utxoView.GetPKIDForPublicKey(publicKeyBytes).PKID
	publicKeyBase58Check := lib.Base58CheckEncode(publicKeyBytes, false, fes.Params)

	return publicKeyBase58Check, pkid, nil
}

func (fes *APIServer) buildDAOCoinLimitOrderResponsesFromEntriesForCoinPair(
	utxoView *lib.UtxoView,
	buyingCoinPublicKeyBase58Check string,
	sellingCoinPublicKeyBase58Check string,
	orders []*lib.DAOCoinLimitOrderEntry,
) []DAOCoinLimitOrderEntryResponse {
	var responses []DAOCoinLimitOrderEntryResponse

	for _, order := range orders {
		transactorPublicKey := utxoView.GetPublicKeyForPKID(order.TransactorPKID)

		operationType, err := orderOperationTypeToString(order.OperationType)
		if err != nil {
			// It should not be possible to hit this error. If we do hit it, it means an order with an unsupported
			// operation type made it through all validations during order creation, and was placed on the book. For
			// these read-only API endpoints, we just skip the bad order and return all the valid orders we know of
			continue
		}

		response := buildDAOCoinLimitOrderResponse(
			lib.Base58CheckEncode(transactorPublicKey, false, fes.Params),
			buyingCoinPublicKeyBase58Check,
			sellingCoinPublicKeyBase58Check,
			operationType,
			order,
		)

		responses = append(responses, response)
	}

	return responses
}

func (fes *APIServer) buildDAOCoinLimitOrderResponsesForTransactor(
	utxoView *lib.UtxoView,
	transactorPublicKeyBase58Check string,
	orders []*lib.DAOCoinLimitOrderEntry,
) []DAOCoinLimitOrderEntryResponse {
	var responses []DAOCoinLimitOrderEntryResponse

	for _, order := range orders {
		operationType, err := orderOperationTypeToString(order.OperationType)
		if err != nil {
			continue
		}

		buyingCoinPublicKeyBase58Check := fes.getPublicKeyBase58CheckForPKID(utxoView, order.BuyingDAOCoinCreatorPKID)
		sellingCoinPublicKeyBase58Check := fes.getPublicKeyBase58CheckForPKID(utxoView, order.SellingDAOCoinCreatorPKID)

		response := buildDAOCoinLimitOrderResponse(
			transactorPublicKeyBase58Check,
			buyingCoinPublicKeyBase58Check,
			sellingCoinPublicKeyBase58Check,
			operationType,
			order,
		)

		responses = append(responses, response)
	}

	return responses
}

func (fes *APIServer) getPublicKeyBase58CheckForPKID(utxoView *lib.UtxoView, pkid *lib.PKID) string {
	base58Check := ""
	if !pkid.IsZeroPKID() {
		base58Check = lib.Base58CheckEncode(utxoView.GetPublicKeyForPKID(pkid), false, fes.Params)
	}
	return base58Check
}

func buildDAOCoinLimitOrderResponse(
	transactorPublicKeyBase58Check string,
	buyingCoinPublicKeyBase58Check string,
	sellingCoinPublicKeyBase58Check string,
	operationType DAOCoinLimitOrderOperationTypeString,
	order *lib.DAOCoinLimitOrderEntry,
) DAOCoinLimitOrderEntryResponse {
	return DAOCoinLimitOrderEntryResponse{
		TransactorPublicKeyBase58Check: transactorPublicKeyBase58Check,

		BuyingDAOCoinCreatorPublicKeyBase58Check:  buyingCoinPublicKeyBase58Check,
		SellingDAOCoinCreatorPublicKeyBase58Check: sellingCoinPublicKeyBase58Check,
		ExchangeRateCoinsToSellPerCoinToBuy: calculateFloatExchangeRate(
			order.ScaledExchangeRateCoinsToSellPerCoinToBuy,
		),
		QuantityToFill: calculateQuantityToFillAsFloat(order.QuantityToFillInBaseUnits),

		OperationType: operationType,

		OrderID: order.OrderID.String(),
	}
}

// calculate (scaledValue / 10^38)
func calculateFloatExchangeRate(scaledValue *uint256.Int) float64 {
	valueBigFloat := big.NewFloat(0).SetInt(scaledValue.ToBig())
	divisorBigFloat := big.NewFloat(0).SetInt(lib.OneE38.ToBig())

	quotientBigFloat := big.NewFloat(0).Quo(valueBigFloat, divisorBigFloat)

	quotientFloat, _ := quotientBigFloat.Float64()
	return quotientFloat
}

// calculate (quantityInBaseUnits * 10^9)
func calculateQuantityToFillAsFloat(quantityInBaseUnits *uint256.Int) float64 {
	quantityInBaseUnitsAsBigFloat := big.NewFloat(0).SetInt(quantityInBaseUnits.ToBig())
	divisor := big.NewFloat(float64(lib.NanosPerUnit))
	quotientAsBigFloat := big.NewFloat(0).Quo(
		quantityInBaseUnitsAsBigFloat,
		divisor,
	)
	quotient, _ := quotientAsBigFloat.Float64()
	return quotient
}

// calculate (quantityInBaseUnits / 10^9)
func calculateQuantityToFillAsBaseUnits(quantityToFill float64) (*uint256.Int, error) {
	multiplier := big.NewFloat(float64(lib.NanosPerUnit))
	product := big.NewFloat(0).Mul(
		big.NewFloat(quantityToFill),
		multiplier,
	)
	productAsBigInt, _ := product.Int(nil)
	productAsUint256, overflow := uint256.FromBig(productAsBigInt)
	if overflow {
		return nil, errors.Errorf("Overflow when converting quantity to buy from float to uint256")
	}
	return productAsUint256, nil
}

// DAOCoinLimitOrderOperationTypeString A convenience type that uses a string to represent BID / ASK side in the API,
// so it's more human-readable
type DAOCoinLimitOrderOperationTypeString string

const (
	DAOCoinLimitOrderOperationTypeStringASK DAOCoinLimitOrderOperationTypeString = "ASK"
	DAOCoinLimitOrderOperationTypeStringBID DAOCoinLimitOrderOperationTypeString = "BID"
)

func orderOperationTypeToString(
	operationType lib.DAOCoinLimitOrderOperationType,
) (DAOCoinLimitOrderOperationTypeString, error) {
	if operationType == lib.DAOCoinLimitOrderOperationTypeASK {
		return DAOCoinLimitOrderOperationTypeStringASK, nil
	}
	if operationType == lib.DAOCoinLimitOrderOperationTypeBID {
		return DAOCoinLimitOrderOperationTypeStringBID, nil
	}
	return "", errors.Errorf("Unknown DAOCoinLimitOrderOperationType %v", operationType)
}

func orderOperationTypeToUint64(
	operationType DAOCoinLimitOrderOperationTypeString,
) (lib.DAOCoinLimitOrderOperationType, error) {
	if operationType == DAOCoinLimitOrderOperationTypeStringASK {
		return lib.DAOCoinLimitOrderOperationTypeASK, nil
	}
	if operationType == DAOCoinLimitOrderOperationTypeStringBID {
		return lib.DAOCoinLimitOrderOperationTypeBID, nil
	}
	return 0, errors.Errorf("Unknown string value for DAOCoinLimitOrderOperationType %v", operationType)
}
