package routes

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/deso-protocol/core/lib"
	"github.com/golang/glog"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
)

type GetDAOCoinLimitOrdersRequest struct {
	DAOCoin1CreatorPublicKeyBase58Check string `safeForLogging:"true"`
	DAOCoin2CreatorPublicKeyBase58Check string `safeForLogging:"true"`
}

type GetDAOCoinLimitOrdersResponse struct {
	Orders []DAOCoinLimitOrderEntryResponse
}

type DAOCoinLimitOrderEntryResponse struct {
	TransactorPublicKeyBase58Check string `safeForLogging:"true"`

	BuyingDAOCoinCreatorPublicKeyBase58Check  string `safeForLogging:"true"`
	SellingDAOCoinCreatorPublicKeyBase58Check string `safeForLogging:"true"`

	// A decimal string (ex: 1.23) that represents the exchange rate between the two coins. If operation type is BID
	// then the denominator represents the coin being bought. If the operation type is ASK, then the denominator
	// represents the coin being sold
	Price string `safeForLogging:"true"`

	// A decimal string (ex: 1.23) that represents the quantity of coins being bought or sold. If operation type is BID,
	// then this quantity refers to the coin being bought. If operation type is ASK, then it refers to the coin being sold
	Quantity string `safeForLogging:"true"`

	// These two fields will be deprecated once the above Price and Quantity fields are deployed, and users have migrated
	// to start using them. Until then, the API will continue to populate ExchangeRateCoinsToSellPerCoinToBuy and QuantityToFill
	// in all responses
	ExchangeRateCoinsToSellPerCoinToBuy float64 `safeForLogging:"true"` // Deprecated
	QuantityToFill                      float64 `safeForLogging:"true"` // Deprecated

	OperationType DAOCoinLimitOrderOperationTypeString

	OrderID string
}

const DESOCoinIdentifierString = "DESO"

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

	if requestData.DAOCoin1CreatorPublicKeyBase58Check == DESOCoinIdentifierString &&
		requestData.DAOCoin2CreatorPublicKeyBase58Check == DESOCoinIdentifierString {
		_AddBadRequestError(
			ww,
			fmt.Sprint("GetDAOCoinLimitOrders: Must provide either a "+
				"DAOCoin1CreatorPublicKeyBase58Check or DAOCoin2CreatorPublicKeyBase58Check "+
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

	if requestData.DAOCoin1CreatorPublicKeyBase58Check != DESOCoinIdentifierString {
		coin1PKID, err = fes.getPKIDFromPublicKeyBase58Check(
			utxoView,
			requestData.DAOCoin1CreatorPublicKeyBase58Check,
		)
		if err != nil {
			_AddBadRequestError(
				ww,
				fmt.Sprintf("GetDAOCoinLimitOrders: Invalid DAOCoin1CreatorPublicKeyBase58Check: %v", err),
			)
			return
		}
	}

	if requestData.DAOCoin2CreatorPublicKeyBase58Check != DESOCoinIdentifierString {
		coin2PKID, err = fes.getPKIDFromPublicKeyBase58Check(
			utxoView,
			requestData.DAOCoin2CreatorPublicKeyBase58Check,
		)
		if err != nil {
			_AddBadRequestError(
				ww,
				fmt.Sprintf("GetDAOCoinLimitOrders: Invalid DAOCoin2CreatorPublicKeyBase58Check: %v", err),
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
			requestData.DAOCoin1CreatorPublicKeyBase58Check,
			requestData.DAOCoin2CreatorPublicKeyBase58Check,
			ordersBuyingCoin1,
		),
		fes.buildDAOCoinLimitOrderResponsesFromEntriesForCoinPair(
			utxoView,
			requestData.DAOCoin2CreatorPublicKeyBase58Check,
			requestData.DAOCoin1CreatorPublicKeyBase58Check,
			ordersBuyingCoin2,
		)...,
	)

	if err = json.NewEncoder(ww).Encode(GetDAOCoinLimitOrdersResponse{Orders: responses}); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDAOCoinLimitOrders: Problem encoding response as JSON: %v", err))
		return
	}
}

type GetTransactorDAOCoinLimitOrdersRequest struct {
	TransactorPublicKeyBase58Check string `safeForLogging:"true"`
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

	transactorPKID, err := fes.getPKIDFromPublicKeyBase58Check(
		utxoView,
		requestData.TransactorPublicKeyBase58Check,
	)
	if err != nil {
		_AddBadRequestError(
			ww,
			fmt.Sprintf("GetTransactorDAOCoinLimitOrders: Invalid TransactorPublicKeyBase58Check: %v", err),
		)
		return
	}

	orders, err := utxoView.GetAllDAOCoinLimitOrdersForThisTransactor(transactorPKID)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetTransactorDAOCoinLimitOrders: Error getting limit orders: %v", err))
		return
	}

	responses := fes.buildDAOCoinLimitOrderResponsesForTransactor(utxoView, requestData.TransactorPublicKeyBase58Check, orders)

	if err = json.NewEncoder(ww).Encode(GetDAOCoinLimitOrdersResponse{Orders: responses}); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetTransactorDAOCoinLimitOrders: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) getPKIDFromPublicKeyBase58Check(
	utxoView *lib.UtxoView,
	publicKeyBase58Check string,
) (*lib.PKID, error) {
	publicKeyBytes, err := GetPubKeyBytesFromBase58Check(publicKeyBase58Check)
	if err != nil {
		return nil, err
	}

	pkid := utxoView.GetPKIDForPublicKey(publicKeyBytes).PKID

	return pkid, nil
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

		response, err := buildDAOCoinLimitOrderResponse(
			lib.Base58CheckEncode(transactorPublicKey, false, fes.Params),
			buyingCoinPublicKeyBase58Check,
			sellingCoinPublicKeyBase58Check,
			order,
		)
		if err != nil {
			continue
		}

		responses = append(responses, *response)
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
		buyingCoinPublicKeyBase58Check := fes.getPublicKeyBase58CheckOrCoinIdentifierForPKID(utxoView, order.BuyingDAOCoinCreatorPKID)
		sellingCoinPublicKeyBase58Check := fes.getPublicKeyBase58CheckOrCoinIdentifierForPKID(utxoView, order.SellingDAOCoinCreatorPKID)

		response, err := buildDAOCoinLimitOrderResponse(
			transactorPublicKeyBase58Check,
			buyingCoinPublicKeyBase58Check,
			sellingCoinPublicKeyBase58Check,
			order,
		)
		if err != nil {
			glog.Errorf(
				"buildDAOCoinLimitOrderResponsesForTransactor: Unable to build DAO coin limit order response for limit order with OrderID: %v",
				order.OrderID,
			)
			continue
		}

		responses = append(responses, *response)
	}

	return responses
}

func (fes *APIServer) getPublicKeyBase58CheckOrCoinIdentifierForPKID(utxoView *lib.UtxoView, pkid *lib.PKID) string {
	base58Check := DESOCoinIdentifierString
	if !pkid.IsZeroPKID() {
		base58Check = lib.Base58CheckEncode(utxoView.GetPublicKeyForPKID(pkid), false, fes.Params)
	}
	return base58Check
}

func buildDAOCoinLimitOrderResponse(
	transactorPublicKeyBase58Check string,
	buyingCoinPublicKeyBase58Check string,
	sellingCoinPublicKeyBase58Check string,
	order *lib.DAOCoinLimitOrderEntry,
) (*DAOCoinLimitOrderEntryResponse, error) {
	// It should not be possible to hit errors in this function. If we do hit them, it means an order with invalid
	// values made it through all validations during order creation, and was placed on the book. In
	// the read-only API endpoints, we just skip such bad orders and return all the valid orders we know of
	operationTypeString, err := orderOperationTypeToString(order.OperationType)
	if err != nil {
		return nil, err
	}

	price, err := CalculatePriceStringFromScaledExchangeRate(
		buyingCoinPublicKeyBase58Check,
		sellingCoinPublicKeyBase58Check,
		order.ScaledExchangeRateCoinsToSellPerCoinToBuy,
		operationTypeString,
	)
	if err != nil {
		return nil, err
	}

	quantity, err := CalculateStringQuantityFromBaseUnits(
		buyingCoinPublicKeyBase58Check,
		sellingCoinPublicKeyBase58Check,
		operationTypeString,
		order.QuantityToFillInBaseUnits,
	)
	if err != nil {
		return nil, err
	}

	exchangeRate, err := CalculateFloatFromScaledExchangeRate(
		buyingCoinPublicKeyBase58Check,
		sellingCoinPublicKeyBase58Check,
		order.ScaledExchangeRateCoinsToSellPerCoinToBuy,
	)
	if err != nil {
		return nil, err
	}

	quantityToFill, err := CalculateFloatQuantityFromBaseUnits(
		buyingCoinPublicKeyBase58Check,
		sellingCoinPublicKeyBase58Check,
		operationTypeString,
		order.QuantityToFillInBaseUnits,
	)
	if err != nil {
		return nil, err
	}

	return &DAOCoinLimitOrderEntryResponse{
		TransactorPublicKeyBase58Check: transactorPublicKeyBase58Check,

		BuyingDAOCoinCreatorPublicKeyBase58Check:  buyingCoinPublicKeyBase58Check,
		SellingDAOCoinCreatorPublicKeyBase58Check: sellingCoinPublicKeyBase58Check,

		Price:    price,
		Quantity: quantity,

		ExchangeRateCoinsToSellPerCoinToBuy: exchangeRate,
		QuantityToFill:                      quantityToFill,

		OperationType: operationTypeString,

		OrderID: order.OrderID.String(),
	}, nil
}

///////////////////////////////////////////////////////////////////////////////////
// Helper functions to calculate price and exchange rates for DAO coin limit orders
///////////////////////////////////////////////////////////////////////////////////

// GetBestAvailableExchangeRateCoinsToBuyPerCoinToSell computes the best available decimal string exchange rate at which
// the market is able to exchange one base unit of the selling coin pair for the buying coin. Since we are interested
// in computing the best exchange rate for the selling coin, the denominator for the output will always be the selling coin.
//   Example: given buying coin B, and selling coin S, an output exchange rate of "1.5" implies an exchange rate of
//            (1.5 coin B) per (1 coin S).
// This function can support any arbitrary coin pair, but is most useful for markets where one coin is always considered
// the denominating coin (ex: DAO coin <> DESO). In such cases, this computes the best available ask price.
func (fes *APIServer) GetBestAvailableExchangeRateCoinsToBuyPerCoinToSell(
	utxoView *lib.UtxoView,
	buyingCoinPKID *lib.PKID,
	sellingCoinPKID *lib.PKID,
) (string, error) {
	// This is relatively inefficient as it pulls all open orders from one side of the book. We need to call this function
	// as an abstraction for core behavior because it performs useful filtering of soft-deleted orders, and merges orders
	// from the mempool and db. Long term, it will be worth further optimizing it further to support pagination, so it can
	// return the top 1 order.
	orders, err := utxoView.GetAllDAOCoinLimitOrdersForThisDAOCoinPair(buyingCoinPKID, sellingCoinPKID)
	if err != nil {
		return "", err
	}
	if len(orders) == 0 {
		// It's OK if there are no orders on the book that allow us to exchange the coin pair. We default the exchange
		// rate to 0 in this case
		return "0", nil
	}

	bestExchangeRate := uint256.NewInt()
	for _, order := range orders {
		// ScaledExchangeRateCoinsToSellPerCoinToBuy has the buying coin is the denominator, so we want to find
		// the highest available ScaledExchangeRateCoinsToSellPerCoinToBuy
		if order.ScaledExchangeRateCoinsToSellPerCoinToBuy.Gt(bestExchangeRate) {
			bestExchangeRate = order.ScaledExchangeRateCoinsToSellPerCoinToBuy
		}
	}

	buyingCoinPublicKeyBase58Check := fes.getPublicKeyBase58CheckOrCoinIdentifierForPKID(utxoView, buyingCoinPKID)
	sellingCoinPublicKeyBase58Check := fes.getPublicKeyBase58CheckOrCoinIdentifierForPKID(utxoView, sellingCoinPKID)

	// Computes exchange rate in decimal string format with the selling coin in the denominator
	return CalculatePriceStringFromScaledExchangeRate(
		buyingCoinPublicKeyBase58Check,
		sellingCoinPublicKeyBase58Check,
		bestExchangeRate,
		// We hardcode operation type to ASK regardless of the order's operation type. This way it ensures the denominator
		// for the computed exchange rate is always the selling coin
		DAOCoinLimitOrderOperationTypeStringASK,
	)
}

// CalculateScaledExchangeRateFromPriceString calculates a scaled ExchangeRateCoinsToSellPerCoinsToBuy given a decimal
// price string (ex: "1.23456") that represents an exchange rate between the two coins where the numerator is the coin
// defined by the operation type.
func CalculateScaledExchangeRateFromPriceString(
	buyingCoinPublicKeyBase58Check string,
	sellingCoinPublicKeyBase58Check string,
	price string,
	operationType lib.DAOCoinLimitOrderOperationType,
) (*uint256.Int, error) {
	if err := validateNonNegativeDecimalString(price); err != nil {
		return nil, err
	}

	rawScaledPrice, err := lib.CalculateScaledExchangeRateFromString(price)
	if err != nil {
		return nil, err
	}
	if rawScaledPrice.IsZero() {
		return nil, errors.Errorf("The value %v is too small to produce a scaled exchange rate", price)
	}

	// This is an ASK order so we need to take the multiplicative inverse in order to produce an ExchangeRateCoinsToSellPerCoinToBuy
	if operationType == lib.DAOCoinLimitOrderOperationTypeASK {
		rawScaledPriceAsBigInt := rawScaledPrice.ToBig()

		// Here we intend to calculate 1e38/price which gives us an ExchangeRateCoinsToSellPerCoinToBuy that's scaled up
		// by 1e38. However, we can't avoid precision loss for irrational numbers, so we need to round up the quotient.
		// The rounding allows ASK orders with irrational ExchangeRateCoinsToSellPerCoinToBuy values to match as expected
		// with BID orders created using the same original input price. The integer division maths that gets us the intended
		// result for ceil(1e38/price) using integer math is as follows:
		//   (1e38*1e38 + price*1e38 - 1) / (price*1e38);
		oneE76 := big.NewInt(0).Mul(lib.OneE38.ToBig(), lib.OneE38.ToBig())
		numerator := big.NewInt(0).Add(oneE76, rawScaledPriceAsBigInt)
		numerator = numerator.Sub(numerator, big.NewInt(1))

		rawScaledExchangeRateAsBigInt := big.NewInt(0).Div(numerator, rawScaledPriceAsBigInt)

		// For DESO <-> DAO coin trades, we scale the calculated exchange rate up or down by 1e9 to account for the
		// scaling factor difference between DESO nanos and DAO coin base units
		if buyingCoinPublicKeyBase58Check == DESOCoinIdentifierString {
			// Scale the exchange rate up by 1e9 if the buying coin is DESO
			rawScaledExchangeRateAsBigInt.Mul(rawScaledExchangeRateAsBigInt, getDESOToDAOCoinBaseUnitsScalingFactor().ToBig())
		} else if sellingCoinPublicKeyBase58Check == DESOCoinIdentifierString {
			// Scale the exchange rate down by 1e9 if the selling coin is DESO if  and round the quotient up.
			// For the same reason as above, we round up the quotient, so it matches with bid orders created using the
			// same input price
			exchangeRateDownscaleNumerator := big.NewInt(0).Add(
				rawScaledExchangeRateAsBigInt,
				getDESOToDAOCoinBaseUnitsScalingFactor().ToBig(),
			)
			exchangeRateDownscaleNumerator.Sub(exchangeRateDownscaleNumerator, big.NewInt(1))
			rawScaledExchangeRateAsBigInt.Div(exchangeRateDownscaleNumerator, getDESOToDAOCoinBaseUnitsScalingFactor().ToBig())
		}

		rawScaledExchangeRateWithPossibleOverflow, overflows := uint256.FromBig(rawScaledExchangeRateAsBigInt)
		if overflows {
			return nil, errors.Errorf("Overflow when converting %v to a scaled exchange rate", price)
		}

		return rawScaledExchangeRateWithPossibleOverflow, nil
	}

	// Beyond this point, we know that the operation type is lib.DAOCoinLimitOrderOperationTypeBID

	// Scale up the price to account for DAO Coin -> DESO trades
	if buyingCoinPublicKeyBase58Check == DESOCoinIdentifierString {
		product := uint256.NewInt()
		overflow := product.MulOverflow(rawScaledPrice, getDESOToDAOCoinBaseUnitsScalingFactor())
		if overflow {
			return nil, errors.Errorf("Overflow when converting %v to a scaled exchange rate", price)
		}
		return product, nil
	}

	// Scale down the price to account for DAO Coin -> DESO trades
	if sellingCoinPublicKeyBase58Check == DESOCoinIdentifierString {
		// We intentionally want to round the exchange rate down for BID orders so precision loss does not prevent the
		// order from not getting matched with an ASK order with the same input price
		quotient := uint256.NewInt().Div(rawScaledPrice, getDESOToDAOCoinBaseUnitsScalingFactor())
		if quotient.IsZero() {
			return nil, errors.Errorf("The %v produces a scaled exchange rate that is too small", price)
		}
		return quotient, nil
	}

	// There's no need to perform any scaling or calculate multiplicative inverse needed
	// This only applies to BID orders for DAO coin <-> DAO coin traders
	return rawScaledPrice, nil
}

// CalculateScaledExchangeRate acts as a pass through function to CalculateScaledExchangeRateFromFloat for backwards
// compatibility
func CalculateScaledExchangeRate(
	buyingCoinPublicKeyBase58Check string,
	sellingCoinPublicKeyBase58Check string,
	exchangeRateCoinsToSellPerCoinToBuy float64,
) (*uint256.Int, error) {
	return CalculateScaledExchangeRateFromFloat(buyingCoinPublicKeyBase58Check, sellingCoinPublicKeyBase58Check, exchangeRateCoinsToSellPerCoinToBuy)
}

// CalculateScaledExchangeRateFromFloat given a buying coin, selling coin, and a coin-level float exchange rate, this calculates
// the base unit to base unit exchange rate for the coin pair, while accounting for the difference in base unit scaling
// factors for $DESO (1e9) and DAO coins (1e18)
func CalculateScaledExchangeRateFromFloat(
	buyingCoinPublicKeyBase58Check string,
	sellingCoinPublicKeyBase58Check string,
	exchangeRateCoinsToSellPerCoinToBuy float64,
) (*uint256.Int, error) {
	rawScaledExchangeRate, err := lib.CalculateScaledExchangeRateFromString(formatFloatAsString(exchangeRateCoinsToSellPerCoinToBuy))
	if err != nil {
		return nil, err
	}
	if rawScaledExchangeRate.IsZero() {
		return nil, errors.Errorf("The float value %f is too small to produce a scaled exchange rate", exchangeRateCoinsToSellPerCoinToBuy)
	}
	if buyingCoinPublicKeyBase58Check == DESOCoinIdentifierString {
		// Buying coin is $DESO
		product := uint256.NewInt()
		overflow := product.MulOverflow(rawScaledExchangeRate, getDESOToDAOCoinBaseUnitsScalingFactor())
		if overflow {
			return nil, errors.Errorf("Overflow when convering %f to a scaled exchange rate", exchangeRateCoinsToSellPerCoinToBuy)
		}
		return product, nil
	} else if sellingCoinPublicKeyBase58Check == DESOCoinIdentifierString {
		// Selling coin is $DESO
		quotient := uint256.NewInt().Div(rawScaledExchangeRate, getDESOToDAOCoinBaseUnitsScalingFactor())
		if quotient.IsZero() {
			return nil, errors.Errorf("The float value %f is too small to produce a scaled exchange rate", exchangeRateCoinsToSellPerCoinToBuy)
		}
		return quotient, nil
	}
	return rawScaledExchangeRate, nil
}

// CalculatePriceStringFromScaledExchangeRate calculates price as a decimal string given a scaled ExchangeRateCoinsToSellPerCoinToBuy
// The denominator for the output price is determined by the operation type
// If operation type = BID, then price is the number of selling coins per buying coin
// If operation type = ASK, then price is the number of buying coins per selling coin
func CalculatePriceStringFromScaledExchangeRate(
	buyingCoinPublicKeyBase58Check string,
	sellingCoinPublicKeyBase58Check string,
	scaledValueExchangeRate *uint256.Int,
	operationTypeString DAOCoinLimitOrderOperationTypeString,
) (string, error) {
	scaledExchangeRateAsBigInt := scaledValueExchangeRate.ToBig()

	if buyingCoinPublicKeyBase58Check == DESOCoinIdentifierString {
		scaledExchangeRateAsBigInt.Div(scaledExchangeRateAsBigInt, getDESOToDAOCoinBaseUnitsScalingFactor().ToBig())
	} else if sellingCoinPublicKeyBase58Check == DESOCoinIdentifierString {
		scaledExchangeRateAsBigInt.Mul(scaledExchangeRateAsBigInt, getDESOToDAOCoinBaseUnitsScalingFactor().ToBig())
	}

	if operationTypeString == DAOCoinLimitOrderOperationTypeStringASK {
		// Here, if this is an ask order, we need to take the inverse of the exchange rate because price needs to be
		// the number of coins bought per coin sold
		oneE76 := big.NewInt(0).Mul(lib.OneE38.ToBig(), lib.OneE38.ToBig())
		scaledExchangeRateAsBigInt = big.NewInt(0).Div(oneE76, scaledExchangeRateAsBigInt)
	}

	return formatScaledUint256AsDecimalString(scaledExchangeRateAsBigInt, lib.OneE38.ToBig()), nil
}

// CalculateExchangeRateAsFloat acts as a pass-through function to CalculateFloatFromScaledExchangeRate for backwards
// compatibility
func CalculateExchangeRateAsFloat(
	buyingCoinPublicKeyBase58Check string,
	sellingCoinPublicKeyBase58Check string,
	scaledValue *uint256.Int,
) (float64, error) {
	return CalculateFloatFromScaledExchangeRate(buyingCoinPublicKeyBase58Check, sellingCoinPublicKeyBase58Check, scaledValue)
}

// CalculateFloatFromScaledExchangeRate given a buying coin, selling coin, and base unit to base unit exchange
// rate, this calculates the coin-level float exchange rate for the coin pair, while accounting for the difference in
// base unit scaling factors for $DESO (1e9) and DAO coins (1e18)
func CalculateFloatFromScaledExchangeRate(
	buyingCoinPublicKeyBase58Check string,
	sellingCoinPublicKeyBase58Check string,
	scaledValue *uint256.Int,
) (float64, error) {
	scaledValueAsBigInt := scaledValue.ToBig()
	if buyingCoinPublicKeyBase58Check == DESOCoinIdentifierString {
		scaledValueAsBigInt.Div(scaledValueAsBigInt, getDESOToDAOCoinBaseUnitsScalingFactor().ToBig())
	} else if sellingCoinPublicKeyBase58Check == DESOCoinIdentifierString {
		scaledValueAsBigInt.Mul(scaledValueAsBigInt, getDESOToDAOCoinBaseUnitsScalingFactor().ToBig())
	}

	return calculateScaledUint256AsFloat(scaledValueAsBigInt, lib.OneE38.ToBig())
}

/////////////////////////////////////////////////////////////////////
// Helper functions to calculate quantities for DAO coin limit orders
/////////////////////////////////////////////////////////////////////

// CalculateStringQuantityFromBaseUnits given a buying coin, selling coin, operationType and quantity in base units,
// this calculates the decimal string coin quantity for the side the operation type refers to
func CalculateStringQuantityFromBaseUnits(
	buyingCoinPublicKeyBase58Check string,
	sellingCoinPublicKeyBase58Check string,
	operationTypeString DAOCoinLimitOrderOperationTypeString,
	quantityToFillInBaseUnits *uint256.Int,
) (string, error) {
	if quantityToFillInBaseUnits.IsZero() {
		// This should never happen since quantityToFillInBaseUnits is coming from consensus. We make this check here
		// to exist early, if there's an issue with the order book
		return "", errors.Errorf("quantityToFillInBaseUnits cannot be less than 0")
	}

	if isCoinToFillDESO(
		buyingCoinPublicKeyBase58Check,
		sellingCoinPublicKeyBase58Check,
		operationTypeString,
	) {
		return formatScaledUint256AsDecimalString(quantityToFillInBaseUnits.ToBig(), big.NewInt(int64(lib.NanosPerUnit))), nil
	}
	return formatScaledUint256AsDecimalString(quantityToFillInBaseUnits.ToBig(), lib.BaseUnitsPerCoin.ToBig()), nil
}

// CalculateFloatQuantityFromBaseUnits calculates the float coin quantity in whole units given a buying coin, selling coin,
// operationType and a quantity in base units
func CalculateFloatQuantityFromBaseUnits(
	buyingCoinPublicKeyBase58Check string,
	sellingCoinPublicKeyBase58Check string,
	operationTypeString DAOCoinLimitOrderOperationTypeString,
	quantityToFillInBaseUnits *uint256.Int,
) (float64, error) {
	if quantityToFillInBaseUnits.IsZero() {
		// This should never happen since quantityToFillInBaseUnits is coming from consensus. We make this check here
		// to exist early, if there's an issue with the order book
		return 0, errors.Errorf("quantityToFillInBaseUnits cannot be less than 0")
	}

	if isCoinToFillDESO(
		buyingCoinPublicKeyBase58Check,
		sellingCoinPublicKeyBase58Check,
		operationTypeString,
	) {
		return calculateScaledUint256AsFloat(
			quantityToFillInBaseUnits.ToBig(),
			big.NewInt(int64(lib.NanosPerUnit)),
		)
	}
	return calculateScaledUint256AsFloat(quantityToFillInBaseUnits.ToBig(), lib.BaseUnitsPerCoin.ToBig())
}

// CalculateQuantityToFillAsBaseUnits given a buying coin, selling coin, operationType and a float coin quantity,
// this calculates the quantity in base units for the side the operationType refers to
func CalculateQuantityToFillAsBaseUnits(
	buyingCoinPublicKeyBase58Check string,
	sellingCoinPublicKeyBase58Check string,
	operationTypeString DAOCoinLimitOrderOperationTypeString,
	quantityToFill string,
) (*uint256.Int, error) {
	if err := validateNonNegativeDecimalString(quantityToFill); err != nil {
		return nil, err
	}

	if isCoinToFillDESO(
		buyingCoinPublicKeyBase58Check,
		sellingCoinPublicKeyBase58Check,
		operationTypeString,
	) {
		return calculateQuantityToFillAsDESONanos(
			quantityToFill,
		)
	}
	return calculateQuantityToFillAsDAOCoinBaseUnits(
		quantityToFill,
	)
}

// calculate (quantityToFill * 10^18)
func calculateQuantityToFillAsDAOCoinBaseUnits(quantityToFill string) (*uint256.Int, error) {
	scaledQuantity, err := lib.ScaleFloatFormatStringToUint256(
		quantityToFill,
		lib.BaseUnitsPerCoin,
	)
	if err != nil {
		return nil, err
	}
	if scaledQuantity.IsZero() {
		return nil, errors.Errorf("The input quantity %v produces a value of 0 when scaled to base units nanos", quantityToFill)
	}
	return scaledQuantity, nil
}

// calculate (quantityToFill * 10^9)
func calculateQuantityToFillAsDESONanos(quantityToFill string) (*uint256.Int, error) {
	scaledQuantity, err := lib.ScaleFloatFormatStringToUint256(
		quantityToFill,
		uint256.NewInt().SetUint64(lib.NanosPerUnit),
	)
	if err != nil {
		return nil, err
	}
	if scaledQuantity.IsZero() {
		return nil, errors.Errorf("The input quantity %v produces a value of 0 when scaled to DESO nanos", quantityToFill)
	}
	return scaledQuantity, nil
}

// given a buying coin, selling coin, and operation type, this determines if the QuantityToFill field
// for the coin the quantity field refers to is $DESO. If it's not $DESO, then it's assumed to be a DAO coin
func isCoinToFillDESO(
	buyingCoinPublicKeyBase58Check string,
	sellingCoinPublicKeyBase58Check string,
	operationTypeString DAOCoinLimitOrderOperationTypeString,
) bool {
	return buyingCoinPublicKeyBase58Check == DESOCoinIdentifierString && operationTypeString == DAOCoinLimitOrderOperationTypeStringBID ||
		sellingCoinPublicKeyBase58Check == DESOCoinIdentifierString && operationTypeString == DAOCoinLimitOrderOperationTypeStringASK
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

type DAOCoinLimitOrderFillTypeString string

const (
	DAOCoinLimitOrderFillTypeGoodTillCancelled DAOCoinLimitOrderFillTypeString = "GOOD_TILL_CANCELLED"
	DAOCoinLimitOrderFillTypeFillOrKill        DAOCoinLimitOrderFillTypeString = "FILL_OR_KILL"
	DAOCoinLimitOrderFillTypeImmediateOrCancel DAOCoinLimitOrderFillTypeString = "IMMEDIATE_OR_CANCEL"
)

func orderFillTypeToUint64(
	fillType DAOCoinLimitOrderFillTypeString,
) (lib.DAOCoinLimitOrderFillType, error) {
	switch fillType {
	case DAOCoinLimitOrderFillTypeGoodTillCancelled:
		return lib.DAOCoinLimitOrderFillTypeGoodTillCancelled, nil
	case DAOCoinLimitOrderFillTypeFillOrKill:
		return lib.DAOCoinLimitOrderFillTypeFillOrKill, nil
	case DAOCoinLimitOrderFillTypeImmediateOrCancel:
		return lib.DAOCoinLimitOrderFillTypeImmediateOrCancel, nil
	}
	return 0, errors.Errorf("Unknown DAO coin limit order fill type %v", fillType)
}

// returns (1e18 / 1e9), which represents the difference in scaling factor for DAO coin base units and $DESO nanos
func getDESOToDAOCoinBaseUnitsScalingFactor() *uint256.Int {
	return uint256.NewInt().Div(
		lib.BaseUnitsPerCoin,
		uint256.NewInt().SetUint64(lib.NanosPerUnit),
	)
}

// Given a value v that is a scaled uint256 with the provided scaling factor, this prints the decimal representation
// of v as a string
// Ex: if v = 12345 and scalingFactor = 100, then this outputs 123.45
func formatScaledUint256AsDecimalString(v *big.Int, scalingFactor *big.Int) string {
	wholeNumber := big.NewInt(0).Div(v, scalingFactor)
	decimalPart := big.NewInt(0).Mod(v, scalingFactor)

	decimalPartIsZero := decimalPart.Cmp(big.NewInt(0)) == 0

	scalingFactorDigits := getNumDigits(scalingFactor)
	decimalPartAsString := fmt.Sprintf("%d", decimalPart)

	// Left pad the decimal part with zeros
	if !decimalPartIsZero && len(decimalPartAsString) != scalingFactorDigits {
		decimalLeadingZeros := strings.Repeat("0", scalingFactorDigits-len(decimalPartAsString)-1)
		decimalPartAsString = fmt.Sprintf("%v%v", decimalLeadingZeros, decimalPartAsString)
	}

	// Trim trailing zeros
	if !decimalPartIsZero {
		decimalPartAsString = strings.TrimRight(decimalPartAsString, "0")
	}
	return fmt.Sprintf("%d.%v", wholeNumber, decimalPartAsString)
}

// Given a value v that is a scaled uint256 with the provided scaling factor, this prints v as a float scaled down
// by the scaling factor
// Ex: if v = 12345 and scalingFactor = 100, then this outputs 123.45
func calculateScaledUint256AsFloat(v *big.Int, scalingFactor *big.Int) (float64, error) {
	wholeNumber := big.NewInt(0).Div(v, scalingFactor)
	decimalPart := big.NewInt(0).Mod(v, scalingFactor)
	decimalLeadingZeros := strings.Repeat("0", getNumDigits(scalingFactor)-getNumDigits(decimalPart)-1)

	str := fmt.Sprintf("%d.%s%d", wholeNumber, decimalLeadingZeros, decimalPart)
	parsedFloat, err := strconv.ParseFloat(str, 64)
	if err != nil {
		// This should never happen since we're formatting the float ourselves above
		return 0, err
	}
	return parsedFloat, nil
}

// 15 is a magic number that represents the precision supported by the IEEE-754 float64 standard.
//
// If f is large (1e15 or higher), then we truncate any values beyond the first 15 digits, as
// the lack of precision can introduce garbage when printing as string
//
// If f is small (ex: 1e-15), then we print up to 15 digits to the right of the decimal point
// to make sure we capture all digits within the supported precision, but without introducing garbage
//
// The range of supported values for f is [1e-15, 1e308] with precision for the 15 most significant digits. The
// minimum value for this range artificially set to 1e-15, but can be extended all the way 1e-308 with a bit better math
func formatFloatAsString(f float64) string {
	fAsBigInt, _ := big.NewFloat(0).SetFloat64(f).Int(nil)
	supportedPrecisionDigits := 15
	numWholeNumberDigits := getNumDigits(fAsBigInt)
	// f is small, we'll print up to 15 total digits to the right of the decimal point
	if numWholeNumberDigits <= supportedPrecisionDigits {
		return fmt.Sprintf("%."+fmt.Sprintf("%d", supportedPrecisionDigits-numWholeNumberDigits)+"f", f)
	}
	// f is a large number > 1e15, so we truncate any values after the first 15 digits
	divisorToDropDigits := big.NewInt(10)
	divisorToDropDigits.Exp(divisorToDropDigits, big.NewInt(int64(numWholeNumberDigits-supportedPrecisionDigits)), nil)
	fAsBigInt.Div(fAsBigInt, divisorToDropDigits)
	fAsBigInt.Mul(fAsBigInt, divisorToDropDigits)
	return fmt.Sprintf("%d.0", fAsBigInt)
}

func getNumDigits(val *big.Int) int {
	quotient := big.NewInt(0).Set(val)
	zero := big.NewInt(0)
	ten := big.NewInt(10)
	numDigits := 0
	for quotient.Cmp(zero) != 0 {
		numDigits += 1
		quotient.Div(quotient, ten)
	}
	return numDigits
}

// This is a quick sanity check. Any valid decimal string should successfully parse into a non-negative float64
func validateNonNegativeDecimalString(str string) error {
	floatValue, err := strconv.ParseFloat(str, 64)
	if err != nil {
		return errors.Errorf("Error parsing input %v as a decimal string: %v", str, err)
	}
	if floatValue < 0 {
		return errors.Errorf("Input decimal string %v is unexpectedly less than 0", str)
	}
	return nil
}

func (fes *APIServer) validateTransactorSellingCoinBalance(
	transactorPublicKeyBase58Check string,
	buyingDAOCoinCreatorPublicKeyBase58Check string,
	sellingDAOCoinCreatorPublicKeyBase58Check string,
	operationType DAOCoinLimitOrderOperationTypeString,
	scaledExchangeRateCoinsToSellPerCoinToBuy *uint256.Int,
	quantityToFillInBaseUnits *uint256.Int) error {
	// Validate transactor has sufficient selling coins to place
	// this new order incorporating all of their open orders.

	// Get UTXO view.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return errors.Errorf("Problem fetching UTXOView: %v", err)
	}

	// Get transactor PKID and public key from public key base58 check.
	transactorPKID, err := fes.getPKIDFromPublicKeyBase58Check(
		utxoView, transactorPublicKeyBase58Check)
	if err != nil {
		return errors.Errorf("Invalid TransactorPublicKeyBase58Check: %v", err)
	}
	transactorPublicKey, _, err := lib.Base58CheckDecode(transactorPublicKeyBase58Check)
	if err != nil {
		return errors.Errorf("Error decoding transactor public key: %v", err)
	}

	// If buying $DESO, the buying PKID is the ZeroPKID. Else it's the DAO coin's PKID.
	buyingCoinPKID := &lib.ZeroPKID
	if buyingDAOCoinCreatorPublicKeyBase58Check != DESOCoinIdentifierString {
		buyingCoinPKID, err = fes.getPKIDFromPublicKeyBase58Check(
			utxoView, buyingDAOCoinCreatorPublicKeyBase58Check)
		if err != nil {
			return errors.Errorf("Invalid BuyingDAOCoinCreatorPublicKeyBase58Check: %v", err)
		}
	}

	// If selling $DESO, the selling PKID is the ZeroPKID. We consider this the default
	// case and update if the transactor is actually selling a DAO coin below.
	sellingCoinPKID := &lib.ZeroPKID

	// Calculate current balance for transactor.
	transactorSellingBalanceBaseUnits := uint256.NewInt()
	if sellingDAOCoinCreatorPublicKeyBase58Check == DESOCoinIdentifierString {
		// Get $DESO balance nanos.
		desoBalanceNanos, err := utxoView.GetDeSoBalanceNanosForPublicKey(transactorPublicKey)
		if err != nil {
			return errors.Errorf("Error getting transactor DESO balance: %v", err)
		}
		transactorSellingBalanceBaseUnits = uint256.NewInt().SetUint64(desoBalanceNanos)
	} else {
		// Get selling coin PKID and public key from public key base58 check.
		sellingCoinPKID, err = fes.getPKIDFromPublicKeyBase58Check(
			utxoView, sellingDAOCoinCreatorPublicKeyBase58Check)
		if err != nil {
			return errors.Errorf("Invalid SellingDAOCoinCreatorPublicKeyBase58Check: %v", err)
		}
		sellingPublicKey, _, err := lib.Base58CheckDecode(sellingDAOCoinCreatorPublicKeyBase58Check)
		if err != nil {
			return errors.Errorf("Error decoding selling public key: %v", err)
		}

		// Get DAO coin balance base units.
		balanceEntry, _, _ := utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(transactorPublicKey, sellingPublicKey, true)
		if balanceEntry == nil {
			return errors.New("Error getting transactor DAO coin balance not found")
		}
		transactorSellingBalanceBaseUnits = &balanceEntry.BalanceNanos
	}

	// Get open orders for this transactor
	orders, err := utxoView.GetAllDAOCoinLimitOrdersForThisTransactor(transactorPKID)
	if err != nil {
		return errors.Errorf("Error getting limit orders: %v", err)
	}

	// Calculate total selling quantity for current order.
	totalSellingBaseUnits := uint256.NewInt()
	if operationType == DAOCoinLimitOrderOperationTypeStringASK {
		totalSellingBaseUnits = quantityToFillInBaseUnits
	} else if operationType == DAOCoinLimitOrderOperationTypeStringBID {
		totalSellingBaseUnits, err = lib.ComputeBaseUnitsToSellUint256(
			scaledExchangeRateCoinsToSellPerCoinToBuy, quantityToFillInBaseUnits)
		if err != nil {
			return errors.Errorf("Error calculating new order selling quantity: %v", err)
		}
	} else {
		return errors.Errorf("Invalid operation type: %s", operationType)
	}

	// Add total selling quantity for existing/open orders.
	for _, order := range orders {
		if buyingCoinPKID.Eq(order.BuyingDAOCoinCreatorPKID) &&
			sellingCoinPKID.Eq(order.SellingDAOCoinCreatorPKID) {
			// Calculate selling quantity.
			orderSellingBaseUnits, err := order.BaseUnitsToSellUint256()
			if err != nil {
				return errors.Errorf("Error calculating open order selling quantity: %v", err)
			}

			// Sum selling quantity.
			totalSellingBaseUnits, err = lib.SafeUint256().Add(totalSellingBaseUnits, orderSellingBaseUnits)
			if err != nil {
				return errors.Errorf("Error adding open order selling quantity: %v", err)
			}
		}
	}

	// Compare transactor selling balance to total selling quantity.
	if transactorSellingBalanceBaseUnits.Lt(totalSellingBaseUnits) {
		return errors.Errorf("Insufficient balance to open order")
	}

	// Happy path. No error. Transactor has sufficient balance to cover their selling quantity.
	return nil
}

func (fes *APIServer) validateDAOCoinOrderTransferRestriction(
	transactorPublicKeyBase58Check string, buyingDAOCoinCreatorPublicKeyBase58Check string) error {

	// If buying $DESO, this never has a transfer restriction. We validate
	// that you own sufficient of your selling coin elsewhere.
	if buyingDAOCoinCreatorPublicKeyBase58Check == DESOCoinIdentifierString {
		return nil
	}

	// Get UTXO view.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return errors.Errorf("Problem fetching UTXOView: %v", err)
	}

	// Get transactor PublicKey from PublicKeyBase58Check.
	transactorPublicKey, _, err := lib.Base58CheckDecode(transactorPublicKeyBase58Check)
	if err != nil {
		return errors.Errorf("Error decoding transactor public key: %v", err)
	}

	// Get buying DAO coin creator PublicKey from PublicKeyBase58Check.
	buyingCoinPublicKey, _, err := lib.Base58CheckDecode(buyingDAOCoinCreatorPublicKeyBase58Check)
	if err != nil {
		return errors.Errorf("Error decoding buying DAO coin creator public key: %v", err)
	}

	// Get buying DAO coin profile entry.
	profileEntry := utxoView.GetProfileEntryForPublicKey(buyingCoinPublicKey)
	if profileEntry == nil || profileEntry.IsDeleted() {
		return errors.New("Buying DAO coin creator profile entry not found")
	}

	// Validate if transfer restriction status is PROFILE OWNER ONLY.
	if profileEntry.DAOCoinEntry.TransferRestrictionStatus == lib.TransferRestrictionStatusProfileOwnerOnly &&
		!bytes.Equal(transactorPublicKey, buyingCoinPublicKey) {
		return errors.New("Buying this DAO coin is restricted to the creator of the DAO")
	}

	// Validate if transfer restriction status is MEMBERS ONLY.
	if profileEntry.DAOCoinEntry.TransferRestrictionStatus == lib.TransferRestrictionStatusDAOMembersOnly {
		// Retrieve transactor's DAO coin balance. Error if balance is zero.
		balanceEntry, _, _ := utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(transactorPublicKey, buyingCoinPublicKey, true)
		if balanceEntry == nil || balanceEntry.BalanceNanos.IsZero() {
			return errors.New("Buying this DAO coin is restricted to users who already own this DAO coin")
		}
	}

	return nil
}

func (fes *APIServer) getDAOCoinLimitOrderSimulatedExecutionResult(
	utxoView *lib.UtxoView,
	transactorPublicKeyBase58Check string,
	buyingDAOCoinCreatorPublicKeyBase58Check string,
	sellingDAOCoinCreatorPublicKeyBase58Check string,
	txn *lib.MsgDeSoTxn,
) (*DAOCoinLimitOrderSimulatedExecutionResult, error) {
	buyingCoinStartingBalance, err := fes.getTransactorDesoOrDaoCoinBalance(utxoView, transactorPublicKeyBase58Check, buyingDAOCoinCreatorPublicKeyBase58Check)
	if err != nil {
		return nil, err
	}
	sellingCoinStartingBalance, err := fes.getTransactorDesoOrDaoCoinBalance(utxoView, transactorPublicKeyBase58Check, sellingDAOCoinCreatorPublicKeyBase58Check)
	if err != nil {
		return nil, err
	}

	txnFees, err := fes.simulateSubmitTransaction(utxoView, txn)
	if err != nil {
		return nil, err
	}

	buyingCoinEndingBalance, err := fes.getTransactorDesoOrDaoCoinBalance(utxoView, transactorPublicKeyBase58Check, buyingDAOCoinCreatorPublicKeyBase58Check)
	if err != nil {
		return nil, err
	}
	if buyingDAOCoinCreatorPublicKeyBase58Check == DESOCoinIdentifierString {
		// If the buying coin is DESO, then the ending balance change will have the transaction fee subtracted. In order to
		// isolate the amount of the buying coin bought as a part of this order, we need to add back the transaction fee
		buyingCoinEndingBalance.Add(buyingCoinEndingBalance, uint256.NewInt().SetUint64(txnFees))
	}

	sellingCoinEndingBalance, err := fes.getTransactorDesoOrDaoCoinBalance(utxoView, transactorPublicKeyBase58Check, sellingDAOCoinCreatorPublicKeyBase58Check)
	if err != nil {
		return nil, err
	}
	if sellingDAOCoinCreatorPublicKeyBase58Check == DESOCoinIdentifierString {
		// If the selling coin is DESO, then the ending balance will have the network fee subtracted. In order to isolate
		// the amount of the selling coin sold as a part of this order, we need to add back the transaction fee to the
		// ending balance
		sellingCoinEndingBalance.Add(sellingCoinEndingBalance, uint256.NewInt().SetUint64(txnFees))
	}

	buyingCoinBalanceChange := "0.0"
	sellingCoinBalanceChange := "0.0"

	if buyingCoinEndingBalance.Lt(buyingCoinStartingBalance) {
		return nil, errors.Errorf("Buying coin balance cannot decrease as a result of a DAO coin limit order execution")
	}

	if sellingCoinEndingBalance.Gt(sellingCoinStartingBalance) {
		return nil, errors.Errorf("Selling coin balance cannot increase as a result of a DAO coin limit order execution")
	}

	// Convert buying coin balance change from uint256 to as a decimal string (ex: 1.23)
	buyingCoinBalanceChange = formatScaledUint256AsDecimalString(
		uint256.NewInt().Sub(buyingCoinEndingBalance, buyingCoinStartingBalance).ToBig(),
		getScalingFactorForCoin(buyingDAOCoinCreatorPublicKeyBase58Check).ToBig(),
	)

	// Convert selling coin balance change from uint256 to as a decimal string (ex: 1.23)
	sellingCoinBalanceChange = formatScaledUint256AsDecimalString(
		uint256.NewInt().Sub(sellingCoinStartingBalance, sellingCoinEndingBalance).ToBig(),
		getScalingFactorForCoin(sellingDAOCoinCreatorPublicKeyBase58Check).ToBig(),
	)

	return &DAOCoinLimitOrderSimulatedExecutionResult{
		BuyingCoinQuantityFilled:  buyingCoinBalanceChange,
		SellingCoinQuantityFilled: sellingCoinBalanceChange,
	}, nil
}

func (fes *APIServer) getTransactorDesoOrDaoCoinBalance(
	utxoView *lib.UtxoView,
	transactorPublicKeyBase58Check string,
	desoOrDAOCoinCreatorPublicKeyBase58Check string,
) (*uint256.Int, error) {
	transactorPublicKey, _, err := lib.Base58CheckDecode(transactorPublicKeyBase58Check)
	if err != nil {
		return nil, errors.Errorf("Error decoding transactor public key: %v", err)
	}

	if desoOrDAOCoinCreatorPublicKeyBase58Check == DESOCoinIdentifierString {
		// Get $DESO balance nanos.
		desoBalanceNanos, err := utxoView.GetDeSoBalanceNanosForPublicKey(transactorPublicKey)
		if err != nil {
			return nil, errors.Errorf("Error getting transactor DESO balance: %v", err)
		}
		return uint256.NewInt().SetUint64(desoBalanceNanos), nil
	}

	daoCoinCreatorPublicKey, _, err := lib.Base58CheckDecode(desoOrDAOCoinCreatorPublicKeyBase58Check)
	if err != nil {
		return nil, errors.Errorf("Error decoding dao coin public key: %v", err)
	}

	// Get DAO coin balance base units.
	balanceEntry, _, _ := utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(transactorPublicKey, daoCoinCreatorPublicKey, true)
	if balanceEntry == nil {
		return nil, errors.New("Error getting transactor DAO coin balance")
	}
	return &balanceEntry.BalanceNanos, nil
}

func getScalingFactorForCoin(coinCreatorPublicKeyBase58Check string) *uint256.Int {
	if coinCreatorPublicKeyBase58Check == DESOCoinIdentifierString {
		return uint256.NewInt().SetUint64(lib.NanosPerUnit)
	}
	return uint256.NewInt().Set(lib.BaseUnitsPerCoin)
}
