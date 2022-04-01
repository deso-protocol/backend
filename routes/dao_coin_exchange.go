package routes

import (
	"encoding/json"
	"fmt"
	"github.com/deso-protocol/core/lib"
	"github.com/holiman/uint256"
	"io"
	"math/big"
	"net/http"
)

type GetDAOCoinLimitOrdersRequest struct {
	DAOCoin1CreatorPublicKeyBase58CheckOrUsername string `safeForLogging:"true"`
	DAOCoin2CreatorPublicKeyBase58CheckOrUsername string `safeForLogging:"true"`
}

type GetDAOCoinLimitOrdersResponse struct {
	Orders []DAOCoinLimitOrder
}

type DAOCoinLimitOrder struct {
	TransactorPublicKeyBase58CheckOrUsername string `safeForLogging:"true"`

	BuyingDAOCoinCreatorPublicKeyBase58CheckOrUsername  string `safeForLogging:"true"`
	SellingDAOCoinCreatorPublicKeyBase58CheckOrUsername string `safeForLogging:"true"`

	// One of these two should be populated
	ScaledExchangeRateCoinsToSellPerCoinToBuy *uint256.Int `safeForLogging:"true"`
	ExchangeRateCoinsToSellPerCoinToBuy       float64      `safeForLogging:"true"`

	// One of these two should be populated
	QuantityToBuyInBaseUnits *uint256.Int `safeForLogging:"true"`
	QuantityToBuy            float64      `safeForLogging:"true"`
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
		_AddBadRequestError(ww, fmt.Sprintf("GetDAOCoinLimitOrders: Problem fetching utxoView: %v", err))
		return
	}

	coin1PKID := &lib.ZeroPKID
	coin2PKID := &lib.ZeroPKID

	coin1ProfilePublicKeyBytes := lib.ZeroPublicKey.ToBytes()
	coin2ProfilePublicKeyBytes := lib.ZeroPublicKey.ToBytes()

	coin1ProfilePublicBase58Check := ""
	coin2ProfilePublicBase58Check := ""

	if requestData.DAOCoin1CreatorPublicKeyBase58CheckOrUsername != "" {
		coin1ProfilePublicKeyBytes, _, err = fes.GetPubKeAndProfileEntryForUsernameOrPublicKeyBase58Check(
			requestData.DAOCoin1CreatorPublicKeyBase58CheckOrUsername,
			utxoView,
		)
		if err != nil {
			_AddBadRequestError(
				ww,
				fmt.Sprint("GetDAOCoinLimitOrders: Invalid DAOCoin1CreatorPublicKeyBase58CheckOrUsername"),
			)
			return
		}
		coin1PKID = utxoView.GetPKIDForPublicKey(coin1ProfilePublicKeyBytes).PKID
		coin1ProfilePublicBase58Check = lib.Base58CheckEncode(coin1ProfilePublicKeyBytes, false, fes.Params)
	}

	if requestData.DAOCoin2CreatorPublicKeyBase58CheckOrUsername != "" {
		coin2ProfilePublicKeyBytes, _, err = fes.GetPubKeAndProfileEntryForUsernameOrPublicKeyBase58Check(
			requestData.DAOCoin2CreatorPublicKeyBase58CheckOrUsername,
			utxoView,
		)
		if err != nil {
			_AddBadRequestError(
				ww,
				fmt.Sprint("GetDAOCoinLimitOrders: Invalid DAOCoin2CreatorPublicKeyBase58CheckOrUsername"),
			)
			return
		}
		coin2PKID = utxoView.GetPKIDForPublicKey(coin2ProfilePublicKeyBytes).PKID
		coin2ProfilePublicBase58Check = lib.Base58CheckEncode(coin2ProfilePublicKeyBytes, false, fes.Params)
	}

	adapter := utxoView.GetDbAdapter()

	ordersBuyingCoin1, err := adapter.GetAllDAOCoinLimitOrdersForThisDAOCoinPair(coin1PKID, coin2PKID)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDAOCoinLimitOrders: Error getting limit orders: %v", err))
		return
	}

	ordersSellingCoin1, err := adapter.GetAllDAOCoinLimitOrdersForThisDAOCoinPair(coin2PKID, coin1PKID)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDAOCoinLimitOrders: Error getting limit orders: %v", err))
		return
	}

	var response []DAOCoinLimitOrder

	for _, order := range ordersBuyingCoin1 {
		transactorPublicKey := utxoView.GetPublicKeyForPKID(order.TransactorPKID)
		response = append(response, DAOCoinLimitOrder{
			TransactorPublicKeyBase58CheckOrUsername: lib.Base58CheckEncode(transactorPublicKey, false, fes.Params),

			BuyingDAOCoinCreatorPublicKeyBase58CheckOrUsername:  coin1ProfilePublicBase58Check,
			SellingDAOCoinCreatorPublicKeyBase58CheckOrUsername: coin2ProfilePublicBase58Check,
			ScaledExchangeRateCoinsToSellPerCoinToBuy:           order.ScaledExchangeRateCoinsToSellPerCoinToBuy,
			ExchangeRateCoinsToSellPerCoinToBuy: floatExchangeRateCoinsToSellPerCoinToBuy(
				order.ScaledExchangeRateCoinsToSellPerCoinToBuy,
			),
			QuantityToBuyInBaseUnits: order.QuantityToBuyInBaseUnits,
			QuantityToBuy:            floatQuantityToBuy(order.QuantityToBuyInBaseUnits),
		})
	}

	for _, order := range ordersSellingCoin1 {
		transactorPublicKey := utxoView.GetPublicKeyForPKID(order.TransactorPKID)
		response = append(response, DAOCoinLimitOrder{
			TransactorPublicKeyBase58CheckOrUsername: lib.Base58CheckEncode(transactorPublicKey, false, fes.Params),

			BuyingDAOCoinCreatorPublicKeyBase58CheckOrUsername:  coin2ProfilePublicBase58Check,
			SellingDAOCoinCreatorPublicKeyBase58CheckOrUsername: coin1ProfilePublicBase58Check,
			ScaledExchangeRateCoinsToSellPerCoinToBuy:           order.ScaledExchangeRateCoinsToSellPerCoinToBuy,
			ExchangeRateCoinsToSellPerCoinToBuy: floatExchangeRateCoinsToSellPerCoinToBuy(
				order.ScaledExchangeRateCoinsToSellPerCoinToBuy,
			),
			QuantityToBuyInBaseUnits: order.QuantityToBuyInBaseUnits,
			QuantityToBuy:            floatQuantityToBuy(order.QuantityToBuyInBaseUnits),
		})
	}

	_ = json.NewEncoder(ww).Encode(GetDAOCoinLimitOrdersResponse{Orders: response})
}

// Given a value v, this computes v / (2 ^ 128) and returns it as float
func floatExchangeRateCoinsToSellPerCoinToBuy(scaledValue *uint256.Int) float64 {
	base := big.NewInt(2)
	exponent := big.NewInt(128)
	divisor := big.NewFloat(0).SetInt(base.Exp(base, exponent, nil))

	scaledValueAsBigFloat := big.NewFloat(0).SetInt(scaledValue.ToBig())

	quotientAsBigFloat := big.NewFloat(0).Quo(
		scaledValueAsBigFloat,
		divisor,
	)
	quotient, _ := quotientAsBigFloat.Float64()
	return quotient
}

// Given a quantity q, this returns q / (NanosPerUnit) as float
func floatQuantityToBuy(quantityInBaseUnits *uint256.Int) float64 {
	quantityInBaseUnitsAsBigFloat := big.NewFloat(0).SetInt(quantityInBaseUnits.ToBig())
	divisor := big.NewFloat(float64(lib.NanosPerUnit))
	quotientAsBigFloat := big.NewFloat(0).Quo(
		quantityInBaseUnitsAsBigFloat,
		divisor,
	)
	quotient, _ := quotientAsBigFloat.Float64()
	return quotient
}
