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
	Orders []DAOCoinLimitOrderEntryResponse
}

type DAOCoinLimitOrderEntryResponse struct {
	TransactorPublicKeyBase58Check string `safeForLogging:"true"`

	BuyingDAOCoinCreatorPublicKeyBase58Check  string `safeForLogging:"true"`
	SellingDAOCoinCreatorPublicKeyBase58Check string `safeForLogging:"true"`

	ScaledExchangeRateCoinsToSellPerCoinToBuy *uint256.Int `safeForLogging:"true"`
	ExchangeRateCoinsToSellPerCoinToBuy       float64      `safeForLogging:"true"`
	
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

	coin1ProfilePublicBase58Check := ""
	coin2ProfilePublicBase58Check := ""

	if requestData.DAOCoin1CreatorPublicKeyBase58CheckOrUsername != "" {
		coin1ProfilePublicBase58Check, coin1PKID, err = fes.validateCreatorPublicKeyBase58CheckOrUsername(
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
		coin2ProfilePublicBase58Check, coin2PKID, err = fes.validateCreatorPublicKeyBase58CheckOrUsername(
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
		_AddBadRequestError(ww, fmt.Sprintf("GetDAOCoinLimitOrders: Error getting limit orders: %v", err))
		return
	}

	ordersSellingCoin1, err := utxoView.GetAllDAOCoinLimitOrdersForThisDAOCoinPair(coin2PKID, coin1PKID)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDAOCoinLimitOrders: Error getting limit orders: %v", err))
		return
	}

	var response []DAOCoinLimitOrderEntryResponse

	for _, order := range ordersBuyingCoin1 {
		transactorPublicKey := utxoView.GetPublicKeyForPKID(order.TransactorPKID)
		response = append(response, DAOCoinLimitOrderEntryResponse{
			TransactorPublicKeyBase58Check: lib.Base58CheckEncode(transactorPublicKey, false, fes.Params),

			BuyingDAOCoinCreatorPublicKeyBase58Check:  coin1ProfilePublicBase58Check,
			SellingDAOCoinCreatorPublicKeyBase58Check: coin2ProfilePublicBase58Check,
			ScaledExchangeRateCoinsToSellPerCoinToBuy: order.ScaledExchangeRateCoinsToSellPerCoinToBuy,
			ExchangeRateCoinsToSellPerCoinToBuy: floatExchangeRateCoinsToSellPerCoinToBuy(
				order.ScaledExchangeRateCoinsToSellPerCoinToBuy,
			),
			QuantityToBuyInBaseUnits: order.QuantityToBuyInBaseUnits,
			QuantityToBuy:            floatQuantityToBuy(order.QuantityToBuyInBaseUnits),
		})
	}

	for _, order := range ordersSellingCoin1 {
		transactorPublicKey := utxoView.GetPublicKeyForPKID(order.TransactorPKID)
		response = append(response, DAOCoinLimitOrderEntryResponse{
			TransactorPublicKeyBase58Check: lib.Base58CheckEncode(transactorPublicKey, false, fes.Params),

			BuyingDAOCoinCreatorPublicKeyBase58Check:  coin2ProfilePublicBase58Check,
			SellingDAOCoinCreatorPublicKeyBase58Check: coin1ProfilePublicBase58Check,
			ScaledExchangeRateCoinsToSellPerCoinToBuy: order.ScaledExchangeRateCoinsToSellPerCoinToBuy,
			ExchangeRateCoinsToSellPerCoinToBuy: floatExchangeRateCoinsToSellPerCoinToBuy(
				order.ScaledExchangeRateCoinsToSellPerCoinToBuy,
			),
			QuantityToBuyInBaseUnits: order.QuantityToBuyInBaseUnits,
			QuantityToBuy:            floatQuantityToBuy(order.QuantityToBuyInBaseUnits),
		})
	}

	if err = json.NewEncoder(ww).Encode(GetDAOCoinLimitOrdersResponse{Orders: response}); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDAOCoinLimitOrders: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) validateCreatorPublicKeyBase58CheckOrUsername(
	utxoView *lib.UtxoView,
	publicKeyBase58CheckOrUsername string,
) (string, *lib.PKID, error) {
	publicKeyBytes, _, err := fes.GetPubKeyAndProfileEntryForUsernameOrPublicKeyBase58Check(
		publicKeyBase58CheckOrUsername,
		utxoView,
	)
	if err != nil {
		return "", &lib.ZeroPKID, err
	}

	pkid := utxoView.GetPKIDForPublicKey(publicKeyBytes).PKID
	publicKeyBase58Check := lib.Base58CheckEncode(publicKeyBytes, false, fes.Params)

	return publicKeyBase58Check, pkid, nil
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
