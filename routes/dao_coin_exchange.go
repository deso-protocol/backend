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
	TransactorPublicKeyBase58Check string `safeForLogging:"true"`

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

	QuantityToFillInBaseUnits *uint256.Int `safeForLogging:"true"`
	QuantityToFill            float64      `safeForLogging:"true"`

	SideToFill string
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

		sideToFill := "BID"
		if order.OperationType == lib.DAOCoinLimitOrderOperationTypeASK {
			sideToFill = "ASK"
		}

		response = append(response, DAOCoinLimitOrderEntryResponse{
			TransactorPublicKeyBase58Check: lib.Base58CheckEncode(transactorPublicKey, false, fes.Params),

			BuyingDAOCoinCreatorPublicKeyBase58Check:  coin1ProfilePublicBase58Check,
			SellingDAOCoinCreatorPublicKeyBase58Check: coin2ProfilePublicBase58Check,
			ScaledExchangeRateCoinsToSellPerCoinToBuy: order.ScaledExchangeRateCoinsToSellPerCoinToBuy,
			ExchangeRateCoinsToSellPerCoinToBuy: floatExchangeRateCoinsToSellPerCoinToBuy(
				order.ScaledExchangeRateCoinsToSellPerCoinToBuy,
			),
			QuantityToFillInBaseUnits: order.QuantityToFillInBaseUnits,
			QuantityToFill:            floatQuantityToFill(order.QuantityToFillInBaseUnits),

			SideToFill: sideToFill,
		})
	}

	for _, order := range ordersSellingCoin1 {
		transactorPublicKey := utxoView.GetPublicKeyForPKID(order.TransactorPKID)

		sideToFill := "BID"
		if order.OperationType == lib.DAOCoinLimitOrderOperationTypeASK {
			sideToFill = "ASK"
		}

		response = append(response, DAOCoinLimitOrderEntryResponse{
			TransactorPublicKeyBase58Check: lib.Base58CheckEncode(transactorPublicKey, false, fes.Params),

			BuyingDAOCoinCreatorPublicKeyBase58Check:  coin2ProfilePublicBase58Check,
			SellingDAOCoinCreatorPublicKeyBase58Check: coin1ProfilePublicBase58Check,
			ScaledExchangeRateCoinsToSellPerCoinToBuy: order.ScaledExchangeRateCoinsToSellPerCoinToBuy,
			ExchangeRateCoinsToSellPerCoinToBuy: floatExchangeRateCoinsToSellPerCoinToBuy(
				order.ScaledExchangeRateCoinsToSellPerCoinToBuy,
			),
			QuantityToFillInBaseUnits: order.QuantityToFillInBaseUnits,
			QuantityToFill:            floatQuantityToFill(order.QuantityToFillInBaseUnits),

			SideToFill: sideToFill,
		})
	}

	if err = json.NewEncoder(ww).Encode(GetDAOCoinLimitOrdersResponse{Orders: response}); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDAOCoinLimitOrders: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) GetDAOCoinTrades(ww http.ResponseWriter, req *http.Request) {
	// If the TxIndex flag was not passed to this node then we don't track order fills
	if fes.TXIndex == nil {
		_AddBadRequestError(
			ww,
			fmt.Sprintf("GetDAOCoinLimitOrderFills: Cannot be called when TXIndexChain "+
				"is nil. This error occurs when --txindex was not passed to the program "+
				"on startup"),
		)
	}

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetDAOCoinLimitOrdersRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(
			ww,
			fmt.Sprintf("GetDAOCoinLimitOrderFills: Problem parsing request body: %v", err),
		)
		return
	}

	getNotificationsRequest := GetNotificationsRequest{
		PublicKeyBase58Check:              requestData.TransactorPublicKeyBase58Check,
		FetchStartIndex:                   -1,
		NumToFetch:                        10000,
		FilteredOutNotificationCategories: map[string]bool{},
	}

	// A valid mempool object is used to compute the TransactionMetadata for the mempool
	// and to allow for things like: filtering notifications for a hidden post.
	utxoView, err := fes.mempool.GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(
			ww,
			fmt.Sprintf("GetDAOCoinLimitOrderFills: Problem getting view: %v", err),
		)
		return
	}

	blocked := map[string]struct{}{}

	// Get notifications from the db
	dbTxnMetadataFound, err := fes._getDBNotifications(&getNotificationsRequest, blocked, utxoView, true)
	if err != nil {
		_AddBadRequestError(
			ww,
			fmt.Sprintf("GetDAOCoinLimitOrderFills: Error getting DB Notifications: %v", err),
		)
		return
	}

	mempoolTxnMetadataFound, err := fes._getMempoolNotifications(
		&getNotificationsRequest,
		blocked,
		utxoView,
		true,
	)
	if err != nil {
		_AddBadRequestError(
			ww,
			fmt.Sprintf("GetDAOCoinLimitOrderFills: Error getting mempool Notifications: %v", err),
		)
		return
	}

	// At this point, the combinedMempoolDBTxnMetadata either contains the latest transactions
	// from the mempool *or* it's empty. The latter occurs when the FetchStartIndex
	// is set to a value below the smallest index of any transaction in the mempool.
	// In either case, appending the transactions we found in the db is the correct
	// thing to do.
	combinedMempoolDBTxnMetadata := append(
		mempoolTxnMetadataFound,
		dbTxnMetadataFound...,
	)

	trades := []*lib.FilledDAOCoinLimitOrderMetadata{}
	for _, metadata := range combinedMempoolDBTxnMetadata {
		if metadata.Metadata.DAOCoinLimitOrderTxindexMetadata != nil {
			fills := metadata.Metadata.DAOCoinLimitOrderTxindexMetadata.FilledDAOCoinLimitOrdersMetadata
			if fills != nil {
				for _, fill := range fills {
					if fill.TransactorPublicKeyBase58Check == requestData.TransactorPublicKeyBase58Check {
						trades = append(trades, fill)
					}
				}
			}
		}
	}

	var response []DAOCoinLimitOrderEntryResponse

	//for _, trade := range trades {
	//	response = append(response, DAOCoinLimitOrderEntryResponse{
	//		TransactorPublicKeyBase58Check: requestData.TransactorPublicKeyBase58Check,
	//
	//		BuyingDAOCoinCreatorPublicKeyBase58Check:  trade.BuyingDAOCoinCreatorPublicKey,
	//		SellingDAOCoinCreatorPublicKeyBase58Check: trade.SellingDAOCoinCreatorPublicKey,
	//		ScaledExchangeRateCoinsToSellPerCoinToBuy: trade.SellingDAOCoinQuantitySold,
	//		ExchangeRateCoinsToSellPerCoinToBuy: floatExchangeRateCoinsToSellPerCoinToBuy(
	//			trade.SellingDAOCoinQuantitySold,
	//		),
	//		QuantityToBuyInBaseUnits: trade.BuyingDAOCoinQuantityPurchased,
	//		QuantityToBuy: floatQuantityToBuy(
	//			trade.BuyingDAOCoinQuantityPurchased,
	//		),
	//	})
	//}

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
	valueBigFloat := big.NewFloat(0).SetInt(scaledValue.ToBig())
	divisorBigFloat := big.NewFloat(0).SetInt(lib.OneE38.ToBig())

	quotientBigFloat := big.NewFloat(0).Quo(valueBigFloat, divisorBigFloat)

	quotientFloat, _ := quotientBigFloat.Float64()
	return quotientFloat
}

// Given a quantity q, this returns q / (NanosPerUnit) as float
func floatQuantityToFill(quantityInBaseUnits *uint256.Int) float64 {
	quantityInBaseUnitsAsBigFloat := big.NewFloat(0).SetInt(quantityInBaseUnits.ToBig())
	divisor := big.NewFloat(float64(lib.NanosPerUnit))
	quotientAsBigFloat := big.NewFloat(0).Quo(
		quantityInBaseUnitsAsBigFloat,
		divisor,
	)
	quotient, _ := quotientAsBigFloat.Float64()
	return quotient
}
