package routes

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/deso-protocol/core/lib"
	"github.com/holiman/uint256"
	"io"
	"math/big"
	"net/http"
	"strconv"
)

type UpdateDaoCoinMarketFeesRequest struct {
	// The public key of the user who is trying to update the
	// fees for their market.
	UpdaterPublicKeyBase58Check string `safeForLogging:"true"`

	// This is only set when the user wants to modify a profile
	// that isn't theirs. Otherwise, the UpdaterPublicKeyBase58Check is
	// assumed to own the profile being updated.
	ProfilePublicKeyBase58Check string `safeForLogging:"true"`

	// A map of pkid->feeBasisPoints that the user wants to set for their market.
	// If the map contains {pkid1: 100, pkid2: 200} then the user is setting the
	// feeBasisPoints for pkid1 to 100 and the feeBasisPoints for pkid2 to 200.
	// This means that pkid1 will get 1% of every taker's trade and pkid2 will get
	// 2%.
	FeeBasisPointsByPkid map[string]uint64 `safeForLogging:"true"`

	MinFeeRateNanosPerKB uint64 `safeForLogging:"true"`

	OptionalPrecedingTransactions []*lib.MsgDeSoTxn `safeForLogging:"true"`
}

type UpdateDaoCoinMarketFeesResponse struct {
	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgDeSoTxn
	TransactionHex    string
	TxnHashHex        string
}

func ValidateTradingFeeMap(feeMap map[string]uint64) error {
	totalFeeBasisPoints := big.NewInt(0)
	for _, feeBasisPoints := range feeMap {
		totalFeeBasisPoints.Add(totalFeeBasisPoints, big.NewInt(int64(feeBasisPoints)))
	}
	if totalFeeBasisPoints.Cmp(big.NewInt(100*100)) > 0 {
		return fmt.Errorf("Trading fees must sum to less than 100%")
	}
	return nil
}

func (fes *APIServer) UpdateDaoCoinMarketFees(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := UpdateDaoCoinMarketFeesRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateDaoCoinMarketFees: Problem parsing request body: %v", err))
		return
	}

	// Decode the public key
	updaterPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.UpdaterPublicKeyBase58Check)
	if err != nil || len(updaterPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		_AddBadRequestError(ww, fmt.Sprintf(
			"UpdateDAOCoinMarketFees: Problem decoding public key %s: %v",
			requestData.UpdaterPublicKeyBase58Check, err))
		return
	}

	// If we're missing trading fees then error
	if len(requestData.FeeBasisPointsByPkid) == 0 {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateDaoCoinMarketFees: Must provide at least one fee to update"))
		return
	}

	// Validate the fee map.
	if err := ValidateTradingFeeMap(requestData.FeeBasisPointsByPkid); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateDaoCoinMarketFees: %v", err))
		return
	}

	utxoView, err := lib.GetAugmentedUniversalViewWithAdditionalTransactions(
		fes.backendServer.GetMempool(),
		requestData.OptionalPrecedingTransactions,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateDaoCoinMarketFees: Error fetching mempool view: %v", err))
		return
	}

	// When this is nil then the UpdaterPublicKey is assumed to be the owner of
	// the profile.
	var profilePublicKeyBytess []byte
	if requestData.ProfilePublicKeyBase58Check != "" {
		profilePublicKeyBytess, _, err = lib.Base58CheckDecode(requestData.ProfilePublicKeyBase58Check)
		if err != nil || len(profilePublicKeyBytess) != btcec.PubKeyBytesLenCompressed {
			_AddBadRequestError(ww, fmt.Sprintf(
				"UpdateDaoCoinMarketFees: Problem decoding public key %s: %v",
				requestData.ProfilePublicKeyBase58Check, err))
			return
		}
	}

	// Get the public key.
	profilePublicKey := updaterPublicKeyBytes
	if requestData.ProfilePublicKeyBase58Check != "" {
		profilePublicKey = profilePublicKeyBytess
	}

	// Pull the existing profile. If one doesn't exist, then we error. The user should
	// create a profile first before trying to update the fee params for their market.
	existingProfileEntry := utxoView.GetProfileEntryForPublicKey(profilePublicKey)
	if existingProfileEntry == nil || existingProfileEntry.IsDeleted() {
		_AddBadRequestError(ww, fmt.Sprintf(
			"UpdateDaoCoinMarketFees: Profile for public key %v does not exist",
			requestData.ProfilePublicKeyBase58Check))
		return
	}

	// Update the fees on the just the trading fees on the extradata map of the profile.
	feeMap := make(map[lib.PublicKey]uint64)
	for pkidString, feeBasisPoints := range requestData.FeeBasisPointsByPkid {
		pkidBytes, _, err := lib.Base58CheckDecode(pkidString)
		if err != nil || len(pkidBytes) != btcec.PubKeyBytesLenCompressed {
			_AddBadRequestError(ww, fmt.Sprintf(
				"UpdateDaoCoinMarketFees: Problem decoding public key %s: %v",
				pkidString, err))
			return
		}
		feeMap[*lib.NewPublicKey(pkidBytes)] = feeBasisPoints
	}
	feeMapBytes, err := lib.SerializePubKeyToUint64Map(feeMap)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateDaoCoinMarketFees: Problem serializing fee map: %v", err))
		return
	}
	if len(existingProfileEntry.ExtraData) == 0 {
		existingProfileEntry.ExtraData = make(map[string][]byte)
	}
	existingProfileEntry.ExtraData[lib.TokenTradingFeesMapKey] = feeMapBytes

	// Try and create the UpdateProfile txn for the user.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateUpdateProfileTxn(
		updaterPublicKeyBytes,
		profilePublicKeyBytess,
		"", // Don't update username
		"", // Don't update description
		"", // Don't update profile pic
		existingProfileEntry.CreatorCoinEntry.CreatorBasisPoints, // Don't update creator basis points
		// StakeMultipleBasisPoints is a deprecated field that we don't use anywhere and will delete soon.
		// I noticed we use a hardcoded value of 12500 in the frontend and when creating a post so I'm doing
		// the same here for now.
		1.25*100*100,                   // Don't update stake multiple basis points
		existingProfileEntry.IsHidden,  // Don't update hidden status
		0,                              // Don't add additionalFees
		existingProfileEntry.ExtraData, // The new ExtraData
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool(), []*lib.DeSoOutput{})
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateDaoCoinMarketFees: Problem creating transaction: %v", err))
		return
	}

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateDaoCoinMarketFees: Problem serializing transaction: %v", err))
		return
	}

	// Return all the data associated with the transaction in the response
	res := UpdateDaoCoinMarketFeesResponse{
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
		TxnHashHex:        txn.Hash().String(),
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateDaoCoinMarketFees: Problem encoding response as JSON: %v", err))
		return
	}
}

type GetDaoCoinMarketFeesRequest struct {
	ProfilePublicKeyBase58Check string `safeForLogging:"true"`
}

type GetDaoCoinMarketFeesResponse struct {
	FeeBasisPointsByPkid map[string]uint64 `safeForLogging:"true"`
}

func GetTradingFeesForMarket(
	utxoView *lib.UtxoView,
	params *lib.DeSoParams,
	profilePublicKey string,
) (
	_feeMap map[string]uint64,
	_err error,
) {

	// Decode the public key
	profilePublicKeyBytes, _, err := lib.Base58CheckDecode(profilePublicKey)
	if err != nil || len(profilePublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		return nil, fmt.Errorf(
			"GetTradingFeesForMarket: Problem decoding public key %s: %v",
			profilePublicKey, err)
	}

	// Pull the existing profile. If one doesn't exist, then we error. The user should
	// create a profile first before trying to update the fee params for their market.
	existingProfileEntry := utxoView.GetProfileEntryForPublicKey(profilePublicKeyBytes)
	if existingProfileEntry == nil || existingProfileEntry.IsDeleted() {
		return nil, fmt.Errorf(
			"GetTradingFeesForMarket: Profile for public key %v does not exist",
			profilePublicKey)
	}

	// Decode the trading fees from the profile.
	tradingFeesBytes, exists := existingProfileEntry.ExtraData[lib.TokenTradingFeesMapKey]
	tradingFeesMapPubkey := make(map[lib.PublicKey]uint64)
	if exists {
		tradingFeesMapPubkey, err = lib.DeserializePubKeyToUint64Map(tradingFeesBytes)
		if err != nil {
			return nil, fmt.Errorf(
				"GetTradingFeesForMarket: Problem deserializing trading fees: %v", err)
		}
	}
	feeMap := map[string]uint64{}
	for publicKey, feeBasisPoints := range tradingFeesMapPubkey {
		// Convert the pkid to a base58 string
		pkBase58 := lib.PkToString(publicKey[:], params)
		feeMap[pkBase58] = feeBasisPoints
	}

	return feeMap, nil
}

func (fes *APIServer) GetDaoCoinMarketFees(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetDaoCoinMarketFeesRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDaoCoinMarketFees: Problem parsing request body: %v", err))
		return
	}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDaoCoinMarketFees: Error fetching mempool view: %v", err))
		return
	}

	feeMap, err := GetTradingFeesForMarket(
		utxoView,
		fes.Params,
		requestData.ProfilePublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDaoCoinMarketFees: Problem getting trading fees: %v", err))
		return
	}

	// Return all the data associated with the transaction in the response
	res := GetDaoCoinMarketFeesResponse{
		FeeBasisPointsByPkid: feeMap,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDaoCoinMarketFees: Problem encoding response as JSON: %v", err))
		return
	}
}

type CurrencyType string

const (
	CurrencyTypeUsd   CurrencyType = "usd"
	CurrencyTypeQuote CurrencyType = "quote"
	CurrencyTypeBase  CurrencyType = "base"
)

type DAOCoinLimitOrderWithFeeRequest struct {
	// The public key of the user who is creating the order
	TransactorPublicKeyBase58Check string `safeForLogging:"true"`

	// For a market, there is always a "base" currency and a "quote" currency. The quote
	// currency is the unit of account, eg usd, while the base currency is the coin people
	// are trying to buy, eg openfund. A market is always denoted as base/quote. Eg openfund/deso
	// or deso/dusdc, for example. If you're still confused, look up base and quote currencies
	// as it's a common concept in trading.
	QuoteCurrencyPublicKeyBase58Check string `safeForLogging:"true"`
	BaseCurrencyPublicKeyBase58Check  string `safeForLogging:"true"`

	// "bid" or "ask"
	OperationType DAOCoinLimitOrderOperationTypeString `safeForLogging:"true"`

	// A choice of "Fill or Kill", "Immediate or Cancel", or "Good Till Cancelled".
	// If it's a market order, then "Good Till Cancelled" is not allowed.
	FillType DAOCoinLimitOrderFillTypeString `safeForLogging:"true"`

	// A decimal string (ex: 1.23) that represents the exchange rate between the two coins.
	// The price should be the amount should be EITHER the amount of quote currency per one
	// unit of base currency OR a USD amount per base currency. Eg
	// for the deso/dusdc market, where deso is base and dusdc is quote, the price would simply
	// be the deso price in usd. For the openfund/deso market, where openfund is base and deso
	// is quote, the price would be the openfund price in deso (eg 0.0002 deso to buy one openfund
	// coin) OR the openfund price in USD (which will convert to DESO under the hood to place
	// the order). Note that PriceCurrencyType="base" doesn't make sense because the base
	// currency is what you're buying/selling in the first place.
	//
	// If the price is 0.0, then the order is assumed to be a market order.
	Price             string       `safeForLogging:"true"`
	PriceCurrencyType CurrencyType `safeForLogging:"true"`

	// Quantity must always be specified either in usd, in quote currency, or in base
	// currency. For bids, we expect usd or quote. For asks, we expect usd or base currency
	// only. Only one of the following fields should be set.
	Quantity             string       `safeForLogging:"true"`
	QuantityCurrencyType CurrencyType `safeForLogging:"true"`

	MinFeeRateNanosPerKB uint64           `safeForLogging:"true"`
	TransactionFees      []TransactionFee `safeForLogging:"true"`

	OptionalPrecedingTransactions []*lib.MsgDeSoTxn `safeForLogging:"true"`
}

type DAOCoinLimitOrderWithFeeResponse struct {
	// The amount in Deso nanos paid in network fees. We consider this independently
	// of trading fees.
	FeeNanos       uint64
	Transaction    *lib.MsgDeSoTxn
	TransactionHex string
	TxnHashHex     string

	// The amount represents either the amount being spent (in the case of a buy) or
	// the amount being sold (in the case of a sell). For a buy, the amount is in quote
	// currency, while for a sell the amount is in base currency. The messages should
	// look as follows in the UI:
	// - For a buy: "You will spend: {AmountUsd} (= {Amount} {QuoteCurrency})"
	// - For a sell: "You will sell: {Amount} {BaseCurrency}"
	// We distinguish the "Limit" amount, which is the maximum the order could possibly
	// execute, from the "Executed" amount, which is the amount that it actually will
	// execute. For a market order, the "Limit" and "Executed" amounts will be the same.
	// For a Limit order, the Executed amount will always be less than or equal to the
	// Limit amount.
	LimitAmount                    string       `safeForLogging:"true"`
	LimitAmountCurrencyType        CurrencyType `safeForLogging:"true"`
	LimitAmountInUsd               string       `safeForLogging:"true"`
	LimitReceiveAmount             string       `safeForLogging:"true"`
	LimitReceiveAmountCurrencyType CurrencyType `safeForLogging:"true"`
	LimitPriceInQuoteCurrency      string       `safeForLogging:"true"`
	LimitPriceInUsd                string       `safeForLogging:"true"`

	// For a market order, the amount will generally match the amount requested. However, for
	// a limit order, the amount may be less than the amount requested if the order was only
	// partially filled.
	ExecutionAmount                    string       `safeForLogging:"true"`
	ExecutionAmountCurrencyType        CurrencyType `safeForLogging:"true"`
	ExecutionAmountUsd                 string       `safeForLogging:"true"`
	ExecutionReceiveAmount             string       `safeForLogging:"true"`
	ExecutionReceiveAmountCurrencyType CurrencyType `safeForLogging:"true"`
	ExecutionReceiveAmountUsd          string       `safeForLogging:"true"`
	ExecutionPriceInQuoteCurrency      string       `safeForLogging:"true"`
	ExecutionPriceInUsd                string       `safeForLogging:"true"`
	ExecutionFeePercentage             string       `safeForLogging:"true"`
	ExecutionFeeAmountInQuoteCurrency  string       `safeForLogging:"true"`
	ExecutionFeeAmountInUsd            string       `safeForLogging:"true"`

	// The total fee percentage the market charges on taker orders (maker fees are zero
	// for now).
	MarketTotalTradingFeeBasisPoints string
	// Trading fees are paid to users based on metadata in the profile. This map states the trading
	// fee split for each user who's been allocated trading fees in the profile.
	MarketTradingFeeBasisPointsByUserPkid map[string]uint64
}

// Used by the client to convert as needed
func GetBuyingSellingPkidFromQuoteBasePkids(
	quotePkid string,
	basePkid string,
	side string,
) (
	_buyingCoinPkid string,
	_sellingCoinPkid string,
	_err error,
) {

	// Kindof annoying. We don't use base/quote currency in consensus, so we have to
	// convert from base/quote to this weird buying/selling thing we did. Oh well.
	// The rule of thumb is we're selling the base with an ASK and buying the base
	// with a bid.
	if side == lib.DAOCoinLimitOrderOperationTypeASK.String() {
		return quotePkid, basePkid, nil
	} else if side == lib.DAOCoinLimitOrderOperationTypeBID.String() {
		return basePkid, quotePkid, nil
	} else {
		return "", "", fmt.Errorf(
			"GetBuyingSellingPkidFromQuoteBasePkids: Invalid side: %v", side)
	}
}

// Used by the client to convert as needed
func GetQuoteBasePkidFromBuyingSellingPkids(
	buyingPkid string,
	sellingPkid string,
	side string,
) (
	_quoteCurrencyPkid string,
	_baseCurrencyPkid string,
	_err error,
) {
	// The rule of thumb is we're seeling the base with an ask and buying the
	// base with a bid.
	if side == lib.DAOCoinLimitOrderOperationTypeBID.String() {
		return sellingPkid, buyingPkid, nil
	} else if side == lib.DAOCoinLimitOrderOperationTypeASK.String() {
		return buyingPkid, sellingPkid, nil
	} else {
		return "", "", fmt.Errorf(
			"GetQuoteBasePkidFromBuyingSellingPkids: Invalid side: %v", side)
	}
}

func (fes *APIServer) GetQuoteCurrencyPriceInUsd(
	quoteCurrencyPublicKey string) (string, error) {
	if IsDesoPkid(quoteCurrencyPublicKey) {
		desoUsdCents := fes.GetExchangeDeSoPrice()
		return fmt.Sprintf("%f", float64(desoUsdCents)/100), nil
	} else {
		return "", fmt.Errorf(
			"GetQuoteCurrencyPriceInUsd: Quote currency %v not supported",
			quoteCurrencyPublicKey)
	}
}

func (fes *APIServer) HandleMarketOrder(
	req *DAOCoinLimitOrderWithFeeRequest,
	isBuyOrder bool,
	feeMap map[string]uint64,
) (
	*DAOCoinLimitOrderWithFeeResponse,
	error,
) {
	quoteCurrencyUsdValue := float64(0.0)
	quoteCurrencyUsdValueStr, err := fes.GetQuoteCurrencyPriceInUsd(
		req.QuoteCurrencyPublicKeyBase58Check)
	if err != nil {
		// If we can't get the price of the quote currency in usd, then we can't
		// convert the usd amount to a quote currency amount. In this case, keep
		// going but don't use the quote currency usd value for anything.
		quoteCurrencyUsdValue = 0.0
	} else {
		quoteCurrencyUsdValue, err = strconv.ParseFloat(quoteCurrencyUsdValueStr, 64)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem converting quote "+
				"currency price to float %v", err)
		}
	}

	quantityStr := req.Quantity
	if req.QuantityCurrencyType == CurrencyTypeUsd {
		// In this case we want to convert the usd amount to an amount of quote
		// currency in base units. To do this we need to get the price of the
		// quote currency in usd and then convert the usd amount to quote currency
		// amount.
		if quoteCurrencyUsdValue == 0.0 {
			return nil, fmt.Errorf("HandleMarketOrder: Quote currency price in " +
				"usd not available. Please use quote or base currency for the amount.")
		}
		// For the rest it's just the following formula:
		// = usd amount / quoteCurrencyUsdValue * base units

		// In this case we parse the quantity as a simple float since its value
		// should not be extreme
		quantityUsd, err := strconv.ParseFloat(req.Quantity, 64)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem converting quantity "+
				"to float %v", err)
		}
		quantityStr = fmt.Sprintf("%f", quantityUsd/quoteCurrencyUsdValue)
	}

	// Next we set the operation type, buying public key, and selling public key based on
	// the currency type of the amount. This is confusing, but the reason we need to do it
	// this way is because consensus requires that the buying currency be used as the quantity
	// for a bid and vice versa for an ask. This causes some bs here.
	var operationType DAOCoinLimitOrderOperationTypeString
	buyingPublicKey := ""
	sellingPublicKey := ""
	if req.QuantityCurrencyType == CurrencyTypeBase {
		if isBuyOrder {
			// If you're buying base currency, then the buying coin is the
			// base and the operationType is bid. This is the easy case.
			operationType = DAOCoinLimitOrderOperationTypeStringBID
			buyingPublicKey = req.BaseCurrencyPublicKeyBase58Check
			sellingPublicKey = req.QuoteCurrencyPublicKeyBase58Check
		} else {
			// If you're selling base currency, then the selling coin is the
			// base and we can do a vanilla ask. This is another easy case.
			operationType = DAOCoinLimitOrderOperationTypeStringASK
			buyingPublicKey = req.QuoteCurrencyPublicKeyBase58Check
			sellingPublicKey = req.BaseCurrencyPublicKeyBase58Check
		}
	} else if req.QuantityCurrencyType == CurrencyTypeQuote ||
		req.QuantityCurrencyType == CurrencyTypeUsd {
		if isBuyOrder {
			// This is where things get weird. If you're buying the base
			// and you want to use quote currency as the quantity, then
			// you need to do an ask where the selling currency is the quote.
			operationType = DAOCoinLimitOrderOperationTypeStringASK
			buyingPublicKey = req.BaseCurrencyPublicKeyBase58Check
			sellingPublicKey = req.QuoteCurrencyPublicKeyBase58Check
		} else {
			// The last hard case. If you're selling the base and you want
			// to use quote currency as the quantity, then you need to do a
			// bid where the buying currency is the quote.
			operationType = DAOCoinLimitOrderOperationTypeStringBID
			buyingPublicKey = req.QuoteCurrencyPublicKeyBase58Check
			sellingPublicKey = req.BaseCurrencyPublicKeyBase58Check
		}
	} else {
		return nil, fmt.Errorf("HandleMarketOrder: Invalid quantity currency type %v",
			req.QuantityCurrencyType)
	}

	// We need to translate the req into a DAOCoinMarketOrderCreationRequest
	daoCoinMarketOrderRequest := &DAOCoinMarketOrderCreationRequest{
		TransactorPublicKeyBase58Check:            req.TransactorPublicKeyBase58Check,
		BuyingDAOCoinCreatorPublicKeyBase58Check:  buyingPublicKey,
		SellingDAOCoinCreatorPublicKeyBase58Check: sellingPublicKey,
		Quantity:             quantityStr,
		OperationType:        operationType,
		FillType:             req.FillType,
		MinFeeRateNanosPerKB: req.MinFeeRateNanosPerKB,
		TransactionFees:      req.TransactionFees,
	}
	marketOrderRes, err := fes.createDaoCoinMarketOrderHelper(daoCoinMarketOrderRequest)
	if err != nil {
		return nil, fmt.Errorf("HandleMarketOrder: Problem creating market order: %v", err)
	}

	quoteCurrencyTotalStr := marketOrderRes.SimulatedExecutionResult.BuyingCoinQuantityFilled
	if daoCoinMarketOrderRequest.SellingDAOCoinCreatorPublicKeyBase58Check == req.QuoteCurrencyPublicKeyBase58Check {
		quoteCurrencyTotalStr = marketOrderRes.SimulatedExecutionResult.SellingCoinQuantityFilled
	}

	// Now we know how much of the buying and selling currency are going to be transacted. This
	// allows us to compute a fee to charge the transactor.
	quoteCurrencyTotalBaseUnits, err := CalculateBaseUnitsFromStringDecimalAmountSimple(
		req.QuoteCurrencyPublicKeyBase58Check, quoteCurrencyTotalStr)
	if err != nil {
		return nil, fmt.Errorf("HandleMarketOrder: Problem calculating quote currency total: %v", err)
	}

	// Compute how much in quote currency we need to pay each constituent
	feeBaseUnitsByPkid := make(map[string]*uint256.Int)
	totalFeeBaseUnits := uint256.NewInt(0)
	for pkid, feeBasisPoints := range feeMap {
		feeBaseUnits, err := lib.SafeUint256().Mul(quoteCurrencyTotalBaseUnits, uint256.NewInt(feeBasisPoints))
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem calculating fee: %v", err)
		}
		feeBaseUnits, err = lib.SafeUint256().Div(feeBaseUnits, uint256.NewInt(10000))
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem calculating fee: %v", err)
		}
		feeBaseUnitsByPkid[pkid] = feeBaseUnits
		totalFeeBaseUnits, err = lib.SafeUint256().Add(totalFeeBaseUnits, feeBaseUnits)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem calculating total fee: %v", err)
		}
	}

	// Validate that the totalFeeBaseUnits is less than or equal to the quote currency total
	if totalFeeBaseUnits.Cmp(quoteCurrencyTotalBaseUnits) > 0 {
		return nil, fmt.Errorf("HandleMarketOrder: Total fees exceed total quote currency")
	}

	// Compute the remaining amount we can spend in quote currency after paying fees
	remainingQuoteCurrencyBaseUnits, err := lib.SafeUint256().Sub(quoteCurrencyTotalBaseUnits, totalFeeBaseUnits)
	if err != nil {
		return nil, fmt.Errorf("HandleMarketOrder: Problem calculating remaining quote currency: %v", err)
	}

	// Precompute the total fee to return it later
	marketTakerFeeBaseUnits := uint64(0)
	for _, feeBaseUnits := range feeMap {
		marketTakerFeeBaseUnits += feeBaseUnits
	}
	marketTakerFeeBaseUnitsStr := fmt.Sprintf("%d", marketTakerFeeBaseUnits)

	// Now we have two possibilities...
	//
	// 1. buy
	// The user is buying the base currency with the quote currency. In this case we can
	// simply deduct the quote currency from the user's balance prior to executing the
	// order, and then execute the order with remainingQuoteCurrencyBaseUnits.
	//
	// 2. sell
	// In this case the user is selling the base currency for quote currency. In this case,
	// we need to execute the order first and then deduct the quote currency fee from the
	// user's balance after the order has been executed.
	//
	// Get a universal view to validate as we go
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return nil, fmt.Errorf("HandleMarketOrder: Error fetching mempool view: %v", err)
	}
	transactorPubkeyBytes, _, err := lib.Base58CheckDecode(req.TransactorPublicKeyBase58Check)
	if err != nil || len(transactorPubkeyBytes) != btcec.PubKeyBytesLenCompressed {
		return nil, fmt.Errorf("HandleMarketOrder: Problem decoding public key %s: %v",
			req.TransactorPublicKeyBase58Check, err)
	}
	quoteCurrencyPkidBytes, _, err := lib.Base58CheckDecode(req.QuoteCurrencyPublicKeyBase58Check)
	if err != nil || len(quoteCurrencyPkidBytes) != btcec.PubKeyBytesLenCompressed {
		return nil, fmt.Errorf("HandleMarketOrder: Problem decoding public key %s: %v",
			req.QuoteCurrencyPublicKeyBase58Check, err)
	}
	if isBuyOrder {
		// For each trading fee we need to pay, construct a transfer txn that sends the amount
		// from the transactor directly to the person receiving the fee.
		transferTxns := []*lib.MsgDeSoTxn{}
		for pkid, feeBaseUnits := range feeBaseUnitsByPkid {
			receiverPkidBytes, _, err := lib.Base58CheckDecode(pkid)
			if err != nil || len(receiverPkidBytes) != btcec.PubKeyBytesLenCompressed {
				return nil, fmt.Errorf("HandleMarketOrder: Problem decoding public key %s: %v",
					pkid, err)
			}
			// Try and create the TransferDaoCoin transaction for the user.
			//
			// TODO: Add ExtraData to the transaction to make it easier to report it as an
			// earning to the user who's receiving the fee.
			txn, _, _, _, err := fes.blockchain.CreateDAOCoinTransferTxn(
				transactorPubkeyBytes,
				&lib.DAOCoinTransferMetadata{
					ProfilePublicKey:       quoteCurrencyPkidBytes,
					ReceiverPublicKey:      receiverPkidBytes,
					DAOCoinToTransferNanos: *feeBaseUnits,
				},
				// Standard transaction fields
				req.MinFeeRateNanosPerKB, fes.backendServer.GetMempool(), nil)
			if err != nil {
				return nil, fmt.Errorf("HandleMarketOrder: Problem creating transaction: %v", err)
			}
			_, _, _, _, err = utxoView.ConnectTransaction(
				txn, txn.Hash(), fes.blockchain.BlockTip().Height,
				fes.blockchain.BlockTip().Header.TstampNanoSecs,
				false, false)
			if err != nil {
				return nil, fmt.Errorf("HandleMarketOrder: Problem connecting transaction: %v", err)
			}
			transferTxns = append(transferTxns, txn)
		}

		remainingQuoteQuantityDecimal, err := CalculateStringDecimalAmountFromBaseUnitsSimple(
			req.QuoteCurrencyPublicKeyBase58Check, remainingQuoteCurrencyBaseUnits)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem calculating remaining quote currency: %v", err)
		}

		// Now we need to execute the order with the remaining quote currency.
		// To make this simple and exact, we can do this as an ask where we are
		// selling the quote currency for base currency. This allows us to specify
		// the amount of quote currency as the quantity (again consensus is confusing
		// sorry about that).
		newDaoCoinMarketOrderRequest := &DAOCoinMarketOrderCreationRequest{
			TransactorPublicKeyBase58Check:            req.TransactorPublicKeyBase58Check,
			BuyingDAOCoinCreatorPublicKeyBase58Check:  req.BaseCurrencyPublicKeyBase58Check,
			SellingDAOCoinCreatorPublicKeyBase58Check: req.QuoteCurrencyPublicKeyBase58Check,
			Quantity:             remainingQuoteQuantityDecimal,
			OperationType:        DAOCoinLimitOrderOperationTypeStringASK,
			FillType:             req.FillType,
			MinFeeRateNanosPerKB: req.MinFeeRateNanosPerKB,
			TransactionFees:      req.TransactionFees,
		}
		newMarketOrderRes, err := fes.createDaoCoinMarketOrderHelper(newDaoCoinMarketOrderRequest)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem creating market order: %v", err)
		}
		// Parse the limit order txn from the response
		bb, err := hex.DecodeString(newMarketOrderRes.TransactionHex)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem decoding txn hex: %v", err)
		}
		txn := &lib.MsgDeSoTxn{}
		if err := txn.FromBytes(bb); err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem parsing txn: %v", err)
		}
		_, _, _, _, err = utxoView.ConnectTransaction(
			txn, txn.Hash(), fes.blockchain.BlockTip().Height,
			fes.blockchain.BlockTip().Header.TstampNanoSecs,
			false, false)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem connecting transaction: %v", err)
		}

		allTxns := append(transferTxns, newMarketOrderRes.Transaction)

		// Wrap all of the resulting txns into an atomic
		// TODO: We can embed helpful extradata in here that will allow us to index these txns
		// more coherently
		extraData := make(map[string][]byte)
		atomicTxn, totalDesoFeeNanos, err := fes.blockchain.CreateAtomicTxnsWrapper(
			allTxns, extraData, fes.backendServer.GetMempool(), req.MinFeeRateNanosPerKB)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem creating atomic txn: %v", err)
		}
		atomixTxnBytes, err := atomicTxn.ToBytes(true)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem serializing atomic txn: %v", err)
		}
		atomicTxnHex := hex.EncodeToString(atomixTxnBytes)

		// Now that we've executed the order, we have everything we need to return to the UI
		// so it can display the order to the user.

		// The amount we're spending is the amount in quote currency, which is the
		// amount we're selling in this case.
		executionAmount := newMarketOrderRes.SimulatedExecutionResult.SellingCoinQuantityFilled
		executionAmountCurrencyType := CurrencyTypeQuote
		executionReceiveAmount := marketOrderRes.SimulatedExecutionResult.BuyingCoinQuantityFilled
		executionReceiveAmountCurrencyType := CurrencyTypeBase
		executionReceiveAmountBaseUnits, err := CalculateBaseUnitsFromStringDecimalAmountSimple(
			req.BaseCurrencyPublicKeyBase58Check, executionReceiveAmount)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem calculating base currency received: %v", err)
		}

		// The price per token the user is getting, expressed as a decimal float
		// - quoteAmountSpentTotal / baseAmountReceived
		// - = (quoteAmountSpentTotal * BaseUnitsPerCoin / baseAmountReceived) / BaseUnitsPerCoin
		priceQuotePerBase := big.NewInt(0).Mul(
			quoteCurrencyTotalBaseUnits.ToBig(), lib.BaseUnitsPerCoin.ToBig())
		priceQuotePerBase = big.NewInt(0).Div(
			priceQuotePerBase, executionReceiveAmountBaseUnits.ToBig())
		executionPriceInQuoteCurrency := lib.FormatScaledUint256AsDecimalString(
			priceQuotePerBase, lib.BaseUnitsPerCoin.ToBig())

		// Compute the percentage of the amount spent that went to fees
		// - totalFeeBaseUnits / quoteAmountSpentTotalBaseUnits
		// - = (totalFeeBaseUnits * BaseUnitsPerCoin / quoteAmountSpentTotalBaseUnits) / BaseUnitsPerCoin
		percentageSpentOnFees := big.NewInt(0).Mul(
			totalFeeBaseUnits.ToBig(), lib.BaseUnitsPerCoin.ToBig())
		percentageSpentOnFees = big.NewInt(0).Div(
			percentageSpentOnFees, quoteCurrencyTotalBaseUnits.ToBig())
		executionFeePercentage := lib.FormatScaledUint256AsDecimalString(
			percentageSpentOnFees, lib.BaseUnitsPerCoin.ToBig())

		executionFeeAmountInQuoteCurrency, err := CalculateStringDecimalAmountFromBaseUnitsSimple(
			req.QuoteCurrencyPublicKeyBase58Check, totalFeeBaseUnits)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem calculating fee: %v", err)
		}

		res := &DAOCoinLimitOrderWithFeeResponse{
			// The amount in Deso nanos paid in network fees. We consider this independently
			// of trading fees.
			FeeNanos:       totalDesoFeeNanos,
			Transaction:    atomicTxn,
			TransactionHex: atomicTxnHex,
			TxnHashHex:     txn.Hash().String(),

			//LimitAmount                    string       `safeForLogging:"true"`
			//LimitAmountCurrencyType        CurrencyType `safeForLogging:"true"`
			//LimitAmountInUsd               string       `safeForLogging:"true"`
			//LimitReceiveAmount             string       `safeForLogging:"true"`
			//LimitReceiveAmountCurrencyType CurrencyType `safeForLogging:"true"`
			//LimitPriceInQuoteCurrency      string       `safeForLogging:"true"`
			//LimitPriceInUsd                string       `safeForLogging:"true"`

			// For a market order, the amount will generally match the amount requested. However, for
			// a limit order, the amount may be less than the amount requested if the order was only
			// partially filled.
			ExecutionAmount:                    executionAmount,
			ExecutionAmountCurrencyType:        executionAmountCurrencyType,
			ExecutionAmountUsd:                 "",
			ExecutionReceiveAmount:             executionReceiveAmount,
			ExecutionReceiveAmountCurrencyType: executionReceiveAmountCurrencyType,
			ExecutionReceiveAmountUsd:          "",
			ExecutionPriceInQuoteCurrency:      executionPriceInQuoteCurrency,
			ExecutionPriceInUsd:                "",
			ExecutionFeePercentage:             executionFeePercentage,
			ExecutionFeeAmountInQuoteCurrency:  executionFeeAmountInQuoteCurrency,
			ExecutionFeeAmountInUsd:            "",

			MarketTotalTradingFeeBasisPoints:      marketTakerFeeBaseUnitsStr,
			MarketTradingFeeBasisPointsByUserPkid: feeMap,
		}

		return res, nil
	} else {
		// We already have the txn that executes the order from previously
		// Connect it to our UtxoView for validation
		bb, err := hex.DecodeString(marketOrderRes.TransactionHex)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem decoding txn hex: %v", err)
		}
		orderTxn := &lib.MsgDeSoTxn{}
		if err := orderTxn.FromBytes(bb); err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem parsing txn: %v", err)
		}
		_, _, _, _, err = utxoView.ConnectTransaction(
			orderTxn, orderTxn.Hash(), fes.blockchain.BlockTip().Height,
			fes.blockchain.BlockTip().Header.TstampNanoSecs,
			false, false)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem connecting transaction: %v", err)
		}

		// Now we need to deduct the fees from the user's balance.
		// For each trading fee we need to pay, construct a transfer txn that sends the amount
		// from the transactor directly to the person receiving the fee.
		transferTxns := []*lib.MsgDeSoTxn{}
		for pkid, feeBaseUnits := range feeBaseUnitsByPkid {
			receiverPkidBytes, _, err := lib.Base58CheckDecode(pkid)
			if err != nil || len(receiverPkidBytes) != btcec.PubKeyBytesLenCompressed {
				return nil, fmt.Errorf("HandleMarketOrder: Problem decoding public key %s: %v",
					pkid, err)
			}
			// Try and create the TransferDaoCoin transaction for the user.
			//
			// TODO: Add ExtraData to the transaction to make it easier to report it as an
			// earning to the user who's receiving the fee.
			txn, _, _, _, err := fes.blockchain.CreateDAOCoinTransferTxn(
				transactorPubkeyBytes,
				&lib.DAOCoinTransferMetadata{
					ProfilePublicKey:       quoteCurrencyPkidBytes,
					ReceiverPublicKey:      receiverPkidBytes,
					DAOCoinToTransferNanos: *feeBaseUnits,
				},
				// Standard transaction fields
				req.MinFeeRateNanosPerKB, fes.backendServer.GetMempool(), nil)
			if err != nil {
				return nil, fmt.Errorf("HandleMarketOrder: Problem creating transaction: %v", err)
			}
			_, _, _, _, err = utxoView.ConnectTransaction(
				txn, txn.Hash(), fes.blockchain.BlockTip().Height,
				fes.blockchain.BlockTip().Header.TstampNanoSecs,
				false, false)
			if err != nil {
				return nil, fmt.Errorf("HandleMarketOrder: Problem connecting transaction: %v", err)
			}
			transferTxns = append(transferTxns, txn)
		}

		// Wrap all of the resulting txns into an atomic
		allTxns := append(transferTxns, orderTxn)
		extraData := make(map[string][]byte)
		atomicTxn, totalDesoFeeNanos, err := fes.blockchain.CreateAtomicTxnsWrapper(
			allTxns, extraData, fes.backendServer.GetMempool(), req.MinFeeRateNanosPerKB)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem creating atomic txn: %v", err)
		}
		atomixTxnBytes, err := atomicTxn.ToBytes(true)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem serializing atomic txn: %v", err)
		}
		atomicTxnHex := hex.EncodeToString(atomixTxnBytes)

		// Now that we've executed the order, we have everything we need to return to the UI
		totalFeeStr, err := CalculateStringDecimalAmountFromBaseUnitsSimple(
			req.QuoteCurrencyPublicKeyBase58Check, totalFeeBaseUnits)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem calculating fee: %v", err)
		}
		quoteAmountReceivedBaseUnits, err := lib.SafeUint256().Sub(
			quoteCurrencyTotalBaseUnits, totalFeeBaseUnits)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem calculating quote currency received: %v", err)
		}
		quoteAmountReceivedStr, err := CalculateStringDecimalAmountFromBaseUnitsSimple(
			req.QuoteCurrencyPublicKeyBase58Check, quoteAmountReceivedBaseUnits)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem calculating quote currency received: %v", err)
		}
		baseAmountSpentStr := marketOrderRes.SimulatedExecutionResult.SellingCoinQuantityFilled
		if daoCoinMarketOrderRequest.SellingDAOCoinCreatorPublicKeyBase58Check == req.QuoteCurrencyPublicKeyBase58Check {
			baseAmountSpentStr = marketOrderRes.SimulatedExecutionResult.BuyingCoinQuantityFilled
		}
		baseAmountSpentBaseUnits, err := CalculateBaseUnitsFromStringDecimalAmountSimple(
			req.BaseCurrencyPublicKeyBase58Check, baseAmountSpentStr)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem calculating base currency spent: %v", err)
		}
		// The price per token the user is getting, expressed as a decimal float
		// - quoteAmountReceived / baseAmountSpent
		// - = (quoteAmountReceived * BaseUnitsPerCoin / baseAmountReceived) / BaseUnitsPerCoin
		finalPriceStr := "0.0"
		if !baseAmountSpentBaseUnits.IsZero() {
			priceQuotePerBase := big.NewInt(0).Mul(
				quoteAmountReceivedBaseUnits.ToBig(), lib.BaseUnitsPerCoin.ToBig())
			priceQuotePerBase = big.NewInt(0).Div(
				priceQuotePerBase, baseAmountSpentBaseUnits.ToBig())
			finalPriceStr = lib.FormatScaledUint256AsDecimalString(priceQuotePerBase, lib.BaseUnitsPerCoin.ToBig())
		}

		// Compute the percentage of the amount spent that went to fees
		// - totalFeeBaseUnits / quoteAmountTotalBaseUnits
		// - = (totalFeeBaseUnits * BaseUnitsPerCoin / quoteAmountTotalBaseUnits) / BaseUnitsPerCoin
		percentageSpentOnFeesStr := "0.0"
		if !quoteCurrencyTotalBaseUnits.IsZero() {
			percentageSpentOnFees := big.NewInt(0).Mul(
				totalFeeBaseUnits.ToBig(), lib.BaseUnitsPerCoin.ToBig())
			percentageSpentOnFees = big.NewInt(0).Div(
				percentageSpentOnFees, quoteCurrencyTotalBaseUnits.ToBig())
			percentageSpentOnFeesStr = lib.FormatScaledUint256AsDecimalString(
				percentageSpentOnFees, lib.BaseUnitsPerCoin.ToBig())
		}

		tradingFeesInQuoteCurrencyByPkid := make(map[string]string)
		for pkid, feeBaseUnits := range feeBaseUnitsByPkid {
			feeStr, err := CalculateStringDecimalAmountFromBaseUnitsSimple(
				req.QuoteCurrencyPublicKeyBase58Check, feeBaseUnits)
			if err != nil {
				return nil, fmt.Errorf("HandleMarketOrder: Problem calculating fee: %v", err)
			}
			tradingFeesInQuoteCurrencyByPkid[pkid] = feeStr
		}

		res := &DAOCoinLimitOrderWithFeeResponse{
			FeeNanos:       totalDesoFeeNanos,
			TransactionHex: atomicTxnHex,
			TxnHashHex:     atomicTxn.Hash().String(),
			Transaction:    atomicTxn,

			//LimitAmount                    string       `safeForLogging:"true"`
			//LimitAmountCurrencyType        CurrencyType `safeForLogging:"true"`
			//LimitAmountInUsd               string       `safeForLogging:"true"`
			//LimitReceiveAmount             string       `safeForLogging:"true"`
			//LimitReceiveAmountCurrencyType CurrencyType `safeForLogging:"true"`
			//LimitPriceInQuoteCurrency      string       `safeForLogging:"true"`
			//LimitPriceInUsd                string       `safeForLogging:"true"`

			ExecutionAmount:                    baseAmountSpentStr,
			ExecutionAmountCurrencyType:        CurrencyTypeBase,
			ExecutionAmountUsd:                 "",
			ExecutionReceiveAmount:             quoteAmountReceivedStr,
			ExecutionReceiveAmountCurrencyType: CurrencyTypeQuote,
			ExecutionReceiveAmountUsd:          "",
			ExecutionPriceInQuoteCurrency:      finalPriceStr,
			ExecutionPriceInUsd:                "",
			ExecutionFeePercentage:             percentageSpentOnFeesStr,
			ExecutionFeeAmountInQuoteCurrency:  totalFeeStr,
			ExecutionFeeAmountInUsd:            "",

			MarketTotalTradingFeeBasisPoints: marketTakerFeeBaseUnitsStr,
			// Trading fees are paid to users based on metadata in the profile. This map states the trading
			// fee split for each user who's been allocated trading fees in the profile.
			MarketTradingFeeBasisPointsByUserPkid: feeMap,
		}
		return res, nil
	}
}

func (fes *APIServer) HandleLimitOrder(
	req *DAOCoinLimitOrderWithFeeRequest,
	isBuyOrder bool,
	feeMap map[string]uint64,
) (
	*DAOCoinLimitOrderWithFeeResponse,
	error,
) {

	return nil, fmt.Errorf("HandleLimitOrder: Not implemented")
}

func (fes *APIServer) CreateDAOCoinLimitOrderWithFee(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := DAOCoinLimitOrderWithFeeRequest{}

	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateDAOCoinLimitOrderWithFee: Problem parsing request body: %v", err))
		return
	}

	// First determine if this is a limit or a market order
	isMarketOrder := false
	floatPrice, _ := strconv.ParseFloat(requestData.Price, 64)
	if floatPrice == 0 {
		isMarketOrder = true
	}

	// Validate the OperationType
	if string(requestData.OperationType) != lib.DAOCoinLimitOrderOperationTypeASK.String() &&
		string(requestData.OperationType) != lib.DAOCoinLimitOrderOperationTypeBID.String() {
		_AddBadRequestError(ww, fmt.Sprintf(
			"CreateDAOCoinLimitOrderWithFee: Invalid operation type: %v. Options are: %v, %v",
			requestData.OperationType, lib.DAOCoinLimitOrderOperationTypeASK.String(),
			lib.DAOCoinLimitOrderOperationTypeBID.String()))
		return
	}

	// Determine if it's a buy or sell order
	isBuyOrder := false
	if string(requestData.OperationType) == lib.DAOCoinLimitOrderOperationTypeBID.String() {
		isBuyOrder = true
	}

	// Validate the fill type
	if requestData.FillType != DAOCoinLimitOrderFillTypeFillOrKill &&
		requestData.FillType != DAOCoinLimitOrderFillTypeImmediateOrCancel &&
		requestData.FillType != DAOCoinLimitOrderFillTypeGoodTillCancelled {
		_AddBadRequestError(ww, fmt.Sprintf(
			"CreateDAOCoinLimitOrderWithFee: Invalid fill type: %v. Options are: "+
				"%v, %v, %v", requestData.FillType, DAOCoinLimitOrderFillTypeFillOrKill,
			DAOCoinLimitOrderFillTypeImmediateOrCancel, DAOCoinLimitOrderFillTypeGoodTillCancelled))
		return
	}

	// If we're dealing with a market order then we don't allow "Good Till Cancelled"
	if isMarketOrder && requestData.FillType == DAOCoinLimitOrderFillTypeGoodTillCancelled {
		_AddBadRequestError(ww, fmt.Sprintf(
			"CreateDAOCoinLimitOrderWithFee: Market orders cannot be Good Till Cancelled"))
		return
	}

	// Get a universal view to do more sophisticated validation
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateDAOCoinLimitOrderWithFee: Error fetching mempool view: %v", err))
		return
	}

	// Get the trading fees for the market. This is the trading fee split for each user
	// Only the base currency can have fees on it. The quote currency cannot.
	feeMap, err := GetTradingFeesForMarket(
		utxoView,
		fes.Params,
		requestData.BaseCurrencyPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDaoCoinMarketFees: Problem getting trading fees: %v", err))
		return
	}
	// Validate the fee map.
	if err := ValidateTradingFeeMap(feeMap); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateDaoCoinMarketFees: %v", err))
		return
	}

	// If the trading user is in the fee map, remove them so that we don't end up
	// doing a self-send
	if _, exists := feeMap[requestData.TransactorPublicKeyBase58Check]; exists {
		delete(feeMap, requestData.TransactorPublicKeyBase58Check)
	}

	var res *DAOCoinLimitOrderWithFeeResponse
	if isMarketOrder {
		res, err = fes.HandleMarketOrder(&requestData, isBuyOrder, feeMap)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("CreateDAOCoinLimitOrderWithFee: %v", err))
			return
		}
	} else {
		res, err = fes.HandleLimitOrder(&requestData, isBuyOrder, feeMap)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("CreateDAOCoinLimitOrderWithFee: %v", err))
			return
		}
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateDAOCoinLimitOrderWithFee: Problem encoding response as JSON: %v", err))
		return
	}
}
