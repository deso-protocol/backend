package routes

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/deso-protocol/core/lib"
	"github.com/deso-protocol/uint256"
	"io"
	"math"
	"math/big"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

type UpdateDaoCoinMarketFeesRequest struct {
	// The profile that the fees are being modified for.
	ProfilePublicKeyBase58Check string `safeForLogging:"true"`

	// A map of pubkey->feeBasisPoints that the user wants to set for this market.
	// If the map contains {pk1: 100, pk2: 200} then the user is setting the
	// feeBasisPoints for pk1 to 100 and the feeBasisPoints for pk2 to 200.
	// This means that pk1 will get 1% of every taker's trade and pk2 will get
	// 2%.
	FeeBasisPointsByPublicKey map[string]uint64 `safeForLogging:"true"`

	// If set to true, trading fee updates will be permanently disabled
	// for this market. Use with caution!
	DisableTradingFeeUpdate bool `safeForLogging:"true"`

	MinFeeRateNanosPerKB uint64           `safeForLogging:"true"`
	TransactionFees      []TransactionFee `safeForLogging:"true"`

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
	if len(feeMap) > 100 {
		return fmt.Errorf("Trading fees map must have 100 or fewer entries")
	}
	for pkStr := range feeMap {
		pkBytes, _, err := lib.Base58CheckDecode(pkStr)
		if err != nil {
			return fmt.Errorf("Trading fee map contains invalid public key: %v", pkStr)
		}
		if len(pkBytes) != btcec.PubKeyBytesLenCompressed {
			return fmt.Errorf("Trading fee map contains invalid public key: %v", pkStr)
		}
	}
	totalFeeBasisPoints := big.NewInt(0)
	for _, feeBasisPoints := range feeMap {
		if feeBasisPoints == 0 {
			return fmt.Errorf("Trading fees must be greater than zero")
		}
		totalFeeBasisPoints.Add(totalFeeBasisPoints, big.NewInt(int64(feeBasisPoints)))
	}
	if totalFeeBasisPoints.Cmp(big.NewInt(100*100)) > 0 {
		return fmt.Errorf("Trading fees must sum to less than 100 percent")
	}
	return nil
}

func IsExtraDataValueTrueString(extraData map[string]string, key string) bool {
	newMap := make(map[string][]byte)
	for k, v := range extraData {
		newMap[k] = []byte(v)
	}
	return IsExtraDataValueTrue(newMap, key)
}

func IsExtraDataValueTrue(extraData map[string][]byte, key string) bool {
	if len(extraData) == 0 {
		return false
	}
	val, exists := extraData[key]
	if exists && len(val) == 1 && val[0] == 1 {
		return true
	}
	return false
}

func SetExtraDataValueTrue(extraData map[string][]byte, key string) {
	extraData[key] = []byte{1}
}

func SetExtraDataValueTrueString(extraData map[string]string, key string) {
	extraData[key] = string([]byte{1})
}

func (fes *APIServer) UpdateDaoCoinMarketFees(ww http.ResponseWriter, req *http.Request) {
	if fes.Config.AmmMetadataPublicKey == "" {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateDaoCoinMarketFees: AMM_METADATA_PUBLIC_KEY must be set "+
			"in the node's config for fees to work"))
		return
	}

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := UpdateDaoCoinMarketFeesRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateDaoCoinMarketFees: Problem parsing request body: %v", err))
		return
	}

	// If we're missing trading fees then error
	if len(requestData.FeeBasisPointsByPublicKey) == 0 {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateDaoCoinMarketFees: Must provide at least one fee to update"))
		return
	}

	// Validate the fee map.
	if err := ValidateTradingFeeMap(requestData.FeeBasisPointsByPublicKey); err != nil {
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

	if requestData.ProfilePublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprintf(
			"UpdateDaoCoinMarketFees: ProfilePublicKeyBase58Check and UpdaterPublicKeyBase58Check must be provided"))
		return
	}

	// Decode the profile public key.
	profilePublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.ProfilePublicKeyBase58Check)
	if err != nil || len(profilePublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		_AddBadRequestError(ww, fmt.Sprintf(
			"UpdateDaoCoinMarketFees: Problem decoding public key %s: %v",
			requestData.ProfilePublicKeyBase58Check, err))
		return
	}

	// Pull the existing profile. If one doesn't exist, then we error. The user should
	// create a profile first before trying to update the fee params for their market.
	existingProfileEntry := utxoView.GetProfileEntryForPublicKey(profilePublicKeyBytes)
	if existingProfileEntry == nil || existingProfileEntry.IsDeleted() {
		_AddBadRequestError(ww, fmt.Sprintf(
			"UpdateDaoCoinMarketFees: Profile for public key %v does not exist",
			requestData.ProfilePublicKeyBase58Check))
		return
	}

	// Update the fees on the just the trading fees on the extradata map of the profile.
	feeMapByPkid := make(map[lib.PublicKey]uint64)
	for pubkeyString, feeBasisPoints := range requestData.FeeBasisPointsByPublicKey {
		pkBytes, _, err := lib.Base58CheckDecode(pubkeyString)
		if err != nil || len(pkBytes) != btcec.PubKeyBytesLenCompressed {
			_AddBadRequestError(ww, fmt.Sprintf(
				"UpdateDaoCoinMarketFees: Problem decoding public key %s: %v",
				pubkeyString, err))
			return
		}
		pkidEntry := utxoView.GetPKIDForPublicKey(pkBytes)
		// TODO: Should maybe also check IsDeleted here, but it's impossible for it to be
		// IsDeleted so it should be fine for now.
		if pkidEntry == nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"UpdateDaoCoinMarketFees: PKID for public key %v does not exist",
				pubkeyString))
			return
		}
		pkidBytes := pkidEntry.PKID[:]
		if err != nil || len(pkidBytes) != btcec.PubKeyBytesLenCompressed {
			_AddBadRequestError(ww, fmt.Sprintf(
				"UpdateDaoCoinMarketFees: Problem decoding public key %s: %v",
				pubkeyString, err))
			return
		}
		feeMapByPkid[*lib.NewPublicKey(pkidBytes)] = feeBasisPoints
	}
	feeMapByPkidBytes, err := lib.SerializePubKeyToUint64Map(feeMapByPkid)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateDaoCoinMarketFees: Problem serializing fee map: %v", err))
		return
	}
	// This will merge in with existing ExtraData.
	additionalExtraData := make(map[string][]byte)
	additionalExtraData[lib.TokenTradingFeesByPkidMapKey] = feeMapByPkidBytes

	// Setting this byte makes it impossible to update the trading fee map in the
	// future. Use with caution.
	if requestData.DisableTradingFeeUpdate {
		SetExtraDataValueTrue(additionalExtraData, lib.DisableTradingFeeUpdateKey)
	}

	ammPublicKeyBytes, _, err := lib.Base58CheckDecode(fes.Config.AmmMetadataPublicKey)
	if err != nil || len(ammPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		_AddBadRequestError(ww, fmt.Sprintf(
			"UpdateDaoCoinMarketFees: Problem decoding public key %s: %v",
			fes.Config.AmmMetadataPublicKey, err))
		return
	}

	// Fetch the existing fee association to check if fee updates are still allowed.
	associationFilter := &lib.UserAssociationQuery{
		AssociationType:  []byte(lib.TokenTradingFeesByPkidMapKey),
		AssociationValue: []byte(lib.TokenTradingFeesByPkidMapKey),
		TransactorPKID:   lib.NewPKID(ammPublicKeyBytes),
		TargetUserPKID:   lib.NewPKID(profilePublicKeyBytes),
		AppPKID:          lib.NewPKID(ammPublicKeyBytes),
	}
	associations, err := utxoView.GetUserAssociationsByAttributes(associationFilter)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateDaoCoinMarketFees: Problem fetching associations: %v", err))
		return
	}
	if len(associations) == 1 {
		association := associations[0]
		if IsExtraDataValueTrue(association.ExtraData, lib.DisableTradingFeeUpdateKey) {
			_AddBadRequestError(ww, fmt.Sprintf(
				"UpdateDaoCoinMarketFees: Trading fee updates are disabled for this market"))
			return
		}
	} else if len(associations) != 0 {
		_AddBadRequestError(ww, fmt.Sprintf(
			"UpdateDaoCoinMarketFees: Expected at most one association but got %d", len(associations)))
		return
	}

	// Compute the additional transaction fees as specified by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(
		lib.TxnTypeUpdateProfile, ammPublicKeyBytes, requestData.TransactionFees)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AuthorizeDerivedKey: TransactionFees specified in Request body are invalid: %v", err))
		return
	}

	// Try and create the association txn for the UpdaterPublicKey.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateCreateUserAssociationTxn(
		ammPublicKeyBytes,
		&lib.CreateUserAssociationMetadata{
			TargetUserPublicKey: lib.NewPublicKey(profilePublicKeyBytes),
			AppPublicKey:        lib.NewPublicKey(ammPublicKeyBytes),
			AssociationType:     []byte(lib.TokenTradingFeesByPkidMapKey),
			AssociationValue:    []byte(lib.TokenTradingFeesByPkidMapKey),
		},
		additionalExtraData,
		requestData.MinFeeRateNanosPerKB,
		fes.backendServer.GetMempool(),
		additionalOutputs,
	)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("CreateUserAssociation: problem creating user "+
			"association txn: %v", err))
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
	FeeBasisPointsByPublicKey map[string]uint64 `safeForLogging:"true"`
	TradingFeeUpdateDisabled  bool              `safeForLogging:"true"`
}

func GetTradingFeesForMarket(
	utxoView *lib.UtxoView,
	params *lib.DeSoParams,
	ammMetadataPublicKey string,
	profilePublicKey string,
) (
	_feeMapByPubkey map[string]uint64,
	_tradingFeeUpdateDisabled bool,
	_err error,
) {
	// Decode the public key
	profilePublicKeyBytes, _, err := lib.Base58CheckDecode(profilePublicKey)
	if err != nil || len(profilePublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		return nil, false, fmt.Errorf(
			"GetTradingFeesForMarket: Problem decoding public key %s: %v",
			profilePublicKey, err)
	}
	profilePkid := utxoView.GetPKIDForPublicKey(profilePublicKeyBytes)
	if profilePkid == nil {
		return nil, false, fmt.Errorf(
			"GetTradingFeesForMarket: Profile for public key %v does not exist",
			profilePublicKey)
	}

	ammMetadataPublicKeyBytes, _, err := lib.Base58CheckDecode(ammMetadataPublicKey)
	if err != nil || len(ammMetadataPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		return nil, false, fmt.Errorf(
			"GetTradingFeesForMarket: Problem decoding public key %s: %v",
			ammMetadataPublicKey, err)
	}
	ammPkid := utxoView.GetPKIDForPublicKey(ammMetadataPublicKeyBytes)
	if ammPkid == nil {
		return nil, false, fmt.Errorf(
			"GetTradingFeesForMarket: AMM metadata for public key %v does not exist",
			ammMetadataPublicKey)
	}

	// Look up the association
	filter := &lib.UserAssociationQuery{
		AssociationType:  []byte(lib.TokenTradingFeesByPkidMapKey),
		AssociationValue: []byte(lib.TokenTradingFeesByPkidMapKey),
		TransactorPKID:   ammPkid.PKID,
		TargetUserPKID:   profilePkid.PKID,
		AppPKID:          ammPkid.PKID,
	}
	associations, err := utxoView.GetUserAssociationsByAttributes(filter)
	if err != nil {
		return nil, false, fmt.Errorf(
			"GetTradingFeesForMarket: Problem fetching associations: %v", err)
	}
	if len(associations) == 0 {
		// Returning a non-nil empty map makes error handling a little easier.
		return make(map[string]uint64), false, nil
	} else if len(associations) > 1 {
		return nil, false, fmt.Errorf(
			"GetTradingFeesForMarket: Expected at most one association but got %d", len(associations))
	}
	association := associations[0]

	tradingFeeUpdateDisabled := false
	if IsExtraDataValueTrue(association.ExtraData, lib.DisableTradingFeeUpdateKey) {
		tradingFeeUpdateDisabled = true
	}

	// Decode the trading fees from the profile.
	tradingFeesByPkidBytes, exists := association.ExtraData[lib.TokenTradingFeesByPkidMapKey]
	tradingFeesMapPubkey := make(map[lib.PublicKey]uint64)
	if exists {
		tradingFeesMapByPkid, err := lib.DeserializePubKeyToUint64Map(tradingFeesByPkidBytes)
		if err != nil {
			return nil, false, fmt.Errorf(
				"GetTradingFeesForMarket: Problem deserializing trading fees: %v", err)
		}
		for pkid, feeBasisPoints := range tradingFeesMapByPkid {
			pkidBytes := pkid.ToBytes()
			if len(pkidBytes) != btcec.PubKeyBytesLenCompressed {
				return nil, false, fmt.Errorf(
					"GetTradingFeesForMarket: Problem decoding public key %s: %v",
					pkid, err)
			}
			pubkey := utxoView.GetPublicKeyForPKID(lib.NewPKID(pkidBytes))
			tradingFeesMapPubkey[*lib.NewPublicKey(pubkey)] = feeBasisPoints
		}
	}
	feeMap := map[string]uint64{}
	for publicKey, feeBasisPoints := range tradingFeesMapPubkey {
		// Convert the pubkey to a base58 string
		pkBase58 := lib.PkToString(publicKey[:], params)
		feeMap[pkBase58] = feeBasisPoints
	}

	return feeMap, tradingFeeUpdateDisabled, nil
}

func (fes *APIServer) GetDaoCoinMarketFees(ww http.ResponseWriter, req *http.Request) {
	if fes.Config.AmmMetadataPublicKey == "" {
		_AddBadRequestError(ww, fmt.Sprintf("GetDaoCoinMarketFees: AMM_METADATA_PUBLIC_KEY must be set "+
			"in the node's config for fees to work"))
		return
	}
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

	feeMapByPubkey, tradingFeeUpdateDisabled, err := GetTradingFeesForMarket(
		utxoView,
		fes.Params,
		fes.Config.AmmMetadataPublicKey,
		requestData.ProfilePublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDaoCoinMarketFees: Problem getting trading fees: %v", err))
		return
	}

	// Return all the data associated with the transaction in the response
	res := GetDaoCoinMarketFeesResponse{
		FeeBasisPointsByPublicKey: feeMapByPubkey,
		TradingFeeUpdateDisabled:  tradingFeeUpdateDisabled,
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
	// only.
	Quantity             string       `safeForLogging:"true"`
	QuantityCurrencyType CurrencyType `safeForLogging:"true"`

	// If set to true, the order will not automatically whitelist the coin being traded.
	// This should be rare, but it's useful if you want to trade a coin without moving
	// it out of the spam folder for whatever reason.
	SkipWhitelist bool `safeForLogging:"true"`

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

	InnerTransactionHexes []string

	QuoteCurrencyPriceInUsd string `safeForLogging:"true"`

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
	LimitReceiveAmountInUsd        string       `safeForLogging:"true"`
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
	MarketTradingFeeBasisPointsByUserPublicKey map[string]uint64
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
	// The rule of thumb is we're selling the base with an ask and buying the
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

type GetBaseCurrencyPriceRequest struct {
	BaseCurrencyPublicKeyBase58Check string `safeForLogging:"true"`
	// Only deso, focus, and usdc supported
	QuoteCurrencyPublicKeyBase58Check string `safeForLogging:"true"`
	// Currently, we only compute values for selling base currency. This is
	// because our only use-case is computing cashout value.
	BaseCurrencyQuantityToSell float64 `safeForLogging:"true"`
}

type GetBaseCurrencyPriceResponse struct {
	// It's useful to include the quote currency price used for USD conversions
	QuoteCurrencyPriceInUsd float64 `safeForLogging:"true"`

	// Traditional price values
	MidPriceInQuoteCurrency float64 `safeForLogging:"true"`
	MidPriceInUsd           float64 `safeForLogging:"true"`
	BestAskInQuoteCurrency  float64 `safeForLogging:"true"`
	BestAskInUsd            float64 `safeForLogging:"true"`
	BestBidInQuoteCurrency  float64 `safeForLogging:"true"`
	BestBidInUsd            float64 `safeForLogging:"true"`

	// Useful for computing "cashout" values on the wallet page
	ExecutionAmountInBaseCurrency float64 `safeForLogging:"true"`
	ReceiveAmountInQuoteCurrency  float64 `safeForLogging:"true"`
	ReceiveAmountInUsd            float64 `safeForLogging:"true"`
	ExecutionPriceInQuoteCurrency float64 `safeForLogging:"true"`
	ExecutionPriceInUsd           float64 `safeForLogging:"true"`
}

func (fes *APIServer) GetBaseCurrencyPriceEndpoint(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetBaseCurrencyPriceRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetBaseCurrencyPrice: Problem parsing request body: %v", err))
		return
	}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetBaseCurrencyPrice: Error fetching mempool view: %v", err))
		return
	}

	quotePkid, err := fes.getPKIDFromPublicKeyBase58CheckOrDESOString(
		utxoView,
		requestData.QuoteCurrencyPublicKeyBase58Check,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetBaseCurrencyPrice: Error getting quote pkid: %v", err))
		return
	}

	basePkid, err := fes.getPKIDFromPublicKeyBase58CheckOrDESOString(
		utxoView,
		requestData.BaseCurrencyPublicKeyBase58Check,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetBaseCurrencyPrice: Error getting base pkid: %v", err))
		return
	}
	// Super annoying, but it takes two fetches to get all the orders for a market
	ordersSide1, err := utxoView.GetAllDAOCoinLimitOrdersForThisDAOCoinPair(
		basePkid, quotePkid)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetBaseCurrencyPrice: Error getting limit orders: %v", err))
		return
	}
	ordersSide2, err := utxoView.GetAllDAOCoinLimitOrdersForThisDAOCoinPair(
		quotePkid, basePkid)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetBaseCurrencyPrice: Error getting limit orders: %v", err))
		return
	}
	allOrders := append(ordersSide1, ordersSide2...)

	type SimpleOrder struct {
		PriceInQuoteCurrency float64
		AmountInBaseCurrency float64
		Side                 string
	}
	simpleBidOrders := []*SimpleOrder{}
	simpleAskOrders := []*SimpleOrder{}
	for _, order := range allOrders {
		// Skip invalid dao coin limit orders. This filters out orders where
		// the transactor does not have sufficient funds to fill the order.
		if err = utxoView.IsValidDAOCoinLimitOrder(order); err != nil {
			continue
		}
		// An order is technically a bid order as long as the "buying" currency is the
		// base currency. Otherwise, it's an ask currency because the base currency is
		// the one being sold.
		if order.BuyingDAOCoinCreatorPKID.Eq(basePkid) {
			// Computing the price "just works" when the base currency is the buying
			// coin because the exchange rate is expressed in quote currency (= selling
			// coin) per base currency (= buying coin).
			priceFloat, err := CalculateFloatFromScaledExchangeRate(
				lib.PkToString(order.BuyingDAOCoinCreatorPKID[:], fes.Params),
				lib.PkToString(order.SellingDAOCoinCreatorPKID[:], fes.Params),
				order.ScaledExchangeRateCoinsToSellPerCoinToBuy)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("GetBaseCurrencyPrice for bid: Error calculating price: %v", err))
				return
			}

			// The quantity is tricky. If we had a bid order then the quantity is just the
			// quantity specified in the order. However, if we had an ask then the quantity
			// is actually the amount of quote currency being sold. In the latter case, a
			// conversion is required.
			quantityToFillFloat, err := CalculateFloatQuantityFromBaseUnits(
				lib.PkToString(order.BuyingDAOCoinCreatorPKID[:], fes.Params),
				lib.PkToString(order.SellingDAOCoinCreatorPKID[:], fes.Params),
				DAOCoinLimitOrderOperationTypeString(order.OperationType.String()),
				order.QuantityToFillInBaseUnits)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("GetBaseCurrencyPrice: Error calculating quantity: %v", err))
				return
			}
			if order.OperationType == lib.DAOCoinLimitOrderOperationTypeASK {
				// If the order is an ask, then the quantity is the amount of quote currency
				// being sold. To convert it to base currency, we just have to divide by the
				// price in quote currency. This ends up doing (quote currency) / (quote currency / base currency)
				quantityToFillFloat = quantityToFillFloat / priceFloat
			}

			simpleBidOrders = append(simpleBidOrders, &SimpleOrder{
				PriceInQuoteCurrency: priceFloat,
				AmountInBaseCurrency: quantityToFillFloat,
				Side:                 "BID",
			})
		} else {
			// If we're here then it means that the order is selling the base currency.
			// This means the exchange rate is (coins to sell) / (coins to buy), which is
			// (base currency) / (quote currency). This is the inverse of what we want
			// so we have to flip it.
			priceFloat, err := CalculateFloatFromScaledExchangeRate(
				lib.PkToString(order.BuyingDAOCoinCreatorPKID[:], fes.Params),
				lib.PkToString(order.SellingDAOCoinCreatorPKID[:], fes.Params),
				order.ScaledExchangeRateCoinsToSellPerCoinToBuy)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("GetBaseCurrencyPrice for ask: Error calculating price: %v", err))
				return
			}
			if priceFloat == 0.0 {
				// We should never see an order with a zero price so error if we see one.
				_AddBadRequestError(ww, fmt.Sprintf("GetBaseCurrencyPrice: Zero price order: %v", order))
				return
			}
			priceFloat = 1.0 / priceFloat

			// The quantity is tricky. If we had a bid order then the quantity is the quote
			// currency (because the buying coin is the quote currency). If we have an ask
			// then the quantity is the base currency (because the selling coin is the base
			// currency). In the latter case, a conversion is required.
			quantityToFillFloat, err := CalculateFloatQuantityFromBaseUnits(
				lib.PkToString(order.BuyingDAOCoinCreatorPKID[:], fes.Params),
				lib.PkToString(order.SellingDAOCoinCreatorPKID[:], fes.Params),
				DAOCoinLimitOrderOperationTypeString(order.OperationType.String()),
				order.QuantityToFillInBaseUnits)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("GetBaseCurrencyPrice: Error calculating quantity: %v", err))
				return
			}
			if order.OperationType == lib.DAOCoinLimitOrderOperationTypeBID {
				// If the order is an bid, then the quantity is the amount of quote currency
				// being bought so we need to invert.
				quantityToFillFloat = quantityToFillFloat / priceFloat
			}

			simpleAskOrders = append(simpleAskOrders, &SimpleOrder{
				PriceInQuoteCurrency: priceFloat,
				AmountInBaseCurrency: quantityToFillFloat,
				Side:                 "ASK",
			})
		}
	}

	// Sort the bids by their price, highest first
	sort.Slice(simpleBidOrders, func(ii, jj int) bool {
		return simpleBidOrders[ii].PriceInQuoteCurrency > simpleBidOrders[jj].PriceInQuoteCurrency
	})
	// Sort the asks by their price, lowest first
	sort.Slice(simpleAskOrders, func(ii, jj int) bool {
		return simpleAskOrders[ii].PriceInQuoteCurrency < simpleAskOrders[jj].PriceInQuoteCurrency
	})

	// We can easily compute the best bid and best ask price in quote currency now.
	var bestBidPriceInQuoteCurrency float64
	var bestAskPriceInQuoteCurrency float64
	var midPriceInQuoteCurrency float64
	baseCurrencyFilled := big.NewFloat(0.0)
	quoteCurrencyReceived := big.NewFloat(0.0)
	priceInQuoteCurrency := big.NewFloat(0.0)
	if len(simpleAskOrders) != 0 {
		bestAskPriceInQuoteCurrency = simpleAskOrders[0].PriceInQuoteCurrency
	}
	if len(simpleBidOrders) != 0 {
		bestBidPriceInQuoteCurrency = simpleBidOrders[0].PriceInQuoteCurrency

		// Iterate through the bids "filling" orders until we hit the base currency
		// quantity we're looking for.
		baseCurrencyToFill := big.NewFloat(requestData.BaseCurrencyQuantityToSell)
		for _, bid := range simpleBidOrders {
			// If the amount filled plus the amount we're about to fill is greater
			// than the amount we're looking to fill, then we just partially fill
			// the order.
			if big.NewFloat(0.0).Add(
				baseCurrencyFilled,
				big.NewFloat(bid.AmountInBaseCurrency),
			).Cmp(baseCurrencyToFill) > 0 {
				baseCurrencyFromThisOrder := big.NewFloat(0).Sub(baseCurrencyToFill, baseCurrencyFilled)
				addlQuoteCurrencyReceivedFromOrdered := big.NewFloat(0).Mul(baseCurrencyFromThisOrder, big.NewFloat(bid.PriceInQuoteCurrency))
				quoteCurrencyReceived = big.NewFloat(0).Add(quoteCurrencyReceived, addlQuoteCurrencyReceivedFromOrdered)
				// Since we've fully filled the order, we can simply set the base currency filled
				// to the amount we're looking to fill from the request.
				baseCurrencyFilled = baseCurrencyToFill
				break
			}
			addlQuoteCurrencyReceivedFromOrder := big.NewFloat(0).Mul(big.NewFloat(bid.AmountInBaseCurrency), big.NewFloat(bid.PriceInQuoteCurrency))
			quoteCurrencyReceived = big.NewFloat(0).Add(quoteCurrencyReceived, addlQuoteCurrencyReceivedFromOrder)
			baseCurrencyFilled = big.NewFloat(0).Add(baseCurrencyFilled, big.NewFloat(bid.AmountInBaseCurrency))
		}

		// Now the amount to fill and the quote currency received should be ready to go
		// so we can compute the price.
		if baseCurrencyFilled.Sign() > 0 {
			priceInQuoteCurrency = big.NewFloat(0).Quo(quoteCurrencyReceived, baseCurrencyFilled)
		}
	}
	if len(simpleAskOrders) != 0 && len(simpleBidOrders) != 0 {
		midPriceInQuoteCurrency = (bestBidPriceInQuoteCurrency + bestAskPriceInQuoteCurrency) / 2
	}

	// Get the price of the quote currency in usd. Use the mid price
	quoteCurrencyPriceInUsdStr, _, _, err := fes.GetQuoteCurrencyPriceInUsd(
		requestData.QuoteCurrencyPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetBaseCurrencyPrice: Problem getting quote currency price in usd: %v", err))
		return
	}
	quoteCurrencyPriceInUsd, err := strconv.ParseFloat(quoteCurrencyPriceInUsdStr, 64)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetBaseCurrencyPrice: Problem parsing quote currency price in usd: %v", err))
		return
	}

	// If any of these are too big for the Float64() it's better to best-effort
	// them rather than error out.
	baseCurrencyFilledFloat, _ := baseCurrencyFilled.Float64()
	quoteCurrencyReceivedFloat, _ := quoteCurrencyReceived.Float64()
	receiveAmountInUsdFloat, _ := big.NewFloat(0).Mul(
		quoteCurrencyReceived, big.NewFloat(quoteCurrencyPriceInUsd)).Float64()
	priceInQuoteCurrencyFloat, _ := priceInQuoteCurrency.Float64()
	executionPriceInUsdFloat, _ := big.NewFloat(0).Mul(
		priceInQuoteCurrency, big.NewFloat(quoteCurrencyPriceInUsd)).Float64()
	res := &GetBaseCurrencyPriceResponse{
		QuoteCurrencyPriceInUsd: quoteCurrencyPriceInUsd,

		// Traditional price values
		MidPriceInQuoteCurrency: midPriceInQuoteCurrency,
		MidPriceInUsd:           midPriceInQuoteCurrency * quoteCurrencyPriceInUsd,
		BestAskInQuoteCurrency:  bestAskPriceInQuoteCurrency,
		BestAskInUsd:            bestAskPriceInQuoteCurrency * quoteCurrencyPriceInUsd,
		BestBidInQuoteCurrency:  bestBidPriceInQuoteCurrency,
		BestBidInUsd:            bestBidPriceInQuoteCurrency * quoteCurrencyPriceInUsd,

		// Useful for computing "cashout" values on the wallet page
		ExecutionAmountInBaseCurrency: baseCurrencyFilledFloat,
		ReceiveAmountInQuoteCurrency:  quoteCurrencyReceivedFloat,
		ReceiveAmountInUsd:            receiveAmountInUsdFloat,
		ExecutionPriceInQuoteCurrency: priceInQuoteCurrencyFloat,
		ExecutionPriceInUsd:           executionPriceInUsdFloat,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetQuoteCurrencyPriceInUsd: Problem encoding response: %v", err))
		return
	}
}

type GetQuoteCurrencyPriceInUsdRequest struct {
	QuoteCurrencyPublicKeyBase58Check string `safeForLogging:"true"`
}

type GetQuoteCurrencyPriceInUsdResponse struct {
	MidPrice string `safeForLogging:"true"`
	BestAsk  string `safeForLogging:"true"`
	BestBid  string `safeForLogging:"true"`
}

func (fes *APIServer) GetQuoteCurrencyPriceInUsdEndpoint(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetQuoteCurrencyPriceInUsdRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetQuoteCurrencyPriceInUsd: Problem parsing request body: %v", err))
		return
	}

	usdPrice, bestBid, bestAsk, err := fes.GetQuoteCurrencyPriceInUsd(requestData.QuoteCurrencyPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetQuoteCurrencyPriceInUsd: Problem getting quote currency price in USD: %v", err))
		return
	}

	res := GetQuoteCurrencyPriceInUsdResponse{
		MidPrice: usdPrice,
		BestAsk:  bestAsk,
		BestBid:  bestBid,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetQuoteCurrencyPriceInUsd: Problem encoding response: %v", err))
		return
	}
}

func (fes *APIServer) GetQuoteCurrencyPriceInUsd(
	quoteCurrencyPublicKey string) (_midmarket string, _bid string, _ask string, _err error) {
	if IsDesoPkid(quoteCurrencyPublicKey) {
		// TODO: We're taking the Coinbase price directly here, but ideally we would get it from
		// a function that abstracts away the exchange we're getting it from. We do this for now
		// in order to minimize discrepancies with other sources.
		desoUsdCents := fes.MostRecentCoinbasePriceUSDCents
		if desoUsdCents == 0 {
			return "", "", "", fmt.Errorf("GetQuoteCurrencyPriceInUsd: Coinbase DESO price is zero")
		}
		price := fmt.Sprintf("%0.9f", float64(desoUsdCents)/100)
		return price, price, price, nil // TODO: get real bid and ask prices.
	}
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return "", "", "", fmt.Errorf(
			"GetQuoteCurrencyPriceInUsd: Error fetching mempool view: %v", err)
	}

	pkBytes, _, err := lib.Base58CheckDecode(quoteCurrencyPublicKey)
	if err != nil || len(pkBytes) != btcec.PubKeyBytesLenCompressed {
		return "", "", "", fmt.Errorf(
			"GetQuoteCurrencyPriceInUsd: Problem decoding public key %s: %v",
			quoteCurrencyPublicKey, err)
	}

	existingProfileEntry := utxoView.GetProfileEntryForPublicKey(pkBytes)
	if existingProfileEntry == nil || existingProfileEntry.IsDeleted() {
		return "", "", "", fmt.Errorf(
			"GetQuoteCurrencyPriceInUsd: Profile for quote currency public "+
				"key %v does not exist",
			quoteCurrencyPublicKey)
	}

	// If the profile is the dusdc profile then just return 1.0
	lowerUsername := strings.ToLower(string(existingProfileEntry.Username))
	if lowerUsername == "dusdc_" {
		return "1.0", "1.0", "1.0", nil
	} else if lowerUsername == "focus" ||
		lowerUsername == "openfund" {

		// TODO: We're taking the Coinbase price directly here, but ideally we would get it from
		// a function that abstracts away the exchange we're getting it from. We do this for now
		// in order to minimize discrepancies with other sources.
		desoUsdCents := fes.MostRecentCoinbasePriceUSDCents
		if desoUsdCents == 0 {
			return "", "", "", fmt.Errorf("GetQuoteCurrencyPriceInUsd: Coinbase DESO price is zero")
		}
		pkid := utxoView.GetPKIDForPublicKey(pkBytes)
		if pkid == nil {
			return "", "", "", fmt.Errorf("GetQuoteCurrencyPriceInUsd: Error getting pkid for public key %v",
				quoteCurrencyPublicKey)
		}
		ordersBuyingCoin1, err := utxoView.GetAllDAOCoinLimitOrdersForThisDAOCoinPair(
			&lib.ZeroPKID, pkid.PKID)
		if err != nil {
			return "", "", "", fmt.Errorf("GetDAOCoinLimitOrders: Error getting limit orders: %v", err)
		}
		ordersBuyingCoin2, err := utxoView.GetAllDAOCoinLimitOrdersForThisDAOCoinPair(
			pkid.PKID, &lib.ZeroPKID)
		if err != nil {
			return "", "", "", fmt.Errorf("GetDAOCoinLimitOrders: Error getting limit orders: %v", err)
		}
		allOrders := append(ordersBuyingCoin1, ordersBuyingCoin2...)
		// Find the highest bid price and the lowest ask price
		highestBidPrice := float64(0.0)
		lowestAskPrice := math.MaxFloat64
		for _, order := range allOrders {
			priceStr, err := CalculatePriceStringFromScaledExchangeRate(
				lib.PkToString(order.BuyingDAOCoinCreatorPKID[:], fes.Params),
				lib.PkToString(order.SellingDAOCoinCreatorPKID[:], fes.Params),
				order.ScaledExchangeRateCoinsToSellPerCoinToBuy,
				DAOCoinLimitOrderOperationTypeString(order.OperationType.String()))
			if err != nil {
				return "", "", "", fmt.Errorf("GetQuoteCurrencyPriceInUsd: Error calculating price: %v", err)
			}
			priceFloat, err := strconv.ParseFloat(priceStr, 64)
			if err != nil {
				return "", "", "", fmt.Errorf("GetQuoteCurrencyPriceInUsd: Error parsing price: %v", err)
			}
			if order.OperationType == lib.DAOCoinLimitOrderOperationTypeBID &&
				priceFloat > highestBidPrice {

				highestBidPrice = priceFloat
			}
			if order.OperationType == lib.DAOCoinLimitOrderOperationTypeASK &&
				priceFloat < lowestAskPrice {

				lowestAskPrice = priceFloat
			}
		}
		if highestBidPrice != 0.0 && lowestAskPrice != math.MaxFloat64 {
			midPriceDeso := (highestBidPrice + lowestAskPrice) / 2.0
			midPriceUsd := midPriceDeso * float64(desoUsdCents) / 100

			return fmt.Sprintf("%0.9f", midPriceUsd),
				fmt.Sprintf("%0.9f", highestBidPrice),
				fmt.Sprintf("%0.9f", lowestAskPrice),
				nil
		}

		return "", "", "", fmt.Errorf("GetQuoteCurrencyPriceInUsd: Error calculating price")
	}

	return "", "", "", fmt.Errorf(
		"GetQuoteCurrencyPriceInUsd: Quote currency %v not supported",
		quoteCurrencyPublicKey)
}

func (fes *APIServer) CreateMarketOrLimitOrder(
	isMarketOrder bool,
	request *DAOCoinLimitOrderCreationRequest,
) (
	*DAOCoinLimitOrderResponse,
	error,
) {

	if isMarketOrder {
		// We need to translate the req into a DAOCoinMarketOrderCreationRequest
		daoCoinMarketOrderRequest := &DAOCoinMarketOrderCreationRequest{
			TransactorPublicKeyBase58Check:            request.TransactorPublicKeyBase58Check,
			BuyingDAOCoinCreatorPublicKeyBase58Check:  request.BuyingDAOCoinCreatorPublicKeyBase58Check,
			SellingDAOCoinCreatorPublicKeyBase58Check: request.SellingDAOCoinCreatorPublicKeyBase58Check,
			Quantity:             request.Quantity,
			OperationType:        request.OperationType,
			FillType:             request.FillType,
			MinFeeRateNanosPerKB: request.MinFeeRateNanosPerKB,
			TransactionFees:      request.TransactionFees,
		}

		marketOrderRes, err := fes.createDaoCoinMarketOrderHelper(daoCoinMarketOrderRequest)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem creating market order: %v", err)
		}

		return marketOrderRes, nil
	} else {
		limitOrderRes, err := fes.createDaoCoinLimitOrderHelper(request)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem creating market order: %v", err)
		}

		return limitOrderRes, nil
	}
}

// priceStr is a decimal string representing the price in quote currency.
func InvertPriceStr(priceStr string) (string, error) {
	// - 1.0 / price
	// = [1e38 * 1e38 / (price * 1e38)] / 1e38
	scaledPrice, err := lib.CalculateScaledExchangeRateFromString(priceStr)
	if err != nil {
		return "", fmt.Errorf("HandleMarketOrder: Problem calculating scaled price: %v", err)
	}
	if scaledPrice.IsZero() {
		return "0", err
	}
	oneE38Squared := big.NewInt(0).Mul(lib.OneE38.ToBig(), lib.OneE38.ToBig())
	invertedScaledPrice := big.NewInt(0).Div(oneE38Squared, scaledPrice.ToBig())
	return lib.FormatScaledUint256AsDecimalString(invertedScaledPrice, lib.OneE38.ToBig()), nil
}

func (fes *APIServer) MaybeCreateTokenWhitelistAssociation(
	transactorPubkey string,
	coinPubkey string,
	minFeeRateNanosPerKB uint64,
	additionalOutputs []*lib.DeSoOutput,
	optionalUtxoView *lib.UtxoView) (
	*lib.MsgDeSoTxn,
	error,
) {
	utxoView := optionalUtxoView
	if utxoView == nil {
		var err error
		utxoView, err = fes.backendServer.GetMempool().GetAugmentedUniversalView()
		if err != nil {
			return nil, fmt.Errorf("MaybeCreateTokenWhitelistAssociation: Error fetching mempool view: %v", err)
		}
	}

	transactorPubkeyBytes, _, err := lib.Base58CheckDecode(transactorPubkey)
	if err != nil {
		return nil, fmt.Errorf("MaybeCreateTokenWhitelistAssociation: Problem decoding "+
			"transactor pubkey %s: %v", transactorPubkey, err)
	}
	transactorPkid := utxoView.GetPKIDForPublicKey(transactorPubkeyBytes)

	coinPubkeyBytes, _, err := lib.Base58CheckDecode(coinPubkey)
	if err != nil {
		return nil, fmt.Errorf("MaybeCreateTokenWhitelistAssociation: Problem decoding "+
			"coin pubkey %s: %v", coinPubkey, err)
	}
	coinPkid := utxoView.GetPKIDForPublicKey(coinPubkeyBytes)

	ammPubkeyBytes, _, err := lib.Base58CheckDecode(fes.Config.AmmMetadataPublicKey)
	if err != nil {
		return nil, fmt.Errorf("MaybeCreateTokenWhitelistAssociation: Problem decoding "+
			"amm metadata pubkey %s: %v", fes.Config.AmmMetadataPublicKey, err)
	}
	ammPkid := utxoView.GetPKIDForPublicKey(ammPubkeyBytes)

	associationQuery := &lib.UserAssociationQuery{
		TransactorPKID:   transactorPkid.PKID,
		TargetUserPKID:   coinPkid.PKID,
		AppPKID:          ammPkid.PKID,
		AssociationType:  []byte(lib.DeSoTokenWhitelistAssociationKey),
		AssociationValue: []byte(lib.DeSoTokenWhitelistAssociationKey),
		Limit:            1,
	}

	associationEntries, err := utxoView.GetUserAssociationsByAttributes(associationQuery)
	if err != nil {
		return nil, fmt.Errorf("MaybeCreateTokenWhitelistAssociation: Error fetching user associations: %v", err)
	}

	// If we found an association, there's no need to create one. In this case just return
	// a nil transaction.
	if len(associationEntries) > 0 {
		return nil, nil
	}

	// Create transaction.
	txn, _, _, _, err := fes.blockchain.CreateCreateUserAssociationTxn(
		transactorPubkeyBytes,
		&lib.CreateUserAssociationMetadata{
			TargetUserPublicKey: lib.NewPublicKey(coinPubkeyBytes),
			AppPublicKey:        lib.NewPublicKey(ammPubkeyBytes),
			AssociationType:     []byte(lib.DeSoTokenWhitelistAssociationKey),
			AssociationValue:    []byte(lib.DeSoTokenWhitelistAssociationKey),
		},
		nil,
		minFeeRateNanosPerKB,
		fes.backendServer.GetMempool(),
		additionalOutputs,
	)
	if err != nil {
		return nil, fmt.Errorf("MaybeCreateTokenWhitelistAssociation: Problem creating transaction: %v", err)
	}

	return txn, nil
}

func (fes *APIServer) SendCoins(
	coinPublicKey string,
	transactorPubkeyBytes []byte,
	receiverPubkeyBytes []byte,
	amountBaseUnits *uint256.Int,
	minFeeRateNanosPerKb uint64,
	additionalOutputs []*lib.DeSoOutput,
) (
	*lib.MsgDeSoTxn,
	error,
) {
	if amountBaseUnits == nil || amountBaseUnits.IsZero() {
		return nil, fmt.Errorf("SendCoins: Amount must be non-zero")
	}
	coinPkBytes, _, err := lib.Base58CheckDecode(coinPublicKey)
	if err != nil || len(coinPkBytes) != btcec.PubKeyBytesLenCompressed {
		return nil, fmt.Errorf("HandleMarketOrder: Problem decoding coin pkid %s: %v", coinPublicKey, err)
	}

	var txn *lib.MsgDeSoTxn
	if IsDesoPkid(coinPublicKey) {
		txn, _, _, _, _, err = fes.CreateSendDesoTxn(
			int64(amountBaseUnits.Uint64()),
			transactorPubkeyBytes,
			receiverPubkeyBytes,
			nil,
			minFeeRateNanosPerKb,
			additionalOutputs)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem creating transaction: %v", err)
		}
	} else {
		txn, _, _, _, err = fes.blockchain.CreateDAOCoinTransferTxn(
			transactorPubkeyBytes,
			&lib.DAOCoinTransferMetadata{
				ProfilePublicKey:       coinPkBytes,
				ReceiverPublicKey:      receiverPubkeyBytes,
				DAOCoinToTransferNanos: *amountBaseUnits,
			},
			// Standard transaction fields
			minFeeRateNanosPerKb,
			fes.backendServer.GetMempool(),
			additionalOutputs)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem creating transaction: %v", err)
		}
	}

	return txn, nil
}

func (fes *APIServer) HandleMarketOrder(
	isMarketOrder bool,
	req *DAOCoinLimitOrderWithFeeRequest,
	isBuyOrder bool,
	feeMapByPubkey map[string]uint64,
	skipWhitelist bool,
) (
	*DAOCoinLimitOrderWithFeeResponse,
	error,
) {
	quoteCurrencyUsdValue := float64(0.0)
	quoteCurrencyUsdValueStr, _, _, err := fes.GetQuoteCurrencyPriceInUsd(
		req.QuoteCurrencyPublicKeyBase58Check)
	if err != nil {
		// If we can't get the price of the quote currency in usd, then we can't
		// convert the usd amount to a quote currency amount. In this case, keep
		// going but don't use the quote currency usd value for anything.
		quoteCurrencyUsdValue = 0.0
	} else {
		quoteCurrencyUsdValue, err = strconv.ParseFloat(quoteCurrencyUsdValueStr, 64)
		if err != nil {
			// Again, get the usd value on a best-effort basis
			quoteCurrencyUsdValue = 0.0
		}
	}
	convertToUsd := func(quoteAmountStr string) string {
		quoteAmount, err := strconv.ParseFloat(quoteAmountStr, 64)
		if err != nil {
			return ""
		}
		return fmt.Sprintf("%.9f", quoteAmount*quoteCurrencyUsdValue)
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
		quantityStr = fmt.Sprintf("%0.9f", quantityUsd/quoteCurrencyUsdValue)
	}

	priceStrQuote := ""
	if !isMarketOrder {
		if req.PriceCurrencyType == CurrencyTypeUsd {
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
			priceUsd, err := strconv.ParseFloat(req.Price, 64)
			if err != nil {
				return nil, fmt.Errorf("HandleMarketOrder: Problem converting price "+
					"to float %v", err)
			}
			priceStrQuote = fmt.Sprintf("%0.9f", priceUsd/quoteCurrencyUsdValue)
		} else if req.PriceCurrencyType == CurrencyTypeQuote {
			// This is the easy case. If the price is in quote currency, then we
			// can just use it directly.
			priceStrQuote = req.Price
		} else {
			return nil, fmt.Errorf("HandleMarketOrder: Invalid price currency type %v."+
				"Options are 'usd' or 'quote'",
				req.PriceCurrencyType)
		}
	}

	// Next we set the operation type, buying public key, and selling public key based on
	// the currency type of the amount. This is confusing, but the reason we need to do it
	// this way is because consensus requires that the buying currency be used as the quantity
	// for a bid and vice versa for an ask. This causes some bs here.
	var operationType DAOCoinLimitOrderOperationTypeString
	buyingPublicKey := ""
	sellingPublicKey := ""
	priceStrConsensus := priceStrQuote
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
			// We also have to invert the price because consensus assumes the
			// denominator is the selling coin for an ask, when it should be
			// the base currency.
			priceStrConsensus, err = InvertPriceStr(priceStrQuote)
			if err != nil {
				return nil, fmt.Errorf("HandleMarketOrder: Problem inverting price: %v", err)
			}
		} else {
			// The last hard case. If you're selling the base and you want
			// to use quote currency as the quantity, then you need to do a
			// bid where the buying currency is the quote.
			operationType = DAOCoinLimitOrderOperationTypeStringBID
			buyingPublicKey = req.QuoteCurrencyPublicKeyBase58Check
			sellingPublicKey = req.BaseCurrencyPublicKeyBase58Check
			// We also have to invert the price because consensus assumes the
			// denominator is the buying coin for a bid, when it should be
			// the base currency.
			priceStrConsensus, err = InvertPriceStr(priceStrQuote)
			if err != nil {
				return nil, fmt.Errorf("HandleMarketOrder: Problem inverting price: %v", err)
			}
		}
	} else {
		return nil, fmt.Errorf("HandleMarketOrder: Invalid quantity currency type %v",
			req.QuantityCurrencyType)
	}

	// We need to translate the req into a DAOCoinMarketOrderCreationRequest
	daoCoinMarketOrderRequest := &DAOCoinLimitOrderCreationRequest{
		TransactorPublicKeyBase58Check:            req.TransactorPublicKeyBase58Check,
		BuyingDAOCoinCreatorPublicKeyBase58Check:  buyingPublicKey,
		SellingDAOCoinCreatorPublicKeyBase58Check: sellingPublicKey,
		Quantity:             quantityStr,
		OperationType:        operationType,
		Price:                priceStrConsensus,
		FillType:             req.FillType,
		MinFeeRateNanosPerKB: req.MinFeeRateNanosPerKB,
		TransactionFees:      req.TransactionFees,
	}
	orderRes, err := fes.CreateMarketOrLimitOrder(
		isMarketOrder,
		daoCoinMarketOrderRequest)
	if err != nil {
		return nil, fmt.Errorf("HandleMarketOrder: Problem creating order: %v", err)
	}

	quoteCurrencyExecutedBeforeFeesStr := orderRes.SimulatedExecutionResult.BuyingCoinQuantityFilled
	if daoCoinMarketOrderRequest.SellingDAOCoinCreatorPublicKeyBase58Check == req.QuoteCurrencyPublicKeyBase58Check {
		quoteCurrencyExecutedBeforeFeesStr = orderRes.SimulatedExecutionResult.SellingCoinQuantityFilled
	}

	// Now we know how much of the buying and selling currency are going to be transacted. This
	// allows us to compute a fee to charge the transactor.
	quoteCurrencyExecutedBeforeFeesBaseUnits, err := CalculateBaseUnitsFromStringDecimalAmountSimple(
		req.QuoteCurrencyPublicKeyBase58Check, quoteCurrencyExecutedBeforeFeesStr)
	if err != nil {
		return nil, fmt.Errorf("HandleMarketOrder: Problem calculating quote currency total: %v", err)
	}

	// Compute how much in quote currency we need to pay each constituent
	feeBaseUnitsByPubkey := make(map[string]*uint256.Int)
	totalFeeBaseUnits := uint256.NewInt(0)
	for pubkey, feeBasisPoints := range feeMapByPubkey {
		feeBaseUnits, err := lib.SafeUint256().Mul(
			quoteCurrencyExecutedBeforeFeesBaseUnits, uint256.NewInt(feeBasisPoints))
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem calculating fee for quote: %v", err)
		}
		feeBaseUnits, err = lib.SafeUint256().Div(feeBaseUnits, uint256.NewInt(10000))
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem calculating fee div: %v", err)
		}
		feeBaseUnitsByPubkey[pubkey] = feeBaseUnits
		totalFeeBaseUnits, err = lib.SafeUint256().Add(totalFeeBaseUnits, feeBaseUnits)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem calculating total fee add: %v", err)
		}
	}

	// Validate that the totalFeeBaseUnits is less than or equal to the quote currency total
	if totalFeeBaseUnits.Cmp(quoteCurrencyExecutedBeforeFeesBaseUnits) > 0 {
		return nil, fmt.Errorf("HandleMarketOrder: Total fees exceed total quote currency")
	}

	// Precompute the total fee to return it later
	marketTakerFeeBaseUnits := uint64(0)
	for _, feeBaseUnits := range feeMapByPubkey {
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
	var tokenWhitelistTxn *lib.MsgDeSoTxn
	// Create a transaction to whitelist the token in the user's wallet if it's not already,
	// and if that's desired.
	if !skipWhitelist {
		tokenWhitelistTxn, err = fes.MaybeCreateTokenWhitelistAssociation(
			req.TransactorPublicKeyBase58Check,
			req.BaseCurrencyPublicKeyBase58Check,
			req.MinFeeRateNanosPerKB,
			nil,
			utxoView)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem creating token whitelist txn: %v", err)
		}
	}
	quoteCurrencyPubkeyBytes, _, err := lib.Base58CheckDecode(req.QuoteCurrencyPublicKeyBase58Check)
	if err != nil || len(quoteCurrencyPubkeyBytes) != btcec.PubKeyBytesLenCompressed {
		return nil, fmt.Errorf("HandleMarketOrder: Problem decoding public key %s: %v",
			req.QuoteCurrencyPublicKeyBase58Check, err)
	}
	if isBuyOrder {
		// For each trading fee we need to pay, construct a transfer txn that sends the amount
		// from the transactor directly to the person receiving the fee.
		transferTxns := []*lib.MsgDeSoTxn{}
		for pubkey, feeBaseUnits := range feeBaseUnitsByPubkey {
			if feeBaseUnits.IsZero() {
				continue
			}
			receiverPubkeyBytes, _, err := lib.Base58CheckDecode(pubkey)
			if err != nil || len(receiverPubkeyBytes) != btcec.PubKeyBytesLenCompressed {
				return nil, fmt.Errorf("HandleMarketOrder: Problem decoding public key %s: %v",
					pubkey, err)
			}
			// Try and create the TransferDaoCoin transaction for the user.
			//
			// TODO: Add ExtraData to the transaction to make it easier to report it as an
			// earning to the user who's receiving the fee.
			txn, err := fes.SendCoins(
				req.QuoteCurrencyPublicKeyBase58Check,
				transactorPubkeyBytes,
				receiverPubkeyBytes,
				feeBaseUnits,
				req.MinFeeRateNanosPerKB,
				nil)
			_, _, _, _, err = utxoView.ConnectTransaction(
				txn, txn.Hash(), fes.blockchain.BlockTip().Height,
				fes.blockchain.BlockTip().Header.TstampNanoSecs,
				false, false)
			if err != nil {
				return nil, fmt.Errorf("HandleMarketOrder: Problem connecting transaction: %v", err)
			}
			transferTxns = append(transferTxns, txn)
		}

		// Specifying the quantity after deducting fees is a bit tricky. If the user specified the
		// original quantity in quote currency, then we can subtract the fee and execute the order
		// with what remains after the fee. However, if they specified the original quantity in base
		// currency, then we want to convert to quote currency and subtract the fee if we can. However,
		// we can only do this if the user specified a price. If they didn't specify a price, then we
		// need to fall back on the simulated amount, which is OK since this is a market order anyway.
		var remainingQuoteQuantityDecimal string
		if req.QuantityCurrencyType == CurrencyTypeQuote || req.QuantityCurrencyType == CurrencyTypeUsd {
			// In this case, quantityStr is the amount that the order executed with
			// originally. So we deduct the fees from that and run.
			quoteCurrencyQuantityTotalBaseUnits, err := CalculateBaseUnitsFromStringDecimalAmountSimple(
				req.QuoteCurrencyPublicKeyBase58Check, quantityStr)
			if err != nil {
				return nil, fmt.Errorf("HandleMarketOrder: Problem calculating quote currency total: %v", err)
			}
			quoteCurrencyQuantityMinusFeesBaseUnits, err := lib.SafeUint256().Sub(
				quoteCurrencyQuantityTotalBaseUnits, totalFeeBaseUnits)
			if err != nil {
				return nil, fmt.Errorf("HandleMarketOrder: Problem calculating remaining quote currency 1: %v", err)
			}
			remainingQuoteQuantityDecimal, err = CalculateStringDecimalAmountFromBaseUnitsSimple(
				req.QuoteCurrencyPublicKeyBase58Check, quoteCurrencyQuantityMinusFeesBaseUnits)
			if err != nil {
				return nil, fmt.Errorf("HandleMarketOrder: Problem calculating remaining quote currency 2: %v", err)
			}
		} else if req.QuantityCurrencyType == CurrencyTypeBase {
			// In this case the user specified base currency. If there's a price then try and estimate
			// the quote amount. Otherwise, just use the simulated amount.
			if priceStrQuote != "" {
				// TODO: This is the same as the limit amount calculation below. We should refactor
				// this to avoid duplication.
				// TODO: This codepath results in the fee percentage being a little lower because we're not
				// directly deducting the fees from the amount filled. This is OK for now, and it's
				// tough to make it work otherwise. Instead of (feePercent * quantity) -> filledAmount,
				// it ends up being:
				// - (1+feePercent)(quantity) -> filledAmount, or
				// - (quantity) -> filledAmount / (1 + feePercent)
				// which is a lower actual fee. I think it's fine for now though. Fixing it would require
				// doing two passes to compute the fee, which isn't worth it right now.
				//
				// In this case the quantityStr needs to be converted from base to quote currency:
				// - scaledPrice := priceQuotePerBase * 1e38
				// - quantityBaseUnits * scaledPrice / 1e38
				//
				// This multiplies the scaled price by 1e38 then we have to reverse it later
				scaledPrice, err := lib.CalculateScaledExchangeRateFromString(priceStrQuote)
				if err != nil {
					return nil, fmt.Errorf("HandleMarketOrder: Problem calculating scaled price: %v", err)
				}
				totalQuantityBaseCurrencyBaseUnits, err := CalculateBaseUnitsFromStringDecimalAmountSimple(
					req.BaseCurrencyPublicKeyBase58Check, quantityStr)
				if err != nil {
					return nil, fmt.Errorf("HandleMarketOrder: Problem calculating base units: %v", err)
				}
				bigLimitAmount := big.NewInt(0).Mul(totalQuantityBaseCurrencyBaseUnits.ToBig(), scaledPrice.ToBig())
				bigLimitAmount = big.NewInt(0).Div(bigLimitAmount, lib.OneE38.ToBig())
				// The reason why this extra step is needed is extremely subtle. It's required because
				// scaledPrice represents (whole coin / whole coin) rather than (base unit / base unit).
				// When the coins have the same number of base units per whole coin, this conversion isn't
				// needed because we have:
				// - (whole coin / whole coin) = ((1e18 base units) / (1e18 base units)) = (base unit / base unit)
				//
				// However, in the case where DESO is the quote currency, the (whole coin / whole coin) exchange
				// rate is NOT the same as the (base unit / base unit) rate because DESO has a different number
				// of base units per whole coin. So we have to first compute:
				// - (deso nanos / daocoin base units)
				// = (1e9 * deso whole coin) / (1e18 * daocoin whole coin))
				// = (1 / 1e9) * (deso whole coin / daocoin whole coin)
				// = (1 / 1e9) * scaledPriceQuotePerBase
				//
				// And so this translates to a modification to the equation above as follows:
				// - quantityBaseUnits * (deso nanos / daocoin base units)
				// = quantityBaseUnits * (1 / 1e9) * scaledPriceQuotePerBase
				// = (1 / 1e9) * quantityBaseUnits * scaledPriceQuotePerBase
				//
				// Again ONLY when deso is the quote currency do we need to do this extra step.
				if IsDesoPkid(req.QuoteCurrencyPublicKeyBase58Check) {
					bigLimitAmount = big.NewInt(0).Div(bigLimitAmount, big.NewInt(int64(lib.NanosPerUnit)))
				}
				uint256LimitAmount, overflow := uint256.FromBig(bigLimitAmount)
				if overflow {
					return nil, fmt.Errorf("HandleMarketOrder: Overflow calculating limit amount")
				}
				// Subtract the fees from the total quantity
				totalQuantityQuoteCurrencyAfterFeesBaseUnits, err := lib.SafeUint256().Sub(
					uint256LimitAmount, totalFeeBaseUnits)
				if err != nil {
					return nil, fmt.Errorf("HandleMarketOrder: Problem calculating remaining quote currency 1: %v", err)
				}
				remainingQuoteQuantityDecimal, err = CalculateStringDecimalAmountFromBaseUnitsSimple(
					req.QuoteCurrencyPublicKeyBase58Check, totalQuantityQuoteCurrencyAfterFeesBaseUnits)
				if err != nil {
					return nil, fmt.Errorf("HandleMarketOrder: Problem calculating remaining quote currency 2: %v", err)
				}
			} else {
				// If there's no price quote then use the simulated amount, minus fees
				quotCurrencyExecutedAfterFeesBaseUnits, err := lib.SafeUint256().Sub(
					quoteCurrencyExecutedBeforeFeesBaseUnits, totalFeeBaseUnits)
				if err != nil {
					return nil, fmt.Errorf("HandleMarketOrder: Problem calculating remaining quote currency 3: %v", err)
				}
				remainingQuoteQuantityDecimal, err = CalculateStringDecimalAmountFromBaseUnitsSimple(
					req.QuoteCurrencyPublicKeyBase58Check, quotCurrencyExecutedAfterFeesBaseUnits)
				if err != nil {
					return nil, fmt.Errorf("HandleMarketOrder: Problem calculating remaining quote currency 4: %v", err)
				}
			}
		} else {
			// Just to be safe, catch an error here
			return nil, fmt.Errorf("HandleMarketOrder: Invalid quantity currency type %v",
				req.QuantityCurrencyType)
		}
		if remainingQuoteQuantityDecimal == "" {
			return nil, fmt.Errorf("HandleMarketOrder: Problem calculating remaining quote currency 5")
		}

		// Now we need to execute the order with the remaining quote currency.
		// To make this simple and exact, we can do this as an ask where we are
		// selling the quote currency for base currency. This allows us to specify
		// the amount of quote currency as the quantity. To make this work we must
		// also set the price to the inverse of the quote price because ask orders
		// specify their price in (buying coin per selling coin), which in this case
		// is (base / quote), or the inversion of priceQuoteStr. Again consensus is
		// confusing sorry about that...
		priceStrQuoteInverted, err := InvertPriceStr(priceStrQuote)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem inverting price: %v", err)
		}
		newDaoCoinMarketOrderRequest := &DAOCoinLimitOrderCreationRequest{
			TransactorPublicKeyBase58Check:            req.TransactorPublicKeyBase58Check,
			BuyingDAOCoinCreatorPublicKeyBase58Check:  req.BaseCurrencyPublicKeyBase58Check,
			SellingDAOCoinCreatorPublicKeyBase58Check: req.QuoteCurrencyPublicKeyBase58Check,
			Quantity:             remainingQuoteQuantityDecimal,
			OperationType:        DAOCoinLimitOrderOperationTypeStringASK,
			Price:                priceStrQuoteInverted,
			FillType:             req.FillType,
			MinFeeRateNanosPerKB: req.MinFeeRateNanosPerKB,
			TransactionFees:      req.TransactionFees,
		}
		newOrderRes, err := fes.CreateMarketOrLimitOrder(
			isMarketOrder, newDaoCoinMarketOrderRequest)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem creating market order: %v", err)
		}
		// Parse the limit order txn from the response
		bb, err := hex.DecodeString(newOrderRes.TransactionHex)
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

		allTxns := append(transferTxns, newOrderRes.Transaction)
		if tokenWhitelistTxn != nil && !skipWhitelist {
			allTxns = append(allTxns, tokenWhitelistTxn)
		}

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

		// This is tricky. The execution amount is the amount that was simulated from the order PLUS
		// the amount we deducted in fees prior to executing the order.
		//
		// We know the quote currency executed amount is the selling coin quantity filled because it's
		// how we set up the order request.
		quoteCurrencyExecutedAfterFeesStr := newOrderRes.SimulatedExecutionResult.SellingCoinQuantityFilled
		quoteCurrencyExecutedAfterFeesBaseUnits, err := CalculateBaseUnitsFromStringDecimalAmountSimple(
			req.QuoteCurrencyPublicKeyBase58Check, quoteCurrencyExecutedAfterFeesStr)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem calculating quote currency total 1: %v", err)
		}
		quoteCurrencyExecutedPlusFeesBaseUnits, err := lib.SafeUint256().Add(
			quoteCurrencyExecutedAfterFeesBaseUnits, totalFeeBaseUnits)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem calculating quote currency total 2: %v", err)
		}
		executionAmount, err := CalculateStringDecimalAmountFromBaseUnitsSimple(
			req.QuoteCurrencyPublicKeyBase58Check, quoteCurrencyExecutedPlusFeesBaseUnits)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem calculating quote currency spent: %v", err)
		}
		executionAmountCurrencyType := CurrencyTypeQuote
		// The receive amount is the buying coin quantity filled because that's how we set up the order.
		executionReceiveAmount := newOrderRes.SimulatedExecutionResult.BuyingCoinQuantityFilled
		executionReceiveAmountCurrencyType := CurrencyTypeBase
		executionReceiveAmountBaseUnits, err := CalculateBaseUnitsFromStringDecimalAmountSimple(
			req.BaseCurrencyPublicKeyBase58Check, executionReceiveAmount)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem calculating base currency received: %v", err)
		}

		// The price per token the user is getting, expressed as a decimal float
		// - quoteAmountSpentTotal / baseAmountReceived
		// - = (quoteAmountSpentTotal * BaseUnitsPerCoin / baseAmountReceived) / BaseUnitsPerCoin
		executionPriceInQuoteCurrency := ""
		if !executionReceiveAmountBaseUnits.IsZero() {
			priceQuotePerBase := big.NewInt(0).Mul(
				quoteCurrencyExecutedPlusFeesBaseUnits.ToBig(), lib.BaseUnitsPerCoin.ToBig())
			priceQuotePerBase = big.NewInt(0).Div(
				priceQuotePerBase, executionReceiveAmountBaseUnits.ToBig())
			uint256PriceQuotePerBase, overflow := uint256.FromBig(priceQuotePerBase)
			if overflow {
				return nil, fmt.Errorf("HandleMarketOrder: Overflow calculating price: %v", err)
			}
			executionPriceInQuoteCurrency, err = CalculateStringDecimalAmountFromBaseUnitsSimple(
				req.QuoteCurrencyPublicKeyBase58Check, uint256PriceQuotePerBase)
			if err != nil {
				return nil, fmt.Errorf("HandleMarketOrder: Problem calculating price: %v", err)
			}
		}

		// Compute the percentage of the amount spent that went to fees
		// - totalFeeBaseUnits / quoteAmountSpentTotalBaseUnits
		// - = (totalFeeBaseUnits * BaseUnitsPerCoin / quoteAmountSpentTotalBaseUnits) / BaseUnitsPerCoin
		executionFeePercentage := ""
		if !quoteCurrencyExecutedPlusFeesBaseUnits.IsZero() {
			percentageSpentOnFees := big.NewInt(0).Mul(
				totalFeeBaseUnits.ToBig(), lib.BaseUnitsPerCoin.ToBig())
			percentageSpentOnFees = big.NewInt(0).Div(
				percentageSpentOnFees, quoteCurrencyExecutedPlusFeesBaseUnits.ToBig())
			executionFeePercentage = lib.FormatScaledUint256AsDecimalString(
				percentageSpentOnFees, lib.BaseUnitsPerCoin.ToBig())
		}

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

			QuoteCurrencyPriceInUsd: fmt.Sprintf("%0.9f", quoteCurrencyUsdValue),

			// For a market order, the amount will generally match the amount requested. However, for
			// a limit order, the amount may be less than the amount requested if the order was only
			// partially filled.
			ExecutionAmount:                    executionAmount,
			ExecutionAmountCurrencyType:        executionAmountCurrencyType,
			ExecutionAmountUsd:                 convertToUsd(executionAmount),
			ExecutionReceiveAmount:             executionReceiveAmount,
			ExecutionReceiveAmountCurrencyType: executionReceiveAmountCurrencyType,
			ExecutionReceiveAmountUsd:          "", // dont convert base currency to usd
			ExecutionPriceInQuoteCurrency:      executionPriceInQuoteCurrency,
			ExecutionPriceInUsd:                convertToUsd(executionPriceInQuoteCurrency),
			ExecutionFeePercentage:             executionFeePercentage,
			ExecutionFeeAmountInQuoteCurrency:  executionFeeAmountInQuoteCurrency,
			ExecutionFeeAmountInUsd:            convertToUsd(executionFeeAmountInQuoteCurrency),

			MarketTotalTradingFeeBasisPoints:           marketTakerFeeBaseUnitsStr,
			MarketTradingFeeBasisPointsByUserPublicKey: feeMapByPubkey,
		}

		if !isMarketOrder {
			// The quantityStr is in quote currency or base units. If it's in base units then
			// we need to do a conversion into quote currency.
			limitAmount := quantityStr
			if req.QuantityCurrencyType == CurrencyTypeBase {
				// In this case the quantityStr needs to be converted from base to quote currency:
				// - scaledPrice := priceQuotePerBase * 1e38
				// - quantityBaseUnits * scaledPriceQuotePerBase / 1e38
				//
				// This multiplies the scaled price by 1e38 then we have to reverse it later
				scaledPrice, err := lib.CalculateScaledExchangeRateFromString(priceStrQuote)
				if err != nil {
					return nil, fmt.Errorf("HandleMarketOrder: Problem calculating scaled price: %v", err)
				}
				quantityBaseUnits, err := CalculateBaseUnitsFromStringDecimalAmountSimple(
					req.BaseCurrencyPublicKeyBase58Check, quantityStr)
				if err != nil {
					return nil, fmt.Errorf("HandleMarketOrder: Problem calculating base units: %v", err)
				}
				bigLimitAmount := big.NewInt(0).Mul(quantityBaseUnits.ToBig(), scaledPrice.ToBig())
				bigLimitAmount = big.NewInt(0).Div(bigLimitAmount, lib.OneE38.ToBig())

				// The reason why this extra step is needed is extremely subtle. It's required because
				// scaledPrice represents (whole coin / whole coin) rather than (base unit / base unit).
				// When the coins have the same number of base units per whole coin, this conversion isn't
				// needed because we have:
				// - (whole coin / whole coin) = ((1e18 base units) / (1e18 base units)) = (base unit / base unit)
				//
				// However, in the case where DESO is one of the pairs, the (whole coin / whole coin) exchange
				// rate is NOT the same as the (base unit / base unit) rate because DESO has a different number
				// of base units per whole coin. So we have:
				// - (deso nanos / daocoin base units)
				// = (1e9 deso whole coin) / (1e18 daocoin whole coin)
				// = (1/1e9) * (deso whole coin / daocoin whole coin)
				// = (1/1e9) * scaledPrice
				//
				// And so we need to modify the previous formula to be:
				// - quantityBaseUnits * (deso nanos / daocoin base units)
				// = quantityBaseUnits * (1 / 1e9) * scaledPrice
				// = 1/1e9 * quantityBaseUnits * scaledPrice
				//
				// Again ONLY when deso is the quote currency do we need to do this extra step.
				if IsDesoPkid(req.QuoteCurrencyPublicKeyBase58Check) {
					bigLimitAmount = big.NewInt(0).Div(bigLimitAmount, big.NewInt(int64(lib.NanosPerUnit)))
				}
				uint256LimitAmount, overflow := uint256.FromBig(bigLimitAmount)
				if overflow {
					return nil, fmt.Errorf("HandleMarketOrder: Overflow calculating limit amount")
				}

				limitAmount, err = CalculateStringDecimalAmountFromBaseUnitsSimple(
					req.QuoteCurrencyPublicKeyBase58Check, uint256LimitAmount)
				if err != nil {
					return nil, fmt.Errorf("HandleMarketOrder: Problem calculating limit amount: %v", err)
				}
			}

			// The limit receive amount is computed as follows:
			// - limitAmountQuote / priceQuotePerBase
			// - = limitAmountQuote * 1e38 / (priceQuotePerBase * 1e38)
			limitReceiveAmountBaseUnits, err := CalculateBaseUnitsFromStringDecimalAmountSimple(
				req.QuoteCurrencyPublicKeyBase58Check, limitAmount)
			if err != nil {
				return nil, fmt.Errorf("HandleMarketOrder: Problem calculating limit receive amount: %v", err)
			}
			bigLimitReceiveAmount := big.NewInt(0).Mul(limitReceiveAmountBaseUnits.ToBig(), lib.OneE38.ToBig())
			// This multiplies the scaled price by 1e38 then we have to reverse it later
			scaledPrice, err := lib.CalculateScaledExchangeRateFromString(priceStrQuote)
			if err != nil {
				return nil, fmt.Errorf("HandleMarketOrder: Problem calculating scaled price: %v", err)
			}
			limitReceiveAmount := ""
			if !scaledPrice.IsZero() {
				bigLimitReceiveAmount = big.NewInt(0).Div(bigLimitReceiveAmount, scaledPrice.ToBig())
				// See above comment on why we need to adjust the scaledPrice when deso is the quote currency
				// - (deso nanos / daocoin base units)
				// = (1e9 deso whole coin) / (1e18 daocoin whole coin)
				// = (1/1e9) * (deso whole coin / daocoin whole coin)
				// = (1/1e9) * scaledPrice
				//
				// - limitAmountQuote / ((deso nanos / daocoin base units))
				// = limitAmountQuote / ((1/1e9) * scaledPrice)
				// = (1e9) * limitAmountQuote / scaledPrice
				if IsDesoPkid(req.QuoteCurrencyPublicKeyBase58Check) {
					bigLimitReceiveAmount = big.NewInt(0).Mul(bigLimitReceiveAmount, big.NewInt(int64(lib.NanosPerUnit)))
				}
				uint256LimitReceiveAmount, overflow := uint256.FromBig(bigLimitReceiveAmount)
				if overflow {
					return nil, fmt.Errorf("HandleMarketOrder: Overflow calculating limit receive amount")
				}
				limitReceiveAmount, err = CalculateStringDecimalAmountFromBaseUnitsSimple(
					req.BaseCurrencyPublicKeyBase58Check, uint256LimitReceiveAmount)
				if err != nil {
					return nil, fmt.Errorf("HandleMarketOrder: Problem calculating limit receive amount: %v", err)
				}
			}

			// Set all the values we calculated
			res.LimitAmount = limitAmount
			res.LimitAmountCurrencyType = CurrencyTypeQuote
			res.LimitAmountInUsd = convertToUsd(limitAmount)
			res.LimitReceiveAmount = limitReceiveAmount
			res.LimitReceiveAmountCurrencyType = CurrencyTypeBase
			res.LimitReceiveAmountInUsd = "" // dont convert base currency to usd
			res.LimitPriceInQuoteCurrency = priceStrQuote
			res.LimitPriceInUsd = convertToUsd(priceStrQuote)
		}

		innerTransactionHexes, err := GetInnerTransactionHexesFromAtomicTxn(res.Transaction)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem getting inner transaction hexes: %v", err)
		}
		res.InnerTransactionHexes = innerTransactionHexes

		return res, nil
	} else {
		// We already have the txn that executes the order from previously
		// Connect it to our UtxoView for validation
		bb, err := hex.DecodeString(orderRes.TransactionHex)
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
		for pubkey, feeBaseUnits := range feeBaseUnitsByPubkey {
			if feeBaseUnits.IsZero() {
				continue
			}
			receiverPubkeyBytes, _, err := lib.Base58CheckDecode(pubkey)
			if err != nil || len(receiverPubkeyBytes) != btcec.PubKeyBytesLenCompressed {
				return nil, fmt.Errorf("HandleMarketOrder: Problem decoding public key %s: %v",
					pubkey, err)
			}
			// Try and create the TransferDaoCoin transaction for the user.
			//
			// TODO: Add ExtraData to the transaction to make it easier to report it as an
			// earning to the user who's receiving the fee.
			txn, err := fes.SendCoins(
				req.QuoteCurrencyPublicKeyBase58Check,
				transactorPubkeyBytes,
				receiverPubkeyBytes,
				feeBaseUnits,
				req.MinFeeRateNanosPerKB,
				nil)
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
		if tokenWhitelistTxn != nil && !skipWhitelist {
			allTxns = append(allTxns, tokenWhitelistTxn)
		}

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
			quoteCurrencyExecutedBeforeFeesBaseUnits, totalFeeBaseUnits)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem calculating quote currency received: %v", err)
		}
		quoteAmountReceivedStr, err := CalculateStringDecimalAmountFromBaseUnitsSimple(
			req.QuoteCurrencyPublicKeyBase58Check, quoteAmountReceivedBaseUnits)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem calculating quote currency received: %v", err)
		}
		baseAmountSpentStr := orderRes.SimulatedExecutionResult.SellingCoinQuantityFilled
		if daoCoinMarketOrderRequest.SellingDAOCoinCreatorPublicKeyBase58Check == req.QuoteCurrencyPublicKeyBase58Check {
			baseAmountSpentStr = orderRes.SimulatedExecutionResult.BuyingCoinQuantityFilled
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
			uint256PriceQuotePerBase, overflow := uint256.FromBig(priceQuotePerBase)
			if overflow {
				return nil, fmt.Errorf("HandleMarketOrder: Overflow calculating price: %v", err)
			}
			finalPriceStr, err = CalculateStringDecimalAmountFromBaseUnitsSimple(
				req.QuoteCurrencyPublicKeyBase58Check, uint256PriceQuotePerBase)
			if err != nil {
				return nil, fmt.Errorf("HandleMarketOrder: Problem calculating price: %v", err)
			}
		}

		// Compute the percentage of the amount spent that went to fees
		// - totalFeeBaseUnits / quoteAmountTotalBaseUnits
		// - = (totalFeeBaseUnits * BaseUnitsPerCoin / quoteAmountTotalBaseUnits) / BaseUnitsPerCoin
		percentageSpentOnFeesStr := "0.0"
		if !quoteCurrencyExecutedBeforeFeesBaseUnits.IsZero() {
			percentageSpentOnFees := big.NewInt(0).Mul(
				totalFeeBaseUnits.ToBig(), lib.BaseUnitsPerCoin.ToBig())
			percentageSpentOnFees = big.NewInt(0).Div(
				percentageSpentOnFees, quoteCurrencyExecutedBeforeFeesBaseUnits.ToBig())
			percentageSpentOnFeesStr = lib.FormatScaledUint256AsDecimalString(
				percentageSpentOnFees, lib.BaseUnitsPerCoin.ToBig())
		}

		tradingFeesInQuoteCurrencyByPubkey := make(map[string]string)
		for pubkey, feeBaseUnits := range feeBaseUnitsByPubkey {
			feeStr, err := CalculateStringDecimalAmountFromBaseUnitsSimple(
				req.QuoteCurrencyPublicKeyBase58Check, feeBaseUnits)
			if err != nil {
				return nil, fmt.Errorf("HandleMarketOrder: Problem calculating fee: %v", err)
			}
			tradingFeesInQuoteCurrencyByPubkey[pubkey] = feeStr
		}

		res := &DAOCoinLimitOrderWithFeeResponse{
			FeeNanos:       totalDesoFeeNanos,
			TransactionHex: atomicTxnHex,
			TxnHashHex:     atomicTxn.Hash().String(),
			Transaction:    atomicTxn,

			QuoteCurrencyPriceInUsd: fmt.Sprintf("%0.9f", quoteCurrencyUsdValue),

			ExecutionAmount:                    baseAmountSpentStr,
			ExecutionAmountCurrencyType:        CurrencyTypeBase,
			ExecutionAmountUsd:                 "", // dont convert base currency to usd
			ExecutionReceiveAmount:             quoteAmountReceivedStr,
			ExecutionReceiveAmountCurrencyType: CurrencyTypeQuote,
			ExecutionReceiveAmountUsd:          convertToUsd(quoteAmountReceivedStr),
			ExecutionPriceInQuoteCurrency:      finalPriceStr,
			ExecutionPriceInUsd:                convertToUsd(finalPriceStr),
			ExecutionFeePercentage:             percentageSpentOnFeesStr,
			ExecutionFeeAmountInQuoteCurrency:  totalFeeStr,
			ExecutionFeeAmountInUsd:            convertToUsd(totalFeeStr),

			MarketTotalTradingFeeBasisPoints: marketTakerFeeBaseUnitsStr,
			// Trading fees are paid to users based on metadata in the profile. This map states the trading
			// fee split for each user who's been allocated trading fees in the profile.
			MarketTradingFeeBasisPointsByUserPublicKey: feeMapByPubkey,
		}

		if !isMarketOrder {
			// The quantityStr is in quote currency or base units. If it's in quote currency
			// then we need to do a conversion to base units.
			limitAmount := quantityStr
			if req.QuantityCurrencyType == CurrencyTypeQuote ||
				req.QuantityCurrencyType == CurrencyTypeUsd {
				// Price is in (base coin amount / quote coin amount), and in this case we need to
				// convert base units of the quote currency to base units of the base currency:
				// - quoteAmount / priceQuotePerBase
				// = quoteAmountBaseUnits / (priceQuotePerBase * 1e38) * 1e38
				quantityBaseUnits, err := CalculateBaseUnitsFromStringDecimalAmountSimple(
					req.QuoteCurrencyPublicKeyBase58Check, quantityStr)
				if err != nil {
					return nil, fmt.Errorf("HandleMarketOrder: Problem calculating base units: %v", err)
				}
				// This multiplies the scaled price by 1e38 then we have to reverse it later
				scaledPrice, err := lib.CalculateScaledExchangeRateFromString(priceStrQuote)
				if err != nil {
					return nil, fmt.Errorf("HandleMarketOrder: Problem calculating scaled price: %v", err)
				}
				limitAmount = ""
				if !scaledPrice.IsZero() {
					bigLimitAmount := big.NewInt(0).Mul(quantityBaseUnits.ToBig(), lib.OneE38.ToBig())
					bigLimitAmount = big.NewInt(0).Div(bigLimitAmount, scaledPrice.ToBig())
					// The reason why this extra step is needed is extremely subtle. It's required because
					// scaledPrice represents (whole coin / whole coin) rather than (base unit / base unit).
					// When the coins have the same number of base units per whole coin, this conversion isn't
					// needed because we have:
					// - (whole coin / whole coin) = ((1e18 base units) / (1e18 base units)) = (base unit / base unit)
					//
					// However, in the case where DESO is one of the pairs, the (whole coin / whole coin) exchange
					// rate is NOT the same as the (base unit / base unit) rate because DESO has a different number
					// of base units per whole coin. So we have:
					// - (deso nanos) / (daocoin base units)
					// = (1e9 deso whole coin) / (1e18 daocoin whole coin)
					// = (1/1e9) * (deso whole coin / daocoin whole coin)
					// = (1/1e9) * scaledPriceQuotePerBase
					//
					// And so we need to modify the previous formula to be:
					// - quoteAmount / ((1/1e9) * scaledPriceQuotePerBase)
					// - 1e9 * quoteAmount / scaledPriceBasePerQuote
					if IsDesoPkid(req.QuoteCurrencyPublicKeyBase58Check) {
						bigLimitAmount = big.NewInt(0).Mul(bigLimitAmount, big.NewInt(int64(lib.NanosPerUnit)))
					}
					uint256LimitAmount, overflow := uint256.FromBig(bigLimitAmount)
					if overflow {
						return nil, fmt.Errorf("HandleMarketOrder: Overflow calculating limit amount")
					}
					limitAmount, err = CalculateStringDecimalAmountFromBaseUnitsSimple(
						req.BaseCurrencyPublicKeyBase58Check, uint256LimitAmount)
					if err != nil {
						return nil, fmt.Errorf("HandleMarketOrder: Problem calculating limit amount: %v", err)
					}
				}
			}

			// The limit receive amount is computed as follows:
			// - limitAmountBaseUnits * priceQuotePerBase
			// - = limitAmountBaseUnits * (priceQuotePerBase * 1e38) / 1e38
			limitReceiveAmountBaseUnits, err := CalculateBaseUnitsFromStringDecimalAmountSimple(
				req.BaseCurrencyPublicKeyBase58Check, limitAmount)
			if err != nil {
				return nil, fmt.Errorf("HandleMarketOrder: Problem calculating limit receive amount: %v", err)
			}
			// This multiplies the scaled price by 1e38 then we have to reverse it later
			scaledPrice, err := lib.CalculateScaledExchangeRateFromString(priceStrQuote)
			if err != nil {
				return nil, fmt.Errorf("HandleMarketOrder: Problem calculating scaled price: %v", err)
			}
			bigLimitReceiveAmount := big.NewInt(0).Mul(limitReceiveAmountBaseUnits.ToBig(), scaledPrice.ToBig())
			bigLimitReceiveAmount = big.NewInt(0).Div(bigLimitReceiveAmount, lib.OneE38.ToBig())
			// The reason why this extra step is needed is extremely subtle. It's required because
			// scaledPrice represents (whole coin / whole coin) rather than (base unit / base unit).
			// When the coins have the same number of base units per whole coin, this conversion isn't
			// needed because we have:
			// - (whole coin / whole coin) = ((1e18 base units) / (1e18 base units)) = (base unit / base unit)
			//
			// However, in the case where DESO is one of the pairs, the (whole coin / whole coin) exchange
			// rate is NOT the same as the (base unit / base unit) rate because DESO has a different number
			// of base units per whole coin. So we have:
			// - (deso nanos) / (daocoin base units)
			// = (1e9 deso whole coin) / (1e18 daocoin whole coin)
			// = (1/1e9) * (deso whole coin / daocoin whole coin)
			// = (1/1e9) * scaledPriceQuotePerBase
			//
			// And so we need to modify the previous formula to be:
			// - limitAmountBaseUnits * (deso nanos / daocoin base units)
			// = limitAmountBaseUnits * (1 / 1e9) * scaledPriceQuotePerBase
			// = 1/1e9 * limitAmountBaseUnits * scaledPriceQuotePerBase
			if IsDesoPkid(req.QuoteCurrencyPublicKeyBase58Check) {
				bigLimitReceiveAmount = big.NewInt(0).Div(bigLimitReceiveAmount, big.NewInt(int64(lib.NanosPerUnit)))
			}
			uint256LimitReceiveAmount, overflow := uint256.FromBig(bigLimitReceiveAmount)
			if overflow {
				return nil, fmt.Errorf("HandleMarketOrder: Overflow calculating limit receive amount")
			}
			limitReceiveAmount, err := CalculateStringDecimalAmountFromBaseUnitsSimple(
				req.QuoteCurrencyPublicKeyBase58Check, uint256LimitReceiveAmount)
			if err != nil {
				return nil, fmt.Errorf("HandleMarketOrder: Problem calculating limit receive amount: %v", err)
			}

			// Set all the values we calculated
			res.LimitAmount = limitAmount
			res.LimitAmountCurrencyType = CurrencyTypeBase
			res.LimitAmountInUsd = "" // dont convert base to usd
			res.LimitReceiveAmount = limitReceiveAmount
			res.LimitReceiveAmountCurrencyType = CurrencyTypeQuote
			res.LimitReceiveAmountInUsd = convertToUsd(res.LimitReceiveAmount)
			res.LimitPriceInQuoteCurrency = priceStrQuote
			res.LimitPriceInUsd = convertToUsd(priceStrQuote)
		}

		innerTransactionHexes, err := GetInnerTransactionHexesFromAtomicTxn(res.Transaction)
		if err != nil {
			return nil, fmt.Errorf("HandleMarketOrder: Problem getting inner transaction hexes: %v", err)
		}
		res.InnerTransactionHexes = innerTransactionHexes

		return res, nil
	}
}

func (fes *APIServer) CreateDAOCoinLimitOrderWithFee(ww http.ResponseWriter, req *http.Request) {
	if fes.Config.AmmMetadataPublicKey == "" {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateDaoCoinMarketFees: AMM_METADATA_PUBLIC_KEY must be set "+
			"in the node's config for fees to work"))
		return
	}

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := DAOCoinLimitOrderWithFeeRequest{}

	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateDAOCoinLimitOrderWithFee: Problem parsing request body: %v", err))
		return
	}

	// Swap the deso key for lib.ZeroPkid
	if IsDesoPkid(requestData.BaseCurrencyPublicKeyBase58Check) {
		requestData.BaseCurrencyPublicKeyBase58Check = lib.PkToString(lib.ZeroPKID[:], fes.Params)
	}
	if IsDesoPkid(requestData.QuoteCurrencyPublicKeyBase58Check) {
		requestData.QuoteCurrencyPublicKeyBase58Check = lib.PkToString(lib.ZeroPKID[:], fes.Params)
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
	feeMapByPubkey, _, err := GetTradingFeesForMarket(
		utxoView,
		fes.Params,
		fes.Config.AmmMetadataPublicKey,
		requestData.BaseCurrencyPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDaoCoinMarketFees: Problem getting trading fees: %v", err))
		return
	}
	// Validate the fee map.
	if err := ValidateTradingFeeMap(feeMapByPubkey); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateDaoCoinMarketFees: %v", err))
		return
	}

	// If the trading user is in the fee map, remove them so that we don't end up
	// doing a self-send
	if _, exists := feeMapByPubkey[requestData.TransactorPublicKeyBase58Check]; exists {
		delete(feeMapByPubkey, requestData.TransactorPublicKeyBase58Check)
	}

	var res *DAOCoinLimitOrderWithFeeResponse
	res, err = fes.HandleMarketOrder(
		isMarketOrder, &requestData, isBuyOrder, feeMapByPubkey, requestData.SkipWhitelist)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateDAOCoinLimitOrderWithFee: %v", err))
		return
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateDAOCoinLimitOrderWithFee: Problem encoding response as JSON: %v", err))
		return
	}
}
