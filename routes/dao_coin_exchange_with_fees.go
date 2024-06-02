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
	mempool lib.Mempool,
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

	utxoView, err := lib.GetAugmentedUniversalViewWithAdditionalTransactions(
		mempool,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("GetTradingFeesForMarket: Error fetching mempool view: %v", err)
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
	for pkid, feeBasisPoints := range tradingFeesMapPubkey {
		// Convert the pkid to a base58 string
		pkidBase58 := lib.PkToString(pkid[:], params)
		feeMap[pkidBase58] = feeBasisPoints
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

	feeMap, err := GetTradingFeesForMarket(
		fes.backendServer.GetMempool(),
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

type DAOCoinLimitOrderWithFeeResponse struct {
	SpendAmountNanos  uint64
	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgDeSoTxn
	TransactionHex    string
	TxnHashHex        string

	// Fees are always charged in the quote currency. Eg if the market is openfund/deso then deso
	// is the quote currency. Similarly if the market is openfund/dusdc, then dusdc is the quote
	// currency. This is a standard concept in markets. We pull out the quote currency for convenience
	// here so it can be shown in the frontend.
	QuoteCurrencyPkid string
	// Trading fees are paid to users based on metadata in the profile. This map states the trading
	// fee split for each user who's been allocated trading fees in the profile.
	TradingFeeBaseUnitsByUserPkid map[string]string
	// This is the total trading fee in the quote currency that will be paid out to users based on
	// the trading fee split in the profile. The values are full precision floats that are in the
	// quote currency, not base units. Eg 5.0 deso or 1000.374 openfund.
	TradingFeesInQuoteCurrencyByPkid map[string]string
	// The total trading fee in quote currency that the user will pay for this order. Can be shown
	// directly in the UI. It is a full precision float, not base units.
	TotalTradingFeeInQuoteCurrency string
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

func (fes *APIServer) CreateDAOCoinLimitOrderWithFee(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := DAOCoinLimitOrderCreationRequest{}

	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateDAOCoinLimitOrderWithFee: Problem parsing request body: %v", err))
		return
	}

	// Get the quote and base pkids from the buying and selling pkids. This is less confusing
	// to deal with.
	quotePkid, basePkid, err := GetQuoteBasePkidFromBuyingSellingPkids(
		requestData.BuyingDAOCoinCreatorPublicKeyBase58Check,
		requestData.SellingDAOCoinCreatorPublicKeyBase58Check,
		string(requestData.OperationType))
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateDAOCoinLimitOrderWithFee: %v", err))
		return
	}

	// Get the trading fees for the market. This is the trading fee split for each user
	// Only the base currency can have fees on it. The quote currency cannot.
	feeMap, err := GetTradingFeesForMarket(
		fes.backendServer.GetMempool(),
		fes.Params,
		basePkid)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDaoCoinMarketFees: Problem getting trading fees: %v", err))
		return
	}
	// Validate the fee map.
	if err := ValidateTradingFeeMap(feeMap); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateDaoCoinMarketFees: %v", err))
		return
	}

	limitOrderRes, err := fes.createDaoCoinLimitOrderHelper(&requestData, fes.backendServer.GetMempool())
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateDAOCoinLimitOrderWithFee: %v", err))
		return
	}

	// Now we know how much of the buying and selling currency are going to be transacted. This
	// allows us to compute a fee to charge the transactor.
	quoteCurrencyTotalStr := limitOrderRes.SimulatedExecutionResult.BuyingCoinQuantityFilled
	if requestData.SellingDAOCoinCreatorPublicKeyBase58Check == quotePkid {
		quoteCurrencyTotalStr = limitOrderRes.SimulatedExecutionResult.SellingCoinQuantityFilled
	}
	quoteCurrencyTotalBaseUnits, err := CalculateQuantityToFillAsBaseUnits(
		requestData.BuyingDAOCoinCreatorPublicKeyBase58Check,
		requestData.SellingDAOCoinCreatorPublicKeyBase58Check,
		requestData.OperationType,
		quoteCurrencyTotalStr)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateDAOCoinLimitOrderWithFee: Problem calculating quote currency total: %v", err))
		return
	}

	// Compute how much in quote currency we need to pay each constituent
	feeBaseUnitsByPkid := make(map[string]*uint256.Int)
	totalFeeBaseUnits := uint256.NewInt(0)
	for pkid, feeBasisPoints := range feeMap {
		feeBaseUnits, err := lib.SafeUint256().Mul(quoteCurrencyTotalBaseUnits, uint256.NewInt(feeBasisPoints))
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("CreateDAOCoinLimitOrderWithFee: Problem calculating fee: %v", err))
			return
		}
		feeBaseUnits, err = lib.SafeUint256().Div(feeBaseUnits, uint256.NewInt(10000))
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("CreateDAOCoinLimitOrderWithFee: Problem calculating fee: %v", err))
			return
		}
		feeBaseUnitsByPkid[pkid] = feeBaseUnits
		totalFeeBaseUnits, err = lib.SafeUint256().Add(totalFeeBaseUnits, feeBaseUnits)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("CreateDAOCoinLimitOrderWithFee: Problem calculating fee: %v", err))
			return
		}
	}

	// Validate that the totalFeeBaseUnits is less than or equal to the quote currency total
	if totalFeeBaseUnits.Cmp(quoteCurrencyTotalBaseUnits) > 0 {
		_AddBadRequestError(ww, fmt.Sprintf("CreateDAOCoinLimitOrderWithFee: Total fee exceeds total quote currency: %v", err))
		return
	}

	// Compute the remaining amount we can spend in quote currency after paying fees
	remainingQuoteCurrencyBaseUnits, err := lib.SafeUint256().Sub(quoteCurrencyTotalBaseUnits, totalFeeBaseUnits)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"CreateDAOCoinLimitOrderWithFee: Problem calculating remaining quote currency: %v", err))
		return
	}

	// Now we have two possibilities.
	//
	// 1. Bid order
	// If this is a bid, then the user is buying the base
	// currency with the quote currency. In this case we can simply deduct the quote
	// currency from the user's balance prior to executing the order, and then execute
	// the order with remainingQuoteCurrencyBaseUnits.
	//
	// 2. Ask order
	// If this is an ask order, then the user is selling the base currency and receiving
	// the quote currency. In this case, we need to execute the order first and then
	// deduct the quote currency fee from the user's balance after the order has been
	// executed.
	if string(requestData.OperationType) == lib.DAOCoinLimitOrderOperationTypeBID.String() {

		sldkfjdksj
	} else if string(requestData.OperationType) == lib.DAOCoinLimitOrderOperationTypeASK.String() {

	} else {
		_AddBadRequestError(ww, fmt.Sprintf("CreateDAOCoinLimitOrderWithFee: Invalid "+
			"operation type: %v", requestData.OperationType))
		return
	}

	_, _, _ = quotePkid, basePkid, limitOrderRes
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("CreateDAOCoinLimitOrderWithFee: Problem encoding response as JSON: %v", err))
		return
	}
}
