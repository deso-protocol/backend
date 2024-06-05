package routes

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/deso-protocol/core/collections"
	"github.com/deso-protocol/core/lib"
	"github.com/gorilla/mux"
	"github.com/holiman/uint256"
	"io"
	"net/http"
	"reflect"
	"time"
)

type CumulativeLockedBalanceEntryResponse struct {
	HODLerPublicKeyBase58Check   string
	ProfilePublicKeyBase58Check  string
	TotalLockedBaseUnits         uint256.Int
	UnlockableBaseUnits          uint256.Int
	UnvestedLockedBalanceEntries []*LockedBalanceEntryResponse
	VestedLockedBalanceEntries   []*LockedBalanceEntryResponse
	ProfileEntryResponse         *ProfileEntryResponse
}

type LockedBalanceEntryResponse struct {
	HODLerPublicKeyBase58Check  string
	ProfilePublicKeyBase58Check string
	UnlockTimestampNanoSecs     int64
	VestingEndTimestampNanoSecs int64
	BalanceBaseUnits            uint256.Int
}

func (fes *APIServer) _lockedBalanceEntryToResponse(
	lockedBalanceEntry *lib.LockedBalanceEntry, utxoView *lib.UtxoView, params *lib.DeSoParams,
) *LockedBalanceEntryResponse {
	hodlerPublicKey := utxoView.GetPublicKeyForPKID(lockedBalanceEntry.HODLerPKID)
	profilePublicKey := utxoView.GetPublicKeyForPKID(lockedBalanceEntry.ProfilePKID)
	return &LockedBalanceEntryResponse{
		HODLerPublicKeyBase58Check:  lib.PkToString(hodlerPublicKey, params),
		ProfilePublicKeyBase58Check: lib.PkToString(profilePublicKey, params),
		UnlockTimestampNanoSecs:     lockedBalanceEntry.UnlockTimestampNanoSecs,
		VestingEndTimestampNanoSecs: lockedBalanceEntry.VestingEndTimestampNanoSecs,
		BalanceBaseUnits:            lockedBalanceEntry.BalanceBaseUnits,
	}
}

type LockupYieldCurvePointResponse struct {
	ProfilePublicKeyBase58Check string
	LockupDurationNanoSecs      int64
	LockupYieldAPYBasisPoints   uint64
	ProfileEntryResponse        *ProfileEntryResponse
}

func (fes *APIServer) _lockupYieldCurvePointToResponse(
	lockupYieldCurvePoint *lib.LockupYieldCurvePoint, utxoView *lib.UtxoView, params *lib.DeSoParams,
) *LockupYieldCurvePointResponse {
	profilePublicKey := utxoView.GetPublicKeyForPKID(lockupYieldCurvePoint.ProfilePKID)
	profileEntry := utxoView.GetProfileEntryForPKID(lockupYieldCurvePoint.ProfilePKID)
	profileEntryResponse := fes._profileEntryToResponse(profileEntry, utxoView)
	return &LockupYieldCurvePointResponse{
		ProfilePublicKeyBase58Check: lib.PkToString(profilePublicKey, params),
		LockupDurationNanoSecs:      lockupYieldCurvePoint.LockupDurationNanoSecs,
		LockupYieldAPYBasisPoints:   lockupYieldCurvePoint.LockupYieldAPYBasisPoints,
		ProfileEntryResponse:        profileEntryResponse,
	}
}

type CoinLockupRequest struct {
	TransactorPublicKeyBase58Check string            `safeForLogging:"true"`
	ProfilePublicKeyBase58Check    string            `safeForLogging:"true"`
	RecipientPublicKeyBase58Check  string            `safeForLogging:"true"`
	UnlockTimestampNanoSecs        int64             `safeForLogging:"true"`
	VestingEndTimestampNanoSecs    int64             `safeForLogging:"true"`
	LockupAmountBaseUnits          *uint256.Int      `safeForLogging:"true"`
	ExtraData                      map[string]string `safeForLogging:"true"`
	MinFeeRateNanosPerKB           uint64            `safeForLogging:"true"`
	TransactionFees                []TransactionFee  `safeForLogging:"true"`
}

type UpdateCoinLockupParamsRequest struct {
	TransactorPublicKeyBase58Check  string                          `safeForLogging:"true"`
	LockupYieldDurationNanoSecs     int64                           `safeForLogging:"true"`
	LockupYieldAPYBasisPoints       uint64                          `safeForLogging:"true"`
	RemoveYieldCurvePoint           bool                            `safeForLogging:"true"`
	NewLockupTransferRestrictions   bool                            `safeForLogging:"true"`
	LockupTransferRestrictionStatus TransferRestrictionStatusString `safeForLogging:"true"`
	ExtraData                       map[string]string               `safeForLogging:"true"`
	MinFeeRateNanosPerKB            uint64                          `safeForLogging:"true"`
	TransactionFees                 []TransactionFee                `safeForLogging:"true"`
}

type CoinLockupTransferRequest struct {
	TransactorPublicKeyBase58Check string            `safeForLogging:"true"`
	ProfilePublicKeyBase58Check    string            `safeForLogging:"true"`
	RecipientPublicKeyBase58Check  string            `safeForLogging:"true"`
	UnlockTimestampNanoSecs        int64             `safeForLogging:"true"`
	LockedCoinsToTransferBaseUnits *uint256.Int      `safeForLogging:"true"`
	ExtraData                      map[string]string `safeForLogging:"true"`
	MinFeeRateNanosPerKB           uint64            `safeForLogging:"true"`
	TransactionFees                []TransactionFee  `safeForLogging:"true"`
}

type CoinUnlockRequest struct {
	TransactorPublicKeyBase58Check string            `safeForLogging:"true"`
	ProfilePublicKeyBase58Check    string            `safeForLogging:"true"`
	ExtraData                      map[string]string `safeForLogging:"true"`
	MinFeeRateNanosPerKB           uint64            `safeForLogging:"true"`
	TransactionFees                []TransactionFee  `safeForLogging:"true"`
}

type CoinLockResponse struct {
	SpendAmountNanos  uint64
	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgDeSoTxn
	TransactionHex    string
	TxnHashHex        string
}

func (fes *APIServer) CoinLockup(ww http.ResponseWriter, req *http.Request) {
	// Decode request body.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := CoinLockupRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CoinLockup: Problem parsing request body: %v", err))
		return
	}

	// Convert TransactorPublicKeyBase58Check to TransactorPublicKeyBytes
	if requestData.TransactorPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprint("CoinLockup: TransactorPublicKeyBase58Check is required"))
		return
	}
	transactorPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.TransactorPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CoinLockup: Problem decoding TransactorPublicKeyBase58Check %s: %v",
			requestData.TransactorPublicKeyBase58Check, err))
		return
	}

	// Convert ProfilePublicKeyBase58Check to ProfilePublicKeyBytes
	if requestData.ProfilePublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprint("CoinLockup: ProfilePublicKeyBase58Check is required"))
		return
	}
	profilePublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.ProfilePublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CoinLockup: Problem decoding ProfilePublicKeyBase58Check %s: %v",
			requestData.ProfilePublicKeyBase58Check, err))
		return

	}

	// Convert RecipientPublicKeyBase58Check to RecipientPublicKeyBytes if it exists
	var recipientPublicKeyBytes []byte
	if requestData.RecipientPublicKeyBase58Check != "" {
		recipientPublicKeyBytes, _, err = lib.Base58CheckDecode(requestData.RecipientPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("CoinLockup: Problem decoding RecipientPublicKeyBase58Check %s: %v",
				requestData.RecipientPublicKeyBase58Check, err))
			return
		}
	}

	// Sanity check that the lockup appears to occur in the future.
	currentTimestampNanoSecs := time.Now().UnixNano()
	if requestData.UnlockTimestampNanoSecs < currentTimestampNanoSecs {
		_AddBadRequestError(ww, fmt.Sprintf("CoinLockup: The unlock timestamp cannot be in the past "+
			"(unlock timestamp: %d, current timestamp: %d)\n",
			requestData.UnlockTimestampNanoSecs, currentTimestampNanoSecs))
		return
	}

	// Sanity check that the vested lockup does not go into the past.
	if requestData.UnlockTimestampNanoSecs > requestData.VestingEndTimestampNanoSecs {
		_AddBadRequestError(ww, fmt.Sprintf("CoinLockup: Vested lockups cannot vest into the past "+
			"(unlock timestamp: %d, vesting end timestamp: %d\n",
			requestData.UnlockTimestampNanoSecs, requestData.VestingEndTimestampNanoSecs))
		return
	}

	// Sanity check that the lockup request amount is non-zero.
	if requestData.LockupAmountBaseUnits.IsZero() {
		_AddBadRequestError(ww, fmt.Sprintf("CoinLockup: Cannot lockup an amount of zero\n"))
		return
	}

	// Encode the extra data.
	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CoinLockup: Problem encoding ExtraData: %v", err))
		return
	}

	// Compute the additional transaction fees as specified
	// by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(
		lib.TxnTypeCoinLockup,
		transactorPublicKeyBytes,
		requestData.TransactionFees,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CoinLockup: specified TransactionFees are invalid: %v", err))
		return
	}

	// Create transaction
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateCoinLockupTxn(
		transactorPublicKeyBytes,
		profilePublicKeyBytes,
		recipientPublicKeyBytes,
		requestData.UnlockTimestampNanoSecs,
		requestData.VestingEndTimestampNanoSecs,
		requestData.LockupAmountBaseUnits,
		extraData,
		requestData.MinFeeRateNanosPerKB,
		fes.backendServer.GetMempool(),
		additionalOutputs,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CoinLockup: Problem creating txn: %v", err))
		return
	}

	// Construct response.
	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("CoinLockup: Problem serializing txn: %v", err))
		return
	}

	res := CoinLockResponse{
		SpendAmountNanos:  totalInput - changeAmount - fees,
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
		TxnHashHex:        txn.Hash().String(),
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("CoinLockup: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) UpdateCoinLockupParams(ww http.ResponseWriter, req *http.Request) {
	// Decode request body.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := UpdateCoinLockupParamsRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateCoinLockupParams: Problem parsing request body: %v", err))
		return
	}

	// Convert TransactorPublicKeyBase58Check to TransactorPublicKeyBytes
	if requestData.TransactorPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprint("UpdateCoinLockupParams: TransactorPublicKeyBase58Check is required"))
		return
	}
	transactorPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.TransactorPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateCoinLockupParams: Problem decoding TransactorPublicKeyBase58Check %s: %v",
			requestData.TransactorPublicKeyBase58Check, err))
		return
	}

	var transferRestrictionStatus lib.TransferRestrictionStatus
	if requestData.NewLockupTransferRestrictions {
		switch requestData.LockupTransferRestrictionStatus {
		case TransferRestrictionStatusStringUnrestricted:
			transferRestrictionStatus = lib.TransferRestrictionStatusUnrestricted
		case TransferRestrictionStatusStringProfileOwnerOnly:
			transferRestrictionStatus = lib.TransferRestrictionStatusProfileOwnerOnly
		case TransferRestrictionStatusStringDAOMembersOnly:
			transferRestrictionStatus = lib.TransferRestrictionStatusDAOMembersOnly
		case TransferRestrictionStatusStringPermanentlyUnrestricted:
			transferRestrictionStatus = lib.TransferRestrictionStatusPermanentlyUnrestricted
		default:
			_AddBadRequestError(ww, fmt.Sprintf(
				"UpdateCoinLockupParams: TransferRestrictionStatus \"%v\" not supported",
				requestData.LockupTransferRestrictionStatus))
			return
		}
	}

	// Parse extra data.
	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateCoinLockupParams: Problem encoding ExtraData: %v", err))
		return
	}

	// Compute the additional transaction fees as specified
	// by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(
		lib.TxnTypeUpdateCoinLockupParams,
		transactorPublicKeyBytes,
		requestData.TransactionFees,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateCoinLockupParams: specified TransactionFees are invalid: %v", err))
		return
	}

	// Create transaction
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateUpdateCoinLockupParamsTxn(
		transactorPublicKeyBytes,
		requestData.LockupYieldDurationNanoSecs,
		requestData.LockupYieldAPYBasisPoints,
		requestData.RemoveYieldCurvePoint,
		requestData.NewLockupTransferRestrictions,
		transferRestrictionStatus,
		extraData,
		requestData.MinFeeRateNanosPerKB,
		fes.backendServer.GetMempool(),
		additionalOutputs,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateCoinLockupParams: Problem creating txn: %v", err))
		return
	}

	// Construct response.
	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("UpdateCoinLockupParams: Problem serializing txn: %v", err))
		return
	}

	res := CoinLockResponse{
		SpendAmountNanos:  totalInput - changeAmount - fees,
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
		TxnHashHex:        txn.Hash().String(),
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("UpdateCoinLockupParams: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) CoinLockupTransfer(ww http.ResponseWriter, req *http.Request) {
	// Decode request body.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := CoinLockupTransferRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CoinLockupTransfer: Problem parsing request body: %v", err))
		return
	}

	// Convert TransactorPublicKeyBase58Check to TransactorPublicKeyBytes
	if requestData.TransactorPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprint("CoinLockupTransfer: TransactorPublicKeyBase58Check is required"))
		return
	}
	transactorPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.TransactorPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"CoinLockupTransfer: Problem decoding TransactorPublicKeyBase58Check %s: %v",
			requestData.TransactorPublicKeyBase58Check, err))
		return
	}

	// Convert ProfilePublicKeyBase58Check to ProfilePublicKeyBytes
	if requestData.ProfilePublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprint("CoinLockupTransfer: ProfilePublicKeyBase58Check is required"))
		return
	}
	profilePublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.ProfilePublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CoinLockupTransfer: Problem decoding ProfilePublicKeyBase58Check %s: %v",
			requestData.ProfilePublicKeyBase58Check, err))
		return
	}

	// Convert RecipientPublicKeyBase58Check to RecipientPublicKeyBytes
	if requestData.RecipientPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprint("CoinLockupTransfer: RecipientPublicKeyBase58Check is required"))
		return
	}
	recipientPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.RecipientPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CoinLockupTransfer: Problem decoding RecipientPublicKeyBase58Check %s: %v",
			requestData.RecipientPublicKeyBase58Check, err))
		return
	}

	// Check to ensure the recipient is different than the sender.
	if reflect.DeepEqual(recipientPublicKeyBytes, transactorPublicKeyBytes) {
		_AddBadRequestError(ww, fmt.Sprintf("CoinLockupTransfer: Sender cannot be receiver of a transfer"))
		return
	}

	// Parse extra data.
	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CoinLockupTransfer: Problem encoding ExtraData: %v", err))
		return
	}

	// Compute the additional transaction fees as specified
	// by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(
		lib.TxnTypeCoinLockupTransfer,
		transactorPublicKeyBytes,
		requestData.TransactionFees,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CoinLockupTransfer: specified TransactionFees are invalid: %v", err))
		return
	}

	// Create transaction
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateCoinLockupTransferTxn(
		transactorPublicKeyBytes,
		recipientPublicKeyBytes,
		profilePublicKeyBytes,
		requestData.UnlockTimestampNanoSecs,
		requestData.LockedCoinsToTransferBaseUnits,
		extraData,
		requestData.MinFeeRateNanosPerKB,
		fes.backendServer.GetMempool(),
		additionalOutputs,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CoinLockupTransfer: Problem creating txn: %v", err))
		return
	}

	// Construct response.
	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("CoinLockupTransfer: Problem serializing txn: %v", err))
		return
	}

	res := CoinLockResponse{
		SpendAmountNanos:  totalInput - changeAmount - fees,
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
		TxnHashHex:        txn.Hash().String(),
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("CoinLockupTransfer: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) CoinUnlock(ww http.ResponseWriter, req *http.Request) {
	// Decode request body.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := CoinUnlockRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CoinUnlock: Problem parsing request body: %v", err))
		return
	}

	// Convert TransactorPublicKeyBase58Check to TransactorPublicKeyBytes
	if requestData.TransactorPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprint("CoinUnlock: TransactorPublicKeyBase58Check is required"))
		return
	}
	transactorPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.TransactorPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CoinUnlock: Problem decoding TransactorPublicKeyBase58Check %s: %v",
			requestData.TransactorPublicKeyBase58Check, err))
		return
	}

	// Convert ProfilePublicKeyBase58Check to ProfilePublicKeyBytes
	if requestData.ProfilePublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprint("CoinUnlock: ProfilePublicKeyBase58Check is required"))
		return
	}
	profilePublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.ProfilePublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CoinUnlock: Problem decoding ProfilePublicKeyBase58Check %s: %v",
			requestData.ProfilePublicKeyBase58Check, err))
		return
	}

	// Parse extra data.
	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CoinUnlock: Problem encoding ExtraData: %v", err))
		return
	}

	// Compute the additional transaction fees as specified
	// by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(
		lib.TxnTypeCoinUnlock,
		transactorPublicKeyBytes,
		requestData.TransactionFees,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CoinUnlock: specified TransactionFees are invalid: %v", err))
		return
	}

	// Create transaction
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateCoinUnlockTxn(
		transactorPublicKeyBytes,
		profilePublicKeyBytes,
		extraData,
		requestData.MinFeeRateNanosPerKB,
		fes.backendServer.GetMempool(),
		additionalOutputs,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CoinUnlock: Problem creating txn: %v", err))
		return
	}

	// Construct response.
	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("CoinUnlock: Problem serializing txn: %v", err))
		return
	}

	res := CoinLockResponse{
		SpendAmountNanos:  totalInput - changeAmount - fees,
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
		TxnHashHex:        txn.Hash().String(),
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("CoinUnlock: Problem encoding response as JSON: %v", err))
		return
	}
}

// GET lockup yield curve points for a profile by public key
func (fes *APIServer) LockedYieldCurvePoints(ww http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	publicKeyBase58Check := vars[publicKeyBase58CheckKey]

	if publicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprintf("LockedYieldCurvePoints: PublicKeyBase58Check is required"))
		return
	}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("LockedYieldCurvePoints: Problem getting utxoView: %v", err))
		return
	}

	// Decode public key
	pkid, err := fes.getPKIDFromPublicKeyBase58Check(utxoView, publicKeyBase58Check)
	if err != nil || pkid == nil {
		_AddBadRequestError(ww, fmt.Sprintf("LockedYieldCurvePoints: Problem decoding public key: %v", err))
		return
	}

	// Get locked yield curve points
	yieldCurvePointsMap, err := utxoView.GetAllYieldCurvePoints(pkid)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("LockedYieldCurvePoints: Problem getting yield curve points: %v", err))
		return
	}

	var allYieldCurvePoints []*LockupYieldCurvePointResponse
	for _, yieldCurvePoint := range yieldCurvePointsMap {
		if yieldCurvePoint.IsDeleted() {
			continue
		}
		allYieldCurvePoints = append(allYieldCurvePoints,
			fes._lockupYieldCurvePointToResponse(yieldCurvePoint, utxoView, fes.Params))
	}

	sortedYieldCurvePoints := collections.SortStable(allYieldCurvePoints,
		func(ii *LockupYieldCurvePointResponse, jj *LockupYieldCurvePointResponse) bool {
			return ii.LockupDurationNanoSecs < jj.LockupDurationNanoSecs
		})

	if err = json.NewEncoder(ww).Encode(sortedYieldCurvePoints); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("LockedYieldCurvePoints: Problem encoding response as JSON: %v", err))
		return
	}
}

// GET all locked balance entries held by a HODLer public key
func (fes *APIServer) LockedBalanceEntries(ww http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	publicKeyBase58Check := vars[publicKeyBase58CheckKey]

	if publicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprintf("LockedBalanceEntriesHeldByPublicKey: PublicKeyBase58Check is required"))
		return
	}

	// Create an augmented UTXO view to include uncomitted transactions.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("LockedBalanceEntriesHeldByPublicKey: Problem getting utxoView: %v", err))
		return
	}

	// Decode public key
	pkid, err := fes.getPKIDFromPublicKeyBase58Check(utxoView, publicKeyBase58Check)
	if err != nil || pkid == nil {
		_AddBadRequestError(ww, fmt.Sprintf("LockedBalanceEntriesHeldByPublicKey: Problem decoding public key: %v", err))
		return
	}

	// Get all locked balance entries for a user.
	lockedBalanceEntries, err := utxoView.GetAllLockedBalanceEntriesForHodlerPKID(pkid)
	if err != nil {
		_AddBadRequestError(ww,
			fmt.Sprintf("LockedBalanceEntries: Problem getting locked balance entries: %v", err))
		return
	}

	// Split the locked balance entries based on the creator.
	creatorPKIDToCumulativeLockedBalanceEntryResponse := make(map[lib.PKID]*CumulativeLockedBalanceEntryResponse)
	currentTimestampNanoSecs := time.Now().UnixNano()
	for _, lockedBalanceEntry := range lockedBalanceEntries {
		// Check if we need to initialize the cumulative response.
		if _, exists := creatorPKIDToCumulativeLockedBalanceEntryResponse[*lockedBalanceEntry.ProfilePKID]; !exists {
			hodlerPublicKey := utxoView.GetPublicKeyForPKID(lockedBalanceEntry.HODLerPKID)
			profilePublicKey := utxoView.GetPublicKeyForPKID(lockedBalanceEntry.ProfilePKID)
			profileEntry := utxoView.GetProfileEntryForPKID(lockedBalanceEntry.ProfilePKID)
			profileEntryResponse := fes._profileEntryToResponse(profileEntry, utxoView)

			creatorPKIDToCumulativeLockedBalanceEntryResponse[*lockedBalanceEntry.ProfilePKID] =
				&CumulativeLockedBalanceEntryResponse{
					HODLerPublicKeyBase58Check:   lib.PkToString(hodlerPublicKey, fes.Params),
					ProfilePublicKeyBase58Check:  lib.PkToString(profilePublicKey, fes.Params),
					TotalLockedBaseUnits:         uint256.Int{},
					UnlockableBaseUnits:          uint256.Int{},
					UnvestedLockedBalanceEntries: []*LockedBalanceEntryResponse{},
					VestedLockedBalanceEntries:   []*LockedBalanceEntryResponse{},
					ProfileEntryResponse:         profileEntryResponse,
				}
		}

		// Get the existing cumulative response.
		cumulativeResponse := creatorPKIDToCumulativeLockedBalanceEntryResponse[*lockedBalanceEntry.ProfilePKID]

		// Update the total locked base units.
		// NOTE: It's possible to create multiple locked balance entries that are impossible to unlock due to overflow.
		// As such, if the addition triggers an overflow we will just ignore adding more and use the max Uint256.
		var newTotalLockedBaseUnits *uint256.Int
		if uint256.NewInt().Sub(
			lib.MaxUint256,
			&cumulativeResponse.TotalLockedBaseUnits).Lt(&lockedBalanceEntry.BalanceBaseUnits) {
			newTotalLockedBaseUnits = lib.MaxUint256
		} else {
			newTotalLockedBaseUnits = uint256.NewInt().Add(
				&cumulativeResponse.TotalLockedBaseUnits,
				&lockedBalanceEntry.BalanceBaseUnits)
		}

		// Compute how much (if any) is unlockable in the give entry.
		unlockableBaseUnitsFromEntry := uint256.NewInt()
		newTotalUnlockableBaseUnits := uint256.NewInt()
		if lockedBalanceEntry.UnlockTimestampNanoSecs < currentTimestampNanoSecs {
			// Check if the locked balance entry is unvested or vested.
			if lockedBalanceEntry.UnlockTimestampNanoSecs == lockedBalanceEntry.VestingEndTimestampNanoSecs {
				unlockableBaseUnitsFromEntry = &lockedBalanceEntry.BalanceBaseUnits
			} else {
				unlockableBaseUnitsFromEntry, err =
					lib.CalculateVestedEarnings(lockedBalanceEntry, currentTimestampNanoSecs)
				if err != nil {
					_AddBadRequestError(ww,
						fmt.Sprintf("LockedBalanceEntries: Problem computing vested earnings: %v", err))
					return
				}
			}
		}
		if uint256.NewInt().Sub(
			lib.MaxUint256,
			&cumulativeResponse.UnlockableBaseUnits).Lt(unlockableBaseUnitsFromEntry) {
			newTotalUnlockableBaseUnits = lib.MaxUint256
		} else {
			newTotalUnlockableBaseUnits = uint256.NewInt().Add(
				&cumulativeResponse.UnlockableBaseUnits,
				unlockableBaseUnitsFromEntry)
		}

		// Update the cumulative response.
		cumulativeResponse.TotalLockedBaseUnits = *newTotalLockedBaseUnits
		cumulativeResponse.UnlockableBaseUnits = *newTotalUnlockableBaseUnits
		if lockedBalanceEntry.UnlockTimestampNanoSecs == lockedBalanceEntry.VestingEndTimestampNanoSecs {
			cumulativeResponse.UnvestedLockedBalanceEntries = append(
				cumulativeResponse.UnvestedLockedBalanceEntries,
				fes._lockedBalanceEntryToResponse(lockedBalanceEntry, utxoView, fes.Params))
		} else {
			cumulativeResponse.VestedLockedBalanceEntries = append(
				cumulativeResponse.VestedLockedBalanceEntries,
				fes._lockedBalanceEntryToResponse(lockedBalanceEntry, utxoView, fes.Params))
		}
	}

	// Create a list of the cumulative locked balance entries and sort based on amount locked.
	var cumulativeLockedBalanceEntryResponses []*CumulativeLockedBalanceEntryResponse
	for _, cumulativeResponse := range creatorPKIDToCumulativeLockedBalanceEntryResponse {
		cumulativeLockedBalanceEntryResponses = append(
			cumulativeLockedBalanceEntryResponses, cumulativeResponse)
	}

	// Sort the response based on the amount locked.
	sortedCumulativeResponses := collections.SortStable(cumulativeLockedBalanceEntryResponses,
		func(ii *CumulativeLockedBalanceEntryResponse, jj *CumulativeLockedBalanceEntryResponse) bool {
			return ii.TotalLockedBaseUnits.Lt(&jj.TotalLockedBaseUnits)
		})

	// Encode and return the responses.
	if err = json.NewEncoder(ww).Encode(sortedCumulativeResponses); err != nil {
		_AddInternalServerError(ww,
			fmt.Sprintf("LockedBalanceEntries: Problem encoding response as JSON: %v", err))
		return
	}
}
