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
)

type LockedBalanceEntryResponse struct {
	HODLerPublicKeyBase58Check  string
	ProfilePublicKeyBase58Check string
	UnlockTimestampNanoSecs     int64
	VestingEndTimestampNanoSecs int64
	BalanceBaseUnits            uint256.Int
	ProfileEntryResponse        *ProfileEntryResponse
}

func (fes *APIServer) _lockedBalanceEntryToResponse(
	lockedBalanceEntry *lib.LockedBalanceEntry, utxoView *lib.UtxoView, params *lib.DeSoParams,
) *LockedBalanceEntryResponse {
	hodlerPublicKey := utxoView.GetPublicKeyForPKID(lockedBalanceEntry.HODLerPKID)
	profilePublicKey := utxoView.GetPublicKeyForPKID(lockedBalanceEntry.ProfilePKID)
	profileEntry := utxoView.GetProfileEntryForPKID(lockedBalanceEntry.ProfilePKID)
	profileEntryResponse := fes._profileEntryToResponse(profileEntry, utxoView)
	return &LockedBalanceEntryResponse{
		HODLerPublicKeyBase58Check:  lib.PkToString(hodlerPublicKey, params),
		ProfilePublicKeyBase58Check: lib.PkToString(profilePublicKey, params),
		UnlockTimestampNanoSecs:     lockedBalanceEntry.UnlockTimestampNanoSecs,
		VestingEndTimestampNanoSecs: lockedBalanceEntry.VestingEndTimestampNanoSecs,
		BalanceBaseUnits:            lockedBalanceEntry.BalanceBaseUnits,
		ProfileEntryResponse:        profileEntryResponse,
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

	// TODO: What other validations are required?

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

	// TODO: validate LockupYieldDurationNanoSecs and LockupYieldAPYBasisPoints and anything else.

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

	// TODO: validate UnlockTimestampNanoSecs, LockedCoinsToTransferBaseUnits

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
		profilePublicKeyBytes,
		recipientPublicKeyBytes,
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

	// TODO: any additional validations

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

// TODO: GET endpoints
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

// GET all locked balances of a profile - NOTE: this is not supported by the current core indexes.

// GET all locked balance entries held by a HODLer public key
func (fes *APIServer) LockedBalanceEntries(ww http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	publicKeyBase58Check := vars[publicKeyBase58CheckKey]

	if publicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprintf("LockedBalanceEntriesHeldByPublicKey: PublicKeyBase58Check is required"))
		return
	}

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

	// TODO: Get all locked balance entries. NOTE: this is not yet implemented.
}
