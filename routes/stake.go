package routes

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/deso-protocol/core/lib"
	"github.com/gorilla/mux"
	"github.com/holiman/uint256"
	"io"
	"math"
	"net/http"
	"strconv"
)

type StakeRewardMethod string

const (
	PayToBalance             StakeRewardMethod = "PAY_TO_BALANCE"
	Restake                  StakeRewardMethod = "RESTAKE"
	UnknownStakeRewardMethod StakeRewardMethod = "UNKNOWN_STAKE_REWARD_METHOD"
)

func (stakeRewardMethod StakeRewardMethod) String() string {
	return string(stakeRewardMethod)
}

func (stakeRewardMethod StakeRewardMethod) ToStakeRewardMethod() lib.StakingRewardMethod {
	switch stakeRewardMethod {
	case PayToBalance:
		return lib.StakingRewardMethodPayToBalance
	case Restake:
		return lib.StakingRewardMethodRestake
	default:
		return lib.StakingRewardMethodUnknown
	}
}

func FromLibStakeRewardMethod(stakeRewardMethod lib.StakingRewardMethod) StakeRewardMethod {
	switch stakeRewardMethod {
	case lib.StakingRewardMethodPayToBalance:
		return PayToBalance
	case lib.StakingRewardMethodRestake:
		return Restake
	default:
		return UnknownStakeRewardMethod
	}
}

type StakeRequest struct {
	TransactorPublicKeyBase58Check string            `safeForLogging:"true"`
	ValidatorPublicKeyBase58Check  string            `safeForLogging:"true"`
	RewardMethod                   StakeRewardMethod `safeForLogging:"true"`
	StakeAmountNanos               *uint256.Int      `safeForLogging:"true"`
	ExtraData                      map[string]string `safeForLogging:"true"`
	MinFeeRateNanosPerKB           uint64            `safeForLogging:"true"`
	TransactionFees                []TransactionFee  `safeForLogging:"true"`

	OptionalPrecedingTransactions []*lib.MsgDeSoTxn `safeForLogging:"true"`
}

type UnstakeRequest struct {
	TransactorPublicKeyBase58Check string            `safeForLogging:"true"`
	ValidatorPublicKeyBase58Check  string            `safeForLogging:"true"`
	UnstakeAmountNanos             *uint256.Int      `safeForLogging:"true"`
	ExtraData                      map[string]string `safeForLogging:"true"`
	MinFeeRateNanosPerKB           uint64            `safeForLogging:"true"`
	TransactionFees                []TransactionFee  `safeForLogging:"true"`

	OptionalPrecedingTransactions []*lib.MsgDeSoTxn `safeForLogging:"true"`
}

type UnlockStakeRequest struct {
	TransactorPublicKeyBase58Check string            `safeForLogging:"true"`
	ValidatorPublicKeyBase58Check  string            `safeForLogging:"true"`
	StartEpochNumber               uint64            `safeForLogging:"true"`
	EndEpochNumber                 uint64            `safeForLogging:"true"`
	ExtraData                      map[string]string `safeForLogging:"true"`
	MinFeeRateNanosPerKB           uint64            `safeForLogging:"true"`
	TransactionFees                []TransactionFee  `safeForLogging:"true"`
}

type StakeTxnResponse struct {
	SpendAmountNanos  uint64
	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgDeSoTxn
	TransactionHex    string
	TxnHashHex        string
}

type StakeEntryResponse struct {
	StakerPublicKeyBase58Check    string
	ValidatorPublicKeyBase58Check string
	RewardMethod                  string
	StakeAmountNanos              *uint256.Int
	ExtraData                     map[string]string
}

type LockedStakeEntryResponse struct {
	StakerPublicKeyBase58Check    string
	ValidatorPublicKeyBase58Check string
	LockedAmountNanos             *uint256.Int
	LockedAtEpochNumber           uint64
	ExtraData                     map[string]string
}

// Constants for query params
const (
	validatorPublicKeyBase58CheckKey = "validatorPublicKeyBase58Check"
	stakerPublicKeyBase58CheckKey    = "stakerPublicKeyBase58Check"
	lockedAtEpochNumberKey           = "lockedAtEpochNumber"
	startEpochNumberKey              = "startEpochNumber"
	endEpochNumberKey                = "endEpochNumber"
	publicKeyBase58CheckKey          = "publicKeyBase58Check"
)

// Stake constructs a transaction that stakes a given amount of DeSo.
func (fes *APIServer) CreateStakeTxn(ww http.ResponseWriter, req *http.Request) {
	// Decode request body.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := StakeRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateStakeTxn: Problem parsing request body: %v", err))
		return
	}

	// Convert TransactorPublicKeyBase58Check to TransactorPublicKeyBytes
	if requestData.TransactorPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprint("CreateStakeTxn: TransactorPublicKeyBase58Check is required"))
		return
	}
	transactorPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.TransactorPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateStakeTxn: Problem decoding TransactorPublicKeyBase58Check %s: %v",
			requestData.TransactorPublicKeyBase58Check, err))
		return
	}

	// Convert ValidatorPublicKeyBase58Check to ValidatorPublicKeyBytes
	if requestData.ValidatorPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprint("CreateStakeTxn: ValidatorPublicKeyBase58Check is required"))
		return
	}
	validatorPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.ValidatorPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateStakeTxn: Problem decoding ValidatorPublicKeyBase58Check %s: %v",
			requestData.ValidatorPublicKeyBase58Check, err))
		return
	}

	// Convert reward method string to enum.
	rewardMethod := requestData.RewardMethod.ToStakeRewardMethod()
	if rewardMethod == lib.StakingRewardMethodUnknown {
		_AddBadRequestError(ww, fmt.Sprintf("CreateStakeTxn: Invalid RewardMethod %s", requestData.RewardMethod))
		return
	}

	// Validate stake amount
	if !requestData.StakeAmountNanos.IsUint64() {
		_AddBadRequestError(ww, fmt.Sprint("CreateStakeTxn: StakeAmountNanos must be a uint64"))
		return
	}
	stakeAmountNanosUint64 := requestData.StakeAmountNanos.Uint64()
	utxoView, err := lib.GetAugmentedUniversalViewWithAdditionalTransactions(
		fes.backendServer.GetMempool(),
		requestData.OptionalPrecedingTransactions,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateStakeTxn: Problem fetching utxoView: %v", err))
		return
	}
	balance, err := utxoView.GetDeSoBalanceNanosForPublicKey(transactorPublicKeyBytes)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateStakeTxn: Problem fetching balance: %v", err))
		return
	}
	if stakeAmountNanosUint64 > balance {
		_AddBadRequestError(ww, fmt.Sprintf("CreateStakeTxn: Insufficient balance: %d", balance))
		return
	}

	// Parse ExtraData.
	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateStakeTxn: Problem parsing ExtraData: %v", err))
		return
	}

	// Compute the additional transaction fees as specified
	// by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(
		lib.TxnTypeStake,
		transactorPublicKeyBytes,
		requestData.TransactionFees,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprint("CreateStakeTxn: specified TransactionFees are invalid"))
		return
	}

	// Create transaction.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateStakeTxn(
		transactorPublicKeyBytes,
		&lib.StakeMetadata{
			ValidatorPublicKey: lib.NewPublicKey(validatorPublicKeyBytes),
			RewardMethod:       rewardMethod,
			StakeAmountNanos:   requestData.StakeAmountNanos,
		},
		extraData,
		requestData.MinFeeRateNanosPerKB,
		fes.backendServer.GetMempool(),
		additionalOutputs,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateStakeTxn: Problem creating transaction: %v", err))
		return
	}

	// Construct response.
	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("CreateStakeTxn: Problem serializing transaction: %v", err))
		return
	}

	// TODO: do we need to specify the stake amount in the spend amount nanos?
	res := StakeTxnResponse{
		SpendAmountNanos:  totalInput - changeAmount - fees,
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
		TxnHashHex:        txn.Hash().String(),
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, "CreateStakeTxn: Problem encoding response as JSON")
		return
	}
}

// Unstake constructs a transaction that unstakes a staked entry.
func (fes *APIServer) CreateUnstakeTxn(ww http.ResponseWriter, req *http.Request) {
	// Decode request body.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := UnstakeRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateUnstakeTxn: Problem parsing request body: %v", err))
		return
	}

	// Convert TransactorPublicKeyBase58Check to TransactorPublicKeyBytes
	if requestData.TransactorPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprint("CreateUnstakeTxn: TransactorPublicKeyBase58Check is required"))
		return
	}
	transactorPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.TransactorPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateUnstakeTxn: Problem decoding TransactorPublicKeyBase58Check %s: %v",
			requestData.TransactorPublicKeyBase58Check, err))
		return
	}

	// Convert ValidatorPublicKeyBase58Check to ValidatorPublicKeyBytes
	if requestData.ValidatorPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprint("CreateUnstakeTxn: ValidatorPublicKeyBase58Check is required"))
		return
	}
	validatorPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.ValidatorPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateUnstakeTxn: Problem decoding ValidatorPublicKeyBase58Check %s: %v",
			requestData.ValidatorPublicKeyBase58Check, err))
		return
	}

	// Validate unstake amount nanos
	if !requestData.UnstakeAmountNanos.IsUint64() {
		_AddBadRequestError(ww, fmt.Sprint("CreateUnstakeTxn: UnstakeAmountNanos must be a uint64"))
		return
	}
	utxoView, err := lib.GetAugmentedUniversalViewWithAdditionalTransactions(
		fes.backendServer.GetMempool(),
		requestData.OptionalPrecedingTransactions,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateUnstakeTxn: Problem fetching utxoView: %v", err))
		return
	}
	// Get staker and validator PKIDs
	stakerPKID := utxoView.GetPKIDForPublicKey(transactorPublicKeyBytes)
	validatorPKID := utxoView.GetPKIDForPublicKey(validatorPublicKeyBytes)
	stakeEntry, err := utxoView.GetStakeEntry(validatorPKID.PKID, stakerPKID.PKID)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateUnstakeTxn: Problem fetching stake entry: %v", err))
		return
	}
	if requestData.UnstakeAmountNanos.Gt(stakeEntry.StakeAmountNanos) {
		_AddBadRequestError(ww, fmt.Sprint("CreateUnstakeTxn: UnstakeAmountNanos cannot be greater than the current stake "+
			"amount"))
		return
	}

	// Parse ExtraData.
	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateUnstakeTxn: Problem parsing ExtraData: %v", err))
		return
	}

	// Compute the additional transaction fees as specified
	// by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(
		lib.TxnTypeUnstake,
		transactorPublicKeyBytes,
		requestData.TransactionFees,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprint("CreateUnstakeTxn: specified TransactionFees are invalid"))
		return
	}

	// Create the transaction.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateUnstakeTxn(
		transactorPublicKeyBytes,
		&lib.UnstakeMetadata{
			ValidatorPublicKey: lib.NewPublicKey(validatorPublicKeyBytes),
			UnstakeAmountNanos: requestData.UnstakeAmountNanos,
		},
		extraData,
		requestData.MinFeeRateNanosPerKB,
		fes.backendServer.GetMempool(),
		additionalOutputs,
	)

	// Construct response.
	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("CreateUnstakeTxn: Problem serializing transaction: %v", err))
		return
	}

	res := StakeTxnResponse{
		SpendAmountNanos:  totalInput - changeAmount - fees,
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
		TxnHashHex:        txn.Hash().String(),
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, "CreateUnstakeTxn: Problem encoding response as JSON")
		return
	}
}

// UnlockStake constructs a transaction that unlocks a locked stake entry.
func (fes *APIServer) CreateUnlockStakeTxn(ww http.ResponseWriter, req *http.Request) {
	// Decode request body.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := UnlockStakeRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateUnlockStakeTxn: Problem parsing request body: %v", err))
		return
	}

	// Convert TransactorPublicKeyBase58Check to TransactorPublicKeyBytes
	if requestData.TransactorPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprint("CreateUnlockStakeTxn: TransactorPublicKeyBase58Check is required"))
		return
	}
	transactorPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.TransactorPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateUnlockStakeTxn: Problem decoding TransactorPublicKeyBase58Check %s: %v",
			requestData.TransactorPublicKeyBase58Check, err))
		return
	}

	// Convert ValidatorPublicKeyBase58Check to ValidatorPublicKeyBytes
	if requestData.ValidatorPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprint("CreateUnlockStakeTxn: ValidatorPublicKeyBase58Check is required"))
		return
	}
	validatorPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.ValidatorPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateUnlockStakeTxn: Problem decoding ValidatorPublicKeyBase58Check %s: %v",
			requestData.ValidatorPublicKeyBase58Check, err))
		return
	}

	// Validate start and end epoch
	if requestData.StartEpochNumber > requestData.EndEpochNumber {
		_AddBadRequestError(ww, fmt.Sprint("CreateUnlockStakeTxn: StartEpochNumber cannot be greater than EndEpochNumber"))
		return
	}

	// Parse ExtraData.
	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateUnlockStakeTxn: Problem parsing ExtraData: %v", err))
		return
	}

	// Compute the additional transaction fees as specified
	// by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(
		lib.TxnTypeUnlockStake,
		transactorPublicKeyBytes,
		requestData.TransactionFees,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprint("CreateUnlockStakeTxn: specified TransactionFees are invalid"))
		return
	}

	// Create the transaction.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateUnlockStakeTxn(
		transactorPublicKeyBytes,
		&lib.UnlockStakeMetadata{
			ValidatorPublicKey: lib.NewPublicKey(validatorPublicKeyBytes),
			StartEpochNumber:   requestData.StartEpochNumber,
			EndEpochNumber:     requestData.EndEpochNumber,
		},
		extraData,
		requestData.MinFeeRateNanosPerKB,
		fes.backendServer.GetMempool(),
		additionalOutputs,
	)

	// Construct response.
	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("CreateUnlockStakeTxn: Problem serializing transaction: %v", err))
		return
	}

	res := StakeTxnResponse{
		SpendAmountNanos:  totalInput - changeAmount - fees,
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
		TxnHashHex:        txn.Hash().String(),
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, "CreateUnlockStakeTxn: Problem encoding response as JSON")
		return
	}
}

// _stakeEntryToResponse converts the core lib.StakeEntry to a StakeEntryResponse
func _stakeEntryToResponse(
	stakeEntry *lib.StakeEntry, params *lib.DeSoParams, utxoView *lib.UtxoView) *StakeEntryResponse {
	stakerPublicKey := utxoView.GetPublicKeyForPKID(stakeEntry.StakerPKID)
	validatorPublicKey := utxoView.GetPublicKeyForPKID(stakeEntry.ValidatorPKID)
	return &StakeEntryResponse{
		StakerPublicKeyBase58Check:    lib.Base58CheckEncode(stakerPublicKey, false, params),
		ValidatorPublicKeyBase58Check: lib.Base58CheckEncode(validatorPublicKey, false, params),
		RewardMethod:                  FromLibStakeRewardMethod(stakeEntry.RewardMethod).String(),
		StakeAmountNanos:              stakeEntry.StakeAmountNanos,
		ExtraData:                     DecodeExtraDataMap(params, utxoView, stakeEntry.ExtraData),
	}
}

// GetStakeForValidatorAndStaker returns the stake entry for a given validator and staker
func (fes *APIServer) GetStakeForValidatorAndStaker(ww http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	validatorPublicKeyBase58Check, validatorExists := vars[validatorPublicKeyBase58CheckKey]
	if !validatorExists {
		_AddBadRequestError(ww, fmt.Sprint("GetStakeForValidatorAndStaker: validatorPublicKeyBase58Check is required"))
		return
	}
	stakerPublicKeyBase58Check, stakerExists := vars[stakerPublicKeyBase58CheckKey]
	if !stakerExists {
		_AddBadRequestError(ww, fmt.Sprint("GetStakeForValidatorAndStaker: stakerPublicKeyBase58Check is required"))
		return
	}

	// Create UTXO View
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetStakeForValidatorAndStaker: Problem fetching utxoView: %v", err))
		return
	}

	// Convert validator public key to bytes
	validatorPKID, err := fes.getPKIDFromPublicKeyBase58Check(utxoView, validatorPublicKeyBase58Check)
	if err != nil || validatorPKID == nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetStakeForValidatorAndStaker: Problem decoding validator public key: %v", err))
		return
	}

	// Convert staker public key to bytes
	stakerPKID, err := fes.getPKIDFromPublicKeyBase58Check(utxoView, stakerPublicKeyBase58Check)
	if err != nil || stakerPKID == nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetStakeForValidatorAndStaker: Problem decoding staker public key: %v", err))
		return
	}

	// Get the stake entry
	stakeEntry, err := utxoView.GetStakeEntry(validatorPKID, stakerPKID)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetStakeForValidatorAndStaker: Problem fetching stake entry: %v", err))
		return
	}
	if stakeEntry == nil {
		_AddNotFoundError(ww, fmt.Sprint("GetStakeForValidatorAndStaker: No stake entry found"))
		return
	}

	if err = json.NewEncoder(ww).Encode(_stakeEntryToResponse(stakeEntry, fes.Params, utxoView)); err != nil {
		_AddInternalServerError(ww, "GetStakeForValidatorAndStaker: Problem encoding response as JSON")
		return
	}
}

// GetStakesForValidator returns all stake entries for a given validator
func (fes *APIServer) GetStakesForValidator(ww http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	validatorPublicKeyBase58Check, validatorExists := vars[validatorPublicKeyBase58CheckKey]
	if !validatorExists {
		_AddBadRequestError(ww, fmt.Sprint("GetStakesForValidator: validatorPublicKeyBase58Check is required"))
		return
	}

	// Create UTXO View
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetStakesForValidator: Problem fetching utxoView: %v", err))
		return
	}

	// Convert validator public key to bytes
	validatorPKID, err := fes.getPKIDFromPublicKeyBase58Check(utxoView, validatorPublicKeyBase58Check)
	if err != nil || validatorPKID == nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetStakesForValidator: Problem decoding validator public key: %v", err))
		return
	}

	// Get the stake entries
	stakeEntries, err := utxoView.GetStakeEntriesForValidatorPKID(validatorPKID)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetStakesForValidator: Problem fetching stake entries: %v", err))
		return
	}

	// Convert to stake entry responses
	var stakeEntryResponses []*StakeEntryResponse
	for _, stakeEntry := range stakeEntries {
		stakeEntryResponses = append(stakeEntryResponses, _stakeEntryToResponse(stakeEntry, fes.Params, utxoView))
	}

	// Encode response.
	if err = json.NewEncoder(ww).Encode(stakeEntryResponses); err != nil {
		_AddInternalServerError(ww, "GetStakesForValidator: Problem encoding response as JSON")
		return
	}
}

// GetLockedStakesForValidatorAndStaker returns all locked stake entries for a given validator and staker
// If lockedAtEpochNumber is specified, only the locked stake entry that was locked at that epoch number is returned
// If startEpochNumber and endEpochNumber are specified, all locked stake entries that were locked between those.
// If none are provided, all locked stake entries are returned.
func (fes *APIServer) GetLockedStakesForValidatorAndStaker(ww http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	validatorPublicKeyBase58Check, validatorExists := vars[validatorPublicKeyBase58CheckKey]
	if !validatorExists {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetLockedStakesForValidatorAndStaker: validatorPublicKeyBase58Check is required"))
		return
	}
	stakerPublicKeyBase58Check, stakerExists := vars[stakerPublicKeyBase58CheckKey]
	if !stakerExists {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetLockedStakesForValidatorAndStaker: stakerPublicKeyBase58Check is required"))
		return
	}

	// Create UTXO View
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf(
			"GetLockedStakesForValidatorAndStaker: Problem fetching utxoView: %v", err))
		return
	}

	// Convert validator public key to bytes
	validatorPKID, err := fes.getPKIDFromPublicKeyBase58Check(utxoView, validatorPublicKeyBase58Check)
	if err != nil || validatorPKID == nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetLockedStakesForValidatorAndStaker: Problem decoding validator public key: %v", err))
		return
	}

	// Convert staker public key to bytes
	stakerPKID, err := fes.getPKIDFromPublicKeyBase58Check(utxoView, stakerPublicKeyBase58Check)
	if err != nil || stakerPKID == nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetLockedStakesForValidatorAndStaker: Problem decoding staker public key: %v", err))
		return
	}

	queryParamBytes, err := json.Marshal(req.URL.Query())

	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetLockedStakesForValidatorAndStaker: Problem parsing query params: %v", err))
		return
	}

	queryParams := make(map[string][]string)

	if err = json.Unmarshal(queryParamBytes, &queryParams); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetLockedStakesForValidatorAndStaker: Problem parsing query params: %v", err))
		return
	}

	var lockedStakeEntries []*lib.LockedStakeEntry
	// First check for lockedAtEpochNumber
	if len(queryParams[lockedAtEpochNumberKey]) != 0 {
		lockedAtEpochNumber, err := strconv.ParseUint(queryParams[lockedAtEpochNumberKey][0], 10, 64)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"GetLockedStakesForValidatorAndStaker: Problem parsing lockedAtEpochNumber: %v", err))
			return
		}
		lockedStakeEntry, err := utxoView.GetLockedStakeEntry(validatorPKID, stakerPKID, lockedAtEpochNumber)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"GetLockedStakesForValidatorAndStaker: Problem fetching locked stake entry: %v", err))
			return
		}
		if lockedStakeEntry == nil {
			_AddNotFoundError(ww, fmt.Sprint("GetLockedStakesForValidatorAndStaker: No locked stake entry found"))
			return
		}
		lockedStakeEntries = append(lockedStakeEntries, lockedStakeEntry)
	} else {
		startEpochNumber := uint64(0)
		endEpochNumber := uint64(math.MaxUint64)
		if len(queryParams[startEpochNumberKey]) != 0 {
			startEpochNumber, err = strconv.ParseUint(queryParams[startEpochNumberKey][0], 10, 64)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf(
					"GetLockedStakesForValidatorAndStaker: Problem parsing startEpochNumber: %v", err))
				return
			}
		}
		if len(queryParams[endEpochNumberKey]) != 0 {
			endEpochNumber, err = strconv.ParseUint(queryParams[endEpochNumberKey][0], 10, 64)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf(
					"GetLockedStakesForValidatorAndStaker: Problem parsing endEpochNumber: %v", err))
				return
			}
		}
		if startEpochNumber > endEpochNumber {
			_AddBadRequestError(ww, fmt.Sprint(
				"GetLockedStakesForValidatorAndStaker: startEpochNumber cannot be greater than endEpochNumber"))
			return
		}
		lockedStakeEntries, err = utxoView.GetLockedStakeEntriesInRange(
			validatorPKID, stakerPKID, startEpochNumber, endEpochNumber)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"GetLockedStakesForValidatorAndStaker: Problem fetching locked stake entries: %v", err))
			return
		}
		if len(lockedStakeEntries) == 0 {
			_AddNotFoundError(ww, fmt.Sprint("GetLockedStakesForValidatorAndStaker: No locked stake entries found"))
			return
		}
	}

	// Convert locked stake entries to responses
	var lockedStakeEntryResponses []*LockedStakeEntryResponse
	for _, lockedStakeEntry := range lockedStakeEntries {
		lockedStakeEntryResponses = append(lockedStakeEntryResponses, _lockedStakeEntryToResponse(
			lockedStakeEntry, fes.Params, utxoView))
	}

	// Encode response.
	if err = json.NewEncoder(ww).Encode(lockedStakeEntryResponses); err != nil {
		_AddInternalServerError(ww, "GetLockedStakesForValidatorAndStaker: Problem encoding response as JSON")
		return
	}
}

// _lockedStakeEntryToResponse converts the core lib.LockedStakeEntry to a LockedStakeEntryResponse
func _lockedStakeEntryToResponse(
	lockedStakeEntry *lib.LockedStakeEntry, params *lib.DeSoParams, utxoView *lib.UtxoView) *LockedStakeEntryResponse {
	stakerPublicKey := utxoView.GetPublicKeyForPKID(lockedStakeEntry.StakerPKID)
	validatorPublicKey := utxoView.GetPublicKeyForPKID(lockedStakeEntry.ValidatorPKID)
	return &LockedStakeEntryResponse{
		StakerPublicKeyBase58Check:    lib.Base58CheckEncode(stakerPublicKey, false, params),
		ValidatorPublicKeyBase58Check: lib.Base58CheckEncode(validatorPublicKey, false, params),
		LockedAmountNanos:             lockedStakeEntry.LockedAmountNanos,
		LockedAtEpochNumber:           lockedStakeEntry.LockedAtEpochNumber,
		ExtraData:                     DecodeExtraDataMap(params, utxoView, lockedStakeEntry.ExtraData),
	}
}
