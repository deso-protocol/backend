package routes

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/deso-protocol/core/lib"
	"github.com/pkg/errors"
)

type GetGlobalParamsRequest struct {
}

type GetGlobalParamsResponse struct {
	// The current exchange rate.
	USDCentsPerBitcoin uint64 `safeForLogging:"true"`

	// The current create profile fee
	CreateProfileFeeNanos uint64 `safeForLogging:"true"`

	// The current minimum fee the network will accept
	MinimumNetworkFeeNanosPerKB uint64 `safeForLogging:"true"`

	// The fee per copy of an NFT minted.
	CreateNFTFeeNanos uint64 `safeForLogging:"true"`

	// The maximum number of copies a single NFT can have.
	MaxCopiesPerNFT uint64 `safeForLogging:"true"`

	// StakeLockupEpochDuration is the number of epochs that a
	// user must wait before unlocking their unstaked stake.
	StakeLockupEpochDuration uint64 `safeForLogging:"true"`

	// ValidatorJailEpochDuration is the number of epochs that a validator must
	// wait after being jailed before submitting an UnjailValidator txn.
	ValidatorJailEpochDuration uint64 `safeForLogging:"true"`

	// LeaderScheduleMaxNumValidators is the maximum number of validators that
	// are included when generating a new Proof-of-Stake leader schedule.
	LeaderScheduleMaxNumValidators uint64 `safeForLogging:"true"`

	// ValidatorSetMaxNumValidators is the maximum number of validators that
	// are included when generating a new Proof-of-Stake validator set.
	ValidatorSetMaxNumValidators uint64 `safeForLogging:"true"`

	// EpochDurationNumBlocks is the number of blocks included in one epoch.
	EpochDurationNumBlocks uint64 `safeForLogging:"true"`

	// JailInactiveValidatorGracePeriodEpochs is the number of epochs we
	// allow a validator to be inactive for (neither voting nor proposing
	// blocks) before they are jailed.
	JailInactiveValidatorGracePeriodEpochs uint64 `safeForLogging:"true"`
}

func (fes *APIServer) GetGlobalParams(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetGlobalParamsRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetGlobalParams: Problem parsing request body: %v", err))
		return
	}

	// Get a view
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetGlobalParams: Error getting utxoView: %v", err))
		return
	}
	globalParamsEntry := utxoView.GetCurrentGlobalParamsEntry()
	// Return all the data associated with the transaction in the response
	res := GetGlobalParamsResponse{
		USDCentsPerBitcoin:                     globalParamsEntry.USDCentsPerBitcoin,
		CreateProfileFeeNanos:                  globalParamsEntry.CreateProfileFeeNanos,
		MinimumNetworkFeeNanosPerKB:            globalParamsEntry.MinimumNetworkFeeNanosPerKB,
		CreateNFTFeeNanos:                      globalParamsEntry.CreateNFTFeeNanos,
		MaxCopiesPerNFT:                        globalParamsEntry.MaxCopiesPerNFT,
		StakeLockupEpochDuration:               globalParamsEntry.StakeLockupEpochDuration,
		ValidatorJailEpochDuration:             globalParamsEntry.ValidatorJailEpochDuration,
		LeaderScheduleMaxNumValidators:         globalParamsEntry.LeaderScheduleMaxNumValidators,
		ValidatorSetMaxNumValidators:           globalParamsEntry.ValidatorSetMaxNumValidators,
		EpochDurationNumBlocks:                 globalParamsEntry.EpochDurationNumBlocks,
		JailInactiveValidatorGracePeriodEpochs: globalParamsEntry.JailInactiveValidatorGracePeriodEpochs,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetGlobalParams: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) GetAllGlobalParams(ww http.ResponseWriter, req *http.Request) {
	// Get a view
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllGlobalParams: Error getting utxoView: %v", err))
		return
	}
	globalParamsEntry := utxoView.GetCurrentGlobalParamsEntry()
	// Return all the data associated with the transaction in the response
	res := globalParamsEntry
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllGlobalParams: Problem encoding response as JSON: %v", err))
		return
	}
}

// UpdateGlobalParamsRequest ...
type UpdateGlobalParamsRequest struct {
	UpdaterPublicKeyBase58Check string `safeForLogging:"true"`
	// The new exchange rate to set.
	USDCentsPerBitcoin int64 `safeForLogging:"true"`

	// The fee to create a profile.
	CreateProfileFeeNanos int64 `safeForLogging:"true"`

	// The fee per copy of an NFT minted.
	CreateNFTFeeNanos int64 `safeForLogging:"true"`

	// The maximum number of copies a single NFT can have.
	MaxCopiesPerNFT int64 `safeForLogging:"true"`

	// The new minimum fee the network will accept
	MinimumNetworkFeeNanosPerKB int64 `safeForLogging:"true"`

	// The new maximum buffer nodes will accept for expiration block
	// heights on nonces.
	MaxNonceExpirationBlockHeightOffset int64 `safeForLogging:"true"`

	// StakeLockupEpochDuration is the number of epochs that a
	// user must wait before unlocking their unstaked stake.
	StakeLockupEpochDuration uint64 `safeForLogging:"true"`

	// ValidatorJailEpochDuration is the number of epochs that a validator must
	// wait after being jailed before submitting an UnjailValidator txn.
	ValidatorJailEpochDuration uint64 `safeForLogging:"true"`

	// LeaderScheduleMaxNumValidators is the maximum number of validators that
	// are included when generating a new Proof-of-Stake leader schedule.
	LeaderScheduleMaxNumValidators uint64 `safeForLogging:"true"`

	// ValidatorSetMaxNumValidators is the maximum number of validators that
	// are included when generating a new Proof-of-Stake validator set.
	ValidatorSetMaxNumValidators uint64 `safeForLogging:"true"`

	// StakingRewardsMaxNumStakes is the maximum number of stakes that
	// are eligible to receive rewards in the end of epoch hook.
	StakingRewardsMaxNumStakes uint64 `safeForLogging:"true"`

	// StakingRewardsAPYBasisPoints is the annual percentage yield that
	// is used to compute end-of-epoch staking rewards.
	StakingRewardsAPYBasisPoints uint64 `safeForLogging:"true"`

	// EpochDurationNumBlocks is the number of blocks included in one epoch.
	EpochDurationNumBlocks uint64 `safeForLogging:"true"`

	// JailInactiveValidatorGracePeriodEpochs is the number of epochs we
	// allow a validator to be inactive for (neither voting nor proposing
	// blocks) before they are jailed.
	JailInactiveValidatorGracePeriodEpochs uint64 `safeForLogging:"true"`

	// MaximumVestedIntersectionsPerLockupTransaction is the maximum number
	// of intersections that can be vested per lockup transaction.
	MaximumVestedIntersectionsPerLockupTransaction int `safeForLogging:"true"`

	// FeeBucketGrowthRateBasisPoints is the growth rate in basis points of
	// fee buckets for the mempool's transaction register.
	FeeBucketGrowthRateBasisPoints uint64 `safeForLogging:"true"`

	// BlockTimestampDriftNanoSecs is the maximum number of nanoseconds from the current timestamp that
	// we will allow a PoS block to be submitted.
	BlockTimestampDriftNanoSecs int64 `safeForLogging:"true"`

	// MempoolMaxSizeBytes is the maximum size of the mempool in bytes.
	MempoolMaxSizeBytes uint64 `safeForLogging:"true"`

	// MempoolFeeEstimatorNumMempoolBlocks is the number of possible future blocks to a txn may be placed
	// into when consider when estimating the fee for a new txn.
	MempoolFeeEstimatorNumMempoolBlocks uint64

	// MempoolFeeEstimatorNumPastBlocks is the number of past blocks to reference txn fees from when estimating
	// the fee for a new txn.
	MempoolFeeEstimatorNumPastBlocks uint64

	// MaxBlockSizeBytesPoS is the maximum size of a block in bytes.
	MaxBlockSizeBytesPoS uint64

	// SoftMaxBlockSizeBytesPoS is the ideal steady state size of a block in bytes.
	// This value will be used to control size of block production and congestion in fee estimation.
	SoftMaxBlockSizeBytesPoS uint64

	// MaxTxnSizeBytesPoS is the maximum size of a transaction in bytes allowed.
	MaxTxnSizeBytesPoS uint64

	// BlockProductionIntervalMillisecondsPoS is the time in milliseconds to produce blocks.
	BlockProductionIntervalMillisecondsPoS uint64

	// TimeoutIntervalMillisecondsPoS is the time in milliseconds to wait before timing out a view.
	TimeoutIntervalMillisecondsPoS uint64

	MinFeeRateNanosPerKB uint64 `safeForLogging:"true"`

	// No need to specify ProfileEntryResponse in each TransactionFee
	TransactionFees []TransactionFee `safeForLogging:"true"`

	// Can be left unset when Signature is false or if the user legitimately
	// doesn't have a password. Can also be left unset if the user has logged
	// in recently as the password will be stored in memory.
	Password string
	// Whether or not we should sign the transaction after constructing it.
	// Setting this flag to false is useful in
	// cases where the caller just wants to construct the transaction
	// to see what the fees will be, for example.
	Sign bool `safeForLogging:"true"`
	// Whether or not we should fully validate the transaction.
	Validate bool `safeForLogging:"true"`
	// Whether or not we should broadcast the transaction after constructing
	// it. This will also validate the transaction if it's set.
	Broadcast bool `safeForLogging:"true"`

	OptionalPrecedingTransactions []*lib.MsgDeSoTxn `safeForLogging:"true"`
}

// UpdateGlobalParamsResponse ...
type UpdateGlobalParamsResponse struct {
	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgDeSoTxn
	TransactionHex    string
}

func (fes *APIServer) UpdateGlobalParams(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := UpdateGlobalParamsRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateGlobalParams: Problem parsing request body: %v", err))
		return
	}

	// Decode the updater public key.
	updaterPkBytes, _, err := lib.Base58CheckDecode(requestData.UpdaterPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateGlobalParams: Problem decoding updater "+
			"base58 public key %s: %v", requestData.UpdaterPublicKeyBase58Check, err))
		return
	}

	// Compute the additional transaction fees as specified by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(lib.TxnTypeUpdateGlobalParams, updaterPkBytes, requestData.TransactionFees)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateGlobalParams: TransactionFees specified in Request body are invalid: %v", err))
		return
	}

	// Get a utxoView.
	utxoView, err := lib.GetAugmentedUniversalViewWithAdditionalTransactions(
		fes.backendServer.GetMempool(),
		requestData.OptionalPrecedingTransactions,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateGlobalParams: Error constucting utxoView: %v", err))
		return
	}

	// Only update values if they have changed. Values less than 0 are excluded from the transaction
	globalParamsEntry := utxoView.GetCurrentGlobalParamsEntry()

	usdCentsPerBitcoin := int64(-1)
	if requestData.USDCentsPerBitcoin >= 0 && uint64(requestData.USDCentsPerBitcoin) != globalParamsEntry.USDCentsPerBitcoin {
		usdCentsPerBitcoin = requestData.USDCentsPerBitcoin
	}
	createProfileFeeNanos := int64(-1)
	if requestData.CreateProfileFeeNanos >= 0 && uint64(requestData.CreateProfileFeeNanos) != globalParamsEntry.CreateProfileFeeNanos {
		createProfileFeeNanos = requestData.CreateProfileFeeNanos
	}
	createNFTFeeNanos := int64(-1)
	if requestData.CreateNFTFeeNanos >= 0 && uint64(requestData.CreateNFTFeeNanos) != globalParamsEntry.CreateNFTFeeNanos {
		createNFTFeeNanos = requestData.CreateNFTFeeNanos
	}
	minimumNetworkFeeNanosPerKb := int64(-1)
	if requestData.MinimumNetworkFeeNanosPerKB >= 0 && uint64(requestData.MinimumNetworkFeeNanosPerKB) != globalParamsEntry.MinimumNetworkFeeNanosPerKB {
		minimumNetworkFeeNanosPerKb = requestData.MinimumNetworkFeeNanosPerKB
	}

	maxCopiesPerNFT := int64(-1)
	if requestData.MaxCopiesPerNFT >= 0 && uint64(requestData.MaxCopiesPerNFT) != globalParamsEntry.MaxCopiesPerNFT {
		maxCopiesPerNFT = requestData.MaxCopiesPerNFT
	}

	maxNonceExpirationBlockHeightOffset := int64(-1)
	if requestData.MaxNonceExpirationBlockHeightOffset >= 0 && uint64(requestData.MaxNonceExpirationBlockHeightOffset) != globalParamsEntry.MaxNonceExpirationBlockHeightOffset {
		maxNonceExpirationBlockHeightOffset = requestData.MaxNonceExpirationBlockHeightOffset
	}

	extraData := make(map[string][]byte)

	// Update Proof of Stake consensus related global params if they have changed.
	if requestData.StakeLockupEpochDuration > 0 &&
		requestData.StakeLockupEpochDuration != globalParamsEntry.StakeLockupEpochDuration {
		extraData[lib.StakeLockupEpochDurationKey] = lib.UintToBuf(requestData.StakeLockupEpochDuration)
	}

	if requestData.ValidatorJailEpochDuration > 0 &&
		requestData.ValidatorJailEpochDuration != globalParamsEntry.ValidatorJailEpochDuration {
		extraData[lib.ValidatorJailEpochDurationKey] = lib.UintToBuf(requestData.ValidatorJailEpochDuration)
	}

	if requestData.LeaderScheduleMaxNumValidators > 0 &&
		requestData.LeaderScheduleMaxNumValidators != globalParamsEntry.LeaderScheduleMaxNumValidators {
		extraData[lib.LeaderScheduleMaxNumValidatorsKey] = lib.UintToBuf(requestData.LeaderScheduleMaxNumValidators)
	}

	if requestData.ValidatorSetMaxNumValidators > 0 &&
		requestData.ValidatorSetMaxNumValidators != globalParamsEntry.ValidatorSetMaxNumValidators {
		extraData[lib.ValidatorSetMaxNumValidatorsKey] = lib.UintToBuf(requestData.ValidatorSetMaxNumValidators)
	}

	if requestData.StakingRewardsMaxNumStakes > 0 &&
		requestData.StakingRewardsMaxNumStakes != globalParamsEntry.StakingRewardsMaxNumStakes {
		extraData[lib.StakingRewardsMaxNumStakesKey] = lib.UintToBuf(requestData.StakingRewardsMaxNumStakes)
	}

	if requestData.StakingRewardsAPYBasisPoints > 0 &&
		requestData.StakingRewardsAPYBasisPoints != globalParamsEntry.StakingRewardsAPYBasisPoints {
		extraData[lib.StakingRewardsAPYBasisPointsKey] = lib.UintToBuf(requestData.StakingRewardsAPYBasisPoints)
	}

	if requestData.EpochDurationNumBlocks > 0 &&
		requestData.EpochDurationNumBlocks != globalParamsEntry.EpochDurationNumBlocks {
		extraData[lib.EpochDurationNumBlocksKey] = lib.UintToBuf(requestData.EpochDurationNumBlocks)
	}

	if requestData.JailInactiveValidatorGracePeriodEpochs > 0 &&
		requestData.JailInactiveValidatorGracePeriodEpochs != globalParamsEntry.JailInactiveValidatorGracePeriodEpochs {
		extraData[lib.JailInactiveValidatorGracePeriodEpochsKey] = lib.UintToBuf(requestData.JailInactiveValidatorGracePeriodEpochs)
	}

	if requestData.MaximumVestedIntersectionsPerLockupTransaction > 0 &&
		requestData.MaximumVestedIntersectionsPerLockupTransaction != globalParamsEntry.MaximumVestedIntersectionsPerLockupTransaction {
		extraData[lib.MaximumVestedIntersectionsPerLockupTransactionKey] = lib.IntToBuf(int64(requestData.MaximumVestedIntersectionsPerLockupTransaction))
	}

	if requestData.FeeBucketGrowthRateBasisPoints > 0 &&
		requestData.FeeBucketGrowthRateBasisPoints != globalParamsEntry.FeeBucketGrowthRateBasisPoints {
		extraData[lib.FeeBucketGrowthRateBasisPointsKey] = lib.UintToBuf(requestData.FeeBucketGrowthRateBasisPoints)
	}

	if requestData.BlockTimestampDriftNanoSecs > 0 &&
		requestData.BlockTimestampDriftNanoSecs != globalParamsEntry.BlockTimestampDriftNanoSecs {
		extraData[lib.BlockTimestampDriftNanoSecsKey] = lib.IntToBuf(requestData.BlockTimestampDriftNanoSecs)
	}

	if requestData.MempoolMaxSizeBytes > 0 &&
		requestData.MempoolMaxSizeBytes != globalParamsEntry.MempoolMaxSizeBytes {
		extraData[lib.MempoolMaxSizeBytesKey] = lib.UintToBuf(requestData.MempoolMaxSizeBytes)
	}

	if requestData.MempoolFeeEstimatorNumMempoolBlocks > 0 &&
		requestData.MempoolFeeEstimatorNumMempoolBlocks != globalParamsEntry.MempoolFeeEstimatorNumMempoolBlocks {
		extraData[lib.MempoolFeeEstimatorNumMempoolBlocksKey] = lib.UintToBuf(requestData.MempoolFeeEstimatorNumMempoolBlocks)
	}

	if requestData.MempoolFeeEstimatorNumPastBlocks > 0 &&
		requestData.MempoolFeeEstimatorNumPastBlocks != globalParamsEntry.MempoolFeeEstimatorNumPastBlocks {
		extraData[lib.MempoolFeeEstimatorNumPastBlocksKey] = lib.UintToBuf(requestData.MempoolFeeEstimatorNumPastBlocks)
	}

	if requestData.MaxBlockSizeBytesPoS > 0 &&
		requestData.MaxBlockSizeBytesPoS != globalParamsEntry.MaxBlockSizeBytesPoS {
		extraData[lib.MaxBlockSizeBytesPoSKey] = lib.UintToBuf(requestData.MaxBlockSizeBytesPoS)
	}

	if requestData.SoftMaxBlockSizeBytesPoS > 0 &&
		requestData.SoftMaxBlockSizeBytesPoS != globalParamsEntry.SoftMaxBlockSizeBytesPoS {
		extraData[lib.SoftMaxBlockSizeBytesPoSKey] = lib.UintToBuf(requestData.SoftMaxBlockSizeBytesPoS)
	}

	if requestData.MaxTxnSizeBytesPoS > 0 &&
		requestData.MaxTxnSizeBytesPoS != globalParamsEntry.MaxTxnSizeBytesPoS {
		extraData[lib.MaxTxnSizeBytesPoSKey] = lib.UintToBuf(requestData.MaxTxnSizeBytesPoS)
	}

	if requestData.BlockProductionIntervalMillisecondsPoS > 0 &&
		requestData.BlockProductionIntervalMillisecondsPoS != globalParamsEntry.BlockProductionIntervalMillisecondsPoS {
		extraData[lib.BlockProductionIntervalPoSKey] = lib.UintToBuf(requestData.BlockProductionIntervalMillisecondsPoS)
	}

	if requestData.TimeoutIntervalMillisecondsPoS > 0 &&
		requestData.TimeoutIntervalMillisecondsPoS != globalParamsEntry.TimeoutIntervalMillisecondsPoS {
		extraData[lib.TimeoutIntervalPoSKey] = lib.UintToBuf(requestData.TimeoutIntervalMillisecondsPoS)
	}

	// Try and create the update txn for the user.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateUpdateGlobalParamsTxn(
		updaterPkBytes,
		usdCentsPerBitcoin,
		createProfileFeeNanos,
		createNFTFeeNanos,
		maxCopiesPerNFT,
		minimumNetworkFeeNanosPerKb,
		[]byte{},
		maxNonceExpirationBlockHeightOffset,
		extraData,
		requestData.MinFeeRateNanosPerKB,
		fes.backendServer.GetMempool(), additionalOutputs)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateGlobalParams: Problem creating transaction: %v", err))
		return
	}

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateGlobalParams: Problem serializing transaction: %v", err))
		return
	}

	// Return all the data associated with the transaction in the response
	res := UpdateGlobalParamsResponse{
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateGlobalParams: Problem encoding response as JSON: %v", err))
		return
	}
}

// SwapIdentityRequest ...
type SwapIdentityRequest struct {
	// This is currently paramUpdater only
	UpdaterPublicKeyBase58Check string `safeForLogging:"true"`

	// Either a username or a public key works. If it starts with BC and
	// is over the username limit it will be interpreted as a username.
	FromUsernameOrPublicKeyBase58Check string `safeForLogging:"true"`

	// Either a username or a public key works. If it starts with BC and
	//	// is over the username limit it will be interpreted as a username.
	ToUsernameOrPublicKeyBase58Check string `safeForLogging:"true"`

	MinFeeRateNanosPerKB uint64 `safeForLogging:"true"`

	// No need to specify ProfileEntryResponse in each TransactionFee
	TransactionFees []TransactionFee `safeForLogging:"true"`

	OptionalPrecedingTransactions []*lib.MsgDeSoTxn `safeForLogging:"true"`
}

// SwapIdentityResponse ...
type SwapIdentityResponse struct {
	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgDeSoTxn
	TransactionHex    string
}

func (fes *APIServer) getPublicKeyFromUsernameOrPublicKeyString(
	usernameOrPublicKey string,
	optionalPrecedingTransactions []*lib.MsgDeSoTxn,
) (
	[]byte,
	error,
) {
	if (strings.HasPrefix(usernameOrPublicKey, fes.PublicKeyBase58Prefix)) &&
		len(usernameOrPublicKey) >= btcec.PubKeyBytesLenCompressed {

		// In this case parse the string as a public key.
		var err error
		fromPublicKey, _, err := lib.Base58CheckDecode(usernameOrPublicKey)
		if err != nil {
			return nil, errors.Wrap(err, "getPublicKeyFromUsernameOrPublicKeyString: ")
		}
		return fromPublicKey, nil
	}

	// Otherwise, parse the string as a username
	utxoView, err := lib.GetAugmentedUniversalViewWithAdditionalTransactions(
		fes.backendServer.GetMempool(),
		optionalPrecedingTransactions,
	)
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf("getPublicKeyFromUsernameOrPublicKeyString: Error generating "+
			"view to verify username: %v", err), "")
	}
	profileEntry := utxoView.GetProfileEntryForUsername([]byte(usernameOrPublicKey))
	if profileEntry == nil {
		return nil, errors.Wrap(
			fmt.Errorf("getPublicKeyFromUsernameOrPublicKeyString: Profile with username %v does not exist",
				usernameOrPublicKey), "")
	}

	return profileEntry.PublicKey, nil
}

// SwapIdentity ...
func (fes *APIServer) SwapIdentity(ww http.ResponseWriter, req *http.Request) {

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := SwapIdentityRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SwapIdentity: Problem parsing request body: %v", err))
		return
	}

	// Decode the updater public key.
	updaterPkBytes, _, err := lib.Base58CheckDecode(requestData.UpdaterPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SwapIdentity: Problem decoding updater "+
			"base58 public key %s: %v", requestData.UpdaterPublicKeyBase58Check, err))
		return
	}

	// Compute the additional transaction fees as specified by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(lib.TxnTypeSwapIdentity, updaterPkBytes, requestData.TransactionFees)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SwapIdentity: TransactionFees specified in Request body are invalid: %v", err))
		return
	}

	fromPublicKey, err := fes.getPublicKeyFromUsernameOrPublicKeyString(
		requestData.FromUsernameOrPublicKeyBase58Check, requestData.OptionalPrecedingTransactions)
	if err != nil {
		_AddBadRequestError(ww, err.Error())
		return
	}
	toPublicKey, err := fes.getPublicKeyFromUsernameOrPublicKeyString(
		requestData.ToUsernameOrPublicKeyBase58Check, requestData.OptionalPrecedingTransactions)
	if err != nil {
		_AddBadRequestError(ww, err.Error())
		return
	}

	// Try and create the update txn for the user.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateSwapIdentityTxn(
		updaterPkBytes,
		fromPublicKey,
		toPublicKey,

		requestData.MinFeeRateNanosPerKB,
		fes.backendServer.GetMempool(), additionalOutputs)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SwapIdentity: Problem creating transaction: %v", err))
		return
	}

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SwapIdentity: Problem serializing transaction: %v", err))
		return
	}

	// Return all the data associated with the transaction in the response
	res := SwapIdentityResponse{
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SwapIdentity: Problem encoding response as JSON: %v", err))
		return
	}
}

// TestSignTransactionWithDerivedKeyRequest ...
type TestSignTransactionWithDerivedKeyRequest struct {
	// Transaction hex.
	TransactionHex string `safeForLogging:"true"`

	// Derived private key in base58Check.
	DerivedKeySeedHex string `safeForLogging:"false"`
}

// TestSignTransactionWithDerivedKeyResponse ...
type TestSignTransactionWithDerivedKeyResponse struct {
	// Signed Transaction hex.
	TransactionHex string `safeForLogging:"true"`
}

// TestSignTransactionWithDerivedKey ...
// This endpoint must not be used by a frontend in a production environment,
// instead it is meant to serve as a debugging tool as well as an example of
// how to properly sign transactions with a derived key.
func (fes *APIServer) TestSignTransactionWithDerivedKey(ww http.ResponseWriter, req *http.Request) {

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := TestSignTransactionWithDerivedKeyRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("TestSignTransactionWithDerivedKey: Problem parsing request body: %v", err))
		return
	}

	// Get the transaction bytes from the request data.
	txnBytes, err := hex.DecodeString(requestData.TransactionHex)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("TestSignTransactionWithDerivedKey: Problem decoding transaction hex %v", err))
		return
	}

	// Get the derived private key from the request data.
	privBytes, err := hex.DecodeString(requestData.DerivedKeySeedHex)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("TestSignTransactionWithDerivedKey: Problem decoding seed hex %v", err))
		return
	}
	privKeyBytes, _ := btcec.PrivKeyFromBytes(btcec.S256(), privBytes)

	// Sign the transaction with a derived key. Since the txn extraData must be modified,
	// we also get new transaction bytes, along with the signature.
	newTxnBytes, txnSignatureBytes, err := lib.SignTransactionBytes(txnBytes, privKeyBytes, true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("TestSignTransactionWithDerivedKey: Problem signing transaction: %v", err))
		return
	}

	// The response will contain the new transaction bytes and a signature.
	var signedTransactionHex []byte
	signedTransactionHex = newTxnBytes[0 : len(newTxnBytes)-1]
	signedTransactionHex = append(signedTransactionHex, lib.UintToBuf(uint64(len(txnSignatureBytes)))...)
	signedTransactionHex = append(signedTransactionHex, txnSignatureBytes...)
	res := TestSignTransactionWithDerivedKeyResponse{
		TransactionHex: hex.EncodeToString(signedTransactionHex),
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("TestSignTransactionWithDerivedKey: Problem encoding response as JSON: %v", err))
		return
	}
}
