package routes

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections"
	"github.com/deso-protocol/core/lib"
	"github.com/gorilla/mux"
	"github.com/holiman/uint256"
)

type RegisterAsValidatorRequest struct {
	TransactorPublicKeyBase58Check      string            `safeForLogging:"true"`
	Domains                             []string          `safeForLogging:"true"`
	DisableDelegatedStake               bool              `safeForLogging:"true"`
	DelegatedStakeCommissionBasisPoints uint64            `safeForLogging:"true"`
	VotingPublicKey                     string            `safeForLogging:"true"`
	VotingAuthorization                 string            `safeForLogging:"true"`
	ExtraData                           map[string]string `safeForLogging:"true"`
	MinFeeRateNanosPerKB                uint64            `safeForLogging:"true"`
	TransactionFees                     []TransactionFee  `safeForLogging:"true"`
}

type UnregisterAsValidatorRequest struct {
	TransactorPublicKeyBase58Check string            `safeForLogging:"true"`
	ExtraData                      map[string]string `safeForLogging:"true"`
	MinFeeRateNanosPerKB           uint64            `safeForLogging:"true"`
	TransactionFees                []TransactionFee  `safeForLogging:"true"`
}

type UnjailValidatorRequest struct {
	TransactorPublicKeyBase58Check string            `safeForLogging:"true"`
	ExtraData                      map[string]string `safeForLogging:"true"`
	MinFeeRateNanosPerKB           uint64            `safeForLogging:"true"`
	TransactionFees                []TransactionFee  `safeForLogging:"true"`
}

type ValidatorTxnResponse struct {
	SpendAmountNanos  uint64
	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgDeSoTxn
	TransactionHex    string
	TxnHashHex        string
}

type ValidatorResponse struct {
	ValidatorPublicKeyBase58Check       string
	Domains                             []string
	DisableDelegatedStake               bool
	DelegatedStakeCommissionBasisPoints uint64
	VotingPublicKey                     string
	VotingAuthorization                 string
	TotalStakeAmountNanos               *uint256.Int
	Status                              string
	LastActiveAtEpochNumber             uint64
	JailedAtEpochNumber                 uint64
	ExtraData                           map[string]string
}

func (fes *APIServer) RegisterAsValidator(ww http.ResponseWriter, req *http.Request) {
	// Decode request body.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := RegisterAsValidatorRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, "RegisterAsValidator: problem parsing request body")
		return
	}

	// Convert TransactorPublicKeyBase58Check to TransactorPublicKeyBytes.
	if requestData.TransactorPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, "RegisterAsValidator: must provide a TransactorPublicKeyBase58Check")
		return
	}
	transactorPublicKeyBytes, err := GetPubKeyBytesFromBase58Check(requestData.TransactorPublicKeyBase58Check)
	if err != nil {
		_AddInternalServerError(ww, "RegisterAsValidator: problem getting public key for the transactor")
		return
	}

	// Convert Domains from []string to [][]byte.
	var domains [][]byte
	for _, domain := range requestData.Domains {
		domains = append(domains, []byte(domain))
	}

	// Convert VotingPublicKeyString to VotingPublicKey.
	votingPublicKey, err := (&bls.PublicKey{}).FromString(requestData.VotingPublicKey)
	if err != nil {
		_AddBadRequestError(ww, "RegisterAsValidator: problem parsing VotingPublicKey")
		return
	}

	// Convert VotingAuthorizationString to VotingAuthorization.
	votingAuthorization, err := (&bls.Signature{}).FromString(requestData.VotingAuthorization)
	if err != nil {
		_AddBadRequestError(ww, "RegisterAsValidator: problem parsing VotingAuthorization")
		return
	}

	// Parse ExtraData.
	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, "RegisterAsValidator: invalid ExtraData provided")
		return
	}

	// Compute the additional transaction fees as specified
	// by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(
		lib.TxnTypeRegisterAsValidator,
		transactorPublicKeyBytes,
		requestData.TransactionFees,
	)
	if err != nil {
		_AddBadRequestError(ww, "RegisterAsValidator: specified TransactionFees are invalid")
		return
	}

	// Create transaction.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateRegisterAsValidatorTxn(
		transactorPublicKeyBytes,
		&lib.RegisterAsValidatorMetadata{
			Domains:                             domains,
			DisableDelegatedStake:               requestData.DisableDelegatedStake,
			DelegatedStakeCommissionBasisPoints: requestData.DelegatedStakeCommissionBasisPoints,
			VotingPublicKey:                     votingPublicKey,
			VotingAuthorization:                 votingAuthorization,
		},
		extraData,
		requestData.MinFeeRateNanosPerKB,
		fes.backendServer.GetMempool(),
		additionalOutputs,
	)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("RegisterAsValidator: problem creating txn: %v", err))
		return
	}

	// Construct response.
	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddInternalServerError(ww, "RegisterAsValidator: problem encoding txn to bytes")
		return
	}
	res := ValidatorTxnResponse{
		SpendAmountNanos:  totalInput - changeAmount - fees,
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
		TxnHashHex:        txn.Hash().String(),
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, "RegisterAsValidator: problem encoding response as JSON")
		return
	}
}

func (fes *APIServer) UnregisterAsValidator(ww http.ResponseWriter, req *http.Request) {
	// Decode request body.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := UnregisterAsValidatorRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, "UnregisterAsValidator: problem parsing request body")
		return
	}

	// Convert TransactorPublicKeyBase58Check to TransactorPublicKeyBytes.
	if requestData.TransactorPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, "UnregisterAsValidator: must provide a TransactorPublicKeyBase58Check")
		return
	}
	transactorPublicKeyBytes, err := GetPubKeyBytesFromBase58Check(requestData.TransactorPublicKeyBase58Check)
	if err != nil {
		_AddInternalServerError(ww, "UnregisterAsValidator: problem getting public key for the transactor")
		return
	}

	// Parse ExtraData.
	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, "UnregisterAsValidator: invalid ExtraData provided")
		return
	}

	// Compute the additional transaction fees as specified
	// by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(
		lib.TxnTypeRegisterAsValidator,
		transactorPublicKeyBytes,
		requestData.TransactionFees,
	)
	if err != nil {
		_AddBadRequestError(ww, "UnregisterAsValidator: specified TransactionFees are invalid")
		return
	}

	// Create transaction.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateUnregisterAsValidatorTxn(
		transactorPublicKeyBytes,
		&lib.UnregisterAsValidatorMetadata{},
		extraData,
		requestData.MinFeeRateNanosPerKB,
		fes.backendServer.GetMempool(),
		additionalOutputs,
	)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("UnregisterAsValidator: problem creating txn: %v", err))
		return
	}

	// Construct response.
	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddInternalServerError(ww, "UnregisterAsValidator: problem encoding txn to bytes")
		return
	}
	res := ValidatorTxnResponse{
		SpendAmountNanos:  totalInput - changeAmount - fees,
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
		TxnHashHex:        txn.Hash().String(),
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, "UnregisterAsValidator: problem encoding response as JSON")
		return
	}
}

func (fes *APIServer) UnjailValidator(ww http.ResponseWriter, req *http.Request) {
	// Decode request body.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := UnjailValidatorRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, "UnjailValidator: problem parsing request body")
		return
	}

	// Convert TransactorPublicKeyBase58Check to TransactorPublicKeyBytes.
	if requestData.TransactorPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, "UnjailValidator: must provide a TransactorPublicKeyBase58Check")
		return
	}
	transactorPublicKeyBytes, err := GetPubKeyBytesFromBase58Check(requestData.TransactorPublicKeyBase58Check)
	if err != nil {
		_AddInternalServerError(ww, "UnjailValidator: problem getting public key for the transactor")
		return
	}

	// Parse ExtraData.
	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, "UnjailValidator: invalid ExtraData provided")
		return
	}

	// Compute the additional transaction fees as specified
	// by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(
		lib.TxnTypeUnjailValidator,
		transactorPublicKeyBytes,
		requestData.TransactionFees,
	)
	if err != nil {
		_AddBadRequestError(ww, "UnjailValidator: specified TransactionFees are invalid")
		return
	}

	// Create transaction.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateUnjailValidatorTxn(
		transactorPublicKeyBytes,
		&lib.UnjailValidatorMetadata{},
		extraData,
		requestData.MinFeeRateNanosPerKB,
		fes.backendServer.GetMempool(),
		additionalOutputs,
	)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("UnjailValidator: problem creating txn: %v", err))
		return
	}

	// Construct response.
	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddInternalServerError(ww, "UnjailValidator: problem encoding txn to bytes")
		return
	}
	res := ValidatorTxnResponse{
		SpendAmountNanos:  totalInput - changeAmount - fees,
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
		TxnHashHex:        txn.Hash().String(),
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, "UnjailValidator: problem encoding response as JSON")
		return
	}
}

func (fes *APIServer) GetValidatorByPublicKeyBase58Check(ww http.ResponseWriter, req *http.Request) {
	// Parse ValidatorPublicKeyBase58Check from URL.
	vars := mux.Vars(req)
	validatorPublicKeyBase58Check, exists := vars["publicKeyBase58Check"]
	if !exists {
		_AddBadRequestError(ww, "GetValidatorByPublicKeyBase58Check: must provide a ValidatorPublicKeyBase58Check")
		return
	}

	// Create UTXO view.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddInternalServerError(ww, "GetValidatorByPublicKeyBase58Check: problem getting UTXO view")
		return
	}

	// Convert ValidatorPublicKeyBase58Check to ValidatorPKID.
	validatorPKID, err := fes.getPKIDFromPublicKeyBase58Check(utxoView, validatorPublicKeyBase58Check)
	if err != nil || validatorPKID == nil {
		_AddInternalServerError(ww, "GetValidatorByPublicKeyBase58Check: problem retrieving validator PKID")
		return
	}

	// Get validator by PKID.
	validatorEntry, err := utxoView.GetValidatorByPKID(validatorPKID)
	if err != nil {
		_AddInternalServerError(ww, "GetValidatorByPublicKeyBase58Check: problem retrieving validator")
		return
	}
	if validatorEntry == nil {
		_AddNotFoundError(ww, "GetValidatorByPublicKeyBase58Check: validator not found")
		return
	}

	// Encode response.
	validatorResponse := _convertValidatorEntryToResponse(utxoView, validatorEntry, fes.Params)
	if err = json.NewEncoder(ww).Encode(validatorResponse); err != nil {
		_AddInternalServerError(ww, "GetValidatorByPublicKeyBase58Check: problem encoding response as JSON")
		return
	}
}

// GetCurrentEpochProgressResponse encodes the current epoch entry, the leader schedule for it, and the
// progress throughout the epoch. Based on the data returned, the client can determine the chain's
// progress through the epoch, the current leader and all upcoming leaders.
type GetEpochProgressResponse struct {
	// The full epoch entry object
	EpochEntry     lib.EpochEntry  `safeForLogging:"true"`
	LeaderSchedule []UserInfoBasic `safeForLogging:"true"`

	CurrentView      uint64        `safeForLogging:"true"`
	CurrentTipHeight uint64        `safeForLogging:"true"`
	CurrentLeader    UserInfoBasic `safeForLogging:"true"`
}

type UserInfoBasic struct {
	PublicKeyBase58Check string `safeForLogging:"true"`
	Username             string `safeForLogging:"true"`
}

func (fes *APIServer) GetCurrentEpochProgress(ww http.ResponseWriter, req *http.Request) {
	// Fetch the current snapshot from the blockchain. We use the latest uncommitted tip.
	utxoView, err := fes.backendServer.GetBlockchain().GetUncommittedTipView()
	if err != nil {
		_AddInternalServerError(ww, "GetCurrentEpochProgress: problem fetching uncommitted tip")
		return
	}

	// Get the current epoch number.
	currentEpochEntry, err := utxoView.GetCurrentEpochEntry()
	if err != nil {
		_AddInternalServerError(ww, "GetCurrentEpochProgress: problem fetching current epoch number")
		return
	}

	// Get the current uncommitted tip.
	currentTip := fes.backendServer.GetBlockchain().BlockTip()

	// Get the leader schedule for the current snapshot epoch.
	leaderSchedulePKIDs, err := utxoView.GetCurrentSnapshotLeaderSchedule()
	if err != nil {
		_AddInternalServerError(ww, "GetCurrentEpochProgress: problem fetching current snapshot epoch number")
		return
	}

	// Fetch the leader schedule for the current epoch. For each leader in the schedule, we fetch
	// the public key and username associated with the leader's PKID.
	leaderSchedule := collections.Transform(leaderSchedulePKIDs, func(pkid *lib.PKID) UserInfoBasic {
		publicKey := utxoView.GetPublicKeyForPKID(pkid)
		publicKeyBase58Check := lib.Base58CheckEncode(publicKey, false, fes.Params)

		// Fetch the profile entry for the leader's PKID.
		profileEntry := utxoView.GetProfileEntryForPKID(pkid)
		if profileEntry == nil {
			// If the user has no profile, then we return an empty username.
			return UserInfoBasic{PublicKeyBase58Check: publicKeyBase58Check, Username: ""}
		}

		// Happy path: we have both a username and a public key for the leader.
		return UserInfoBasic{PublicKeyBase58Check: publicKeyBase58Check, Username: string(profileEntry.Username)}
	})

	// By default, set the current View to the tip block's view. The GetView() function is safe to use
	// whether we are on PoW or PoS.
	currentView := currentTip.Header.GetView()

	// Try to fetch the current Fast-HotStuff view. If the server is running the Fast-HotStuff consensus,
	// then this will return a non-zero value. This value always overrides the tip block's current view.
	fastHotStuffConsensusView := fes.backendServer.GetLatestView()
	if fastHotStuffConsensusView != 0 {
		currentView = fastHotStuffConsensusView
	}

	// If the current tip is at or past the final PoW block height, but we don't have a view returned by the
	// Fast-HotStuff consensus, then we can estimate the current view based on the Fast-HotStuff rules. This
	// is the best fallback value we can use once the chain has transitioned to PoS.
	if currentView == 0 && currentTip.Header.Height >= fes.Params.GetFinalPoWBlockHeight() {
		timeoutDuration := time.Duration(utxoView.GetCurrentGlobalParamsEntry().TimeoutIntervalMillisecondsPoS) * time.Millisecond
		currentTipTimestamp := time.Unix(0, currentTip.Header.TstampNanoSecs)
		currentView = currentTip.Header.GetView() + estimateNumTimeoutsSinceTip(time.Now(), currentTipTimestamp, timeoutDuration)
	}

	currentLeaderIdx := (currentEpochEntry.InitialLeaderIndexOffset +
		(currentView - currentEpochEntry.InitialView) -
		(currentTip.Header.Height - currentEpochEntry.InitialBlockHeight)) % uint64(len(leaderSchedule))
	currentLeader := leaderSchedule[currentLeaderIdx]

	// Construct the response
	response := GetEpochProgressResponse{
		EpochEntry:       *currentEpochEntry,
		LeaderSchedule:   leaderSchedule,
		CurrentView:      currentView,
		CurrentTipHeight: currentTip.Header.Height,
		CurrentLeader:    currentLeader,
	}

	// Encode response.
	if err = json.NewEncoder(ww).Encode(response); err != nil {
		_AddInternalServerError(ww, "GetValidatorByPublicKeyBase58Check: problem encoding response as JSON")
		return
	}
}

// estimateNumTimeoutsSinceTip computes the number for PoS timeouts that have occurred since a tip block
// with the provided timestamp. It simulates the same math as in consensus and works whether the current
// node is running a PoS validator or not.
//
// Examples:
// - Current time = 8:59:00, tip time = 09:00:00, timeout duration = 1 min => 0 timeouts
// - Current time = 9:00:00, tip time = 09:00:00, timeout duration = 1 min => 0 timeouts
// - Current time = 9:01:00, tip time = 09:00:00, timeout duration = 1 min => 1 timeout
// - Current time = 9:02:00, tip time = 09:00:00, timeout duration = 1 min => 1 timeout
// - Current time = 9:03:00, tip time = 09:00:00, timeout duration = 1 min + 2 mins => 2 timeout
// - Current time = 9:05:00, tip time = 09:00:00, timeout duration = 1 min + 2 mins => 2 timeout
// - Current time = 9:07:00, tip time = 09:00:00, timeout duration = 1 min + 2 mins + 4 mins => 3 timeout
// - Current time = 9:14:59, tip time = 09:00:00, timeout duration = 1 min + 2 mins + 4 mins => 3 timeout
// - Current time = 9:15:00, tip time = 09:00:00, timeout duration = 1 min + 2 mins + 4 mins + 8 mins => 4 timeout
func estimateNumTimeoutsSinceTip(currentTimestamp time.Time, tipTimestamp time.Time, timeoutDuration time.Duration) uint64 {
	// Count the number of timeouts.
	numTimeouts := uint64(0)

	// The first timeout occurs after the timeout duration elapses starting from the tip's
	// timestamp. We use the updated timestamp as the starting time for the first timeout.
	tipTimestampAndTimeouts := tipTimestamp.Add(timeoutDuration)

	// Once the tip timestamp + cumulative timeout exceed the current time, then we have found
	// the exact number of timeouts that have elapsed
	for tipTimestampAndTimeouts.Compare(currentTimestamp) <= 0 {
		// The timeout duration doubles on every timeout.
		timeoutDuration *= 2

		// The next timeout occurs after the timeout duration elapses after the previous timeout.
		tipTimestampAndTimeouts = tipTimestampAndTimeouts.Add(timeoutDuration)

		// Increment the number of timeouts.
		numTimeouts++
	}

	return numTimeouts
}

type CheckNodeStatusRequest struct {
	NodeHostPort string `safeForLogging:"true"`
}

type CheckNodeStatusResponse struct {
	Success bool `safeForLogging:"true"`
}

func (fes *APIServer) CheckNodeStatus(ww http.ResponseWriter, req *http.Request) {
	// Decode request body.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := CheckNodeStatusRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, "UnjailValidator: problem parsing request body")
		return
	}

	// We do an *extremely* simple check for now, which is that we just check to see if the node
	// is reachable at all.
	// TODO: We should beef this up to test an actual version handshake or something more robust.
	conn, err := net.DialTimeout("tcp", requestData.NodeHostPort, 5*time.Second)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"Problem connecting to %v: %v", requestData.NodeHostPort, err))
		return
	}
	// If we get here it means we succeeded. Close the connection to clean up.
	conn.Close()

	res := CheckNodeStatusResponse{
		Success: true,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, "UnjailValidator: problem encoding response as JSON")
		return
	}
}

func _convertValidatorEntryToResponse(
	utxoView *lib.UtxoView, validatorEntry *lib.ValidatorEntry, params *lib.DeSoParams,
) *ValidatorResponse {
	// Nil check: this should never happen but just to be safe.
	if validatorEntry == nil {
		return &ValidatorResponse{}
	}

	// Convert ValidatorPKID to ValidatorPublicKeyBase58Check.
	validatorPublicKeyBase58Check := lib.Base58CheckEncode(
		utxoView.GetPublicKeyForPKID(validatorEntry.ValidatorPKID), false, params,
	)

	// Convert Domains [][]byte to []string.
	var domains []string
	for _, domain := range validatorEntry.Domains {
		domains = append(domains, string(domain))
	}

	// Convert ValidatorEntry to ValidatorResponse.
	return &ValidatorResponse{
		ValidatorPublicKeyBase58Check:       validatorPublicKeyBase58Check,
		Domains:                             domains,
		DisableDelegatedStake:               validatorEntry.DisableDelegatedStake,
		DelegatedStakeCommissionBasisPoints: validatorEntry.DelegatedStakeCommissionBasisPoints,
		VotingPublicKey:                     validatorEntry.VotingPublicKey.ToString(),
		VotingAuthorization:                 validatorEntry.VotingAuthorization.ToString(),
		TotalStakeAmountNanos:               validatorEntry.TotalStakeAmountNanos.Clone(),
		Status:                              validatorEntry.Status().ToString(),
		LastActiveAtEpochNumber:             validatorEntry.LastActiveAtEpochNumber,
		JailedAtEpochNumber:                 validatorEntry.JailedAtEpochNumber,
		ExtraData:                           DecodeExtraDataMap(params, utxoView, validatorEntry.ExtraData),
	}
}
