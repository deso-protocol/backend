package routes

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/deso-protocol/core/lib"
	"github.com/gorilla/mux"
	"io"
	"net/http"
)

// ------------
// Constants
// ------------

// This is the maximum number of associations that can be retrieved in a single
// Get{User|Post}Associations request. The client can always paginate through
// results using the LastSeenAssociationID field and additional requests.
const MaxAssociationsPerQueryLimit = 100

// This is the maximum number of AssociationValues that can be retrieved in a
// single Get{User|Post}Associations or Count{User|Post}Associations request.
// The client can always send multiple requests to retrieve additional
// associations or counts.
const MaxAssociationValuesPerQueryLimit = 12

// ------------
// Types
// ------------

type CreateUserAssociationRequest struct {
	TransactorPublicKeyBase58Check string            `safeForLogging:"true"`
	TargetUserPublicKeyBase58Check string            `safeForLogging:"true"`
	AppPublicKeyBase58Check        string            `safeForLogging:"true"`
	AssociationType                string            `safeForLogging:"true"`
	AssociationValue               string            `safeForLogging:"true"`
	ExtraData                      map[string]string `safeForLogging:"true"`
	MinFeeRateNanosPerKB           uint64            `safeForLogging:"true"`
	TransactionFees                []TransactionFee  `safeForLogging:"true"`
}

type UserAssociationQuery struct {
	TransactorPublicKeyBase58Check string   `safeForLogging:"true"`
	TargetUserPublicKeyBase58Check string   `safeForLogging:"true"`
	AppPublicKeyBase58Check        string   `safeForLogging:"true"`
	AssociationType                string   `safeForLogging:"true"`
	AssociationTypePrefix          string   `safeForLogging:"true"`
	AssociationValue               string   `safeForLogging:"true"`
	AssociationValuePrefix         string   `safeForLogging:"true"`
	AssociationValues              []string `safeForLogging:"true"`
	Limit                          int      `safeForLogging:"true"`
	LastSeenAssociationID          string   `safeForLogging:"true"`
	SortDescending                 bool     `safeForLogging:"true"`
}

type UserAssociationResponse struct {
	AssociationID                  string            `safeForLogging:"true"`
	TransactorPublicKeyBase58Check string            `safeForLogging:"true"`
	TargetUserPublicKeyBase58Check string            `safeForLogging:"true"`
	AppPublicKeyBase58Check        string            `safeForLogging:"true"`
	AssociationType                string            `safeForLogging:"true"`
	AssociationValue               string            `safeForLogging:"true"`
	ExtraData                      map[string]string `safeForLogging:"true"`
	BlockHeight                    uint32            `safeForLogging:"true"`
}

type UserAssociationsResponse struct {
	Associations []*UserAssociationResponse
}

type CreatePostAssociationRequest struct {
	TransactorPublicKeyBase58Check string            `safeForLogging:"true"`
	PostHashHex                    string            `safeForLogging:"true"`
	AppPublicKeyBase58Check        string            `safeForLogging:"true"`
	AssociationType                string            `safeForLogging:"true"`
	AssociationValue               string            `safeForLogging:"true"`
	ExtraData                      map[string]string `safeForLogging:"true"`
	MinFeeRateNanosPerKB           uint64            `safeForLogging:"true"`
	TransactionFees                []TransactionFee  `safeForLogging:"true"`
}

type PostAssociationQuery struct {
	TransactorPublicKeyBase58Check string   `safeForLogging:"true"`
	PostHashHex                    string   `safeForLogging:"true"`
	AppPublicKeyBase58Check        string   `safeForLogging:"true"`
	AssociationType                string   `safeForLogging:"true"`
	AssociationTypePrefix          string   `safeForLogging:"true"`
	AssociationValue               string   `safeForLogging:"true"`
	AssociationValuePrefix         string   `safeForLogging:"true"`
	AssociationValues              []string `safeForLogging:"true"`
	Limit                          int      `safeForLogging:"true"`
	LastSeenAssociationID          string   `safeForLogging:"true"`
	SortDescending                 bool     `safeForLogging:"true"`
}

type PostAssociationResponse struct {
	AssociationID                  string            `safeForLogging:"true"`
	TransactorPublicKeyBase58Check string            `safeForLogging:"true"`
	PostHashHex                    string            `safeForLogging:"true"`
	AppPublicKeyBase58Check        string            `safeForLogging:"true"`
	AssociationType                string            `safeForLogging:"true"`
	AssociationValue               string            `safeForLogging:"true"`
	ExtraData                      map[string]string `safeForLogging:"true"`
	BlockHeight                    uint32            `safeForLogging:"true"`
}

type PostAssociationsResponse struct {
	Associations []*PostAssociationResponse
}

type DeleteAssociationRequest struct {
	TransactorPublicKeyBase58Check string            `safeForLogging:"true"`
	AssociationID                  string            `safeForLogging:"true"`
	ExtraData                      map[string]string `safeForLogging:"true"`
	MinFeeRateNanosPerKB           uint64            `safeForLogging:"true"`
	TransactionFees                []TransactionFee  `safeForLogging:"true"`
}

type AssociationTxnResponse struct {
	SpendAmountNanos  uint64
	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgDeSoTxn
	TransactionHex    string
	TxnHashHex        string
}

type AssociationsCountResponse struct {
	Count uint64
}

type AssociationCountsReponse struct {
	Counts map[string]uint64
	Total  uint64
}

type AssociationQueryType uint8

const (
	AssociationQueryTypeQuery        AssociationQueryType = 0
	AssociationQueryTypeCount        AssociationQueryType = 1
	AssociationQueryTypeCountByValue AssociationQueryType = 2
)

// ------------
// Routes
// ------------

func (fes *APIServer) CreateUserAssociation(ww http.ResponseWriter, req *http.Request) {
	// Decode request body.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := CreateUserAssociationRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, "CreateUserAssociation: problem parsing request body")
		return
	}

	// Parse TransactorPublicKeyBytes from TransactorPublicKeyBase58Check.
	if requestData.TransactorPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, "CreateUserAssociation: must provide a TransactorPublicKeyBase58Check")
		return
	}
	transactorPublicKeyBytes, err := GetPubKeyBytesFromBase58Check(requestData.TransactorPublicKeyBase58Check)
	if err != nil {
		_AddInternalServerError(ww, "CreateUserAssociation: problem getting public key for the transactor")
		return
	}

	// Parse TargetUserPublicKeyBytes from TargetUserPublicKeyBase58Check.
	if requestData.TargetUserPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, "CreateUserAssociation: must provide a TargetUserPublicKeyBase58Check")
		return
	}
	targetUserPublicKeyBytes, err := GetPubKeyBytesFromBase58Check(requestData.TargetUserPublicKeyBase58Check)
	if err != nil {
		_AddInternalServerError(ww, "CreateUserAssociation: problem getting public key for the target user")
		return
	}

	// Parse AppPublicKeyBytes from AppPublicKeyBase58Check.
	// If not provided, we default to the ZeroPublicKey (global).
	appPublicKeyBytes := lib.ZeroPublicKey.ToBytes()
	if requestData.AppPublicKeyBase58Check != "" {
		appPublicKeyBytes, err = GetPubKeyBytesFromBase58Check(requestData.AppPublicKeyBase58Check)
		if err != nil {
			_AddInternalServerError(ww, "CreateUserAssociation: problem getting public key for the app")
			return
		}
	}

	// Validate AssociationType.
	if requestData.AssociationType == "" {
		_AddBadRequestError(ww, "CreateUserAssociation: must provide an AssociationType")
		return
	}

	// Validate AssociationValue.
	if requestData.AssociationValue == "" {
		_AddBadRequestError(ww, "CreateUserAssociation: must provide an AssociationValue")
		return
	}

	// Parse ExtraData.
	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, "CreateUserAssociation: invalid ExtraData provided")
		return
	}

	// Compute the additional transaction fees as specified
	// by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(
		lib.TxnTypeCreateUserAssociation,
		transactorPublicKeyBytes,
		requestData.TransactionFees,
	)
	if err != nil {
		_AddBadRequestError(ww, "CreateUserAssociation: specified TransactionFees are invalid")
		return
	}

	// Create transaction.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateCreateUserAssociationTxn(
		transactorPublicKeyBytes,
		&lib.CreateUserAssociationMetadata{
			TargetUserPublicKey: lib.NewPublicKey(targetUserPublicKeyBytes),
			AppPublicKey:        lib.NewPublicKey(appPublicKeyBytes),
			AssociationType:     []byte(requestData.AssociationType),
			AssociationValue:    []byte(requestData.AssociationValue),
		},
		extraData,
		requestData.MinFeeRateNanosPerKB,
		fes.backendServer.GetMempool(),
		additionalOutputs,
	)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("CreateUserAssociation: problem creating txn: %v", err))
		return
	}

	// Construct response.
	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddInternalServerError(ww, "CreateUserAssociation: problem encoding txn to bytes")
		return
	}
	res := AssociationTxnResponse{
		SpendAmountNanos:  totalInput - changeAmount - fees,
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
		TxnHashHex:        txn.Hash().String(),
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, "CreateUserAssociation: problem encoding response as JSON")
		return
	}
}

func (fes *APIServer) DeleteUserAssociation(ww http.ResponseWriter, req *http.Request) {
	// Decode request body.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := DeleteAssociationRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, "DeleteUserAssociation: problem parsing request body")
		return
	}

	// Parse TransactorPublicKeyBytes from TransactorPublicKeyBase58Check.
	if requestData.TransactorPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, "DeleteUserAssociation: must provide a TransactorPublicKeyBase58Check")
		return
	}
	transactorPublicKeyBytes, err := GetPubKeyBytesFromBase58Check(requestData.TransactorPublicKeyBase58Check)
	if err != nil {
		_AddInternalServerError(ww, "DeleteUserAssociation: problem getting public key for the transactor")
		return
	}

	// Parse AssociationIDBytes from AssociationID (hex string).
	if requestData.AssociationID == "" {
		_AddBadRequestError(ww, "DeleteUserAssociation: must provide an AssociationID")
		return
	}
	associationIdBytes, err := hex.DecodeString(requestData.AssociationID)
	if err != nil {
		_AddBadRequestError(ww, "DeleteUserAssociation: invalid AssociationID provided")
		return
	}

	// Parse ExtraData.
	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, "DeleteUserAssociation: invalid ExtraData provided")
		return
	}

	// Compute the additional transaction fees as specified
	// by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(
		lib.TxnTypeDeleteUserAssociation,
		transactorPublicKeyBytes,
		requestData.TransactionFees,
	)
	if err != nil {
		_AddBadRequestError(ww, "DeleteUserAssociation: specified TransactionFees are invalid")
		return
	}

	// Create transaction.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateDeleteUserAssociationTxn(
		transactorPublicKeyBytes,
		&lib.DeleteUserAssociationMetadata{AssociationID: lib.NewBlockHash(associationIdBytes)},
		extraData,
		requestData.MinFeeRateNanosPerKB,
		fes.backendServer.GetMempool(),
		additionalOutputs,
	)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("DeleteUserAssociation: problem creating txn: %v", err))
		return
	}

	// Construct response.
	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddInternalServerError(ww, "DeleteUserAssociation: problem encoding txn to bytes")
		return
	}
	res := AssociationTxnResponse{
		SpendAmountNanos:  totalInput - changeAmount - fees,
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
		TxnHashHex:        txn.Hash().String(),
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, "DeleteUserAssociation: problem encoding response as JSON")
		return
	}
}

func (fes *APIServer) GetUserAssociationByID(ww http.ResponseWriter, req *http.Request) {
	// Parse AssociationID from URL.
	vars := mux.Vars(req)
	associationIdHex, associationIdExists := vars["associationID"]
	if !associationIdExists {
		_AddBadRequestError(ww, fmt.Sprintf("GetUserAssociationByID: must provide an AssociationID"))
		return
	}

	// Parse AssociationID (BlockHash) from AssociationIdHex (string).
	associationIdBytes, err := hex.DecodeString(associationIdHex)
	if err != nil {
		_AddBadRequestError(ww, "GetUserAssociationByID: invalid AssociationID provided")
		return
	}

	// Create UTXO view.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddInternalServerError(ww, "GetUserAssociationByID: problem getting UTXO view")
		return
	}

	// Fetch AssociationEntry.
	associationEntry, err := utxoView.GetUserAssociationByID(lib.NewBlockHash(associationIdBytes))
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetUserAssociationByID: problem retrieving association: %v", err))
		return
	}
	if associationEntry == nil {
		_AddNotFoundError(ww, "GetUserAssociationByID: association not found")
		return
	}

	// Convert AssociationEntry to AssociationResponse.
	response := fes._convertUserAssociationEntryToResponse(utxoView, associationEntry)

	// JSON encode response.
	if err = json.NewEncoder(ww).Encode(response); err != nil {
		_AddInternalServerError(ww, "GetUserAssociationByID: problem encoding response as JSON")
		return
	}
}

func (fes *APIServer) GetUserAssociations(ww http.ResponseWriter, req *http.Request) {
	// Create UTXO view.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddInternalServerError(ww, "GetUserAssociations: problem getting UTXO view")
		return
	}

	// Construct association queries.
	associationQueries, err := fes._constructUserAssociationQueriesFromParams(utxoView, req.Body, AssociationQueryTypeQuery)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetUserAssociations: %v", err))
		return
	}

	// Query for association entries.
	var associationEntries []*lib.UserAssociationEntry
	for _, associationQuery := range associationQueries {
		currentAssociationEntries, err := utxoView.GetUserAssociationsByAttributes(associationQuery)
		if err != nil {
			_AddInternalServerError(ww, fmt.Sprintf("GetUserAssociations: %v", err))
			return
		}
		associationEntries = append(associationEntries, currentAssociationEntries...)
	}

	// Convert AssociationEntries to AssociationResponses.
	associationResponses := []*UserAssociationResponse{}
	for _, associationEntry := range associationEntries {
		associationResponses = append(
			associationResponses, fes._convertUserAssociationEntryToResponse(utxoView, associationEntry),
		)
	}

	// JSON encode response.
	response := UserAssociationsResponse{Associations: associationResponses}
	if err = json.NewEncoder(ww).Encode(response); err != nil {
		_AddInternalServerError(ww, "GetUserAssociations: problem encoding response as JSON")
		return
	}
}

func (fes *APIServer) CountUserAssociations(ww http.ResponseWriter, req *http.Request) {
	// Create UTXO view.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddInternalServerError(ww, "CountUserAssociations: problem getting UTXO view")
		return
	}

	// Construct association queries.
	associationQueries, err := fes._constructUserAssociationQueriesFromParams(utxoView, req.Body, AssociationQueryTypeCount)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CountUserAssociations: %v", err))
		return
	}

	// Count association entries.
	count, err := utxoView.CountUserAssociationsByAttributes(associationQueries[0])
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("CountUserAssociations: %v", err))
		return
	}

	// JSON encode response.
	response := AssociationsCountResponse{Count: count}
	if err = json.NewEncoder(ww).Encode(response); err != nil {
		_AddInternalServerError(ww, "CountUserAssociations: problem encoding response as JSON")
		return
	}
}

func (fes *APIServer) CountUserAssociationsByValue(ww http.ResponseWriter, req *http.Request) {
	// Create UTXO view.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddInternalServerError(ww, "CountUserAssociationsByValue: problem getting UTXO view")
		return
	}

	// Construct association queries.
	associationQueries, err := fes._constructUserAssociationQueriesFromParams(
		utxoView, req.Body, AssociationQueryTypeCountByValue,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CountUserAssociationsByValue: %v", err))
		return
	}

	// Retrieve count for each AssociationValue.
	counts := make(map[string]uint64)
	total := uint64(0)
	for _, associationQuery := range associationQueries {
		count, err := utxoView.CountUserAssociationsByAttributes(associationQuery)
		if err != nil {
			_AddInternalServerError(ww, fmt.Sprintf("CountUserAssociationsByValue: %v", err))
			return
		}
		counts[string(associationQuery.AssociationValue)] = count
		total += count
	}

	// JSON encode response.
	response := AssociationCountsReponse{Counts: counts, Total: total}
	if err = json.NewEncoder(ww).Encode(response); err != nil {
		_AddInternalServerError(ww, "CountUserAssociationsByValue: problem encoding response as JSON")
		return
	}
}

func (fes *APIServer) _convertUserAssociationEntryToResponse(
	utxoView *lib.UtxoView, associationEntry *lib.UserAssociationEntry,
) *UserAssociationResponse {
	return &UserAssociationResponse{
		AssociationID:                  hex.EncodeToString(associationEntry.AssociationID.ToBytes()),
		TransactorPublicKeyBase58Check: lib.Base58CheckEncode(utxoView.GetPublicKeyForPKID(associationEntry.TransactorPKID), false, fes.Params),
		TargetUserPublicKeyBase58Check: lib.Base58CheckEncode(utxoView.GetPublicKeyForPKID(associationEntry.TargetUserPKID), false, fes.Params),
		AppPublicKeyBase58Check:        lib.Base58CheckEncode(utxoView.GetPublicKeyForPKID(associationEntry.AppPKID), false, fes.Params),
		AssociationType:                string(associationEntry.AssociationType),
		AssociationValue:               string(associationEntry.AssociationValue),
		ExtraData:                      DecodeExtraDataMap(fes.Params, utxoView, associationEntry.ExtraData),
		BlockHeight:                    associationEntry.BlockHeight,
	}
}

func (fes *APIServer) _constructUserAssociationQueriesFromParams(
	utxoView *lib.UtxoView, requestBody io.ReadCloser, queryType AssociationQueryType,
) ([]*lib.UserAssociationQuery, error) {
	var err error

	// Decode request body.
	decoder := json.NewDecoder(io.LimitReader(requestBody, MaxRequestBodySizeBytes))
	requestData := UserAssociationQuery{}
	if err = decoder.Decode(&requestData); err != nil {
		return nil, errors.New("problem parsing request body")
	}

	// Parse Limit.
	switch queryType {
	case AssociationQueryTypeQuery:
		if requestData.Limit < 0 || requestData.Limit > MaxAssociationsPerQueryLimit {
			return nil, errors.New("invalid Limit provided")
		}
		if requestData.Limit == 0 {
			requestData.Limit = MaxAssociationsPerQueryLimit
		}
	case AssociationQueryTypeCount, AssociationQueryTypeCountByValue:
		if requestData.Limit != 0 {
			return nil, errors.New("unsupported Limit param for count operation")
		}
	default:
		return nil, errors.New("invalid query type") // This can never happen.
	}

	// Parse LastSeenAssociationID (BlockHash) from LastSeenAssociationIdHex (string).
	var lastSeenAssociationID *lib.BlockHash
	switch queryType {
	case AssociationQueryTypeQuery:
		if requestData.LastSeenAssociationID != "" {
			lastSeenAssociationIdBytes, err := hex.DecodeString(requestData.LastSeenAssociationID)
			if err != nil {
				return nil, errors.New("invalid LastSeenAssociationID provided")
			}
			lastSeenAssociationID = lib.NewBlockHash(lastSeenAssociationIdBytes)
		}
	case AssociationQueryTypeCount, AssociationQueryTypeCountByValue:
		if requestData.LastSeenAssociationID != "" {
			return nil, errors.New("unsupported LastSeenAssociationID param for count operation")
		}
	default:
		return nil, errors.New("invalid query type") // This can never happen.
	}

	// Validate SortDescending.
	if (queryType == AssociationQueryTypeCount || queryType == AssociationQueryTypeCountByValue) && requestData.SortDescending {
		return nil, errors.New("unsupported SortDescending param for count operation")
	}

	// Parse other query params.
	transactorPKID, targetUserPKID, _, appPKID, err := fes._parseAssociationQueryParams(
		utxoView,
		requestData.TransactorPublicKeyBase58Check,
		requestData.TargetUserPublicKeyBase58Check,
		"",
		requestData.AppPublicKeyBase58Check,
	)
	if err != nil {
		return nil, err
	}

	// Construct association queries.
	var associationQueries []*lib.UserAssociationQuery
	if len(requestData.AssociationValues) > 0 {
		if err = _isValidUserAssociationValuesParam(requestData, queryType); err != nil {
			return nil, err
		}
		for _, associationValue := range requestData.AssociationValues {
			associationQuery := &lib.UserAssociationQuery{
				TransactorPKID:   transactorPKID,
				TargetUserPKID:   targetUserPKID,
				AppPKID:          appPKID,
				AssociationType:  []byte(requestData.AssociationType),
				AssociationValue: []byte(associationValue),
				Limit:            requestData.Limit,
			}
			associationQueries = append(associationQueries, associationQuery)
		}
	} else {
		associationQuery := &lib.UserAssociationQuery{
			TransactorPKID:         transactorPKID,
			TargetUserPKID:         targetUserPKID,
			AppPKID:                appPKID,
			AssociationType:        []byte(requestData.AssociationType),
			AssociationTypePrefix:  []byte(requestData.AssociationTypePrefix),
			AssociationValue:       []byte(requestData.AssociationValue),
			AssociationValuePrefix: []byte(requestData.AssociationValuePrefix),
			Limit:                  requestData.Limit,
			LastSeenAssociationID:  lastSeenAssociationID,
			SortDescending:         requestData.SortDescending,
		}
		associationQueries = append(associationQueries, associationQuery)
	}
	return associationQueries, nil
}

func (fes *APIServer) CreatePostAssociation(ww http.ResponseWriter, req *http.Request) {
	// Decode request body.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := CreatePostAssociationRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, "CreatePostAssociation: problem parsing request body")
		return
	}

	// Parse TransactorPublicKeyBytes from TransactorPublicKeyBase58Check.
	if requestData.TransactorPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, "CreatePostAssociation: must provide a TransactorPublicKeyBase58Check")
		return
	}
	transactorPublicKeyBytes, err := GetPubKeyBytesFromBase58Check(requestData.TransactorPublicKeyBase58Check)
	if err != nil {
		_AddInternalServerError(ww, "CreatePostAssociation: problem getting public key for the transactor")
		return
	}

	// Parse PostHashBytes from PostHashHex.
	if requestData.PostHashHex == "" {
		_AddBadRequestError(ww, "CreatePostAssociation: must provide a PostHashHex")
		return
	}
	postHashBytes, err := hex.DecodeString(requestData.PostHashHex)
	if err != nil {
		_AddBadRequestError(ww, "CreatePostAssociation: invalid PostHashHex provided")
		return
	}

	// Parse AppPublicKeyBytes from AppPublicKeyBase58Check.
	// If not provided, we default to the ZeroPublicKey (global).
	appPublicKeyBytes := lib.ZeroPublicKey.ToBytes()
	if requestData.AppPublicKeyBase58Check != "" {
		appPublicKeyBytes, err = GetPubKeyBytesFromBase58Check(requestData.AppPublicKeyBase58Check)
		if err != nil {
			_AddInternalServerError(ww, "CreatePostAssociation: problem getting public key for the app")
			return
		}
	}
	// Validate AssociationType.
	if requestData.AssociationType == "" {
		_AddBadRequestError(ww, "CreatePostAssociation: must provide an AssociationType")
		return
	}

	// Validate AssociationValue.
	if requestData.AssociationValue == "" {
		_AddBadRequestError(ww, "CreatePostAssociation: must provide an AssociationValue")
		return
	}

	// Parse ExtraData.
	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, "CreatePostAssociation: invalid ExtraData provided")
		return
	}

	// Compute the additional transaction fees as specified
	// by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(
		lib.TxnTypeCreatePostAssociation,
		transactorPublicKeyBytes,
		requestData.TransactionFees,
	)
	if err != nil {
		_AddBadRequestError(ww, "CreatePostAssociation: specified TransactionFees are invalid")
		return
	}

	// Create transaction.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateCreatePostAssociationTxn(
		transactorPublicKeyBytes,
		&lib.CreatePostAssociationMetadata{
			PostHash:         lib.NewBlockHash(postHashBytes),
			AppPublicKey:     lib.NewPublicKey(appPublicKeyBytes),
			AssociationType:  []byte(requestData.AssociationType),
			AssociationValue: []byte(requestData.AssociationValue),
		},
		extraData,
		requestData.MinFeeRateNanosPerKB,
		fes.backendServer.GetMempool(),
		additionalOutputs,
	)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("CreatePostAssociation: problem creating txn: %v", err))
		return
	}

	// Construct response.
	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddInternalServerError(ww, "CreatePostAssociation: problem encoding txn to bytes")
		return
	}
	res := AssociationTxnResponse{
		SpendAmountNanos:  totalInput - changeAmount - fees,
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
		TxnHashHex:        txn.Hash().String(),
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, "CreatePostAssociation: problem encoding response as JSON")
		return
	}
}

func (fes *APIServer) DeletePostAssociation(ww http.ResponseWriter, req *http.Request) {
	// Decode request body.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := DeleteAssociationRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, "DeletePostAssociation: problem parsing request body")
		return
	}

	// Parse TransactorPublicKeyBytes from TransactorPublicKeyBase58Check.
	if requestData.TransactorPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, "DeletePostAssociation: must provide a TransactorPublicKeyBase58Check")
		return
	}
	transactorPublicKeyBytes, err := GetPubKeyBytesFromBase58Check(requestData.TransactorPublicKeyBase58Check)
	if err != nil {
		_AddInternalServerError(ww, "DeletePostAssociation: problem getting public key for the transactor")
		return
	}

	// Parse AssociationIDBytes from AssociationID (hex string).
	if requestData.AssociationID == "" {
		_AddBadRequestError(ww, "DeletePostAssociation: must provide an AssociationID")
		return
	}
	associationIdBytes, err := hex.DecodeString(requestData.AssociationID)
	if err != nil {
		_AddBadRequestError(ww, "DeletePostAssociation: invalid AssociationID provided")
		return
	}

	// Parse ExtraData.
	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, "DeletePostAssociation: invalid ExtraData provided")
		return
	}

	// Compute the additional transaction fees as specified
	// by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(
		lib.TxnTypeDeletePostAssociation,
		transactorPublicKeyBytes,
		requestData.TransactionFees,
	)
	if err != nil {
		_AddBadRequestError(ww, "DeletePostAssociation: specified TransactionFees are invalid")
		return
	}

	// Create transaction.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateDeletePostAssociationTxn(
		transactorPublicKeyBytes,
		&lib.DeletePostAssociationMetadata{AssociationID: lib.NewBlockHash(associationIdBytes)},
		extraData,
		requestData.MinFeeRateNanosPerKB,
		fes.backendServer.GetMempool(),
		additionalOutputs,
	)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("DeletePostAssociation: problem creating txn: %v", err))
		return
	}

	// Construct response.
	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddInternalServerError(ww, "DeletePostAssociation: problem encoding txn to bytes")
		return
	}
	res := AssociationTxnResponse{
		SpendAmountNanos:  totalInput - changeAmount - fees,
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
		TxnHashHex:        txn.Hash().String(),
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, "DeletePostAssociation: problem encoding response as JSON")
		return
	}
}

func (fes *APIServer) GetPostAssociationByID(ww http.ResponseWriter, req *http.Request) {
	// Parse AssociationID from URL.
	vars := mux.Vars(req)
	associationIdHex, associationIdExists := vars["associationID"]
	if !associationIdExists {
		_AddBadRequestError(ww, fmt.Sprintf("GetPostAssociationByID: must provide an AssociationID"))
		return
	}

	// Parse AssociationID (BlockHash) from AssociationIdHex (string).
	associationIdBytes, err := hex.DecodeString(associationIdHex)
	if err != nil {
		_AddBadRequestError(ww, "GetPostAssociationByID: invalid AssociationID provided")
		return
	}

	// Create UTXO view.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddInternalServerError(ww, "GetPostAssociationByID: problem getting UTXO view")
		return
	}

	// Fetch AssociationEntry.
	associationEntry, err := utxoView.GetPostAssociationByID(lib.NewBlockHash(associationIdBytes))
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetPostAssociationByID: problem retrieving association: %v", err))
		return
	}
	if associationEntry == nil {
		_AddNotFoundError(ww, "GetPostAssociationByID: association not found")
		return
	}

	// Convert AssociationEntry to AssociationResponse.
	response := fes._convertPostAssociationEntryToResponse(utxoView, associationEntry)

	// JSON encode response.
	if err = json.NewEncoder(ww).Encode(response); err != nil {
		_AddInternalServerError(ww, "GetPostAssociationByID: problem encoding response as JSON")
		return
	}
}

func (fes *APIServer) GetPostAssociations(ww http.ResponseWriter, req *http.Request) {
	// Create UTXO view.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddInternalServerError(ww, "GetPostAssociations: problem getting UTXO view")
		return
	}

	// Construct association queries.
	associationQueries, err := fes._constructPostAssociationQueriesFromParams(utxoView, req.Body, AssociationQueryTypeQuery)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPostAssociations: %v", err))
		return
	}

	// Query for association entries.
	var associationEntries []*lib.PostAssociationEntry
	for _, associationQuery := range associationQueries {
		currentAssociationEntries, err := utxoView.GetPostAssociationsByAttributes(associationQuery)
		if err != nil {
			_AddInternalServerError(ww, fmt.Sprintf("GetPostAssociations: %v", err))
			return
		}
		associationEntries = append(associationEntries, currentAssociationEntries...)
	}

	// Convert AssociationEntries to AssociationResponses.
	associationResponses := []*PostAssociationResponse{}
	for _, associationEntry := range associationEntries {
		associationResponses = append(
			associationResponses, fes._convertPostAssociationEntryToResponse(utxoView, associationEntry),
		)
	}

	// JSON encode response.
	response := PostAssociationsResponse{Associations: associationResponses}
	if err = json.NewEncoder(ww).Encode(response); err != nil {
		_AddInternalServerError(ww, "GetPostAssociations: problem encoding response as JSON")
		return
	}
}

func (fes *APIServer) CountPostAssociations(ww http.ResponseWriter, req *http.Request) {
	// Create UTXO view.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddInternalServerError(ww, "CountPostAssociations: problem getting UTXO view")
		return
	}

	// Construct association queries.
	associationQueries, err := fes._constructPostAssociationQueriesFromParams(utxoView, req.Body, AssociationQueryTypeCount)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CountPostAssociations: %v", err))
		return
	}

	// Count association entries.
	count, err := utxoView.CountPostAssociationsByAttributes(associationQueries[0])
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("CountPostAssociations: %v", err))
		return
	}

	// JSON encode response.
	response := AssociationsCountResponse{Count: count}
	if err = json.NewEncoder(ww).Encode(response); err != nil {
		_AddInternalServerError(ww, "CountPostAssociations: problem encoding response as JSON")
		return
	}
}

func (fes *APIServer) CountPostAssociationsByValue(ww http.ResponseWriter, req *http.Request) {
	// Create UTXO view.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddInternalServerError(ww, "CountPostAssociationsByValue: problem getting UTXO view")
		return
	}

	// Construct association queries.
	associationQueries, err := fes._constructPostAssociationQueriesFromParams(
		utxoView, req.Body, AssociationQueryTypeCountByValue,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CountPostAssociationsByValue: %v", err))
		return
	}

	// Retrieve count for each AssociationValue.
	counts := make(map[string]uint64)
	total := uint64(0)
	for _, associationQuery := range associationQueries {
		count, err := utxoView.CountPostAssociationsByAttributes(associationQuery)
		if err != nil {
			_AddInternalServerError(ww, fmt.Sprintf("CountPostAssociationsByValue: %v", err))
			return
		}
		counts[string(associationQuery.AssociationValue)] = count
		total += count
	}

	// JSON encode response.
	response := AssociationCountsReponse{Counts: counts, Total: total}
	if err = json.NewEncoder(ww).Encode(response); err != nil {
		_AddInternalServerError(ww, "CountPostAssociationsByValue: problem encoding response as JSON")
		return
	}
}

func (fes *APIServer) _convertPostAssociationEntryToResponse(
	utxoView *lib.UtxoView, associationEntry *lib.PostAssociationEntry,
) *PostAssociationResponse {
	return &PostAssociationResponse{
		AssociationID:                  hex.EncodeToString(associationEntry.AssociationID.ToBytes()),
		TransactorPublicKeyBase58Check: lib.Base58CheckEncode(utxoView.GetPublicKeyForPKID(associationEntry.TransactorPKID), false, fes.Params),
		PostHashHex:                    hex.EncodeToString(associationEntry.PostHash.ToBytes()),
		AppPublicKeyBase58Check:        lib.Base58CheckEncode(utxoView.GetPublicKeyForPKID(associationEntry.AppPKID), false, fes.Params),
		AssociationType:                string(associationEntry.AssociationType),
		AssociationValue:               string(associationEntry.AssociationValue),
		ExtraData:                      DecodeExtraDataMap(fes.Params, utxoView, associationEntry.ExtraData),
		BlockHeight:                    associationEntry.BlockHeight,
	}
}

func (fes *APIServer) _constructPostAssociationQueriesFromParams(
	utxoView *lib.UtxoView, requestBody io.ReadCloser, queryType AssociationQueryType,
) ([]*lib.PostAssociationQuery, error) {
	var err error

	// Decode request body.
	decoder := json.NewDecoder(io.LimitReader(requestBody, MaxRequestBodySizeBytes))
	requestData := PostAssociationQuery{}
	if err = decoder.Decode(&requestData); err != nil {
		return nil, errors.New("problem parsing request body")
	}

	// Parse Limit.
	switch queryType {
	case AssociationQueryTypeQuery:
		if requestData.Limit < 0 || requestData.Limit > MaxAssociationsPerQueryLimit {
			return nil, errors.New("invalid Limit provided")
		}
		if requestData.Limit == 0 {
			requestData.Limit = MaxAssociationsPerQueryLimit
		}
	case AssociationQueryTypeCount, AssociationQueryTypeCountByValue:
		if requestData.Limit != 0 {
			return nil, errors.New("unsupported Limit param for count operation")
		}
	default:
		return nil, errors.New("invalid query type") // This can never happen.
	}

	// Parse LastSeenAssociationID (BlockHash) from LastSeenAssociationIdHex (string).
	var lastSeenAssociationID *lib.BlockHash
	switch queryType {
	case AssociationQueryTypeQuery:
		if requestData.LastSeenAssociationID != "" {
			lastSeenAssociationIdBytes, err := hex.DecodeString(requestData.LastSeenAssociationID)
			if err != nil {
				return nil, errors.New("invalid LastSeenAssociationID provided")
			}
			lastSeenAssociationID = lib.NewBlockHash(lastSeenAssociationIdBytes)
		}
	case AssociationQueryTypeCount, AssociationQueryTypeCountByValue:
		if requestData.LastSeenAssociationID != "" {
			return nil, errors.New("unsupported Limit param for count operation")
		}
	default:
		return nil, errors.New("invalid query type") // This can never happen.
	}

	// Validate SortDescending.
	if (queryType == AssociationQueryTypeCount || queryType == AssociationQueryTypeCountByValue) && requestData.SortDescending {
		return nil, errors.New("unsupported SortDescending param for count operation")
	}

	// Parse other query params.
	transactorPKID, _, postHash, appPKID, err := fes._parseAssociationQueryParams(
		utxoView,
		requestData.TransactorPublicKeyBase58Check,
		"",
		requestData.PostHashHex,
		requestData.AppPublicKeyBase58Check,
	)
	if err != nil {
		return nil, err
	}

	// Construct association queries.
	var associationQueries []*lib.PostAssociationQuery
	if len(requestData.AssociationValues) > 0 {
		if err = _isValidPostAssociationValuesParam(requestData, queryType); err != nil {
			return nil, err
		}
		for _, associationValue := range requestData.AssociationValues {
			associationQuery := &lib.PostAssociationQuery{
				TransactorPKID:   transactorPKID,
				PostHash:         postHash,
				AppPKID:          appPKID,
				AssociationType:  []byte(requestData.AssociationType),
				AssociationValue: []byte(associationValue),
				Limit:            requestData.Limit,
			}
			associationQueries = append(associationQueries, associationQuery)
		}
	} else {
		associationQuery := &lib.PostAssociationQuery{
			TransactorPKID:         transactorPKID,
			PostHash:               postHash,
			AppPKID:                appPKID,
			AssociationType:        []byte(requestData.AssociationType),
			AssociationTypePrefix:  []byte(requestData.AssociationTypePrefix),
			AssociationValue:       []byte(requestData.AssociationValue),
			AssociationValuePrefix: []byte(requestData.AssociationValuePrefix),
			Limit:                  requestData.Limit,
			LastSeenAssociationID:  lastSeenAssociationID,
			SortDescending:         requestData.SortDescending,
		}
		associationQueries = append(associationQueries, associationQuery)
	}
	return associationQueries, nil
}

func (fes *APIServer) _parseAssociationQueryParams(
	utxoView *lib.UtxoView,
	transactorPublicKeyBase58Check string,
	targetUserPublicKeyBase58Check string,
	postHashHex string,
	appPublicKeyBase58Check string,
) (*lib.PKID, *lib.PKID, *lib.BlockHash, *lib.PKID, error) {
	// Parse TransactorPKID from TransactorPublicKeyBase58Check.
	var transactorPKID *lib.PKID
	var err error
	if transactorPublicKeyBase58Check != "" {
		transactorPKID, err = fes.getPKIDFromPublicKeyBase58Check(utxoView, transactorPublicKeyBase58Check)
		if err != nil {
			return nil, nil, nil, nil, errors.New("problem getting PKID for the transactor")
		}
	}

	// Parse TargetUserPKID from TargetUserPublicKeyBase58Check.
	var targetUserPKID *lib.PKID
	if targetUserPublicKeyBase58Check != "" {
		targetUserPKID, err = fes.getPKIDFromPublicKeyBase58Check(utxoView, targetUserPublicKeyBase58Check)
		if err != nil {
			return nil, nil, nil, nil, errors.New("problem getting PKID for the target user")
		}
	}

	// Parse PostHash from PostHashHex.
	var postHash *lib.BlockHash
	if postHashHex != "" {
		postHashBytes, err := hex.DecodeString(postHashHex)
		if err != nil {
			return nil, nil, nil, nil, errors.New("invalid PostHashHex provided")
		}
		postHash = lib.NewBlockHash(postHashBytes)
	}

	// Parse AppPKID from TransactorPublicKeyBase58Check.
	var appPKID *lib.PKID
	if appPublicKeyBase58Check != "" {
		appPKID, err = fes.getPKIDFromPublicKeyBase58Check(utxoView, appPublicKeyBase58Check)
		if err != nil {
			return nil, nil, nil, nil, errors.New("problem getting PKID for the app")
		}
	}
	return transactorPKID, targetUserPKID, postHash, appPKID, nil
}

func _isValidUserAssociationValuesParam(requestData UserAssociationQuery, queryType AssociationQueryType) error {
	switch queryType {
	case AssociationQueryTypeQuery:
		if len(requestData.AssociationValues) == 0 {
			return nil
		}
	case AssociationQueryTypeCount:
		if len(requestData.AssociationValues) > 0 {
			return errors.New("unsupported AssociationValues param provided")
		}
	case AssociationQueryTypeCountByValue:
		if len(requestData.AssociationValues) == 0 {
			return errors.New("no AssociationValues provided")
		}
	}
	if len(requestData.AssociationValues) > MaxAssociationValuesPerQueryLimit {
		return errors.New("too many AssociationValues values provided")
	}
	if requestData.SortDescending {
		return errors.New("cannot provide both SortDescending and AssociationValues")
	}
	for _, param := range []string{
		requestData.AssociationTypePrefix,
		requestData.AssociationValue,
		requestData.AssociationValuePrefix,
		requestData.LastSeenAssociationID,
	} {
		if param != "" {
			return fmt.Errorf("cannot provide both %s and AssociationValues", param)
		}
	}
	return nil
}

func _isValidPostAssociationValuesParam(requestData PostAssociationQuery, queryType AssociationQueryType) error {
	switch queryType {
	case AssociationQueryTypeQuery:
		if len(requestData.AssociationValues) == 0 {
			return nil
		}
	case AssociationQueryTypeCount:
		if len(requestData.AssociationValues) > 0 {
			return errors.New("unsupported AssociationValues param provided")
		}
	case AssociationQueryTypeCountByValue:
		if len(requestData.AssociationValues) == 0 {
			return errors.New("no AssociationValues provided")
		}
	}
	if len(requestData.AssociationValues) > MaxAssociationValuesPerQueryLimit {
		return errors.New("too many AssociationValues values provided")
	}
	if requestData.SortDescending {
		return errors.New("cannot provide both SortDescending and AssociationValues")
	}
	for _, param := range []string{
		requestData.AssociationTypePrefix,
		requestData.AssociationValue,
		requestData.AssociationValuePrefix,
		requestData.LastSeenAssociationID,
	} {
		if param != "" {
			return fmt.Errorf("cannot provide both %s and AssociationValues", param)
		}
	}
	return nil
}
