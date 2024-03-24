package routes

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/deso-protocol/core/lib"
	"github.com/pkg/errors"
)

type CreateAccessGroupRequest struct {
	// AccessGroupOwnerPublicKeyBase58Check is the public key of the access group owner.
	// This needs to match your public key used for signing the transaction.
	// You cannot create a group for another public key.
	AccessGroupOwnerPublicKeyBase58Check string `safeForLogging:"true"`
	// AccessGroupPublicKeyBase58Check is the Public key required to participate in the access groups.
	AccessGroupPublicKeyBase58Check string `safeForLogging:"true"`
	// Name of the access group to be created.
	AccessGroupKeyName string `safeForLogging:"true"`

	MinFeeRateNanosPerKB uint64 `safeForLogging:"true"`
	// No need to specify ProfileEntryResponse in each TransactionFee
	TransactionFees []TransactionFee `safeForLogging:"true"`
	// ExtraData is an arbitrary key value map
	ExtraData map[string]string
}

// struct to construct the response to create an access group.
type CreateAccessGroupResponse struct {
	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgDeSoTxn
	TransactionHex    string
}

func (fes *APIServer) accessGroupHandler(
	ww http.ResponseWriter,
	req *http.Request,
	accessGroupOperationType lib.AccessGroupOperationType,
) error {

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := CreateAccessGroupRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		return fmt.Errorf("problem parsing request body: %v", err)
	}

	// Decode the access group owner public key.
	accessGroupOwnerPkBytes, _, err := lib.Base58CheckDecode(requestData.AccessGroupOwnerPublicKeyBase58Check)
	if err != nil {
		return fmt.Errorf("problem decoding owner"+
			"base58 public key %s: %v", requestData.AccessGroupOwnerPublicKeyBase58Check, err)
	}

	accessGroupKeyNameBytes := []byte(requestData.AccessGroupKeyName)

	// get the byte array of the access group key name.

	// Validates whether the accessGroupOwner key is a valid public key and
	// some basic checks on access group key name like Min and Max characters.
	if err = lib.ValidateAccessGroupPublicKeyAndName(accessGroupOwnerPkBytes, accessGroupKeyNameBytes); err != nil {
		return fmt.Errorf("problem validating access group owner "+
			"public key and access group key name %s: %v", requestData.AccessGroupKeyName, err)
	}

	// Access group name key cannot be equal to base name key (equal to all zeros).
	if lib.EqualGroupKeyName(lib.NewGroupKeyName(accessGroupKeyNameBytes), lib.BaseGroupKeyName()) {
		return fmt.Errorf(
			"access group key cannot be same as base key (all zeros)."+"access group key name %s", requestData.AccessGroupKeyName)
	}
	// Decode the access group public key.
	accessGroupPkBytes, _, err := lib.Base58CheckDecode(requestData.AccessGroupPublicKeyBase58Check)
	if err != nil {
		return fmt.Errorf("problem decoding access group "+
			"base58 public key %s: %v", requestData.AccessGroupPublicKeyBase58Check, err)
	}
	// validate whether the access group public key is a valid public key.
	if err = lib.IsByteArrayValidPublicKey(accessGroupPkBytes); err != nil {
		return fmt.Errorf("problem validating access group "+
			"public key %s: %v", accessGroupPkBytes, err)
	}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return fmt.Errorf("error getting view: %v", err)
	}

	accessGroupEntry, err := utxoView.GetAccessGroupEntry(lib.NewPublicKey(accessGroupOwnerPkBytes), lib.NewGroupKeyName(accessGroupKeyNameBytes))
	if err != nil {
		return fmt.Errorf("error checking existence of access group entry: %v", err)
	}
	if accessGroupOperationType == lib.AccessGroupOperationTypeUpdate && (accessGroupEntry == nil || accessGroupEntry.IsDeleted()) {
		return fmt.Errorf("cannot update an access group entry that does not exist or has been deleted")
	}
	if accessGroupOperationType == lib.AccessGroupOperationTypeCreate && accessGroupEntry != nil && !accessGroupEntry.IsDeleted() {
		return fmt.Errorf("cannot create an access group entry that already exists")
	}

	// Compute the additional transaction fees as specified by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(lib.TxnTypeAccessGroup, accessGroupOwnerPkBytes, requestData.TransactionFees)
	if err != nil {
		return fmt.Errorf("transactionFees specified in Request body are invalid: %v", err)
	}

	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		return fmt.Errorf("problem encoding ExtraData: %v", err)
	}

	// Core from the core lib to construct the transaction to create an access group.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateAccessGroupTxn(
		accessGroupOwnerPkBytes, accessGroupPkBytes,
		accessGroupKeyNameBytes, accessGroupOperationType,
		extraData,
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool(), additionalOutputs)
	if err != nil {
		return fmt.Errorf("problem creating transaction: %v", err)
	}

	// Add node source to txn metadata
	fes.AddNodeSourceToTxnMetadata(txn)

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		return fmt.Errorf("problem serializing transaction: %v", err)
	}

	// Return all the data associated with the transaction in the response
	res := CreateAccessGroupResponse{
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		return fmt.Errorf("problem encoding response as JSON: %v", err)
	}
	return nil
}

// Endpoint implementation to create new access group.
// This endpoint should enable users to create a new access group.
// The endpoint should call the CreateAccessGroupTxn function from the core repo.
// Here are some useful info about creating access groups.

// 1. Creating an access group requires two public keys
//    One is of course your account public key, which is your identity on the blockchain.
//    You submit your public key as AccessGroupOwnerPublicKeyBase58Check in the request field.
//    Again, AccessGroupOwnerPublicKey should match the key used for signing the transaction.
//    You cannot create access groups for a different account or a public key.
//    In addition to that you need an AccessGroupPublicKey, which is used to create identity for access control.
// 2. The AccessGroupPublicKey must be different than your account public key.
//    If they are the same the API will return lib.RuleErrorAccessPublicKeyCannotBeOwnerKey
// 3. On creating a new access group, the you will become the owner of the access group.
//    Hence, the AccessGroupOwnerPublicKey will be same your accounts Public key.
// 4. Every on-chain write operation creates a transaction using the core protocol.
// 5. The transaction type for creating access group is lib.TxnTypeAccessGroup
// 6. The primary key for access groups is the tuple combination of
//    <Publickey of Group Owner, Unique Group name (Group Key String)>
//    So, you cannot create two access groups with same name for a given public key or an account.
// 7. If the key name is just a list of 0s, then return because this name is reserved for the base key access group.
//    The base key access group is a special group natively registered for every user. The base key access group
//    is an "access group expansion" of user's public key, i.e. accessGroupPublicKey = accessGroupOwnerPublicKey.
//    We decided to hard-code the base access group for convenience, since it's useful in some use-cases of access
//    such as DMs.
// 8. This endpoint like most, only helps you construct a transaction, it doesn't execute it! The client need
// 	  sign the response of this transaction and call SubmitTransaction endpoint.
//    Check out the three step process of creating transaction here https://docs.deso.org/for-developers/backend/transactions .

func (fes *APIServer) CreateAccessGroup(ww http.ResponseWriter, req *http.Request) {
	if err := fes.accessGroupHandler(ww, req, lib.AccessGroupOperationTypeCreate); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateAccessGroup: %v", err))
		return
	}
}

func (fes *APIServer) UpdateAccessGroup(ww http.ResponseWriter, req *http.Request) {
	if err := fes.accessGroupHandler(ww, req, lib.AccessGroupOperationTypeUpdate); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateAccessGroup: %v", err))
		return
	}
}

type AccessGroupMember struct {
	//   AccessGroupMemberPublicKeyBase58Check : The public key of the member to be added to the group.
	//     Should be a valid public key.
	AccessGroupMemberPublicKeyBase58Check string `safeForLogging:"true"`

	//  1. String containing the key of one of the existing access group to which the user belongs to.
	//  2. Cannot be a random string/byte-array. It should be a previously created/already existing access group with the member public key being the owner.
	//     member to the access group with AccessGroupMemberKeyName.
	//  3. The access group owner can add themselves as a member using lib.BaseGroup() as AccessGroupMemberKeyName.
	//     This is possible because every user by default belongs to the BaseGroup()
	//  4. Can't add the owner of the group as a member of the group using the same group key name.
	//     In other words, if the owner of a access group are adding themselves, the AccessGroupMemberKeyName in the member list
	//     cannot be same as the access group key name of the same group.
	AccessGroupMemberKeyName string `safeForLogging:"true"`
	//  1. Stores the main group's access public key encrypted to the member group's access public key.
	//  2. This is used to allow the member to decrypt the main group's access public key
	//     using their individual access groups' secrets.
	//  3. This value cannot be empty.

	EncryptedKey string

	ExtraData map[string]string
}

type AddAccessGroupMembersRequest struct {
	// AccessGroupOwnerPublicKeyBase58Check is the public key of the access group owner.
	// This needs to match your public key used for signing the transaction since only the group owner can add a member.
	AccessGroupOwnerPublicKeyBase58Check string `safeForLogging:"true"`
	// Access group identifier
	AccessGroupKeyName string `safeForLogging:"true"`
	// The details of the members to add are contained in the accessGroupMemberList array.
	// Each entry in the accessGroupMemberList represents one user to add to the access group.
	// Invalid to add multiple entry of the same public key in the list.
	AccessGroupMemberList []AccessGroupMember `safeForLogging:"true"`

	MinFeeRateNanosPerKB uint64 `safeForLogging:"true"`
	// No need to specify ProfileEntryResponse in each TransactionFee
	TransactionFees []TransactionFee `safeForLogging:"true"`
	// ExtraData is an arbitrary key value map
	ExtraData map[string]string
}

// struct to construct the response to create an access group.
type AddAccessGroupMembersResponse struct {
	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64

	Transaction    *lib.MsgDeSoTxn
	TransactionHex string
}

func (fes *APIServer) accessGroupMemberHandler(
	ww http.ResponseWriter,
	req *http.Request,
	accessGroupMemberOperationType lib.AccessGroupMemberOperationType,
) error {
	// Parse the request body.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AddAccessGroupMembersRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		return fmt.Errorf("problem parsing request body: %v", err)
	}
	// Decode the access group owner public key.
	// Public key should be sent encoded in Base58 with Checksum format.
	accessGroupOwnerPkBytes, _, err := lib.Base58CheckDecode(requestData.AccessGroupOwnerPublicKeyBase58Check)
	if err != nil {
		return fmt.Errorf("problem decoding owner"+
			"base58 public key %s: %v", requestData.AccessGroupOwnerPublicKeyBase58Check, err)
	}

	accessGroupKeyNameBytes := []byte(requestData.AccessGroupKeyName)

	// Access group name key cannot be equal to base name key  (equal to all zeros).
	// Base access group key is reserved and by default all users belong to an access group with base group key.
	if lib.EqualGroupKeyName(lib.NewGroupKeyName(accessGroupKeyNameBytes), lib.BaseGroupKeyName()) {
		return fmt.Errorf("access group key cannot be same as base key (all zeros). "+
			"access group key name %s", requestData.AccessGroupKeyName)
	}

	// Validate whether the accessGroupOwner key is a valid public key and
	// some basic checks on access group key name like Min and Max characters are performed.
	if err = lib.ValidateAccessGroupPublicKeyAndName(accessGroupOwnerPkBytes, accessGroupKeyNameBytes); err != nil {
		return fmt.Errorf("problem validating access group owner "+
			"public key and access group key name %s: %v", requestData.AccessGroupKeyName, err)
	}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return fmt.Errorf("error getting utxo view: %v", err)
	}

	// DeSo core library expects the member list input the form of []*lib.AccessGroupMember{}
	accessGroupMembers := []*lib.AccessGroupMember{}
	// Map is used to identify Duplicate entries in the access member list.
	// More than one entry of a public key in the member list in invalid.
	accessGroupMemberPublicKeys := lib.NewSet([]lib.PublicKey{})

	// Iterate through the member list.
	for i := 0; i < len(requestData.AccessGroupMemberList); i++ {

		member := requestData.AccessGroupMemberList[i]

		// Decode the member public key.
		var accessGroupMemberPkBytes []byte
		// As usual any public key is expected to be wired in Base58 Checksum format.
		accessGroupMemberPkBytes, _, err = lib.Base58CheckDecode(member.AccessGroupMemberPublicKeyBase58Check)
		if err != nil {
			return fmt.Errorf("problem decoding member"+
				"base58 public key %s: %v", member.AccessGroupMemberPublicKeyBase58Check, err)
		}

		memberAccessGroupKeyNameBytes := []byte(member.AccessGroupMemberKeyName)
		if len(memberAccessGroupKeyNameBytes) == 0 {
			// Special case: base key needs to have at least one byte
			memberAccessGroupKeyNameBytes = []byte{0}
		}
		// Checks whether the accessGroupMember key is a valid public key and
		// some basic checks on access group key name like Min and Max characters are done.
		if err = lib.ValidateAccessGroupPublicKeyAndName(accessGroupMemberPkBytes,
			memberAccessGroupKeyNameBytes); err != nil {
			return fmt.Errorf("problem validating access group member "+
				"public key and access group key name %s %s: %v",
				member.AccessGroupMemberPublicKeyBase58Check, member.AccessGroupMemberKeyName, err)
		}

		// It's possible for the access group owner to list themselves as a member to be added or removed.
		// But there's a restriction! The accessGroupKey names in the member list cannot be
		// same as the key of the access group being added.
		if bytes.Equal(accessGroupOwnerPkBytes, accessGroupMemberPkBytes) &&
			bytes.Equal(lib.NewGroupKeyName(accessGroupKeyNameBytes).ToBytes(),
				lib.NewGroupKeyName(memberAccessGroupKeyNameBytes).ToBytes()) {
			return errors.New("can't include the owner of the group in the member list of the " +
				"group using the same group key name.")
		}

		// We have extra validations to do for the remove and update operations.
		if accessGroupMemberOperationType == lib.AccessGroupMemberOperationTypeRemove && member.EncryptedKey != "" {
			return fmt.Errorf("encryptedKey should be empty for remove operations")
		}

		if accessGroupMemberOperationType == lib.AccessGroupMemberOperationTypeRemove && len(member.ExtraData) != 0 {
			return fmt.Errorf("extraData should be empty for remove operations")
		}

		// Checking for duplicate entry in the member list.
		memberPublicKey := *lib.NewPublicKey(accessGroupMemberPkBytes)
		if accessGroupMemberPublicKeys.Includes(memberPublicKey) {
			return fmt.Errorf("duplicate member entry in the member list for (%v)"+
				"cannot be empty", memberPublicKey)
		}
		accessGroupMemberPublicKeys.Add(memberPublicKey)

		extraData, err := EncodeExtraDataMap(member.ExtraData)
		if err != nil {
			return fmt.Errorf("error encoding extra data for member: %v", err)
		}

		// We need to check that these are already members of the group. Can't update or
		// remove if they aren't already members.
		accessGroupMemberEntry, err := utxoView.GetAccessGroupMemberEntry(
			lib.NewPublicKey(accessGroupMemberPkBytes),
			lib.NewPublicKey(accessGroupOwnerPkBytes),
			lib.NewGroupKeyName(accessGroupKeyNameBytes))

		if err != nil {
			return fmt.Errorf("error getting access group member entry: %v", err)
		}

		if accessGroupMemberOperationType == lib.AccessGroupMemberOperationTypeRemove ||
			accessGroupMemberOperationType == lib.AccessGroupMemberOperationTypeUpdate {
			if accessGroupMemberEntry == nil || accessGroupMemberEntry.IsDeleted() {
				return fmt.Errorf("access group member entry not found for publicKey %v", member.AccessGroupMemberPublicKeyBase58Check)
			}

			if !bytes.Equal(accessGroupMemberEntry.AccessGroupMemberKeyName.ToBytes(), lib.NewGroupKeyName(memberAccessGroupKeyNameBytes).ToBytes()) {
				return fmt.Errorf("can't %v group member with a different access group key name", accessGroupMemberOperationType.ToString())
			}
		}

		if accessGroupMemberOperationType == lib.AccessGroupMemberOperationTypeAdd && (accessGroupMemberEntry != nil && !accessGroupMemberEntry.IsDeleted()) {
			return fmt.Errorf("access group member entry already exists for publicKey %v", member.AccessGroupMemberPublicKeyBase58Check)
		}

		// Assembling the information inside an array of &lib.AccessGroupMember as expected by the core library.
		accessGroupMember := &lib.AccessGroupMember{
			AccessGroupMemberPublicKey: accessGroupMemberPkBytes,
			AccessGroupMemberKeyName:   memberAccessGroupKeyNameBytes,
			EncryptedKey:               []byte(member.EncryptedKey),
			ExtraData:                  extraData,
		}
		accessGroupMembers = append(accessGroupMembers, accessGroupMember)
	}

	// Compute the additional transaction fees as specified by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(lib.TxnTypeAccessGroupMembers, accessGroupOwnerPkBytes, requestData.TransactionFees)
	if err != nil {
		return fmt.Errorf("transactionFees specified in Request body are invalid: %v", err)
	}

	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		return fmt.Errorf("problem encoding ExtraData: %v", err)
	}

	// Core from the core lib to construct the transaction to create an access group.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateAccessGroupMembersTxn(
		accessGroupOwnerPkBytes, accessGroupKeyNameBytes,
		accessGroupMembers, accessGroupMemberOperationType,
		extraData,
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool(), additionalOutputs)
	if err != nil {
		return fmt.Errorf("problem creating transaction: %v", err)
	}

	// Add node source to txn metadata
	fes.AddNodeSourceToTxnMetadata(txn)

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		return fmt.Errorf("problem serializing transaction: %v", err)
	}

	// Return all the data associated with the transaction in the response
	res := AddAccessGroupMembersResponse{
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		return fmt.Errorf("problem encoding response as JSON: %v", err)
	}
	return nil
}

// Here are some of the important rules to use this API to add members to an access group.
// Note: This API helps you only construct a transaction to add a member. This doesn't execute a transaction.
//		You need to follow up with signing the transaction and submitting it to Submit Transaction API to execute the transaction.
//	 1. The access group should already exist to able to add a member.
//	 2. Only the owner of the access group can add a member.
//	    This means the AccessGroupOwnerPublicKeyBase58Check in this request should
//	    match with the key used for signing the transaction while submitting the transaction.
//	 3. An existing member of a group cannot add a member, again, only the owner can add members.
//	 4. More than one member can be added at a time.
//	 5. The information of the members to be added should be included in accessGroupMemberList.

func (fes *APIServer) AddAccessGroupMembers(ww http.ResponseWriter, req *http.Request) {
	if err := fes.accessGroupMemberHandler(ww, req, lib.AccessGroupMemberOperationTypeAdd); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AddAccessGroupMembers: %v", err))
		return
	}
}

func (fes *APIServer) RemoveAccessGroupMembers(ww http.ResponseWriter, req *http.Request) {
	if err := fes.accessGroupMemberHandler(ww, req, lib.AccessGroupMemberOperationTypeRemove); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("RemoveAccessGroupMembers: %v", err))
		return
	}
}

func (fes *APIServer) UpdateAccessGroupMembers(ww http.ResponseWriter, req *http.Request) {
	if err := fes.accessGroupMemberHandler(ww, req, lib.AccessGroupMemberOperationTypeUpdate); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateAccessGroupMembers: %v", err))
		return
	}
}

type AccessGroupMemberEntryResponse struct {
	AccessGroupMemberPublicKeyBase58Check string
	AccessGroupMemberKeyName              string
	EncryptedKey                          string
	ExtraData                             map[string]string
}

func (fes *APIServer) AccessGroupMemberEntryToResponse(accessGroupMemberEntry *lib.AccessGroupMemberEntry, utxoView *lib.UtxoView) *AccessGroupMemberEntryResponse {
	if accessGroupMemberEntry == nil {
		return nil
	}
	return &AccessGroupMemberEntryResponse{
		AccessGroupMemberPublicKeyBase58Check: lib.PkToString(accessGroupMemberEntry.AccessGroupMemberPublicKey.ToBytes(), fes.Params),
		AccessGroupMemberKeyName:              string(lib.MessagingKeyNameDecode(accessGroupMemberEntry.AccessGroupMemberKeyName)),
		EncryptedKey:                          string(accessGroupMemberEntry.EncryptedKey), // This may not be right?
		ExtraData:                             DecodeExtraDataMap(fes.Params, utxoView, accessGroupMemberEntry.ExtraData),
	}
}

type AccessGroupEntryResponse struct {
	AccessGroupOwnerPublicKeyBase58Check string
	AccessGroupKeyName                   string
	AccessGroupPublicKeyBase58Check      string
	ExtraData                            map[string]string
	AccessGroupMemberEntryResponse       *AccessGroupMemberEntryResponse
}

func (fes *APIServer) AccessGroupEntryToResponse(accessGroupEntry *lib.AccessGroupEntry, utxoView *lib.UtxoView, accessGroupMemberEntry *lib.AccessGroupMemberEntry) AccessGroupEntryResponse {

	return AccessGroupEntryResponse{
		AccessGroupOwnerPublicKeyBase58Check: lib.PkToString(accessGroupEntry.AccessGroupOwnerPublicKey.ToBytes(), fes.Params),
		AccessGroupPublicKeyBase58Check:      lib.PkToString(accessGroupEntry.AccessGroupPublicKey.ToBytes(), fes.Params),
		AccessGroupKeyName:                   string(lib.MessagingKeyNameDecode(accessGroupEntry.AccessGroupKeyName)),
		ExtraData:                            DecodeExtraDataMap(fes.Params, utxoView, accessGroupEntry.ExtraData),
		AccessGroupMemberEntryResponse:       fes.AccessGroupMemberEntryToResponse(accessGroupMemberEntry, utxoView),
	}
}

type GetAccessGroupsRequest struct {
	// PublicKeyBase58Check is the public key whose group IDs needs to be queried.
	PublicKeyBase58Check string `safeForLogging:"true"`
}

type GetAccessGroupsResponse struct {
	// Access Group Entry Responses.
	AccessGroupsOwned  []AccessGroupEntryResponse `json:",omitempty" safeForLogging:"true"`
	AccessGroupsMember []AccessGroupEntryResponse `json:",omitempty" safeForLogging:"true"`
}

func (fes *APIServer) getAccessEntryResponsesForAccessIds(accessGroupIds []*lib.AccessGroupId, utxoView *lib.UtxoView, pkBytes []byte) (
	[]AccessGroupEntryResponse, error) {
	var accessGroupEntryResponses []AccessGroupEntryResponse
	memberPublicKey := lib.NewPublicKey(pkBytes)
	for _, accessGroupId := range accessGroupIds {
		accessGroupEntry, err := utxoView.GetAccessGroupEntryWithAccessGroupId(accessGroupId)
		if err != nil {
			return nil, err
		}
		accessGroupMemberEntry, err := utxoView.GetAccessGroupMemberEntry(memberPublicKey, accessGroupEntry.AccessGroupOwnerPublicKey, accessGroupEntry.AccessGroupKeyName)
		accessGroupEntryResponses = append(
			accessGroupEntryResponses,
			fes.AccessGroupEntryToResponse(accessGroupEntry, utxoView, accessGroupMemberEntry),
		)
	}
	return accessGroupEntryResponses, nil
}

// returns only the access groups owned by the public key.
func (fes *APIServer) getGroupOwnerAccessEntriesForPublicKey(pkBytes []byte, utxoView *lib.UtxoView) ([]AccessGroupEntryResponse, error) {
	// call the core library and fetch group IDs owned by the public key.
	accessGroupIdsOwned, err := utxoView.GetAccessGroupIdsForOwner(pkBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "getGroupOwnerAccessIdsForPublicKey: Problem getting access group ids for member")
	}

	return fes.getAccessEntryResponsesForAccessIds(accessGroupIdsOwned, utxoView, pkBytes)
}

// returns the access groups where the given public key is only a member.
func (fes *APIServer) getMemberOnlyAccessEntriesForPublicKey(pkBytes []byte, utxoView *lib.UtxoView) ([]AccessGroupEntryResponse, error) {
	// call the core library and fetch group IDs where the public key is a member.
	accessGroupIdsMember, err := utxoView.GetAccessGroupIdsForMember(pkBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "getMemberOnlyAccessIdsForPublicKey: Problem getting access group ids for member")
	}
	return fes.getAccessEntryResponsesForAccessIds(accessGroupIdsMember, utxoView, pkBytes)
}

// API to get all access groups of a given public key.
// Returns groups where the public key is a owner and a member.
func (fes *APIServer) GetAllUserAccessGroups(ww http.ResponseWriter, req *http.Request) {
	if err := fes.getUserAccessGroupsHandler(ww, req, true, true); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllUserAccessGroups: %v", err))
		return
	}
}

// API to fetch access groups where the given public key is an owner.
func (fes *APIServer) GetAllUserAccessGroupsOwned(ww http.ResponseWriter, req *http.Request) {
	if err := fes.getUserAccessGroupsHandler(ww, req, true, false); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllUserAccessGroupsOwned: %v", err))
		return
	}
}

// API to fetch access groups where the given public key is a member.
func (fes *APIServer) GetAllUserAccessGroupsMemberOnly(ww http.ResponseWriter, req *http.Request) {
	if err := fes.getUserAccessGroupsHandler(ww, req, false, true); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllUserAccessGroupsMemberOnly: %v", err))
		return
	}
}

func (fes *APIServer) getUserAccessGroupsHandler(ww http.ResponseWriter, req *http.Request, getOwned bool, getMember bool) error {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetAccessGroupsRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		return errors.Wrapf(err, "Problem parsing request body: ")
	}

	// Decode the access group owner public key.
	accessGroupOwnerPkBytes, _, err := lib.Base58CheckDecode(requestData.PublicKeyBase58Check)
	if err != nil {
		return errors.Wrapf(err, fmt.Sprintf(
			"Problem decoding ownerbase58 public key %s: ",
			requestData.PublicKeyBase58Check,
		))
	}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return errors.Wrapf(err, "Error generating utxo view: ")
	}

	res := GetAccessGroupsResponse{}

	if getOwned {
		res.AccessGroupsOwned, err = fes.getGroupOwnerAccessEntriesForPublicKey(accessGroupOwnerPkBytes, utxoView)
		if err != nil {
			return errors.Wrapf(err, "Problem getting owned access groups: ")
		}
	}

	if getMember {
		res.AccessGroupsMember, err = fes.getMemberOnlyAccessEntriesForPublicKey(accessGroupOwnerPkBytes, utxoView)
		if err != nil {
			return errors.Wrapf(err, "Problem getting owned access groups: ")
		}
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		return errors.Wrapf(err, "Problem encoding response as JSON: ")
	}

	return nil
}

type CheckPartyAccessGroupsRequest struct {
	SenderPublicKeyBase58Check string
	SenderAccessGroupKeyName   string

	RecipientPublicKeyBase58Check string
	RecipientAccessGroupKeyName   string
}

type CheckPartyAccessGroupsResponse struct {
	SenderPublicKeyBase58Check            string
	SenderAccessGroupPublicKeyBase58Check string
	SenderAccessGroupKeyName              string
	IsSenderAccessGroupKey                bool

	RecipientPublicKeyBase58Check            string
	RecipientAccessGroupPublicKeyBase58Check string
	RecipientAccessGroupKeyName              string
	IsRecipientAccessGroupKey                bool
}

func (fes *APIServer) CheckPartyAccessGroups(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := CheckPartyAccessGroupsRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CheckPartyAccessGroups: Problem parsing request body: %v", err))
		return
	}

	// Decode the sender public key.
	senderPublicKey, _, err := lib.Base58CheckDecode(requestData.SenderPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CheckPartyAccessGroups: Problem decoding sender public key: %v", err))
		return
	}
	// Parse the sender's messaging key name from string to a byte array.
	senderKeyName := lib.NewGroupKeyName([]byte(requestData.SenderAccessGroupKeyName))
	// Validate that the sender's public key and key name have the correct format.
	if err = lib.ValidateGroupPublicKeyAndName(senderPublicKey, senderKeyName[:]); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CheckPartyAccessGroups: Problem validating sender public key and key name: %v", err))
		return
	}

	// Decode the recipient public key.
	recipientPublicKey, _, err := lib.Base58CheckDecode(requestData.RecipientPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CheckPartyAccessGroups: Problem decoding recipient public key: %v", err))
		return
	}
	// Parse the recipient's messaging key name from string to a byte array.
	recipientKeyName := lib.NewGroupKeyName([]byte(requestData.RecipientAccessGroupKeyName))
	// Validate that the recipient's public key and key name have the correct format.
	if err = lib.ValidateGroupPublicKeyAndName(recipientPublicKey, recipientKeyName[:]); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CheckPartyAccessGroups: Problem validating recipient public key and key name: %v", err))
		return
	}

	res, err := fes.CreateCheckPartyAccessGroupKeysResponse(
		lib.NewPublicKey(senderPublicKey),
		senderKeyName,
		lib.NewPublicKey(recipientPublicKey),
		recipientKeyName)

	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CheckPartyAccessGroups: %v", err))
		return
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CheckPartyAccessGroups: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) CreateCheckPartyAccessGroupKeysResponse(
	senderPublicKey *lib.PublicKey,
	senderAccessGroupKeyName *lib.GroupKeyName,
	recipientPublicKey *lib.PublicKey,
	recipientAccessGroupKeyName *lib.GroupKeyName) (
	*CheckPartyAccessGroupsResponse, error) {
	response := &CheckPartyAccessGroupsResponse{
		SenderPublicKeyBase58Check:    lib.PkToString(senderPublicKey.ToBytes(), fes.Params),
		IsSenderAccessGroupKey:        false,
		SenderAccessGroupKeyName:      "",
		RecipientPublicKeyBase58Check: lib.PkToString(recipientPublicKey.ToBytes(), fes.Params),
		IsRecipientAccessGroupKey:     false,
		RecipientAccessGroupKeyName:   "",
	}

	// Get the augmented UtxoView.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return nil, err
	}

	senderAccessGroupId := lib.NewAccessGroupId(senderPublicKey, senderAccessGroupKeyName.ToBytes())
	senderAccessGroupEntry, err := utxoView.GetAccessGroupEntryWithAccessGroupId(senderAccessGroupId)
	if err != nil {
		return nil, err
	}
	if senderAccessGroupEntry != nil && !senderAccessGroupEntry.IsDeleted() {
		response.SenderAccessGroupPublicKeyBase58Check = lib.PkToString(senderAccessGroupEntry.AccessGroupPublicKey.ToBytes(), fes.Params)
		response.IsSenderAccessGroupKey = true
		response.SenderAccessGroupKeyName = string(lib.MessagingKeyNameDecode(senderAccessGroupEntry.AccessGroupKeyName))
	}

	recipientAccessGroupId := lib.NewAccessGroupId(recipientPublicKey, recipientAccessGroupKeyName.ToBytes())
	recipientAccessGroupEntry, err := utxoView.GetAccessGroupEntryWithAccessGroupId(recipientAccessGroupId)
	if err != nil {
		return nil, err
	}
	if recipientAccessGroupEntry != nil && !recipientAccessGroupEntry.IsDeleted() {
		response.RecipientAccessGroupPublicKeyBase58Check = lib.PkToString(recipientAccessGroupEntry.AccessGroupPublicKey.ToBytes(), fes.Params)
		response.IsRecipientAccessGroupKey = true
		response.RecipientAccessGroupKeyName = string(lib.MessagingKeyNameDecode(recipientAccessGroupEntry.AccessGroupKeyName))
	}

	return response, nil
}

// Type and API to get access group information.
// API is available at "RoutePathGetAccessGroupInfo".
type GetAccessGroupInfoRequest struct {
	// AccessGroupOwnerPublicKeyBase58Check is the public key of the access group owner.
	// This needs to match your public key used for signing the transaction since only the group owner can add a member.
	AccessGroupOwnerPublicKeyBase58Check string `safeForLogging:"true"`
	// Access group identifier
	AccessGroupKeyName string `safeForLogging:"true"`
}

// returns information about the access group.
func (fes *APIServer) getAccessGroupInfo(publicKeyBase58DecodedBytes []byte, accessGroupKeyNameBytes []byte) (*AccessGroupEntryResponse, error) {
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf("getAccessGroupInfo: Error generating "+
			"utxo view: %v", err), "")
	}

	// call the core library to fetch info about the access group.
	accessGroupInfoCore, err := utxoView.GetAccessGroupEntry(lib.NewPublicKey(publicKeyBase58DecodedBytes),
		lib.NewGroupKeyName(accessGroupKeyNameBytes))
	if err != nil {
		return nil, errors.Wrapf(err, "getAccessGroupInfo: Problem getting access group ids for member")
	}

	if accessGroupInfoCore == nil {
		return nil, nil
	}

	accessGroupInfo := fes.AccessGroupEntryToResponse(accessGroupInfoCore, utxoView, nil)

	return &accessGroupInfo, nil
}

func (fes *APIServer) GetAccessGroupInfo(ww http.ResponseWriter, req *http.Request) {
	// Parse the request body.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetAccessGroupInfoRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAccessGroupInfo: Problem parsing request body: %v", err))
		return
	}

	// Decode the access group owner public key.
	// Public key should be sent encoded in Base58 with Checksum format.
	accessGroupOwnerPkBytes, _, err := lib.Base58CheckDecode(requestData.AccessGroupOwnerPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAccessGroupInfo: Problem decoding owner"+
			"base58 public key %s: %v", requestData.AccessGroupOwnerPublicKeyBase58Check, err))
		return
	}

	accessGroupKeyNameBytes := []byte(requestData.AccessGroupKeyName)

	// Validate whether the accessGroupOwner key is a valid public key and
	// some basic checks on access group key name like Min and Max characters are performed.
	if err = lib.ValidateAccessGroupPublicKeyAndName(accessGroupOwnerPkBytes, accessGroupKeyNameBytes); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAccessGroupInfo: Problem validating access group owner "+
			"public key and access group key name %s: %v", requestData.AccessGroupKeyName, err))
		return
	}

	// Base access group key is reserved and by default all users belong to an access group with base group key.
	if lib.EqualGroupKeyName(lib.NewGroupKeyName(accessGroupKeyNameBytes), lib.BaseGroupKeyName()) {
		res := &AccessGroupEntryResponse{
			AccessGroupOwnerPublicKeyBase58Check: requestData.AccessGroupOwnerPublicKeyBase58Check,
			AccessGroupKeyName:                   string(lib.BaseGroupKeyName().ToBytes()),
			AccessGroupPublicKeyBase58Check:      requestData.AccessGroupOwnerPublicKeyBase58Check,
		}

		if err := json.NewEncoder(ww).Encode(res); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetAccessGroupInfo: Problem encoding response as JSON: %v", err))
		}
		return
	}
	// get all the access groups associated with the public key.
	accessGroupInfo, err := fes.getAccessGroupInfo(accessGroupOwnerPkBytes, accessGroupKeyNameBytes)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAccessGroupInfo: Problem getting access group of"+
			"public key, access group key name %s: %s: %v",
			requestData.AccessGroupOwnerPublicKeyBase58Check, requestData.AccessGroupKeyName, err))
		return
	}
	if accessGroupInfo == nil {
		_AddNotFoundError(ww, fmt.Sprintf("GetAccessGroupInfo: Access group not found for public key %s and access "+
			"group key name %s",
			requestData.AccessGroupOwnerPublicKeyBase58Check, requestData.AccessGroupKeyName))
		return
	}

	res := accessGroupInfo

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAccessGroupInfo: Problem encoding response as JSON: %v", err))
		return
	}
}

// Types and API to get access group member information.
// API is available at "RoutePathGetAccessGroupMemberInfo".
type GetAccessGroupMemberRequest struct {
	// Public key of the member whose info needs to be fetched.
	AccessGroupMemberPublicKeyBase58Check string `safeForLogging:"true"`
	// AccessGroupOwnerPublicKeyBase58Check is the public key of the access group owner.
	// This needs to match your public key used for signing the transaction since only the group owner can add a member.
	AccessGroupOwnerPublicKeyBase58Check string `safeForLogging:"true"`
	// Access group identifier
	AccessGroupKeyName string `safeForLogging:"true"`
}

// returns information about the access group.
func (fes *APIServer) getAccessGroupMemberInfo(memberPkBase58DecodedBytes []byte, ownerPkBase58DecodedBytes []byte, accessGroupKeyNameBytes []byte) (*AccessGroupMemberEntryResponse, error) {
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf("getAccessGroupMemberInfo: Error generating "+
			"utxo view: %v", err), "")
	}

	// call the core library to fetch info about the access group.
	accessGroupMemberInfo, err := utxoView.GetAccessGroupMemberEntry(lib.NewPublicKey(memberPkBase58DecodedBytes),
		lib.NewPublicKey(ownerPkBase58DecodedBytes), lib.NewGroupKeyName(accessGroupKeyNameBytes))
	if err != nil {
		return nil, errors.Wrapf(err, "getAccessGroupMemberInfo: Problem getting access group member entry")
	}

	return fes.AccessGroupMemberEntryToResponse(accessGroupMemberInfo, utxoView), nil
}

func (fes *APIServer) GetAccessGroupMemberInfo(ww http.ResponseWriter, req *http.Request) {
	// Parse the request body.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetAccessGroupMemberRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAccessGroupMemberInfo: Problem parsing request body: %v", err))
		return
	}

	// Decode the access group owner public key.
	// Public key should be sent encoded in Base58 with Checksum format.
	accessGroupOwnerPkBytes, _, err := lib.Base58CheckDecode(requestData.AccessGroupOwnerPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAccessGroupMemberInfo: Problem decoding owner"+
			"base58 public key %s: %v", requestData.AccessGroupOwnerPublicKeyBase58Check, err))
		return
	}

	accessGroupKeyNameBytes := []byte(requestData.AccessGroupKeyName)

	// Validate whether the accessGroupOwner key is a valid public key and
	// some basic checks on access group key name like Min and Max characters are performed.
	if err = lib.ValidateAccessGroupPublicKeyAndName(accessGroupOwnerPkBytes, accessGroupKeyNameBytes); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAccessGroupMemberInfo: Problem validating access group owner "+
			"public key and access group key name %s: %v", requestData.AccessGroupKeyName, err))
		return
	}

	// Decode the access group public key.
	accessGroupMemberPkBytes, _, err := lib.Base58CheckDecode(requestData.AccessGroupMemberPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAccessGroupMemberInfo: Problem decoding access group "+
			"member base58 public key %s: %v", requestData.AccessGroupMemberPublicKeyBase58Check, err))
		return
	}
	// validate whether the access group public key is a valid public key.
	if err = lib.IsByteArrayValidPublicKey(accessGroupMemberPkBytes); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAccessGroupMemberInfo: Problem validating access group "+
			"public key %s: %v", requestData.AccessGroupMemberPublicKeyBase58Check, err))
		return
	}

	// get all the access groups associated with the public key.
	accessGroupMember, err := fes.getAccessGroupMemberInfo(accessGroupMemberPkBytes, accessGroupOwnerPkBytes, accessGroupKeyNameBytes)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAccessGroupMemberInfo: Problem getting access group member info of"+
			"member publickey, owner publickey, access group key name %s: %s: %s: %v",
			requestData.AccessGroupMemberPublicKeyBase58Check, requestData.AccessGroupOwnerPublicKeyBase58Check,
			requestData.AccessGroupKeyName, err))
		return
	}

	res := accessGroupMember

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAccessGroupInfo: Problem encoding response as JSON: %v", err))
		return
	}
}

// Type and API to get access group information.
// API is available at "RoutePathGetPaginatedAccessGroupMembersRequest".
// API returns the list of public keys of the members.
// To fetch complete details of a member make a call to GetAccessGroupMemberInfo.
type GetPaginatedAccessGroupMembersRequest struct {
	// AccessGroupOwnerPublicKeyBase58Check is the public key of the access group owner.
	AccessGroupOwnerPublicKeyBase58Check string `safeForLogging:"true"`
	// Access group identifier
	AccessGroupKeyName string `safeForLogging:"true"`
	// Since the results are paginated, this public key is the starting point for max results with subsequent pagination calls.
	// Set it to empty in the first call to fetch results from the beginning.
	StartingAccessGroupMemberPublicKeyBase58Check string `safeForLogging:"true"`
	MaxMembersToFetch                             int    `safeForLogging:"true"`
}

// The API returns the list of public key of the members of the group.
type GetPaginatedAccessGroupMembersResponse struct {
	AccessGroupMembersBase58Check []string // We should probably return ProfileEntryResponses

	PublicKeyToProfileEntryResponse map[string]*ProfileEntryResponse
}

func (fes *APIServer) GetPaginatedAccessGroupMembers(ww http.ResponseWriter, req *http.Request) {

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetPaginatedAccessGroupMembersRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedAccessGroupMembers: Problem parsing request body: %v", err))
		return
	}

	// Why fetch if there's less than one message to fetch!!!!!
	if requestData.MaxMembersToFetch < 1 {
		_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedAccessGroupMembers: "+
			"MaxMembersToFetch cannot be less than 1: %v", requestData.MaxMembersToFetch))
		return
	}

	// Decode the access group owner public key.
	accessGroupOwnerPkBytes, _, err := lib.Base58CheckDecode(requestData.AccessGroupOwnerPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedAccessGroupMembers: Problem decoding owner"+
			"base58 public key %s: %v", requestData.AccessGroupOwnerPublicKeyBase58Check, err))
		return
	}

	accessGroupKeyNameBytes := []byte(requestData.AccessGroupKeyName)

	// get the byte array of the access group key name.

	// Validates whether the accessGroupOwner key is a valid public key and
	// some basic checks on access group key name like Min and Max characters.
	if err = lib.ValidateAccessGroupPublicKeyAndName(accessGroupOwnerPkBytes, accessGroupKeyNameBytes); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedAccessGroupMembers: Problem validating access group owner "+
			"public key and access group key name %s: %s: %v",
			requestData.AccessGroupOwnerPublicKeyBase58Check, requestData.AccessGroupKeyName, err))
		return
	}

	// Decode the access group public key.
	var startingPkBytes []byte
	if requestData.StartingAccessGroupMemberPublicKeyBase58Check != "" {
		startingPkBytes, _, err = lib.Base58CheckDecode(requestData.StartingAccessGroupMemberPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedAccessGroupMembers: Problem decoding pagination "+
				"starting point base58 public key %s: %v", requestData.StartingAccessGroupMemberPublicKeyBase58Check, err))
			return
		}
		// validate whether the access group public key is a valid public key.
		if err = lib.IsByteArrayValidPublicKey(startingPkBytes); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedAccessGroupMembers: Problem validating access group "+
				"starting point base58 public key: Not a valid public key: %s: %v",
				requestData.StartingAccessGroupMemberPublicKeyBase58Check, err))
			return
		}
	}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedAccessGroupMembers: Error generating "+
			"utxo view: %v", err))
		return
	}

	// Fetch the max messages between the sender and the party.
	accessGroupMembers, err := fes.fetchMaxMembersFromAccessGroup(accessGroupOwnerPkBytes, accessGroupKeyNameBytes,
		startingPkBytes, requestData.MaxMembersToFetch, utxoView)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedAccessGroupMembers: Problem getting paginated members for "+
			"Request Data: %v: %v", requestData, err))
		return
	}

	var accessGroupMembersBase58Check []string
	for _, member := range accessGroupMembers {
		accessGroupMembersBase58Check = append(accessGroupMembersBase58Check, lib.PkToString(member.ToBytes(), fes.Params))
	}

	res := GetPaginatedAccessGroupMembersResponse{
		AccessGroupMembersBase58Check: accessGroupMembersBase58Check,
	}

	res.PublicKeyToProfileEntryResponse = make(map[string]*ProfileEntryResponse)
	for _, member := range accessGroupMembers {
		res.PublicKeyToProfileEntryResponse[lib.PkToString(member.ToBytes(), fes.Params)] = fes.GetProfileEntryResponseForPublicKeyBytes(
			member.ToBytes(), utxoView)
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedAccessGroupMembers: Problem encoding response as JSON: %v", err))
		return
	}
}

// Fetches max number of members from the access group.
func (fes *APIServer) fetchMaxMembersFromAccessGroup(groupOwnerPublicKeyBytes []byte, groupKeyNameBytes []byte,
	startingAccessGroupMemberPublicKeyBytes []byte, maxMembersToFetch int, utxoView *lib.UtxoView) ([]*lib.PublicKey, error) {
	// call the core library to fetch info about the access group.
	accessGroupMembers, err := utxoView.GetPaginatedAccessGroupMembersEnumerationEntries(lib.NewPublicKey(groupOwnerPublicKeyBytes),
		lib.NewGroupKeyName(groupKeyNameBytes), startingAccessGroupMemberPublicKeyBytes, uint32(maxMembersToFetch))
	if err != nil {
		return nil, errors.Wrapf(err, "fetchMaxMembersFromAccessGroup: Problem getting access group member entry")
	}

	return accessGroupMembers, nil
}

type GroupOwnerAndGroupKeyNamePair struct {
	GroupOwnerPublicKeyBase58Check string
	GroupKeyName                   string
}

type GetBulkAccessGroupEntriesRequest struct {
	GroupOwnerAndGroupKeyNamePairs []GroupOwnerAndGroupKeyNamePair
}

type GetBulkAccessGroupEntriesResponse struct {
	AccessGroupEntries []AccessGroupEntryResponse
	PairsNotFound      []GroupOwnerAndGroupKeyNamePair
}

func (fes *APIServer) GetBulkAccessGroupEntries(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetBulkAccessGroupEntriesRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetBulkAccessGroupEntries: Problem parsing request body: %v", err))
		return
	}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetBulkAccessGroupEntries: Problem fetching utxoView: %v", err))
		return
	}

	res := GetBulkAccessGroupEntriesResponse{}
	for _, pair := range requestData.GroupOwnerAndGroupKeyNamePairs {
		groupOwnerPublicKeyBytes, _, err := lib.Base58CheckDecode(pair.GroupOwnerPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"GetBulkAccessGroupEntries: Problem decoding group owner public key: %v", err))
			return
		}
		groupOwnerPublicKey := lib.NewPublicKey(groupOwnerPublicKeyBytes)

		accessGroupKeyName := lib.NewGroupKeyName([]byte(pair.GroupKeyName))

		accessGroupEntry, err := utxoView.GetAccessGroupEntry(groupOwnerPublicKey, accessGroupKeyName)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"GetBulkAccessGroupEntries: Problem getting access group entry: %v", err))
			return
		}
		if accessGroupEntry != nil {
			res.AccessGroupEntries = append(
				res.AccessGroupEntries,
				fes.AccessGroupEntryToResponse(accessGroupEntry, utxoView, nil))
		} else {
			res.PairsNotFound = append(res.PairsNotFound, pair)
		}
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetBulkAccessGroupEntries: Problem encoding response as JSON: %v", err))
		return
	}
}
