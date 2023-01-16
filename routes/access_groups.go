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
	// Value needs to encoded in Hex.
	AccessGroupKeyNameHexEncoded string `safeForLogging:"true"`

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

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := CreateAccessGroupRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateAccessGroup: Problem parsing request body: %v", err))
		return
	}

	// Decode the access group owner public key.
	accessGroupOwnerPkBytes, _, err := lib.Base58CheckDecode(requestData.AccessGroupOwnerPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateAccessGroup: Problem decoding owner"+
			"base58 public key %s: %v", requestData.AccessGroupOwnerPublicKeyBase58Check, err))
		return
	}

	// Hex decoding the access group name.
	// The client should hex encode the group name while calling the API.
	accessGroupKeyNameBytes, err := hex.DecodeString(requestData.AccessGroupKeyNameHexEncoded)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateAccessGroup: Problem hex decoding "+
			"access group key name %v %v", requestData.AccessGroupKeyNameHexEncoded, err))
		return
	}

	// get the byte array of the access group key name.

	// Validates whether the accessGroupOwner key is a valid public key and
	// some basic checks on access group key name like Min and Max characters.
	if err = lib.ValidateAccessGroupPublicKeyAndName(accessGroupOwnerPkBytes, accessGroupKeyNameBytes); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateAccessGroup: Problem validating access group owner "+
			"public key and access group key name %s: %v", requestData.AccessGroupKeyNameHexEncoded, err))
		return
	}

	// Access group name key cannot be equal to base name key (equal to all zeros).
	if lib.EqualGroupKeyName(lib.NewGroupKeyName(accessGroupKeyNameBytes), lib.BaseGroupKeyName()) {
		_AddBadRequestError(ww, fmt.Sprintf(
			"CreateAccessGroup: Access Group key cannot be same as base key (all zeros)."+"access group key name %s", requestData.AccessGroupKeyNameHexEncoded))
		return
	}
	// Decode the access group public key.
	accessGroupPkBytes, _, err := lib.Base58CheckDecode(requestData.AccessGroupPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateAccessGroup: Problem decoding access group "+
			"base58 public key %s: %v", requestData.AccessGroupPublicKeyBase58Check, err))
		return
	}
	// validate whether the access group public key is a valid public key.
	if err = lib.IsByteArrayValidPublicKey(accessGroupPkBytes); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateAccessGroup: Problem validating access group "+
			"public key %s: %v", accessGroupPkBytes, err))
		return
	}

	// Compute the additional transaction fees as specified by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(lib.TxnTypeAccessGroup, accessGroupOwnerPkBytes, requestData.TransactionFees)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateAccessGroup: TransactionFees specified in Request body are invalid: %v", err))
		return
	}

	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateAccessGroup: Problem encoding ExtraData: %v", err))
		return
	}

	// Core from the core lib to construct the transaction to create an access group.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateAccessGroupTxn(
		accessGroupOwnerPkBytes, accessGroupPkBytes,
		accessGroupKeyNameBytes, lib.AccessGroupOperationTypeCreate,
		extraData,
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool(), additionalOutputs)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateAccessGroup: Problem creating transaction: %v", err))
		return
	}

	// Add node source to txn metadata
	fes.AddNodeSourceToTxnMetadata(txn)

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateAccessGroup: Problem serializing transaction: %v", err))
		return
	}

	// Return all the data associated with the transaction in the response
	res := CreateAccessGroupResponse{
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateAccessGroup: Problem encoding response as JSON: %v", err))
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
	//     In other words, if the owner of a access group are adding themselves, the AccessGroupMemberKeyName in the member list i
	//     cannot be same as the access group key name of the same group.
	//  5. The client need to hex encode the key name while calling the API.
	AccessGroupMemberKeyNameHexEncoded string `safeForLogging:"true"`
	//  1. Stores the main group's access public key encrypted to the member group's access public key.
	//  2. This is used to allow the member to decrypt the main group's access public key
	//     using their individual access groups' secrets.
	//  3. This value cannot be empty.

	EncryptedKey []byte

	ExtraData map[string][]byte
}

type AddAccessGroupMembersRequest struct {
	// AccessGroupOwnerPublicKeyBase58Check is the public key of the access group owner.
	// This needs to match your public key used for signing the transaction since only the group owner can add a member.
	AccessGroupOwnerPublicKeyBase58Check string `safeForLogging:"true"`
	// Access group identifier
	AccessGroupKeyNameHexEncoded string `safeForLogging:"true"`
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
	// Parse the request body.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AddAccessGroupMembersRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AddAccessGroupMembers: Problem parsing request body: %v", err))
		return
	}

	// Decode the access group owner public key.
	// Public key should be sent encoded in Base58 with Checksum format.
	accessGroupOwnerPkBytes, _, err := lib.Base58CheckDecode(requestData.AccessGroupOwnerPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AddAccessGroupMembers: Problem decoding owner"+
			"base58 public key %s: %v", requestData.AccessGroupOwnerPublicKeyBase58Check, err))
		return
	}

	// Hex decoding the access group name.
	// The client should hex encode the group name while calling the API.
	accessGroupKeyNameBytes, err := hex.DecodeString(requestData.AccessGroupKeyNameHexEncoded)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AddAccessGroupMembers: Problem hex decoding "+
			"access group key name %v %v", requestData.AccessGroupKeyNameHexEncoded, err))
		return
	}

	// Access group name key cannot be equal to base name key  (equal to all zeros).
	// Base access group key is reserved and by default all users belong to an access group with base group key.
	if lib.EqualGroupKeyName(lib.NewGroupKeyName(accessGroupKeyNameBytes), lib.BaseGroupKeyName()) {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AddAccessGroupMembers: Access Group key cannot be same as base key (all zeros). "+
				"access group key name %s", requestData.AccessGroupKeyNameHexEncoded))
		return
	}

	// Validate whether the accessGroupOwner key is a valid public key and
	// some basic checks on access group key name like Min and Max characters are performed.
	if err = lib.ValidateAccessGroupPublicKeyAndName(accessGroupOwnerPkBytes, accessGroupKeyNameBytes); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AddAccessGroupMembers: Problem validating access group owner "+
			"public key and access group key name %s: %v", requestData.AccessGroupKeyNameHexEncoded, err))
		return
	}

	// DeSo core library expects the member list input the form of []*lib.AccessGroupMember{}
	accessGroupMembers := []*lib.AccessGroupMember{}
	// Map is used to identify Duplicate entries in the access member list.
	// More than one entry of a public key in the member list in invalid.
	accessGroupMemberPublicKeys := make(map[lib.PublicKey]struct{})

	// Iterate through the member list.
	for i := 0; i < len(requestData.AccessGroupMemberList); i++ {

		member := requestData.AccessGroupMemberList[i]

		// Decode the member public key.
		// As usual any public key is expected to be wired in Base58 Checksum format.
		accessGroupMemberPkBytes, _, err := lib.Base58CheckDecode(member.AccessGroupMemberPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AddAccessGroupMembers: Problem decoding member"+
				"base58 public key %s: %v", member.AccessGroupMemberPublicKeyBase58Check, err))
			return
		}
		// Hex decoding the access group name.
		// The client should hex encode the group name while calling the API.
		accessGroupKeyNameBytes, err := hex.DecodeString(member.AccessGroupMemberKeyNameHexEncoded)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AddAccessGroupMembers: Problem hex decoding "+
				"access group key name %v %v", member.AccessGroupMemberKeyNameHexEncoded, err))
			return
		}
		// Checks whether the accessGroupMember key is a valid public key and
		// some basic checks on access group key name like Min and Max characters are done.
		if err = lib.ValidateAccessGroupPublicKeyAndName(accessGroupMemberPkBytes,
			accessGroupKeyNameBytes); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AddAccessGroupMembers: Problem validating access group owner "+
				"public key and access group key name %s %s: %v",
				member.AccessGroupMemberPublicKeyBase58Check, member.AccessGroupMemberKeyNameHexEncoded, err))
			return
		}

		// It's possible for the access group owner to list themselves as a member to be added.
		// But there's a restriction! The accessGroupKey names in the member list cannot be
		// same as the key of the access group being added.
		if bytes.Equal(accessGroupOwnerPkBytes, accessGroupMemberPkBytes) &&
			bytes.Equal(lib.NewGroupKeyName(accessGroupKeyNameBytes).ToBytes(),
				lib.NewGroupKeyName(accessGroupKeyNameBytes).ToBytes()) {

			_AddBadRequestError(ww, fmt.Sprintf("AddAccessGroupMembers: Can't add the owner of the group as a member of the "+
				"group using the same group key name."))
			return

		}

		// Encrypted key filed cannot be empty.
		if len(member.EncryptedKey) == 0 {
			_AddBadRequestError(ww, fmt.Sprintf("EncryptedKey for access member (%v)"+
				"cannot be empty.", member))
			return
		}

		// Checking for duplicate entry in the member list.
		memberPublicKey := *lib.NewPublicKey(accessGroupMemberPkBytes)
		if _, exists := accessGroupMemberPublicKeys[memberPublicKey]; exists {
			_AddBadRequestError(ww, fmt.Sprintf("EncryptedKey for access member (%v)"+
				"cannot be empty.", member))
			return
		}
		accessGroupMemberPublicKeys[memberPublicKey] = struct{}{}

		// Assembling the information inside an array of &lib.AccessGroupMember as expected by the core library.
		accessGroupMember := &lib.AccessGroupMember{
			AccessGroupMemberPublicKey: accessGroupMemberPkBytes,
			AccessGroupMemberKeyName:   accessGroupKeyNameBytes,
			EncryptedKey:               member.EncryptedKey,
			ExtraData:                  member.ExtraData,
		}
		accessGroupMembers = append(accessGroupMembers, accessGroupMember)

	}

	// Compute the additional transaction fees as specified by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(lib.TxnTypeAccessGroupMembers, accessGroupOwnerPkBytes, requestData.TransactionFees)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateAccessGroup: TransactionFees specified in Request body are invalid: %v", err))
		return
	}

	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateAccessGroup: Problem encoding ExtraData: %v", err))
		return
	}

	// Core from the core lib to construct the transaction to create an access group.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateAccessGroupMembersTxn(
		accessGroupOwnerPkBytes, accessGroupKeyNameBytes,
		accessGroupMembers, lib.AccessGroupMemberOperationTypeAdd,
		extraData,
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool(), additionalOutputs)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateAccessGroup: Problem creating transaction: %v", err))
		return
	}

	// Add node source to txn metadata
	fes.AddNodeSourceToTxnMetadata(txn)

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateAccessGroup: Problem serializing transaction: %v", err))
		return
	}

	// Return all the data associated with the transaction in the response
	res := AddAccessGroupMembersResponse{
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateAccessGroup: Problem encoding response as JSON: %v", err))
		return
	}
}

type GetAccessGroupIDsRequest struct {
	// PublicKeyBase58Check is the public key whose group IDs needs to be queried.
	PublicKeyBase58Check string `safeForLogging:"true"`
}

type GetAccessGroupIDsResponse struct {
	// Access Groups IDs.
	AccessGroupIds *AccessGroupIds `safeForLogging:"true"`
}

// represents access group owner along with the name of the Access group name encoded in hex.
type AccessGroupIdEncoded struct {
	// public key of the access group owner.
	AccessGroupOwnerPublicKeyBase58Check string
	AccessGroupKeyNameHex                string
}

// PublicKeyBase58Check is the public key whose group IDs needs to be queried.
// struct to construct the response to create an access group.
type AccessGroupIds struct {
	// access group Ids of groups owned by a given public Key.
	// using omitempty tag so that the filed is omitted if empty during serialization.
	AccessGroupIdsOwned []*AccessGroupIdEncoded `json:",omitempty" safeForLogging:"true"`
	// access group Ids of groups where a given public key account is just a member.
	AccessGroupIdsMember []*AccessGroupIdEncoded `json:",omitempty" safeForLogging:"true"`
}

// Helper function retrieve access groups of the given public keys.
// Returns both the accessGroupIdsOwned , accessGroupIdsMember by the public key.
func (fes *APIServer) getAllAccessIdsForPublicKey(publicKeyBase58DecodedBytes []byte) (groupIds *AccessGroupIds, err error) {

	// Fetch group IDs owned by the public key.
	// Return value is type  []*lib.AccessGroupId from core library.
	accessGroupIdsOwned, err := fes.getGroupOwnerAccessIdsForPublicKey(publicKeyBase58DecodedBytes)
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf("getAllAccessIdsForPublicKey: %v", err), "")
	}

	// Fetch group IDs where the public key is a member.
	// Return value is type  []*lib.AccessGroupId from core library.
	accessGroupIdsMember, err := fes.getMemberOnlyAccessIdsForPublicKey(publicKeyBase58DecodedBytes)
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf("getAllAccessIdsForPublicKey: %v", err), "")
	}

	groupIds = &AccessGroupIds{
		AccessGroupIdsOwned:  accessGroupIdsOwned,
		AccessGroupIdsMember: accessGroupIdsMember,
	}

	return groupIds, nil
}

// returns only the access groups owned by the public key.
func (fes *APIServer) getGroupOwnerAccessIdsForPublicKey(publicKeyBase58DecodedBytes []byte) ([]*AccessGroupIdEncoded, error) {
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf("getGroupOwnerAccessIdsForPublicKey: Error generating "+
			"utxo view: %v", err), "")
	}

	// call the core library and fetch group IDs owned by the public key.
	accessGroupIdsOwned, err := utxoView.GetAccessGroupIdsForOwner(publicKeyBase58DecodedBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "getGroupOwnerAccessIdsForPublicKey: Problem getting access group ids for member")
	}
	//  []*lib.AccessGroupId type doesn't encoded the publickey of the user is base 58 check format.
	// Also the access group key name is not in hex encoded format.
	// Hence, encoded the user publickey in Base58 checksum format and the access group key name in the hex encoded string format.
	accessGroupIdsOwnedEncoded := []*AccessGroupIdEncoded{}

	for _, accessGroupID := range accessGroupIdsOwned {
		accessGroupIdEncoded := &AccessGroupIdEncoded{
			AccessGroupOwnerPublicKeyBase58Check: Base58CheckEncodePublickey(accessGroupID.AccessGroupOwnerPublicKey.ToBytes()),
			AccessGroupKeyNameHex:                hex.EncodeToString(accessGroupID.AccessGroupKeyName.ToBytes()),
		}

		accessGroupIdsOwnedEncoded = append(accessGroupIdsOwnedEncoded, accessGroupIdEncoded)
	}
	return accessGroupIdsOwnedEncoded, nil
}

// returns the access groups where the given public key is only a member.
func (fes *APIServer) getMemberOnlyAccessIdsForPublicKey(publicKeyBase58DecodedBytes []byte) ([]*AccessGroupIdEncoded, error) {
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf("getMemberOnlyAccessIdsForPublicKey: Error generating "+
			"utxo view: %v", err), "")
	}

	// call the core library and fetch group IDs where the public key is a member.
	accessGroupIdsMember, err := utxoView.GetAccessGroupIdsForMember(publicKeyBase58DecodedBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "getMemberOnlyAccessIdsForPublicKey: Problem getting access group ids for member")
	}

	// []*lib.AccessGroupId type doesn't encoded the publickey of the user is base 58 check format.
	// Also the access group key name is not in hex encoded format.
	// Hence, encoded the user publickey in Base58 checksum format and the access group key name in the hex encoded string format.
	accessGroupIdsMemberEncoded := []*AccessGroupIdEncoded{}

	for _, accessGroupID := range accessGroupIdsMember {
		accessGroupIdEncoded := &AccessGroupIdEncoded{
			AccessGroupOwnerPublicKeyBase58Check: Base58CheckEncodePublickey(accessGroupID.AccessGroupOwnerPublicKey.ToBytes()),
			AccessGroupKeyNameHex:                hex.EncodeToString(accessGroupID.AccessGroupKeyName.ToBytes()),
		}

		accessGroupIdsMemberEncoded = append(accessGroupIdsMemberEncoded, accessGroupIdEncoded)
	}

	return accessGroupIdsMemberEncoded, nil
}

// API to get all access groups of a given public key.
// Returns groups where the public key is a owner and a member.
func (fes *APIServer) GetAllUserAccessGroups(ww http.ResponseWriter, req *http.Request) {

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetAccessGroupIDsRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllAccessGroups: Problem parsing request body: %v", err))
		return
	}

	// Decode the access group owner public key.
	accessGroupOwnerPkBytes, _, err := lib.Base58CheckDecode(requestData.PublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllAccessGroups: Problem decoding owner"+
			"base58 public key %s: %v", requestData.PublicKeyBase58Check, err))
		return
	}

	// get all the access groups associated with the public key.
	groupIds, err := fes.getAllAccessIdsForPublicKey(accessGroupOwnerPkBytes)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllUserAccessGroups: Problem getting access group IDs of"+
			"public key %s: %v", requestData.PublicKeyBase58Check, err))
		return
	}

	// response containing the list of access groups.
	res := GetAccessGroupIDsResponse{
		AccessGroupIds: groupIds,
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllUserAccessGroups: Problem encoding response as JSON: %v", err))
		return
	}
}

// API to fetch access groups where the given public key is an owner.
func (fes *APIServer) GetAllUserAccessGroupsOwned(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetAccessGroupIDsRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllUserAccessGroupsOwned: Problem parsing request body: %v", err))
		return
	}

	// Decode the access group owner public key.
	accessGroupOwnerPkBytes, _, err := lib.Base58CheckDecode(requestData.PublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllUserAccessGroupsOwned: Problem decoding owner"+
			"base58 public key %s: %v", requestData.PublicKeyBase58Check, err))
		return
	}

	// get owner only access groups associated with the public key.
	groupIds, err := fes.getGroupOwnerAccessIdsForPublicKey(accessGroupOwnerPkBytes)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllUserAccessGroupsOwned: Problem getting access group IDs of"+
			"public key %s: %v", requestData.PublicKeyBase58Check, err))
		return
	}

	// response containing the list of access groups.
	res := GetAccessGroupIDsResponse{
		AccessGroupIds: &AccessGroupIds{AccessGroupIdsOwned: groupIds},
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllUserAccessGroupsOwned: Problem encoding response as JSON: %v", err))
		return
	}
}

// API to fetch access groups where the given public key is a member.
func (fes *APIServer) GetAllUserAccessGroupsMemberOnly(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetAccessGroupIDsRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllUserAccessGroupsMemberOnly: Problem parsing request body: %v", err))
		return
	}

	// Decode the access group owner public key.
	accessGroupOwnerPkBytes, _, err := lib.Base58CheckDecode(requestData.PublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllUserAccessGroupsMemberOnly: Problem decoding owner"+
			"base58 public key %s: %v", requestData.PublicKeyBase58Check, err))
		return
	}

	// get member only access Ids for the public key.
	groupIds, err := fes.getMemberOnlyAccessIdsForPublicKey(accessGroupOwnerPkBytes)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllUserAccessGroupsMemberOnly: Problem getting access group IDs of"+
			"public key %s: %v", requestData.PublicKeyBase58Check, err))
		return
	}

	// response containing the list of access groups.
	res := GetAccessGroupIDsResponse{
		AccessGroupIds: &AccessGroupIds{AccessGroupIdsMember: groupIds},
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllUserAccessGroupsMemberOnly: Problem encoding response as JSON: %v", err))
		return
	}
}
