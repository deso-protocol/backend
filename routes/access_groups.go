package routes

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/deso-protocol/core/lib"
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
	// get the byte array of the access group key name.
	accessGroupKeyNameBytes := []byte(requestData.AccessGroupKeyName)
	// Validates whether the accessGroupOwner key is a valid public key and
	// some basic checks on access group key name like Min and Max characters.
	// FIXME: Should we call lib.ValidateAccessGroupPublicKeyAndNameWithUtxoView to validate whether the access group key is already taken?
	if err = lib.ValidateAccessGroupPublicKeyAndName(accessGroupOwnerPkBytes, accessGroupKeyNameBytes); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateAccessGroup: Problem validating access group owner "+
			"public key and access group key name %s: %v", requestData.AccessGroupKeyName, err))
		return
	}

	// Access group name key cannot be equal to base name key (equal to all zeros).
	if lib.EqualGroupKeyName(lib.NewGroupKeyName(accessGroupKeyNameBytes), lib.BaseGroupKeyName()) {
		_AddBadRequestError(ww, fmt.Sprintf(
			"CreateAccessGroup: Access Group key cannot be same as base key (all zeros)."+"access group key name %s", requestData.AccessGroupKeyName))
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

//  1. AccessGroupMemberPublicKeyBase58Check : The public key of the member to be added to the group.
//     Should be a valid public key.
//  2. AccessGroupMemberKeyName:  String containing the key of one of the existing access group to which the user belongs to.
//     Cannot be a random string. A validation is performed to check that the AccessGroupMemberPublicKey is indeed a
//     member to the access group with AccessGroupMemberKeyName.
//     Hence you cannot pass a value to AccessGroupMemberKeyName if the user doesn't belong to an access group with key AccessGroupMemberKeyName.
//     The access group owner can add themselves as a member using lib.BaseGroup() as AccessGroupMemberKeyName.
//     Access Group owners cannot add themselves to the same group using the
//     name of the access group they own as the value of the AccessGroupMemberKeyName field.
//  3. EncryptedKey, which stores the main group's access public key encrypted to the member group's access public key.
//     This is used to allow the member to decrypt the main group's access public key
//     using their individual access groups' secrets.
//     This value cannot be empty.
type AccessGroupMember struct {
	// AccessGroupOwnerPublicKeyBase58Check is the public key of the access group owner.
	// This needs to match your public key used for signing the transaction.
	// You cannot create a group for another public key.
	AccessGroupMemberPublicKeyBase58Check string `safeForLogging:"true"`

	// AccessGroupMemberKeyName is the name of the user in the access group
	AccessGroupMemberKeyName string `safeForLogging:"true"`

	EncryptedKey []byte

	ExtraData map[string][]byte
}

type AddAccessGroupMembersRequest struct {
	// AccessGroupOwnerPublicKeyBase58Check is the public key of the access group owner.
	// This needs to match your public key used for signing the transaction.
	// You cannot create a group for another public key.
	AccessGroupOwnerPublicKeyBase58Check string `safeForLogging:"true"`
	// Name of the access group to be created.
	AccessGroupKeyName string `safeForLogging:"true"`
	// The details of the members to add are contained in the accessGroupMemberList array.
	// Each entry in the accessGroupMemberList represents one user to add to the access group.

	accessGroupMemberList []AccessGroupMember `safeForLogging:"true"`
	MinFeeRateNanosPerKB  uint64              `safeForLogging:"true"`
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
	Transaction       *lib.MsgDeSoTxn
	TransactionHex    string
}

// Here are some of the important rules to use this API to add members to an access group.
// Note: This API helps you only construct a transaction to add a member. This doesn't execute a transaction.
//
//		You need to follow up with signing the transaction and submitting it to Submit Transaction API to execute the transaction.
//	 1. The access group should already exist to able to add a member.
//	 2. Only the owner of the access group can add a member.
//	    This means the AccessGroupOwnerPublicKeyBase58Check in this request should
//	    match with the key used for signing the transaction while submitting the transaction.
//	 3. An existing member of a group cannot add a member, again, only the owner can add members.
//	 4. More than one member can be added at a time.
//	 5. The information of the members to be added should be included in accessGroupMemberList.

func (fes *APIServer) AddAccessGroupMembers(ww http.ResponseWriter, req *http.Request) {

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AddAccessGroupMembersRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AddAccessGroupMembers: Problem parsing request body: %v", err))
		return
	}

	// Decode the access group owner public key.
	accessGroupOwnerPkBytes, _, err := lib.Base58CheckDecode(requestData.AccessGroupOwnerPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateAccessGroup: Problem decoding owner"+
			"base58 public key %s: %v", requestData.AccessGroupOwnerPublicKeyBase58Check, err))
		return
	}
	// get the byte array of the access group key name.
	accessGroupKeyNameBytes := []byte(requestData.AccessGroupKeyName)

	// Access group name key cannot be equal to base name key (equal to all zeros).
	if lib.EqualGroupKeyName(lib.NewGroupKeyName(accessGroupKeyNameBytes), lib.BaseGroupKeyName()) {
		_AddBadRequestError(ww, fmt.Sprintf(
			"CreateAccessGroup: Access Group key cannot be same as base key (all zeros). "+
				"access group key name %s", requestData.AccessGroupKeyName))
		return
	}
	// Validates whether the accessGroupOwner key is a valid public key and
	// some basic checks on access group key name like Min and Max characters.
	if err = lib.ValidateAccessGroupPublicKeyAndName(accessGroupOwnerPkBytes, accessGroupKeyNameBytes); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateAccessGroup: Problem validating access group owner "+
			"public key and access group key name %s: %v", requestData.AccessGroupKeyName, err))
		return
	}

	accessGroupMembers := []*lib.AccessGroupMemberEntry{}
	accessGroupMemberPublicKeys := make(map[lib.PublicKey]struct{})
	for i := 0; i < len(requestData.accessGroupMemberList); i++ {

		member := requestData.accessGroupMemberList[i]

		// Decode the access group owner public key.
		accessGroupMemberPkBytes, _, err := lib.Base58CheckDecode(member.AccessGroupMemberPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("CreateAccessGroup: Problem decoding member"+
				"base58 public key %s: %v", member.AccessGroupMemberPublicKeyBase58Check, err))
			return
		}
		// get the byte array of the access group key name.

		// Validates whether the accessGroupOwner key is a valid public key and
		// some basic checks on access group key name like Min and Max characters.
		if err = lib.ValidateAccessGroupPublicKeyAndName(accessGroupMemberPkBytes,
			[]byte(member.AccessGroupMemberKeyName)); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("CreateAccessGroup: Problem validating access group owner "+
				"public key and access group key name %s: %v", requestData.AccessGroupKeyName, err))
			return
		}

		if bytes.Equal(accessGroupOwnerPkBytes, accessGroupMemberPkBytes) &&
			bytes.Equal(lib.NewGroupKeyName(accessGroupKeyNameBytes).ToBytes(),
				lib.NewGroupKeyName([]byte(member.AccessGroupMemberKeyName)).ToBytes()) {

			_AddBadRequestError(ww, fmt.Sprintf("Can't add the owner of the group as a member of the "+
				"group using the same group key name."))
			return

		}

		if len(member.EncryptedKey) == 0 {
			_AddBadRequestError(ww, fmt.Sprintf("EncryptedKey for access member (%v)"+
				"cannot be empty.", member))
			return
		}

		memberPublicKey := *lib.NewPublicKey(accessGroupMemberPkBytes)
		if _, exists := accessGroupMemberPublicKeys[memberPublicKey]; exists {
			_AddBadRequestError(ww, fmt.Sprintf("EncryptedKey for access member (%v)"+
				"cannot be empty.", member))
			return
		}

		accessGroupMemberEntry := &lib.AccessGroupMemberEntry{
			AccessGroupMemberPublicKey: lib.NewPublicKey(accessGroupMemberPkBytes),
			AccessGroupMemberKeyName:   lib.NewGroupKeyName([]byte(member.AccessGroupMemberKeyName)),
			EncryptedKey:               member.EncryptedKey,
			ExtraData:                  member.ExtraData,
		}
		accessGroupMembers = append(accessGroupMembers, accessGroupMemberEntry)

		accessGroupMemberPublicKeys[memberPublicKey] = struct{}{}
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

func (fes *APIServer) GetAllAccessGroups(ww http.ResponseWriter, req *http.Request) {

}
func (fes *APIServer) GetAllUserAccessGroupsOwned(ww http.ResponseWriter, req *http.Request) {

}
func (fes *APIServer) GetAllUserAccessGroupsMemberOnly(ww http.ResponseWriter, req *http.Request) {

}
