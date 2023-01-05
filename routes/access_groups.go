package routes

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/deso-protocol/core/lib"
)

type CreateAccessGroupRequest struct {
	// SenderPublicKeyBase58Check is the public key in base58check of the message sender.
	SenderPublicKeyBase58Check string `safeForLogging:"true"`
	// AccessGroupPublicKeyBase58Check is the Public key required to participate in the access groups.
	AccessGroupPublicKeyBase58Check string `safeForLogging:"true"`
	// Name of the access group to be created.
	AccessGroupKeyName string `safeForLogging:"true"`

	MinFeeRateNanosPerKB uint64 `safeForLogging:"true"`
	// No need to specify ProfileEntryResponse in each TransactionFee
	TransactionFees []TransactionFee `safeForLogging:"true"`
}

// Endpoint implementation to create new access group.
// This endpoint should enable users to create a new access group.
// The endpoint should call the CreateAccessGroupTxn function from the core repo.
// Here are some useful info about creating access groups.

// 1. Creating an access group requires two public keys
//    One is of course your account public key, which is your identity on the blockchain.
//    In addition to that you need an AccessGroupPublicKey, which is used to create identity for access control.
// 2. The AccessGroupPublicKey must be different your account public key.
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

func (fes *APIServer) CreateAccessGroup(ww http.ResponseWriter, req *http.Request) {

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := CreateAccessGroupRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendMessageStateless: Problem parsing request body: %v", err))
		return
	}
	// Decode the sender public key.
	senderPkBytes, _, err := lib.Base58CheckDecode(requestData.SenderPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendMessageStateless: Problem decoding sender "+
			"base58 public key %s: %v", requestData.SenderPublicKeyBase58Check, err))
		return
	}

	// Parse sender public key to lib.PublicKey
	senderPublicKey := lib.NewPublicKey(senderPkBytes)

	accessGroupPkBytes, _, err := lib.Base58CheckDecode(requestData.AccessGroupPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendMessageStateless: Problem decoding recipient "+
			"base58 public key %s: %v", requestData.AccessGroupPublicKeyBase58Check, err))
		return
	}

	accessGroupKeyNameBytes := []byte(requestData.AccessGroupKeyName)

}

func (fes *APIServer) AddAccessGroupMembers(ww http.ResponseWriter, req *http.Request) {

}
func (fes *APIServer) GetAllAccessGroups(ww http.ResponseWriter, req *http.Request) {

}
func (fes *APIServer) GetAllUserAccessGroupsOwned(ww http.ResponseWriter, req *http.Request) {

}
func (fes *APIServer) GetAllUserAccessGroupsMemberOnly(ww http.ResponseWriter, req *http.Request) {

}
