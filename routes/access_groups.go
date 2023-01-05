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
	// Name of the access group to be created.
	AccessGroupKeyName string `safeForLogging:"true"`

	MinFeeRateNanosPerKB uint64 `safeForLogging:"true"`
	// No need to specify ProfileEntryResponse in each TransactionFee
	TransactionFees []TransactionFee `safeForLogging:"true"`
}

// Endpoint implementation to create new access group.
// This endpoint should enable users to create a new access group.
// The endpoint should call the CreateAccessGroupTxn function from the core repo.
func (fes *APIServer) CreateAccessGroup(ww http.ResponseWriter, req *http.Request) {

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := SendMessageStatelessRequest{}
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
}

func (fes *APIServer) AddAccessGroupMembers(ww http.ResponseWriter, req *http.Request) {

}
func (fes *APIServer) GetAllAccessGroups(ww http.ResponseWriter, req *http.Request) {

}
func (fes *APIServer) GetAllUserAccessGroupsOwned(ww http.ResponseWriter, req *http.Request) {

}
func (fes *APIServer) GetAllUserAccessGroupsMemberOnly(ww http.ResponseWriter, req *http.Request) {

}
