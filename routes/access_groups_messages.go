package routes

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/deso-protocol/core/lib"
)

/*type NewMessageMetadata struct {
	SenderAccessGroupOwnerPublicKey    PublicKey
	SenderAccessGroupKeyName           GroupKeyName
	SenderAccessGroupPublicKey         PublicKey
	RecipientAccessGroupOwnerPublicKey PublicKey
	RecipientAccessGroupKeyName        GroupKeyName
	RecipientAccessGroupPublicKey      PublicKey
	EncryptedText                      []byte
	TimestampNanos                     uint64
	// TODO: Add operation type create/update
	NewMessageType
	NewMessageOperation
}*/

type SendDmMessageRequest struct {
	// Public key of the direct message sender.
	// This needs to match your public key used for signing the transaction.
	SenderAccessGroupOwnerPublicKeyBase58Check string `safeForLogging:"true"`
	// AccessGroupPublicKeyBase58Check is the Public key required to participate in the access groups.
	SenderAccessGroupPublicKeyBase58Check string `safeForLogging:"true"`
	// Name of the access group to be created.
	SenderAccessGroupKeyName string `safeForLogging:"true"`

	// Public key of the direct message receiver.
	RecipientAccessGroupOwnerPublicKeyBase58Check string `safeForLogging:"true"`
	// AccessGroupPublicKeyBase58Check is the Public key required to participate in the access groups.
	RecipientAccessGroupPublicKeyBase58Check string `safeForLogging:"true"`
	// Name of the access group to be created.
	RecipientAccessGroupKeyName string `safeForLogging:"true"`

	// EncryptedMessageText is the intended message content. It is recommended to pass actual encrypted message here,
	// although unencrypted message can be passed as well.
	EncryptedMessageText []byte

	MinFeeRateNanosPerKB uint64 `safeForLogging:"true"`
	// No need to specify ProfileEntryResponse in each TransactionFee
	TransactionFees []TransactionFee `safeForLogging:"true"`
	// ExtraData is an arbitrary key value map
	ExtraData map[string]string
}

type SendDmResponse struct {
	TstampNanos uint64

	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgDeSoTxn
	TransactionHex    string
}

func (fes *APIServer) SendDmMessage(ww http.ResponseWriter, req *http.Request) {

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
