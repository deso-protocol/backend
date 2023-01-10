package routes

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/deso-protocol/core/lib"
	"github.com/pkg/errors"
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

// Base58 decodes a public key string and verifies if it is in a valid public key format.
func Base58DecodeAndValidatePublickey(publicKeyBase58Check string) (publicKeyBytes []byte, err error) {

	publicKeyBytes, _, err = lib.Base58CheckDecode(publicKeyBase58Check)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Base58DecodeAndValidatePublickey: Problem decoding "+
			"base58 public key %s: %v", publicKeyBase58Check, err))

	}

	// validate whether the access group public key is a valid public key.
	err = lib.IsByteArrayValidPublicKey(publicKeyBytes)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Base58DecodeAndValidatePublickey: Problem validating "+
			"base58 public key %s: %v", publicKeyBase58Check, err))

	}

	return publicKeyBytes, nil
}

func ValidateAccessGroupPublicKeyAndName(publicKeyBase58Check, accessGroupKeyName string) (publicKeyBytes []byte, accessGroupKeyNameBytes []byte, err error) {
	publicKeyBytes, _, err = lib.Base58CheckDecode(publicKeyBase58Check)
	if err != nil {
		return nil, nil, errors.New(fmt.Sprintf("ValidateAccessGroupPublicKeyAndName: Problem decoding "+
			"base58 public key %s: %v", publicKeyBase58Check, err))

	}
	// get the byte array of the access group key name.
	accessGroupKeyNameBytes = []byte(accessGroupKeyName)
	// Validates whether the accessGroupOwner key is a valid public key and
	// some basic checks on access group key name like Min and Max characters.
	if err = lib.ValidateAccessGroupPublicKeyAndName(accessGroupKeyNameBytes, accessGroupKeyNameBytes); err != nil {
		return nil, nil, errors.New(fmt.Sprintf("ValidateAccessGroupPublicKeyAndName: Problem validating access group owner "+
			"public key and access group key name %s: %v", accessGroupKeyName, err))

	}

	// Access group name key cannot be equal to base group name key (equal to all zeros).
	// By default all users belong to the access group with base name key.
	if lib.EqualGroupKeyName(lib.NewGroupKeyName(accessGroupKeyNameBytes), lib.BaseGroupKeyName()) {
		errors.New(fmt.Sprintf(
			"ValidateAccessGroupPublicKeyAndName: Access Group key cannot be same as base key (all zeros)."+"access group key name %s", accessGroupKeyName))
		return
	}

	return publicKeyBytes, accessGroupKeyNameBytes, nil
}

func (fes *APIServer) SendDmMessage(ww http.ResponseWriter, req *http.Request) {

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := SendDmMessageRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendDmMessage: Problem parsing request body: %v", err))
		return
	}
	senderGroupOwnerPkBytes, senderGroupKeyNameBytes, err :=
		ValidateAccessGroupPublicKeyAndName(requestData.SenderAccessGroupOwnerPublicKeyBase58Check, requestData.SenderAccessGroupKeyName)
	// Decode the access group owner public key.
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendDmMessage: Problem validating sender public key and access group name"+
			"base58 public key %s: %s %v",
			requestData.SenderAccessGroupOwnerPublicKeyBase58Check, requestData.SenderAccessGroupKeyName, err))
		return
	}

	recipientGroupOwnerPkBytes, recipientGroupKeyNameBytes, err :=
		ValidateAccessGroupPublicKeyAndName(requestData.RecipientAccessGroupOwnerPublicKeyBase58Check, requestData.RecipientAccessGroupKeyName)
	// Decode the access group owner public key.
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendDmMessage: Problem validating sender public key and access group name"+
			"base58 public key %s: %s %v",
			requestData.SenderAccessGroupOwnerPublicKeyBase58Check, requestData.SenderAccessGroupKeyName, err))
		return
	}

	if bytes.Equal(senderGroupOwnerPkBytes, recipientGroupOwnerPkBytes) {
		_AddBadRequestError(ww, fmt.Sprintf("SendDmMessage: Dm sender and recipient "+
			"cannot be the same %s: %s",
			requestData.SenderAccessGroupOwnerPublicKeyBase58Check, requestData.SenderAccessGroupKeyName))
		return

	}

	senderAccessGroupPkbytes, err := Base58DecodeAndValidatePublickey(requestData.SenderAccessGroupPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendDmMessage: Problem validating sender "+
			"base58 public key %s: %v", requestData.SenderAccessGroupPublicKeyBase58Check, err))
		return
	}

	recipientAccessGroupPkbytes, err := Base58DecodeAndValidatePublickey(requestData.SenderAccessGroupPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendDmMessage: Problem validating recipient "+
			"base58 public key %s: %v", requestData.SenderAccessGroupPublicKeyBase58Check, err))
		return
	}

	// Compute the additional transaction fees as specified by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(lib.TxnTypeAccessGroup, senderGroupOwnerPkBytes, requestData.TransactionFees)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendDmMessage: TransactionFees specified in Request body are invalid: %v", err))
		return
	}

	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendDmMessage: Problem encoding ExtraData: %v", err))
		return
	}

	tstamp := uint64(time.Now().UnixNano())

	// Core from the core lib to construct the transaction to create an access group.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateNewMessageTxn(
		senderGroupOwnerPkBytes, *lib.NewPublicKey(senderGroupOwnerPkBytes), *lib.NewGroupKeyName(senderGroupKeyNameBytes), *lib.NewPublicKey(senderAccessGroupPkbytes),
		*lib.NewPublicKey(recipientGroupOwnerPkBytes), *lib.NewGroupKeyName(recipientGroupKeyNameBytes), *lib.NewPublicKey(recipientAccessGroupPkbytes),
		requestData.EncryptedMessageText, tstamp,
		lib.NewMessageTypeDm, lib.NewMessageOperationCreate,
		extraData, requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool(), additionalOutputs)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendDmMessage: Problem creating transaction: %v", err))
		return
	}

	// Add node source to txn metadata
	fes.AddNodeSourceToTxnMetadata(txn)

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendDmMessage: Problem serializing transaction: %v", err))
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
		_AddBadRequestError(ww, fmt.Sprintf("SendDmMessage: Problem encoding response as JSON: %v", err))
		return
	}

}

func (fes *APIServer) SendGroupChatMessage(ww http.ResponseWriter, req *http.Request) {

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := SendDmMessageRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendGroupChatMessage: Problem parsing request body: %v", err))
		return
	}
	senderGroupOwnerPkBytes, senderGroupKeyNameBytes, err :=
		ValidateAccessGroupPublicKeyAndName(requestData.SenderAccessGroupOwnerPublicKeyBase58Check, requestData.SenderAccessGroupKeyName)
	// Decode the access group owner public key.
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendGroupChatMessage: Problem validating sender public key and access group name"+
			"base58 public key %s: %s %v",
			requestData.SenderAccessGroupOwnerPublicKeyBase58Check, requestData.SenderAccessGroupKeyName, err))
		return
	}

	recipientGroupOwnerPkBytes, recipientGroupKeyNameBytes, err :=
		ValidateAccessGroupPublicKeyAndName(requestData.RecipientAccessGroupOwnerPublicKeyBase58Check, requestData.RecipientAccessGroupKeyName)
	// Decode the access group owner public key.
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendGroupChatMessage: Problem validating sender public key and access group name"+
			"base58 public key %s: %s %v",
			requestData.SenderAccessGroupOwnerPublicKeyBase58Check, requestData.SenderAccessGroupKeyName, err))
		return
	}

	if bytes.Equal(senderGroupOwnerPkBytes, recipientGroupOwnerPkBytes) {
		_AddBadRequestError(ww, fmt.Sprintf("SendGroupChatMessage: Dm sender and recipient "+
			"cannot be the same %s: %s",
			requestData.SenderAccessGroupOwnerPublicKeyBase58Check, requestData.SenderAccessGroupKeyName))
		return

	}

	senderAccessGroupPkbytes, err := Base58DecodeAndValidatePublickey(requestData.SenderAccessGroupPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendGroupChatMessage: Problem validating sender "+
			"base58 public key %s: %v", requestData.SenderAccessGroupPublicKeyBase58Check, err))
		return
	}

	recipientAccessGroupPkbytes, err := Base58DecodeAndValidatePublickey(requestData.SenderAccessGroupPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendGroupChatMessage: Problem validating recipient "+
			"base58 public key %s: %v", requestData.SenderAccessGroupPublicKeyBase58Check, err))
		return
	}

	// Compute the additional transaction fees as specified by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(lib.TxnTypeAccessGroup, senderGroupOwnerPkBytes, requestData.TransactionFees)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendGroupChatMessage: TransactionFees specified in Request body are invalid: %v", err))
		return
	}

	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendGroupChatMessage: Problem encoding ExtraData: %v", err))
		return
	}

	tstamp := uint64(time.Now().UnixNano())

	// Core from the core lib to construct the transaction to create an access group.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateNewMessageTxn(
		senderGroupOwnerPkBytes, *lib.NewPublicKey(senderGroupOwnerPkBytes), *lib.NewGroupKeyName(senderGroupKeyNameBytes), *lib.NewPublicKey(senderAccessGroupPkbytes),
		*lib.NewPublicKey(recipientGroupOwnerPkBytes), *lib.NewGroupKeyName(recipientGroupKeyNameBytes), *lib.NewPublicKey(recipientAccessGroupPkbytes),
		requestData.EncryptedMessageText, tstamp,
		lib.NewMessageTypeGroupChat, lib.NewMessageOperationCreate,
		extraData, requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool(), additionalOutputs)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendGroupChatMessage: Problem creating transaction: %v", err))
		return
	}

	// Add node source to txn metadata
	fes.AddNodeSourceToTxnMetadata(txn)

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendGroupChatMessage: Problem serializing transaction: %v", err))
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
		_AddBadRequestError(ww, fmt.Sprintf("SendGroupChatMessage: Problem encoding response as JSON: %v", err))
		return
	}

}
