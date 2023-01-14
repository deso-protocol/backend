package routes

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/deso-protocol/core/lib"
	"github.com/pkg/errors"
)

// Base58 decodes a public key string and verifies if it is in a valid public key format.
func Base58DecodeAndValidatePublickey(publicKeyBase58Check string) (publicKeyBytes []byte, err error) {
	// Decode in Base58 Checksum format.
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

// Basic validations on public key and access Group Keu name.
func ValidateAccessGroupPublicKeyAndName(publicKeyBase58Check, accessGroupKeyName string) (publicKeyBytes []byte, accessGroupKeyNameBytes []byte, err error) {
	publicKeyBytes, err = Base58DecodeAndValidatePublickey(publicKeyBase58Check)
	if err != nil {
		return nil, nil, errors.New(fmt.Sprintf("ValidateAccessGroupPublicKeyAndName: Problem decoding "+
			"base58 public key %s: %v", publicKeyBase58Check, err))

	}
	// get the byte array of the access group key name.
	accessGroupKeyNameBytes = []byte(accessGroupKeyName)
	// Validates whether the accessGroupOwner key is a valid public key and
	// some basic checks on access group key name like Min and Max characters.
	if err = lib.ValidateAccessGroupPublicKeyAndName(accessGroupKeyNameBytes, accessGroupKeyNameBytes); err != nil {
		return nil, nil, errors.New(fmt.Sprintf("ValidateAccessGroupPublicKeyAndName: Problem validating "+
			"public key and access group key name %s %s: %v", publicKeyBase58Check, accessGroupKeyName, err))

	}

	// Access group name key cannot be equal to base group name key (equal to all zeros).
	// By default all users belong to the access group with the base name key, hence it is reserved.
	if lib.EqualGroupKeyName(lib.NewGroupKeyName(accessGroupKeyNameBytes), lib.BaseGroupKeyName()) {
		errors.New(fmt.Sprintf(
			"ValidateAccessGroupPublicKeyAndName: Access Group key cannot be same as base key (all zeros)."+
				"Access group key name %s", accessGroupKeyName))
		return
	}

	return publicKeyBytes, accessGroupKeyNameBytes, nil
}

// Helper function to encode a public key to Base58 Checksum format.
func Base58EncodePublickey(publickeyBytes []byte) (Base58EncodedPublickey string) {
	// 3 byte public key prefix as per the base58 checksum format.
	Base58CheckPrefix := [3]byte{0xcd, 0x14, 0x0}
	return lib.Base58CheckEncodeWithPrefix(publickeyBytes, Base58CheckPrefix)
}

// Helper function to fetch just the latest message from the given Dm thread.
// StartTimestamp is set to current unix time to fetch the latest message.
// DmThread key consists of the sender and recipient public key and access group key names to fetch the direct messages
// between the two parties.
func (fes *APIServer) fetchLatestMessageFromSingleDmThread(dmThreadKey *lib.DmThreadKey, startTimestamp uint64) (*lib.NewMessageEntry, error) {
	// Fetch just one message.
	latestMessageEntries, err := fes.fetchMaxMessagesFromDmThread(dmThreadKey, startTimestamp, 1)
	if err != nil {
		return nil, errors.Wrap(err, "")
	}
	// If there are more than one entries fetch just the last message.
	if len(latestMessageEntries) > 0 {
		return latestMessageEntries[0], nil
	}
	// Don't return an error if there are zero entries, return empty value.
	// client might be dependent on empty value to implement the fetching logic.
	return &lib.NewMessageEntry{}, nil
}

// Fetch MaxMessagesToFetch with message time stamp starting from startTimestamp.
// Fetches the Direct messages between the sender and recipient information inside the dmThreadKey.
func (fes *APIServer) fetchMaxMessagesFromDmThread(dmThreadKey *lib.DmThreadKey, startTimestamp uint64, MaxMessagesToFetch int) ([]*lib.NewMessageEntry, error) {
	// Universal view gives the endpoint a "union" of the "state" between what's in the mempool and what's in the blocks.
	// Basically gives you access to both the transactions in mined blocks, and not yet mined transaction data in the mempool.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf("Error generating "+
			"utxo view: %v", err), "")
	}

	// Fetch MaxMessagesToFetch with message time stamp starting from startTimestamp.
	latestMessageEntries, err := utxoView.GetPaginatedMessageEntriesForDmThread(*dmThreadKey, startTimestamp, uint64(MaxMessagesToFetch))
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf("Error fetching dm entries for dmThreadKey, "+
			"startTimestamp, and MaxMessagesToFetch: %v %v %v", dmThreadKey, startTimestamp, MaxMessagesToFetch), "")
	}

	return latestMessageEntries, nil
}

// Takes an array of DmThread Keys (Sender and Recipient public keys and access group key names),
// returns the latest message with their timestamp for each dmthread key.
func (fes *APIServer) fetchLatestMessageFromDmThreads(dmThreads []*lib.DmThreadKey) ([]*lib.NewMessageEntry, error) {
	// *lib.NewMessageEntry is data structure used in core library for each direct message or a message in a group chat.
	var latestMessageEntries []*lib.NewMessageEntry
	// Using current unix time as a time stamp since we're fetching the latest message.
	currentUnixTime := time.Now().Unix()
	// Iterate over DmThreads and Fetch latest message for each of them.
	for _, dmThread := range dmThreads {
		latestMessageEntry, err := fes.fetchLatestMessageFromSingleDmThread(dmThread, uint64(currentUnixTime))
		if err != nil {
			return nil, errors.Wrap(err, "")
		}

		latestMessageEntries = append(latestMessageEntries, latestMessageEntry)
	}

	return latestMessageEntries, nil
}

// Helper function retrieve all the keys of the direct messages of the user(identified by publicKeyBase58DecodedBytes)(identified by )
// Returns the <Public key, access group key> of every direct message conversation of the user.
func (fes *APIServer) getAllDmThreadsForPublicKey(publicKeyBase58DecodedBytes []byte) (dmThreads []*lib.DmThreadKey, err error) {
	// Universal view gives the endpoint a "union" of the "state" between what's in the mempool and what's in the blocks.
	// Basically gives you access to both the transactions in mined blocks, and not yet mined transaction data in the mempool.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf("getGroupOwnerAccessIdsForPublicKey: Error generating "+
			"utxo view: %v", err), "")
	}

	// call the core library function to fetch the direct message threads (dmThreads) of the user.
	dmThreads, err = utxoView.GetAllUserDmThreads(*lib.NewPublicKey(publicKeyBase58DecodedBytes))
	if err != nil {
		return nil, errors.Wrapf(err, "Problem getting direct message threads for user %s", Base58EncodePublickey(publicKeyBase58DecodedBytes))
	}

	return dmThreads, nil
}

// Helper function to fetch just the latest message from the given group chat thread.
// StartTimestamp is set to current unix time to fetch the latest message.
// accessGroupId (type  *lib.AccessGroupId) consists of a member public key and the access key name to be used to fetch the group chats.
func (fes *APIServer) fetchLatestMessageFromGroupChatThread(accessGroupId *lib.AccessGroupId, startTimestamp uint64) (*lib.NewMessageEntry, error) {
	// Just fetch the latest message from the group chat represented by accessGroupId.
	latestMessageEntries, err := fes.fetchMaxMessagesFromGroupChatThread(accessGroupId, startTimestamp, 1)
	if err != nil {
		return nil, errors.Wrap(err, "")
	}
	// If there are more than one entry, just send the latest one.
	if len(latestMessageEntries) > 0 {
		return latestMessageEntries[0], nil
	}
	// Send empty response for nil entries.
	// Don't send an error, since clients/caller can form a logic based on empty entries.
	return &lib.NewMessageEntry{}, nil
}

// Fetch MaxMessagesToFetch number of group chat messages, starting from the message timestamp of startTimestamp,
// where the public key and access group key name in accessGroupId is a member.
// accessGroupId (type  *lib.AccessGroupId) consists of a member public key and the access key name to be used to fetch the group chats.
func (fes *APIServer) fetchMaxMessagesFromGroupChatThread(accessGroupId *lib.AccessGroupId, startTimestamp uint64, MaxMessagesToFetch int) ([]*lib.NewMessageEntry, error) {
	// Universal view gives the endpoint a "union" of the "state" between what's in the mempool and what's in the blocks.
	// Basically gives you access to both the transactions in mined blocks, and not yet mined transaction data in the mempool.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf("getGroupOwnerAccessIdsForPublicKey: Error generating "+
			"utxo view: %v", err), "")
	}
	latestMessageEntries, err := utxoView.GetPaginatedMessageEntriesForGroupChatThread(*accessGroupId, startTimestamp, uint64(MaxMessagesToFetch))
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf("Error fetching messages for access group ID, "+
			"startTimestamp, and MaxMessagesToFetch: %v %v %v", accessGroupId, startTimestamp, MaxMessagesToFetch), "")
	}
	return latestMessageEntries, nil
}

// Fetch only the latest group chat message threads.
// Iterates the access group key names in groupChatThreads, and fetches their latest message.
// accessGroupId (type  *lib.AccessGroupId) consists of a member public key and the access key name to be used to fetch the group chats.
func (fes *APIServer) fetchLatestMessageFromGroupChatThreads(groupChatThreads []*lib.AccessGroupId) ([]*lib.NewMessageEntry, error) {

	var latestMessageEntries []*lib.NewMessageEntry
	// Use current unix time stamp since we're fetching only the latest message.
	currTime := time.Now().Unix()
	// Iterate through each group chat thread and fetch their latest message.
	for _, dmThread := range groupChatThreads {
		latestMessageEntry, err := fes.fetchLatestMessageFromGroupChatThread(dmThread, uint64(currTime))
		if err != nil {
			return nil, errors.Wrap(err, "")
		}

		latestMessageEntries = append(latestMessageEntries, latestMessageEntry)
	}
	return latestMessageEntries, nil
}

// Helper function retrieve group chat threads for a given public key.
// Returns the Access group Ids of all the group chats where publicKeyBase58DecodedBytes is participating.
func (fes *APIServer) getAllGroupChatThreadsForPublicKey(publicKeyBase58DecodedBytes []byte) (groupChatThreads []*lib.AccessGroupId, err error) {
	// Universal view gives the endpoint a "union" of the "state" between what's in the mempool and what's in the blocks.
	// Basically gives you access to both the transactions in mined blocks, and not yet mined transaction data in the mempool.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf("getGroupOwnerAccessIdsForPublicKey: Error generating "+
			"utxo view: %v", err), "")
	}

	// call the core library and fetch group chats where the user(publicKeyBase58DecodedBytes) is participating.
	groupChatThreads, err = utxoView.GetAllUserGroupChatThreads(*lib.NewPublicKey(publicKeyBase58DecodedBytes))
	if err != nil {
		return nil, errors.Wrapf(err, "getGroupOwnerAccessIdsForPublicKey: Problem getting access group ids for member")
	}

	return groupChatThreads, nil
}

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

// struct to serialize the response.
type SendDmResponse struct {
	TstampNanos uint64

	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgDeSoTxn
	TransactionHex    string
}

// API to send Direct message.
// Direct message is from <SenderPublicKey, Access Group Key Name> to <RecipientPublickey, Access Group Key Name>
// This API only helps you compose a Direct message transaction, it doesn't execute it.
// To execute the Direct message transaction, you need to collect the response from this API, sign it and then submit the transaction for on-chain execution.
// Read more about the three step transaction submission process here https://docs.deso.org/for-developers/backend/transactions.
// Since the transaction execution doesn't happen here, deeper validations like whether the user is the owner of access group key name
// are performed after submitting the transaction.
// Only basic validations on the input data are performed here.
func (fes *APIServer) SendDmMessage(ww http.ResponseWriter, req *http.Request) {
	// Deserialize the request data.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := SendDmMessageRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendDmMessage: Problem parsing request body: %v", err))
		return
	}

	// Basic validation of the sender public key and access group name.
	senderGroupOwnerPkBytes, senderGroupKeyNameBytes, err :=
		ValidateAccessGroupPublicKeyAndName(requestData.SenderAccessGroupOwnerPublicKeyBase58Check, requestData.SenderAccessGroupKeyName)
		// Abruptly end the request processing on error and return.
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendDmMessage: Problem validating sender public key and access group name"+
			"base58 public key %s: %s %v",
			requestData.SenderAccessGroupOwnerPublicKeyBase58Check, requestData.SenderAccessGroupKeyName, err))
		return
	}

	// Basic validation of the recipient public key and access group name.
	recipientGroupOwnerPkBytes, recipientGroupKeyNameBytes, err :=
		ValidateAccessGroupPublicKeyAndName(requestData.RecipientAccessGroupOwnerPublicKeyBase58Check, requestData.RecipientAccessGroupKeyName)
		// Abruptly end the request processing on error and return.
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendDmMessage: Problem validating sender public key and access group name"+
			"base58 public key %s: %s %v",
			requestData.SenderAccessGroupOwnerPublicKeyBase58Check, requestData.SenderAccessGroupKeyName, err))
		return
	}

	// sender and the recipient public keys cannot be the same.
	if bytes.Equal(senderGroupOwnerPkBytes, recipientGroupOwnerPkBytes) {
		// Abruptly end the request processing on error and return.
		_AddBadRequestError(ww, fmt.Sprintf("SendDmMessage: Dm sender and recipient "+
			"cannot be the same %s: %s",
			requestData.SenderAccessGroupOwnerPublicKeyBase58Check, requestData.SenderAccessGroupKeyName))
		return
	}

	// Validate the sender access group public key.
	senderAccessGroupPkbytes, err := Base58DecodeAndValidatePublickey(requestData.SenderAccessGroupPublicKeyBase58Check)
	if err != nil {
		// Abruptly end the request processing on error and return.
		_AddBadRequestError(ww, fmt.Sprintf("SendDmMessage: Problem validating sender "+
			"base58 public key %s: %v", requestData.SenderAccessGroupPublicKeyBase58Check, err))
		return
	}

	// Validate the recipient access group public key.
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

	// extra data is relevant for certain type of requests. Refer to documentation for any requirement of adding extra data.
	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendDmMessage: Problem encoding ExtraData: %v", err))
		return
	}

	tstamp := uint64(time.Now().UnixNano())

	// Invoke function from the core library to construct the transaction to create an access group.
	// Returns the Input, change amount and fee required to create a new transaction.
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
	res := SendDmResponse{
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
	}

	// Response to the client.
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendDmMessage: Problem encoding response as JSON: %v", err))
		return
	}

}

// API to compose transaction to send a GroupChat Message.
// This API only helps you compose a group chat message transaction, it doesn't execute it.
// To execute the transaction, you need to collect the response from this API, sign it and then submit the transaction for on-chain execution.
// Read more about the three step transaction submission process here https://docs.deso.org/for-developers/backend/transactions.
// Since the transaction execution doesn't happen here, deeper validations like whether the user is the owner of access group key name
// are performed after submitting the transaction.
// Only basic validations on the input data are performed here.
func (fes *APIServer) SendGroupChatMessage(ww http.ResponseWriter, req *http.Request) {
	// Deserialize the request data.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := SendDmMessageRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendGroupChatMessage: Problem parsing request body: %v", err))
		return
	}

	// Basic validation of the sender public key and access group name.
	senderGroupOwnerPkBytes, senderGroupKeyNameBytes, err :=
		ValidateAccessGroupPublicKeyAndName(requestData.SenderAccessGroupOwnerPublicKeyBase58Check, requestData.SenderAccessGroupKeyName)
		// Abruptly end the request processing on error and return.
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendGroupChatMessage: Problem validating sender public key and access group name"+
			"base58 public key %s: %s %v",
			requestData.SenderAccessGroupOwnerPublicKeyBase58Check, requestData.SenderAccessGroupKeyName, err))
		return
	}

	// Basic validation of the recipient public key and access group name.
	recipientGroupOwnerPkBytes, recipientGroupKeyNameBytes, err :=
		ValidateAccessGroupPublicKeyAndName(requestData.RecipientAccessGroupOwnerPublicKeyBase58Check, requestData.RecipientAccessGroupKeyName)
		// Abruptly end the request processing on error and return.
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendGroupChatMessage: Problem validating sender public key and access group name"+
			"base58 public key %s: %s %v",
			requestData.SenderAccessGroupOwnerPublicKeyBase58Check, requestData.SenderAccessGroupKeyName, err))
		return
	}

	// sender and the recipient public keys cannot be the same.
	if bytes.Equal(senderGroupOwnerPkBytes, recipientGroupOwnerPkBytes) {
		// Abruptly end the request processing on error and return.
		_AddBadRequestError(ww, fmt.Sprintf("SendGroupChatMessage: Dm sender and recipient "+
			"cannot be the same %s: %s",
			requestData.SenderAccessGroupOwnerPublicKeyBase58Check, requestData.SenderAccessGroupKeyName))
		return

	}

	// Validate the sender access group public key.
	senderAccessGroupPkbytes, err := Base58DecodeAndValidatePublickey(requestData.SenderAccessGroupPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendGroupChatMessage: Problem validating sender "+
			"base58 public key %s: %v", requestData.SenderAccessGroupPublicKeyBase58Check, err))
		return
	}

	// Validate the recipient access group public key.
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

	// extra data is relevant for certain type of requests. Refer to documentation for any requirement of adding extra data.
	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendGroupChatMessage: Problem encoding ExtraData: %v", err))
		return
	}

	tstamp := uint64(time.Now().UnixNano())

	// Call CreateNewMessageTxn the core lib to construct the transaction to send a group chat message.
	// The message type must be lib.NewMessageTypeGroupChat, and operation type is lib.NewMessageOperationCreate.
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
	res := SendDmResponse{
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

// Types to store the chat messages.

type AccessGroupInfo struct {
	OwnerPublicKeyBase58Check       string `safeForLogging:"true"`
	AccessGroupPublicKeyBase58Check string `safeForLogging:"true"`
	AccessGroupKeyName              string `safeForLogging:"true"`
}

type DmMessageInfo struct {
	EncryptedText  []byte
	TimestampNanos uint64
}

// Represents a direct message thread with sender, recipient information
// and the latest message.
// Dm Thread + LatestMessage.
type DmThreadWithLatestMessage struct {
	SenderInfo    AccessGroupInfo
	RecipientInfo AccessGroupInfo
	MessageInfo   DmMessageInfo
}

// Type to deserialize the request to fetch user dm threads.
type GetUserDmThreadsRequest struct {
	// PublicKeyBase58Check is the public key whose group IDs needs to be queried.
	UserPublicKeyBase58Check string `safeForLogging:"true"`
}

// Type to serialize the response containing direct message threads.
type GetUserDmThreadsResponse struct {
	DmThreads []DmThreadWithLatestMessage
}

// This endpoint should returns all dm threads for a user.
// Calls the GetAllUserDmThreads function from the core library.
// Should return the direct message threads of the user along with the latest message sent for each of them.
// This API just doesn't write any data, hence it doesn't create a new transaction.
// It's a public API, hence anyone with a valid public key can query the system to fetch their Direct message threads.
func (fes *APIServer) GetUserDmThreadsOrderedByTimeStamp(ww http.ResponseWriter, req *http.Request) {
	// Deserialize the request data.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetUserDmThreadsRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetUserDmThreadsOrderedByTimeStamp: Problem parsing request body: %v", err))
		return
	}

	// Decode and validate the access group owner public key.
	accessGroupOwnerPkBytes, err := Base58DecodeAndValidatePublickey(requestData.UserPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetUserDmThreadsOrderedByTimeStamp: Problem decoding owner"+
			"base58 public key %s: %v", requestData.UserPublicKeyBase58Check, err))
		return
	}

	// get all the access groups associated with the public key.
	dmThreads, err := fes.getAllDmThreadsForPublicKey(accessGroupOwnerPkBytes)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetUserDmThreadsOrderedByTimeStamp: Problem getting access group IDs of"+
			"public key %s: %v", requestData.UserPublicKeyBase58Check, err))
		return
	}

	// TODO: Right now we iterate over each dmthread and perform `n` calls to fetch latest dm message for each of them
	// This can be optimized in future by caching the latest Dm.
	// get the latest dm message for each of the Dmthread them.
	latestMessagesForThreadKeys, err := fes.fetchLatestMessageFromDmThreads(dmThreads)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetUserDmThreadsOrderedByTimeStamp: Problem getting access group IDs of"+
			"public key %s: %v", requestData.UserPublicKeyBase58Check, err))
		return
	}

	// Sort based on timestamp of the latest message of the Dm thread.
	// The most recent conversation should come first.
	sort.Slice(latestMessagesForThreadKeys, func(i, j int) bool {
		return latestMessagesForThreadKeys[i].TimestampNanos > latestMessagesForThreadKeys[j].TimestampNanos
	})
	// Dm threads with each dm represented by DmThreadWithLatestMessage.
	// Each entry consists of the sender account, recipient account info and the latest message.
	// Though the publickey of the user who initiated the request is known earlier (is part of the request data),
	// its duplicated in the api response for consistency.
	dmMessageThreads := []DmThreadWithLatestMessage{}
	for _, threadMsg := range latestMessagesForThreadKeys {
		msgThread := DmThreadWithLatestMessage{
			// public key, access group public key, and access group key name of the sender of the DM.
			SenderInfo: AccessGroupInfo{
				OwnerPublicKeyBase58Check:       Base58EncodePublickey(threadMsg.SenderAccessGroupOwnerPublicKey.ToBytes()),
				AccessGroupPublicKeyBase58Check: Base58EncodePublickey(threadMsg.SenderAccessGroupPublicKey.ToBytes()),
				AccessGroupKeyName:              hex.EncodeToString(threadMsg.SenderAccessGroupKeyName.ToBytes()),
			},
			// public key, access group public key, and access group key name of the recipient of the DM.
			RecipientInfo: AccessGroupInfo{
				OwnerPublicKeyBase58Check:       Base58EncodePublickey(threadMsg.RecipientAccessGroupOwnerPublicKey.ToBytes()),
				AccessGroupPublicKeyBase58Check: Base58EncodePublickey(threadMsg.RecipientAccessGroupPublicKey.ToBytes()),
				// access group key name is hex encoded.
				AccessGroupKeyName: hex.EncodeToString((threadMsg.RecipientAccessGroupKeyName.ToBytes())),
			},
			// Direct message encrypted text and timestamp.
			MessageInfo: DmMessageInfo{
				EncryptedText:  threadMsg.EncryptedText,
				TimestampNanos: threadMsg.TimestampNanos,
			},
		}

		dmMessageThreads = append(dmMessageThreads, msgThread)
	}

	// response containing the list of access groups.
	res := GetUserDmThreadsResponse{
		DmThreads: dmMessageThreads,
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetUserDmThreadsOrderedByTimeStamp: Problem encoding response as JSON: %v", err))
		return
	}
}

// type to deserialize the http request to fetch message from a specific direct message thread (dmThread).
type GetPaginatedMessagesForDmThreadRequest struct {
	//  A Direct message thread is a conversation between two parties.
	// The first party is represented by the prefix "User".
	UserGroupOwnerPublicKeyBase58Check string
	UserGroupKeyName                   string
	// The second party is represented by prefix "party"
	PartyGroupOwnerPublicKeyBase58Check string
	PartyGroupKeyName                   string
	// Filter to fetch direct messages who time stamp is less than StartTimeStamp.
	// So you need to set this to current time and MaxMessagesToFetch to 10, to fetch
	//  the latest 10 messages.
	StartTimeStamp     uint64
	MaxMessagesToFetch int
}

// type to serialize the response containing the direct messages between two parties.
type GetPaginatedMessagesForDmResponse struct {
	// First party info.
	SenderInfo AccessGroupInfo
	// Second party info.
	RecipientInfo AccessGroupInfo
	// Messages between them.
	MessageInfo []DmMessageInfo
}

// API is used to fetch the direct messages between two parties in a paginated way.
// This is useful for applications to fetch only N number of direct messages between two parties at once.
// Timestamp in the request data can be altered to fetch subsequent N messages in each call to fetch the direct messages.

// This API just doesn't write any data, hence it doesn't create a new transaction.
// It's a public API, hence anyone with a valid input data can query the system to fetch their Direct messages.
func (fes *APIServer) GetPaginatedMessagesForDmThread(ww http.ResponseWriter, req *http.Request) {
	// Deserialize the request data.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetPaginatedMessagesForDmThreadRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedMessagesForDmThread: Problem parsing request body: %v", err))
		return
	}

	// Why fetch if there's less than one message to fetch!!!!!
	if requestData.MaxMessagesToFetch < 1 {
		_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedMessagesForDmThread: MaxMessagesToFetch cannot be less than 1: %v", requestData.MaxMessagesToFetch))
		return
	}

	// Basic validation of the sender public key and access group name.
	senderGroupOwnerPkBytes, senderGroupKeyNameBytes, err :=
		ValidateAccessGroupPublicKeyAndName(requestData.UserGroupOwnerPublicKeyBase58Check, requestData.UserGroupKeyName)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedMessagesForDmThread: Problem validating "+
			"user group owner public key and access group name %s: %s %v",
			requestData.UserGroupOwnerPublicKeyBase58Check, requestData.PartyGroupOwnerPublicKeyBase58Check, err))
		return
	}

	// Basic validation of the public key and access group name of the other party in the dm.
	recipientGroupOwnerPkBytes, recipientGroupKeyNameBytes, err :=
		ValidateAccessGroupPublicKeyAndName(requestData.PartyGroupOwnerPublicKeyBase58Check, requestData.PartyGroupKeyName)
	// Decode the access group owner public key.
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedMessagesForDmThread: Problem validating "+
			"party group owner public key and access group name %s: %s %v",
			requestData.PartyGroupOwnerPublicKeyBase58Check, requestData.PartyGroupKeyName, err))
		return
	}

	// sender and the recipient public keys cannot be the same.
	if bytes.Equal(senderGroupOwnerPkBytes, recipientGroupOwnerPkBytes) {
		_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedMessagesForDmThread: Dm sender and recipient "+
			"cannot be the same %s: %s",
			requestData.UserGroupOwnerPublicKeyBase58Check, requestData.PartyGroupOwnerPublicKeyBase58Check))
		return

	}

	// The information of the two parties involved in Dm has to encoded in lib.DmThreadKey.
	dmThreadKey := lib.MakeDmThreadKey(*lib.NewPublicKey(senderGroupKeyNameBytes), *lib.NewGroupKeyName(senderGroupKeyNameBytes),
		*lib.NewPublicKey(recipientGroupOwnerPkBytes), *lib.NewGroupKeyName(recipientGroupKeyNameBytes))

	// Fetch the max messages between the sender and the party.
	latestMessages, err := fes.fetchMaxMessagesFromDmThread(&dmThreadKey, requestData.StartTimeStamp, requestData.MaxMessagesToFetch)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedMessagesForDmThread: Problem getting paginated messages for "+
			"Request Data: %v: %v", requestData, err))
		return
	}

	// Since the two parties in the conversation in same in all the message if added this info upfront.
	dms := GetPaginatedMessagesForDmResponse{
		SenderInfo: AccessGroupInfo{
			OwnerPublicKeyBase58Check: Base58EncodePublickey(senderGroupKeyNameBytes),
			AccessGroupKeyName:        hex.EncodeToString(senderGroupKeyNameBytes),
		},
		RecipientInfo: AccessGroupInfo{
			OwnerPublicKeyBase58Check: Base58EncodePublickey(recipientGroupOwnerPkBytes),
			AccessGroupKeyName:        hex.EncodeToString(recipientGroupKeyNameBytes),
		},
		MessageInfo: []DmMessageInfo{},
	}

	// Now append each of their Direct message (Dm) conversations.
	for _, threadMsg := range latestMessages {
		dms.MessageInfo = append(dms.MessageInfo,
			DmMessageInfo{
				EncryptedText:  threadMsg.EncryptedText,
				TimestampNanos: threadMsg.TimestampNanos,
			},
		)
	}

	// response containing dms between sender and the party.
	res := dms

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedMessagesForDmThread: Problem encoding response as JSON: %v", err))
		return
	}

}

// type and APIs to operate with Group chat feature.
type GetUserGroupChatRequest struct {
	// PublicKeyBase58Check is the public key whose group IDs needs to be queried.
	UserPublicKeyBase58Check string `safeForLogging:"true"`
}

type GetUserGroupChatResponse struct {
	GroupChatThreads []GroupChatThread
}

type GroupChatThread struct {
	SenderInfo    AccessGroupInfo
	RecipientInfo AccessGroupInfo
	MessageInfo   DmMessageInfo
}

// Similar to GetUserDmThreadsOrderedByTimeStamp, expect that it fetches the group chat threads instead of direct messages.
// Need to call lib.GetAllUserGroupChatThreads from the core library.
// Just need the public key of the user in the request data.
// Returns the group chat threads along with their latest messages.
// The group chats are sorted/ordered by the time stamp of their latest message.

// This API just doesn't write any data, hence it doesn't create a new transaction.
// It's a public API, hence anyone with a valid public key can query the system to fetch their Direct message threads.
func (fes *APIServer) GetUserGroupChatThreadsOrderedByTimestamp(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetUserGroupChatRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetUserGroupChatThreadsOrderedByTimestamp: Problem parsing request body: %v", err))
		return
	}

	// Decode the access group owner public key.
	accessGroupOwnerPkBytes, _, err := lib.Base58CheckDecode(requestData.UserPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetUserGroupChatThreadsOrderedByTimestamp: Problem decoding owner"+
			"base58 public key %s: %v", requestData.UserPublicKeyBase58Check, err))
		return
	}

	// get all the group chat threads for the public key.
	groupChatThreads, err := fes.getAllGroupChatThreadsForPublicKey(accessGroupOwnerPkBytes)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetUserGroupChatThreadsOrderedByTimestamp: Problem getting access group IDs of"+
			"public key %s: %v", requestData.UserPublicKeyBase58Check, err))
		return
	}

	// get all the thread keys along with the latest group chat message for each of them.
	latestMessagesForGroupChats, err := fes.fetchLatestMessageFromGroupChatThreads(groupChatThreads)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetUserGroupChatThreadsOrderedByTimestamp: Problem getting access group IDs of"+
			"public key %s: %v", requestData.UserPublicKeyBase58Check, err))
		return
	}

	// Sort by the time stamp of the latest message of the group chat threads.
	sort.Slice(latestMessagesForGroupChats, func(i, j int) bool {
		return latestMessagesForGroupChats[i].TimestampNanos > latestMessagesForGroupChats[j].TimestampNanos
	})

	// group chat threads with each group chat represented by GroupChatThread.
	// Each entry consists of the sender account, recipient account info and the latest message.
	groupChats := []GroupChatThread{}

	for _, threadMsg := range latestMessagesForGroupChats {
		groupChat := GroupChatThread{
			// public key, access group public key, and access group key name of the sender of the group chat.
			SenderInfo: AccessGroupInfo{
				OwnerPublicKeyBase58Check:       Base58EncodePublickey(threadMsg.SenderAccessGroupOwnerPublicKey.ToBytes()),
				AccessGroupPublicKeyBase58Check: Base58EncodePublickey(threadMsg.SenderAccessGroupPublicKey.ToBytes()),
				AccessGroupKeyName:              hex.EncodeToString(threadMsg.SenderAccessGroupKeyName.ToBytes()),
			},
			// public key, access group public key, and access group key name of the recipient of the group chat.
			RecipientInfo: AccessGroupInfo{
				OwnerPublicKeyBase58Check:       Base58EncodePublickey(threadMsg.RecipientAccessGroupOwnerPublicKey.ToBytes()),
				AccessGroupPublicKeyBase58Check: Base58EncodePublickey(threadMsg.RecipientAccessGroupPublicKey.ToBytes()),
				AccessGroupKeyName:              hex.EncodeToString((threadMsg.RecipientAccessGroupKeyName.ToBytes())),
			},
			// group chat message and its timestamp.
			MessageInfo: DmMessageInfo{
				EncryptedText:  threadMsg.EncryptedText,
				TimestampNanos: threadMsg.TimestampNanos,
			},
		}

		groupChats = append(groupChats, groupChat)
	}

	// response containing the list of group chat threads with latest message
	// the group chat threads are sorted by the latest timestamp of their last message.
	res := GetUserGroupChatResponse{
		GroupChatThreads: groupChats,
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetUserGroupChatThreadsOrderedByTimestamp: Problem encoding response as JSON: %v", err))
		return
	}
}

// types and functions to Fetch messages from the group chat thread of a user
type GetPaginatedMessagesForGroupChatThreadRequest struct {
	// Need the member/owner public key and the access group key name of the group they belong
	// to fetch the group chat messages.
	UserPublicKeyBase58Check string
	AccessGroupKeyName       string

	StartTimeStamp     uint64
	MaxMessagesToFetch int
}

type GetPaginatedMessagesForGroupChatThreadResponse struct {
	GroupChatMessages []GroupChatThread
}

// Similar to GetPaginatedMessagesForDmThread API, but fetches messages from a group chat instead.

// This API just doesn't write any data, hence it doesn't create a new transaction.
// It's a public API, hence anyone with a valid public key can query the system to fetch their Direct message threads.
func (fes *APIServer) GetPaginatedMessagesForGroupChatThread(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetPaginatedMessagesForGroupChatThreadRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedMessagesForGroupChatThread: Problem parsing request body: %v", err))
		return
	}

	// Why fetch if there's less than one message to fetch!!!!!
	if requestData.MaxMessagesToFetch < 1 {
		_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedMessagesForGroupChatThread: MaxMessagesToFetch cannot be less than 1: %v", requestData.MaxMessagesToFetch))
		return
	}

	// Basic validation of the sender public key and access group name.
	accessGroupOwnerPkBytes, AccessGroupKeyNameBytes, err :=
		ValidateAccessGroupPublicKeyAndName(requestData.UserPublicKeyBase58Check, requestData.AccessGroupKeyName)
	// Decode the access group owner public key.
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedMessagesForGroupChatThread: Problem validating "+
			"user group owner public key and access group name %s: %s %v",
			requestData.UserPublicKeyBase58Check, requestData.AccessGroupKeyName, err))
		return
	}

	// The public of the member of the group and their access key
	// have to represented using the lib.AccessGroupId type.
	accessGroupId := lib.AccessGroupId{
		AccessGroupOwnerPublicKey: *lib.NewPublicKey(accessGroupOwnerPkBytes),
		AccessGroupKeyName:        *lib.NewGroupKeyName(AccessGroupKeyNameBytes),
	}

	// Fetch the max group chat messages from the access group.
	groupChatMessages, err := fes.fetchMaxMessagesFromGroupChatThread(&accessGroupId, requestData.StartTimeStamp, requestData.MaxMessagesToFetch)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedMessagesForGroupChatThread: Problem getting paginated messages for "+
			"Request Data: %v: %v", requestData, err))
		return
	}

	// group chat threads with each group chat represented by GroupChatThread.
	// Each entry consists of the sender account, recipient account info and the latest message.
	messages := []GroupChatThread{}

	for _, threadMsg := range groupChatMessages {
		message := GroupChatThread{
			// public key, access group public key, and access group key name of the sender of the group chat.
			SenderInfo: AccessGroupInfo{
				OwnerPublicKeyBase58Check:       Base58EncodePublickey(threadMsg.SenderAccessGroupOwnerPublicKey.ToBytes()),
				AccessGroupPublicKeyBase58Check: Base58EncodePublickey(threadMsg.SenderAccessGroupPublicKey.ToBytes()),
				AccessGroupKeyName:              hex.EncodeToString(threadMsg.SenderAccessGroupKeyName.ToBytes()),
			},
			// public key, access group public key, and access group key name of the recipient of the group chat.
			RecipientInfo: AccessGroupInfo{
				OwnerPublicKeyBase58Check:       Base58EncodePublickey(threadMsg.RecipientAccessGroupOwnerPublicKey.ToBytes()),
				AccessGroupPublicKeyBase58Check: Base58EncodePublickey(threadMsg.RecipientAccessGroupPublicKey.ToBytes()),
				AccessGroupKeyName:              hex.EncodeToString((threadMsg.RecipientAccessGroupKeyName.ToBytes())),
			},
			// group chat message and its timestamp.
			MessageInfo: DmMessageInfo{
				EncryptedText:  threadMsg.EncryptedText,
				TimestampNanos: threadMsg.TimestampNanos,
			},
		}

		messages = append(messages, message)
	}

	// response containing group chat messages from the given access group ID of a public key.
	res := GetPaginatedMessagesForGroupChatThreadResponse{
		GroupChatMessages: messages,
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedMessagesForGroupChatThread: Problem encoding response as JSON: %v", err))
		return
	}
}

// Types and API to aggregate threads from both direct messages and group chat messages.
const (
	// Used to mark the message as a Direct Message (Dm)
	chatTypeDm = iota
	// USed to mark the message as a group chat.
	chatTypeGroupChat
)

type UserThread struct {
	// Used to mark whether the message is a dm or a group chat.
	ChatType int

	SenderInfo    AccessGroupInfo
	RecipientInfo AccessGroupInfo
	MessageInfo   DmMessageInfo
}

// aggregate threads from both direct messages and group chat messages.
type GetAllUserMessageThreadsRequest struct {
	// PublicKeyBase58Check is the public key whose group IDs needs to be queried.
	UserPublicKeyBase58Check string `safeForLogging:"true"`
}

type GetAllUserMessageThreadsResponse struct {
	DmThreads []UserThread
}

// This API just doesn't write any data, hence it doesn't create a new transaction.
// It's a public API, hence anyone with a valid public key can query the system to fetch their Direct message threads.
func (fes *APIServer) GetAllUserMessageThreads(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetAllUserMessageThreadsRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllUserMessageThreads: Problem parsing request body: %v", err))
		return
	}

	// Decode the access group owner public key.
	accessGroupOwnerPkBytes, _, err := lib.Base58CheckDecode(requestData.UserPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllUserMessageThreads: Problem decoding owner"+
			"base58 public key %s: %v", requestData.UserPublicKeyBase58Check, err))
		return
	}

	// get all the direct message threads associated with the public key.
	dmThreads, err := fes.getAllDmThreadsForPublicKey(accessGroupOwnerPkBytes)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllUserMessageThreads: Problem getting access group IDs of"+
			"public key %s: %v", requestData.UserPublicKeyBase58Check, err))
		return
	}

	// fetch the latest message for each of the dmThread.
	latestMessagesForThreadKeys, err := fes.fetchLatestMessageFromDmThreads(dmThreads)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllUserMessageThreads: Problem getting access group IDs of"+
			"public key %s: %v", requestData.UserPublicKeyBase58Check, err))
		return
	}

	// get all the group chat threads for the public key.
	groupChatThreads, err := fes.getAllGroupChatThreadsForPublicKey(accessGroupOwnerPkBytes)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllUserMessageThreads: Problem getting access group IDs of"+
			"public key %s: %v", requestData.UserPublicKeyBase58Check, err))
		return
	}
	// get the latest message for each group chat thread.
	latestMessagesForGroupChats, err := fes.fetchLatestMessageFromGroupChatThreads(groupChatThreads)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllUserMessageThreads: Problem getting access group IDs of"+
			"public key %s: %v", requestData.UserPublicKeyBase58Check, err))
		return
	}

	// Add the group chat messages into UserThread type.
	userThreads := []UserThread{}

	for _, threadMsg := range latestMessagesForGroupChats {
		msgThread := UserThread{
			ChatType: chatTypeGroupChat,
			SenderInfo: AccessGroupInfo{
				OwnerPublicKeyBase58Check:       Base58EncodePublickey(threadMsg.SenderAccessGroupOwnerPublicKey.ToBytes()),
				AccessGroupPublicKeyBase58Check: Base58EncodePublickey(threadMsg.SenderAccessGroupPublicKey.ToBytes()),
				AccessGroupKeyName:              hex.EncodeToString(threadMsg.SenderAccessGroupKeyName.ToBytes()),
			},
			RecipientInfo: AccessGroupInfo{
				OwnerPublicKeyBase58Check:       Base58EncodePublickey(threadMsg.RecipientAccessGroupOwnerPublicKey.ToBytes()),
				AccessGroupPublicKeyBase58Check: Base58EncodePublickey(threadMsg.RecipientAccessGroupPublicKey.ToBytes()),
				AccessGroupKeyName:              hex.EncodeToString((threadMsg.RecipientAccessGroupKeyName.ToBytes())),
			},
			MessageInfo: DmMessageInfo{
				EncryptedText:  threadMsg.EncryptedText,
				TimestampNanos: threadMsg.TimestampNanos,
			},
		}
		userThreads = append(userThreads, msgThread)
	}

	// Add direct messages into UserThread type.
	for _, threadMsg := range latestMessagesForThreadKeys {
		msgThread := UserThread{
			ChatType: chatTypeDm,
			SenderInfo: AccessGroupInfo{
				OwnerPublicKeyBase58Check:       Base58EncodePublickey(threadMsg.SenderAccessGroupOwnerPublicKey.ToBytes()),
				AccessGroupPublicKeyBase58Check: Base58EncodePublickey(threadMsg.SenderAccessGroupPublicKey.ToBytes()),
				AccessGroupKeyName:              hex.EncodeToString(threadMsg.SenderAccessGroupKeyName.ToBytes()),
			},
			RecipientInfo: AccessGroupInfo{
				OwnerPublicKeyBase58Check:       Base58EncodePublickey(threadMsg.RecipientAccessGroupOwnerPublicKey.ToBytes()),
				AccessGroupPublicKeyBase58Check: Base58EncodePublickey(threadMsg.RecipientAccessGroupPublicKey.ToBytes()),
				AccessGroupKeyName:              hex.EncodeToString((threadMsg.RecipientAccessGroupKeyName.ToBytes())),
			},
			MessageInfo: DmMessageInfo{
				EncryptedText:  threadMsg.EncryptedText,
				TimestampNanos: threadMsg.TimestampNanos,
			},
		}
		userThreads = append(userThreads, msgThread)
	}

	// Sorting Group chats and Dms by timestamp of their latest messages.
	sort.Slice(userThreads, func(i, j int) bool {
		return userThreads[i].MessageInfo.TimestampNanos > userThreads[j].MessageInfo.TimestampNanos
	})

	// response containing all user chats.
	res := GetAllUserMessageThreadsResponse{
		DmThreads: userThreads,
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllUserMessageThreads: Problem encoding response as JSON: %v", err))
		return
	}
}
