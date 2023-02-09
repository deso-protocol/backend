package routes

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/deso-protocol/core/lib"
	"github.com/pkg/errors"
)

// Base58 decodes a public key string and verifies if it is in a valid public key format.
func Base58DecodeAndValidatePublickey(publicKeyBase58Check string) ([]byte, error) {
	// Decode in Base58 Checksum format.
	publicKeyBytes, _, err := lib.Base58CheckDecode(publicKeyBase58Check)
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
func ValidateAccessGroupPublicKeyAndName(publicKeyBase58Check string, accessGroupKeyName string) ([]byte, []byte, error) {
	publicKeyBytes, _, err := lib.Base58CheckDecode(publicKeyBase58Check)
	if err != nil {
		return nil, nil, errors.New(fmt.Sprintf("ValidateAccessGroupPublicKeyAndName: Problem decoding "+
			"base58 public key %s: %v", publicKeyBase58Check, err))

	}
	// get the byte array of the access group key name.
	accessGroupKeyNameBytes := []byte(accessGroupKeyName)
	// If it's the base key, we're fine with it and just let it rip.
	if len(accessGroupKeyNameBytes) == 0 {
		return publicKeyBytes, accessGroupKeyNameBytes, nil
	}
	// Validates whether the accessGroupOwner key is a valid public key and
	// some basic checks on access group key name like Min and Max characters.
	if err = lib.ValidateAccessGroupPublicKeyAndName(publicKeyBytes, accessGroupKeyNameBytes); err != nil {
		return nil, nil, errors.New(fmt.Sprintf("ValidateAccessGroupPublicKeyAndName: Problem validating "+
			"public key and access group key name %s %s: %v", publicKeyBase58Check, accessGroupKeyName, err))
	}

	return publicKeyBytes, accessGroupKeyNameBytes, nil
}

func (fes *APIServer) makeAccessGroupInfo(
	groupOwnerPublicKey *lib.PublicKey,
	publicKey *lib.PublicKey,
	groupKeyName *lib.GroupKeyName) AccessGroupInfo {
	var ownerPublicKeyBase58Check string
	if groupOwnerPublicKey != nil {
		ownerPublicKeyBase58Check = lib.PkToString(groupOwnerPublicKey.ToBytes(), fes.Params)
	}
	var accessGroupPublicKeyBase58Check string
	if publicKey != nil {
		accessGroupPublicKeyBase58Check = lib.PkToString(publicKey.ToBytes(), fes.Params)
	}
	var accessGroupKeyName string
	if groupKeyName != nil {
		accessGroupKeyName = string(lib.MessagingKeyNameDecode(groupKeyName))
	}
	return AccessGroupInfo{
		OwnerPublicKeyBase58Check:       ownerPublicKeyBase58Check,
		AccessGroupPublicKeyBase58Check: accessGroupPublicKeyBase58Check,
		AccessGroupKeyName:              accessGroupKeyName,
	}
}

func getFirstMessage(latestMessageEntries []*lib.NewMessageEntry) *lib.NewMessageEntry {
	// If there are more than one entries fetch just the last message.
	if len(latestMessageEntries) > 0 {
		return latestMessageEntries[0]
	}
	return nil
}

// Helper function to fetch just the latest message from the given Dm thread.
// StartTimestamp is set to current unix time to fetch the latest message.
// DmThread key consists of the sender and recipient public key and access group key names to fetch the direct messages
// between the two parties.
func (fes *APIServer) fetchLatestMessageFromSingleDmThread(
	dmThreadKey *lib.DmThreadKey,
	startTimestamp uint64,
	utxoView *lib.UtxoView,
) (*lib.NewMessageEntry, error) {
	// Fetch just one message.
	latestMessageEntries, err := fes.fetchMaxMessagesFromDmThread(dmThreadKey, startTimestamp, 1, utxoView)
	if err != nil {
		return nil, err
	}
	return getFirstMessage(latestMessageEntries), nil
}

// Fetch MaxMessagesToFetch with message time stamp starting from startTimestamp.
// Fetches the Direct messages between the sender and recipient information inside the dmThreadKey.
func (fes *APIServer) fetchMaxMessagesFromDmThread(
	dmThreadKey *lib.DmThreadKey,
	startTimestamp uint64,
	MaxMessagesToFetch int,
	utxoView *lib.UtxoView,
) ([]*lib.NewMessageEntry, error) {
	// Fetch MaxMessagesToFetch with message time stamp starting from startTimestamp.
	latestMessageEntries, err := utxoView.GetPaginatedMessageEntriesForDmThread(*dmThreadKey, startTimestamp, uint64(MaxMessagesToFetch))
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("Error fetching dm entries for dmThreadKey, "+
			"startTimestamp, and MaxMessagesToFetch: %v %v %v", dmThreadKey, startTimestamp, MaxMessagesToFetch))
	}

	return latestMessageEntries, nil
}

// Takes an array of DmThread Keys (Sender and Recipient public keys and access group key names),
// returns the latest message with their timestamp for each dmthread key.
func (fes *APIServer) fetchLatestMessageFromDmThreads(
	dmThreads []*lib.DmThreadKey,
	utxoView *lib.UtxoView,
) ([]*lib.NewMessageEntry, error) {
	// *lib.NewMessageEntry is data structure used in core library for each direct message or a message in a group chat.
	var latestMessageEntries []*lib.NewMessageEntry
	// Using current unix time as a time stamp since we're fetching the latest message.
	currentUnixTime := time.Now().UnixNano()
	// Iterate over DmThreads and Fetch latest message for each of them.
	for _, dmThread := range dmThreads {
		latestMessageEntry, err := fes.fetchLatestMessageFromSingleDmThread(dmThread, uint64(currentUnixTime), utxoView)
		if err != nil {
			return nil, err
		}
		if latestMessageEntry == nil {
			continue
		}
		latestMessageEntries = append(latestMessageEntries, latestMessageEntry)
	}

	return latestMessageEntries, nil
}

// Helper function to fetch just the latest message from the given group chat thread.
// StartTimestamp is set to current unix time to fetch the latest message.
// accessGroupId (type  *lib.AccessGroupId) consists of a member public key and the access key name to be used to fetch the group chats.
func (fes *APIServer) fetchLatestMessageFromGroupChatThread(
	accessGroupId *lib.AccessGroupId,
	startTimestamp uint64,
	utxoView *lib.UtxoView,
) (*lib.NewMessageEntry, error) {
	// Just fetch the latest message from the group chat represented by accessGroupId.
	latestMessageEntries, err := fes.fetchMaxMessagesFromGroupChatThread(accessGroupId, startTimestamp, 1, utxoView)
	if err != nil {
		return nil, err
	}
	return getFirstMessage(latestMessageEntries), nil
}

// Fetch MaxMessagesToFetch number of group chat messages, starting from the message timestamp of startTimestamp,
// where the public key and access group key name in accessGroupId is a member.
// accessGroupId (type  *lib.AccessGroupId) consists of a member public key and the access key name to be used to fetch the group chats.
func (fes *APIServer) fetchMaxMessagesFromGroupChatThread(
	accessGroupId *lib.AccessGroupId,
	startTimestamp uint64,
	MaxMessagesToFetch int,
	utxoView *lib.UtxoView,
) ([]*lib.NewMessageEntry, error) {
	latestMessageEntries, err := utxoView.GetPaginatedMessageEntriesForGroupChatThread(*accessGroupId, startTimestamp, uint64(MaxMessagesToFetch))
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("Error fetching messages for access group ID, "+
			"startTimestamp, and MaxMessagesToFetch: %v %v %v", accessGroupId, startTimestamp, MaxMessagesToFetch))
	}
	return latestMessageEntries, nil
}

// Fetch only the latest group chat message threads.
// Iterates the access group key names in groupChatThreads, and fetches their latest message.
// accessGroupId (type  *lib.AccessGroupId) consists of a member public key and the access key name to be used to fetch the group chats.
func (fes *APIServer) fetchLatestMessageFromGroupChatThreads(groupChatThreads []*lib.AccessGroupId, utxoView *lib.UtxoView) ([]*lib.NewMessageEntry, error) {

	var latestMessageEntries []*lib.NewMessageEntry
	// Use current unix time stamp since we're fetching only the latest message.
	currTime := time.Now().UnixNano()
	// Iterate through each group chat thread and fetch their latest message.
	for _, dmThread := range groupChatThreads {
		latestMessageEntry, err := fes.fetchLatestMessageFromGroupChatThread(dmThread, uint64(currTime), utxoView)
		if err != nil {
			return nil, errors.Wrap(err, "")
		}
		if latestMessageEntry == nil {
			continue
		}
		latestMessageEntries = append(latestMessageEntries, latestMessageEntry)
	}
	return latestMessageEntries, nil
}

type SendNewMessageRequest struct {
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
	EncryptedMessageText string

	// Only set if we are updating a message
	TimestampNanosString string `safeForLogging:"true"`

	MinFeeRateNanosPerKB uint64 `safeForLogging:"true"`
	// No need to specify ProfileEntryResponse in each TransactionFee
	TransactionFees []TransactionFee `safeForLogging:"true"`
	// ExtraData is an arbitrary key value map
	ExtraData map[string]string
}

// struct to serialize the response.
type SendNewMessageResponse struct {
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
	if err := fes.sendMessageHandler(ww, req, lib.NewMessageTypeDm, lib.NewMessageOperationCreate); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendDmMessage: %v", err))
		return
	}
}

func (fes *APIServer) UpdateDmMessage(ww http.ResponseWriter, req *http.Request) {
	if err := fes.sendMessageHandler(ww, req, lib.NewMessageTypeDm, lib.NewMessageOperationUpdate); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateDmMessage: %v", err))
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
	if err := fes.sendMessageHandler(ww, req, lib.NewMessageTypeGroupChat, lib.NewMessageOperationCreate); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendGroupChatMessage: %v", err))
		return
	}
}

func (fes *APIServer) UpdateGroupChatMessage(ww http.ResponseWriter, req *http.Request) {
	if err := fes.sendMessageHandler(ww, req, lib.NewMessageTypeGroupChat, lib.NewMessageOperationUpdate); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateGroupChatMessage: %v", err))
		return
	}
}

func (fes *APIServer) sendMessageHandler(
	ww http.ResponseWriter,
	req *http.Request,
	newMessageType lib.NewMessageType,
	newMessageOperationType lib.NewMessageOperation,
) error {
	// Deserialize the request data.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := SendNewMessageRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		return errors.Wrapf(err, "Problem parsing request body: ")
	}

	// Basic validation of the sender public key and access group name.
	senderGroupOwnerPkBytes, senderGroupKeyNameBytes, err :=
		ValidateAccessGroupPublicKeyAndName(requestData.SenderAccessGroupOwnerPublicKeyBase58Check, requestData.SenderAccessGroupKeyName)
	// Abruptly end the request processing on error and return.
	if err != nil {
		return errors.Wrapf(err, fmt.Sprintf("Problem validating sender public key and access group name"+
			"base58 public key %s: %s ",
			requestData.SenderAccessGroupOwnerPublicKeyBase58Check, requestData.SenderAccessGroupKeyName))
	}

	// Basic validation of the recipient public key and access group name.
	recipientGroupOwnerPkBytes, recipientGroupKeyNameBytes, err :=
		ValidateAccessGroupPublicKeyAndName(requestData.RecipientAccessGroupOwnerPublicKeyBase58Check, requestData.RecipientAccessGroupKeyName)
	// Abruptly end the request processing on error and return.
	if err != nil {
		return errors.Wrapf(err, fmt.Sprintf("Problem validating sender public key and access group name"+
			"base58 public key %s: %s ",
			requestData.SenderAccessGroupOwnerPublicKeyBase58Check, requestData.SenderAccessGroupKeyName))
	}

	hexDecodedEncryptedMessageBytes, err := hex.DecodeString(requestData.EncryptedMessageText)
	if err != nil {
		return errors.Wrapf(err, "Problem decoding encrypted message text hex")
	}

	// Validate the sender access group public key.
	senderAccessGroupPkbytes, err := Base58DecodeAndValidatePublickey(requestData.SenderAccessGroupPublicKeyBase58Check)
	if err != nil {
		return errors.Wrapf(err, fmt.Sprintf("Problem validating sender "+
			"base58 public key %s: ", requestData.SenderAccessGroupPublicKeyBase58Check))
	}

	// Validate the recipient access group public key.
	recipientAccessGroupPkbytes, err := Base58DecodeAndValidatePublickey(requestData.RecipientAccessGroupPublicKeyBase58Check)
	if err != nil {
		return errors.Wrapf(err, fmt.Sprintf("Problem validating recipient "+
			"base58 public key %s: ", requestData.SenderAccessGroupPublicKeyBase58Check))
	}

	// Compute the additional transaction fees as specified by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(lib.TxnTypeNewMessage, senderGroupOwnerPkBytes, requestData.TransactionFees)
	if err != nil {
		return errors.Wrapf(err, "TransactionFees specified in Request body are invalid: ")
	}

	// extra data is relevant for certain type of requests. Refer to documentation for any requirement of adding extra data.
	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		return errors.Wrapf(err, "Problem encoding ExtraData: ")
	}

	tstamp := uint64(time.Now().UnixNano())

	if newMessageOperationType == lib.NewMessageOperationUpdate {
		// convert timestampnanos string to uint64
		tstamp, err = strconv.ParseUint(requestData.TimestampNanosString, 10, 64)
		if err != nil {
			return errors.Wrapf(err, "Problem converting TimestampNanosString to uint64: ")
		}
		if tstamp == 0 {
			return errors.Wrapf(err, "TimestampNanosString cannot be 0: ")
		}
		// Note that for now we do not validate that the message exists
		// before updating or creating.
	}

	// Call CreateNewMessageTxn the core lib to construct the transaction to send a group chat message.
	// The message type must be lib.NewMessageTypeGroupChat, and operation type is lib.NewMessageOperationCreate.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateNewMessageTxn(
		senderGroupOwnerPkBytes, *lib.NewPublicKey(senderGroupOwnerPkBytes), *lib.NewGroupKeyName(senderGroupKeyNameBytes), *lib.NewPublicKey(senderAccessGroupPkbytes),
		*lib.NewPublicKey(recipientGroupOwnerPkBytes), *lib.NewGroupKeyName(recipientGroupKeyNameBytes), *lib.NewPublicKey(recipientAccessGroupPkbytes),
		hexDecodedEncryptedMessageBytes, tstamp,
		newMessageType, newMessageOperationType,
		extraData, requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool(), additionalOutputs)
	if err != nil {
		return errors.Wrapf(err, "Problem creating transaction: ")
	}

	// Add node source to txn metadata
	fes.AddNodeSourceToTxnMetadata(txn)

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		return errors.Wrapf(err, "Problem serializing transaction: ")
	}

	// Return all the data associated with the transaction in the response
	res := SendNewMessageResponse{
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		return errors.Wrapf(err, "Problem encoding response as JSON: ")
	}
	return nil
}

type ChatType string

const (
	ChatTypeDM        = "DM"
	ChatTypeGroupChat = "GroupChat"
)

type NewMessageEntryResponse struct {
	ChatType      ChatType
	SenderInfo    AccessGroupInfo
	RecipientInfo AccessGroupInfo
	MessageInfo   MessageInfo
}

// Types to store the chat messages.
type AccessGroupInfo struct {
	OwnerPublicKeyBase58Check       string `safeForLogging:"true"`
	AccessGroupPublicKeyBase58Check string `safeForLogging:"true"`
	AccessGroupKeyName              string `safeForLogging:"true"`
}
type MessageInfo struct {
	EncryptedText        string
	TimestampNanos       uint64
	TimestampNanosString string
	ExtraData            map[string]string
}

func (fes *APIServer) NewMessageEntryToResponse(newMessageEntry *lib.NewMessageEntry, chatType ChatType, utxoView *lib.UtxoView) NewMessageEntryResponse {
	return NewMessageEntryResponse{
		ChatType: chatType,
		SenderInfo: fes.makeAccessGroupInfo(
			newMessageEntry.SenderAccessGroupOwnerPublicKey,
			newMessageEntry.SenderAccessGroupPublicKey,
			newMessageEntry.SenderAccessGroupKeyName),
		RecipientInfo: fes.makeAccessGroupInfo(
			newMessageEntry.RecipientAccessGroupOwnerPublicKey,
			newMessageEntry.RecipientAccessGroupPublicKey,
			newMessageEntry.RecipientAccessGroupKeyName),
		MessageInfo: MessageInfo{
			EncryptedText:        hex.EncodeToString(newMessageEntry.EncryptedText),
			TimestampNanos:       newMessageEntry.TimestampNanos,
			TimestampNanosString: strconv.FormatUint(newMessageEntry.TimestampNanos, 10),
			ExtraData:            DecodeExtraDataMap(fes.Params, utxoView, newMessageEntry.ExtraData),
		},
	}
}

// This endpoint should returns all dm threads for a user.
// Calls the GetAllUserDmThreads function from the core library.
// Should return the direct message threads of the user along with the latest message sent for each of them.
// This API just doesn't write any data, hence it doesn't create a new transaction.
// It's a public API, hence anyone with a valid public key can query the system to fetch their Direct message threads.
func (fes *APIServer) GetUserDmThreadsOrderedByTimestamp(ww http.ResponseWriter, req *http.Request) {
	if err := fes.getUserMessageThreadsHandler(ww, req, false, true); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetUserDmThreadsOrderedByTimestamp: %v", err))
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
	// Filter to fetch direct messages who time stamp is less than StartTimestamp.
	// So you need to set this to current time and MaxMessagesToFetch to 10, to fetch
	//  the latest 10 messages. We support passing start timestamp as string and uint64.
	// uint64 can lose precision when being JSON decoded, so we prefer StartTimestampString.
	StartTimestamp       uint64
	StartTimestampString string
	MaxMessagesToFetch   int
}

// type to serialize the response containing the direct messages between two parties.
type GetPaginatedMessagesForDmResponse struct {
	ThreadMessages                  []NewMessageEntryResponse
	PublicKeyToProfileEntryResponse map[string]*ProfileEntryResponse
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

	startTimestamp := requestData.StartTimestamp
	if requestData.StartTimestampString != "" {
		startTimestamp, err = strconv.ParseUint(requestData.StartTimestampString, 10, 64)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedMessagesForDmThread: Error parsing "+
				"StartTimestampString: %v", err))
			return
		}
	}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedMessagesForDmThread: Error generating "+
			"utxo view: %v", err))
		return
	}

	senderPublicKey := *lib.NewPublicKey(senderGroupOwnerPkBytes)
	senderGroupKeyName := *lib.NewGroupKeyName(senderGroupKeyNameBytes)
	recipientPublicKey := *lib.NewPublicKey(recipientGroupOwnerPkBytes)
	recipientGroupKeyName := *lib.NewGroupKeyName(recipientGroupKeyNameBytes)
	// The information of the two parties involved in Dm has to encoded in lib.DmThreadKey.
	dmThreadKey := lib.MakeDmThreadKey(senderPublicKey, senderGroupKeyName, recipientPublicKey, recipientGroupKeyName)

	// Fetch the max messages between the sender and the party.
	latestMessages, err := fes.fetchMaxMessagesFromDmThread(&dmThreadKey, startTimestamp, requestData.MaxMessagesToFetch, utxoView)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedMessagesForDmThread: Problem getting paginated messages for "+
			"Request Data: %v: %v", requestData, err))
		return
	}

	// Special case: If we're getting the DM thread for the default-key for
	// both parties, then we also fetch base key DMs.
	if senderGroupKeyName == *lib.DefaultGroupKeyName() &&
		recipientGroupKeyName == *lib.DefaultGroupKeyName() {
		baseKey := *lib.BaseGroupKeyName()
		baseKeyBaseKeyThreadKey := lib.MakeDmThreadKey(senderPublicKey, baseKey, recipientPublicKey, baseKey)
		baseKeyBaseKeyLatestMessages, err := fes.fetchMaxMessagesFromDmThread(
			&baseKeyBaseKeyThreadKey, startTimestamp, requestData.MaxMessagesToFetch, utxoView)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedMessagesForDmThread: Problem getting paginated "+
				"messages for base key - base key - Request Data: %v: %v", requestData, err))
			return
		}
		latestMessages = append(latestMessages, baseKeyBaseKeyLatestMessages...)

		baseKeyDefaultKeyThreadKey := lib.MakeDmThreadKey(senderPublicKey, baseKey, recipientPublicKey, recipientGroupKeyName)
		baseKeyDefaultKeyLatestMessages, err := fes.fetchMaxMessagesFromDmThread(
			&baseKeyDefaultKeyThreadKey, startTimestamp, requestData.MaxMessagesToFetch, utxoView)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedMessagesForDmThread: Problem getting paginated "+
				"messages for base key - default key - Request Data: %v: %v", requestData, err))
			return
		}
		latestMessages = append(latestMessages, baseKeyDefaultKeyLatestMessages...)

		defaultKeyBaseKeyThreadKey := lib.MakeDmThreadKey(senderPublicKey, senderGroupKeyName, recipientPublicKey, baseKey)
		defaultKeyBaseKeyLatestMessages, err := fes.fetchMaxMessagesFromDmThread(
			&defaultKeyBaseKeyThreadKey, startTimestamp, requestData.MaxMessagesToFetch, utxoView)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedMessagesForDmThread: Problem getting paginated "+
				"messages for default key - base key - Request Data: %v: %v", requestData, err))
			return
		}
		latestMessages = append(latestMessages, defaultKeyBaseKeyLatestMessages...)

		// Now we sort them and take the first MaxMessagesToFetch
		sort.Slice(latestMessages, func(ii, jj int) bool {
			return latestMessages[ii].TimestampNanos > latestMessages[jj].TimestampNanos
		})

		lastIndex := requestData.MaxMessagesToFetch
		if lastIndex > len(latestMessages) {
			lastIndex = len(latestMessages)
		}
		latestMessages = latestMessages[:lastIndex]
	}

	// Since the two parties in the conversation in same in all the message if added this info upfront.
	res := GetPaginatedMessagesForDmResponse{
		ThreadMessages:                  []NewMessageEntryResponse{},
		PublicKeyToProfileEntryResponse: make(map[string]*ProfileEntryResponse),
	}

	// Now append each of their Direct message (Dm) conversations.
	for _, threadMsg := range latestMessages {
		res.ThreadMessages = append(
			res.ThreadMessages,
			fes.NewMessageEntryToResponse(threadMsg, ChatTypeDM, utxoView),
		)
	}

	// Add the sender's profile to the response.
	res.PublicKeyToProfileEntryResponse[requestData.UserGroupOwnerPublicKeyBase58Check] = fes.GetProfileEntryResponseForPublicKeyBytes(
		senderGroupOwnerPkBytes, utxoView)

	// Add the recipient's profile to the response.
	res.PublicKeyToProfileEntryResponse[requestData.PartyGroupOwnerPublicKeyBase58Check] = fes.GetProfileEntryResponseForPublicKeyBytes(
		recipientGroupOwnerPkBytes, utxoView)

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedMessagesForDmThread: Problem encoding response as JSON: %v", err))
		return
	}

}

// Similar to GetUserDmThreadsOrderedByTimestamp, expect that it fetches the group chat threads instead of direct messages.
// Need to call lib.GetAllUserGroupChatThreads from the core library.
// Just need the public key of the user in the request data.
// Returns the group chat threads along with their latest messages.
// The group chats are sorted/ordered by the time stamp of their latest message.

// This API just doesn't write any data, hence it doesn't create a new transaction.
// It's a public API, hence anyone with a valid public key can query the system to fetch their Direct message threads.
func (fes *APIServer) GetUserGroupChatThreadsOrderedByTimestamp(ww http.ResponseWriter, req *http.Request) {
	if err := fes.getUserMessageThreadsHandler(ww, req, true, false); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetUserGroupChatThreadsOrderedByTimestamp: %v", err))
		return
	}
}

// types and functions to Fetch messages from the group chat thread of a user
type GetPaginatedMessagesForGroupChatThreadRequest struct {
	// Need the member/owner public key and the access group key name of the group they belong
	// to fetch the group chat messages.
	UserPublicKeyBase58Check string
	AccessGroupKeyName       string

	// We support passing start timestamp as string and uint64.
	// uint64 can lose precision when being JSON decoded, so we prefer StartTimestampString.
	StartTimestamp       uint64
	StartTimestampString string
	MaxMessagesToFetch   int
}

type GetPaginatedMessagesForGroupChatThreadResponse struct {
	GroupChatMessages               []NewMessageEntryResponse
	PublicKeyToProfileEntryResponse map[string]*ProfileEntryResponse
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

	startTimestamp := requestData.StartTimestamp
	if requestData.StartTimestampString != "" {
		startTimestamp, err = strconv.ParseUint(requestData.StartTimestampString, 10, 64)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedMessagesForDmThread: Error parsing "+
				"StartTimestampString: %v", err))
			return
		}
	}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedMessagesForGroupChatThread: Error generating "+
			"utxo view: %v", err))
		return
	}

	// The public of the member of the group and their access key
	// have to represented using the lib.AccessGroupId type.
	accessGroupId := lib.AccessGroupId{
		AccessGroupOwnerPublicKey: *lib.NewPublicKey(accessGroupOwnerPkBytes),
		AccessGroupKeyName:        *lib.NewGroupKeyName(AccessGroupKeyNameBytes),
	}

	// Fetch the max group chat messages from the access group.
	groupChatMessages, err := fes.fetchMaxMessagesFromGroupChatThread(&accessGroupId, startTimestamp, requestData.MaxMessagesToFetch, utxoView)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedMessagesForGroupChatThread: Problem getting paginated messages for "+
			"Request Data: %v: %v", requestData, err))
		return
	}

	// group chat threads with each group chat represented by GroupChatThread.
	// Each entry consists of the sender account, recipient account info and the latest message.
	messages := []NewMessageEntryResponse{}
	publicKeyToProfileEntryResponseMap := make(map[string]*ProfileEntryResponse)

	for _, threadMsg := range groupChatMessages {
		message := fes.NewMessageEntryToResponse(threadMsg, ChatTypeGroupChat, utxoView)
		messages = append(messages, message)
		// Add the sender's profile to the response.
		senderPublicKeyBase58Check := message.SenderInfo.OwnerPublicKeyBase58Check
		if _, ok := publicKeyToProfileEntryResponseMap[senderPublicKeyBase58Check]; !ok {
			publicKeyToProfileEntryResponseMap[senderPublicKeyBase58Check] = fes.GetProfileEntryResponseForPublicKeyBytes(
				threadMsg.SenderAccessGroupOwnerPublicKey.ToBytes(), utxoView)
		}

		// Add the recipient's profile to the response.
		if _, ok := publicKeyToProfileEntryResponseMap[message.RecipientInfo.OwnerPublicKeyBase58Check]; !ok {
			publicKeyToProfileEntryResponseMap[message.RecipientInfo.OwnerPublicKeyBase58Check] = fes.GetProfileEntryResponseForPublicKeyBytes(
				threadMsg.RecipientAccessGroupOwnerPublicKey.ToBytes(), utxoView)
		}
	}

	// response containing group chat messages from the given access group ID of a public key.
	res := GetPaginatedMessagesForGroupChatThreadResponse{
		GroupChatMessages:               messages,
		PublicKeyToProfileEntryResponse: publicKeyToProfileEntryResponseMap,
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPaginatedMessagesForGroupChatThread: Problem encoding response as JSON: %v", err))
		return
	}
}

// aggregate threads from both direct messages and group chat messages.
type GetUserMessageThreadsRequest struct {
	// PublicKeyBase58Check is the public key whose group IDs needs to be queried.
	UserPublicKeyBase58Check string `safeForLogging:"true"`
}

type GetUserMessageThreadsResponse struct {
	MessageThreads []NewMessageEntryResponse

	PublicKeyToProfileEntryResponse map[string]*ProfileEntryResponse
}

// This API just doesn't write any data, hence it doesn't create a new transaction.
// It's a public API, hence anyone with a valid public key can query the system to fetch their Direct message threads.
func (fes *APIServer) GetAllUserMessageThreads(ww http.ResponseWriter, req *http.Request) {
	if err := fes.getUserMessageThreadsHandler(ww, req, true, true); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllUserMessageThreads: %v", err))
		return
	}
}

func (fes *APIServer) getUserMessageThreadsHandler(ww http.ResponseWriter, req *http.Request, getGroupChats bool, getDMs bool) error {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetUserMessageThreadsRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		return errors.Wrapf(err, "Problem parsing request body: ")
	}

	// Decode the access group owner public key.
	accessGroupOwnerPkBytes, _, err := lib.Base58CheckDecode(requestData.UserPublicKeyBase58Check)
	if err != nil {
		return errors.Wrapf(err, fmt.Sprintf("Problem decoding owner"+
			"base58 public key %s: ", requestData.UserPublicKeyBase58Check))
	}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return errors.Wrapf(err, "Error generating "+
			"utxo view: ")
	}

	var messageThreads []NewMessageEntryResponse
	if getDMs {
		// get all the direct message threads associated with the public key.
		dmThreads, err := utxoView.GetAllUserDmThreads(*lib.NewPublicKey(accessGroupOwnerPkBytes))
		if err != nil {
			return errors.Wrapf(err, fmt.Sprintf("Problem getting access group IDs of"+
				"public key %s: ", requestData.UserPublicKeyBase58Check))
		}

		// fetch the latest message for each of the dmThread.
		latestMessagesForThreadKeys, err := fes.fetchLatestMessageFromDmThreads(dmThreads, utxoView)
		if err != nil {
			return errors.Wrapf(err, fmt.Sprintf("Problem getting access group IDs of"+
				"public key %s: ", requestData.UserPublicKeyBase58Check))
		}

		for _, threadMsg := range latestMessagesForThreadKeys {
			messageThreads = append(messageThreads,
				fes.NewMessageEntryToResponse(threadMsg, ChatTypeDM, utxoView))
		}
	}

	if getGroupChats {
		// get all the group chat threads for the public key.
		groupChatThreads, err := utxoView.GetAllUserGroupChatThreads(*lib.NewPublicKey(accessGroupOwnerPkBytes))
		if err != nil {
			return errors.Wrapf(err, fmt.Sprintf("Problem getting access group IDs of"+
				"public key %s: ", requestData.UserPublicKeyBase58Check))
		}
		// get the latest message for each group chat thread.
		latestMessagesForGroupChats, err := fes.fetchLatestMessageFromGroupChatThreads(groupChatThreads, utxoView)
		if err != nil {
			return errors.Wrapf(err, fmt.Sprintf("Problem getting access group IDs of"+
				"public key %s: ", requestData.UserPublicKeyBase58Check))
		}

		// Add direct messages into MessageThread type.
		for _, threadMsg := range latestMessagesForGroupChats {
			messageThreads = append(messageThreads, fes.NewMessageEntryToResponse(threadMsg, ChatTypeGroupChat, utxoView))
		}
	}

	// Sorting Group chats and Dms by timestamp of their latest messages.
	sort.Slice(messageThreads, func(i, j int) bool {
		return messageThreads[i].MessageInfo.TimestampNanos > messageThreads[j].MessageInfo.TimestampNanos
	})

	publicKeyToProfileEntryResponseMap := make(map[string]*ProfileEntryResponse)

	for _, message := range messageThreads {
		// Get Sender Profile.
		if _, ok := publicKeyToProfileEntryResponseMap[message.SenderInfo.OwnerPublicKeyBase58Check]; !ok {
			profileEntryResponse, err := fes.GetProfileEntryResponseForPublicKeyBase58Check(message.SenderInfo.OwnerPublicKeyBase58Check, utxoView)
			if err != nil {
				return errors.Wrapf(err, "GetUserMessageThreads: ")
			}
			publicKeyToProfileEntryResponseMap[message.SenderInfo.OwnerPublicKeyBase58Check] = profileEntryResponse
		}

		if _, ok := publicKeyToProfileEntryResponseMap[message.RecipientInfo.OwnerPublicKeyBase58Check]; !ok {
			profileEntryResponse, err := fes.GetProfileEntryResponseForPublicKeyBase58Check(message.RecipientInfo.OwnerPublicKeyBase58Check, utxoView)
			if err != nil {
				return errors.Wrapf(err, "GetUserMessageThreads: ")
			}
			publicKeyToProfileEntryResponseMap[message.RecipientInfo.OwnerPublicKeyBase58Check] = profileEntryResponse
		}
	}

	// response containing all user chats.
	res := GetUserMessageThreadsResponse{
		MessageThreads:                  messageThreads,
		PublicKeyToProfileEntryResponse: publicKeyToProfileEntryResponseMap,
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		return errors.Wrapf(err, "Problem encoding response as JSON: ")
	}
	return nil
}
