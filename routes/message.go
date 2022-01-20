package routes

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/deso-protocol/core/lib"
	"github.com/pkg/errors"
	"io"
	"net/http"
	"reflect"
	"sort"
	"time"
)

// GetMessagesStatelessRequest ...
type GetMessagesStatelessRequest struct {
	PublicKeyBase58Check string `safeForLogging:"true"`

	// FetchAfterPublicKeyBase58Check specifies where to start
	// in the messages to begin fetching new messages. If set empty,
	// we start fetching threads from the most recent message.
	FetchAfterPublicKeyBase58Check string `safeForLogging:"true"`

	// NumToFetch specifies the number of message threads to return. Defaults to 20
	// unless otherwise specified.
	NumToFetch uint64 `safeForLogging:"true"`

	// There are four filters: HoldersOnly, HoldingsOnly, FollowersOnly, FollowedOnly
	// If all filters are false, we return all messages. Otherwise we include
	// messages from the sets set true.

	// HoldersOnly when set true includes messages from holders.
	HoldersOnly bool `safeForLogging:"true"`

	// HoldingsOnly when set true includes messages from the user's holdings.
	HoldingsOnly bool `safeForLogging:"true"`

	// FollowersOnly when set true includes messages from the user's followers.
	FollowersOnly bool `safeForLogging:"true"`

	// FollowedOnly when set true includes messages from who the user follows.
	FollowingOnly bool `safeForLogging:"true"`

	// SortAlgorithm determines how the messages should be returned. Currently
	// it support time, deso, and followers based sorting.
	SortAlgorithm string `safeForLogging:"true"`
}

// GetMessagesResponse ...
type GetMessagesResponse struct {
	PublicKeyToProfileEntry     map[string]*ProfileEntryResponse
	OrderedContactsWithMessages []*MessageContactResponse
	UnreadStateByContact        map[string]bool
	NumberOfUnreadThreads       int
	MessagingKeys               []*MessagingGroupEntryResponse
}

func (fes *APIServer) getMessagesStateless(publicKeyBytes []byte,
	fetchAfterPublicKeyBytes []byte, numToFetch uint64, holdersOnly bool,
	holdingsOnly bool, followersOnly bool, followingOnly bool, sortAlgorithm string) (
	_publicKeyToProfileEntry map[string]*ProfileEntryResponse,
	_orderedContactsWithMessages []*MessageContactResponse,
	_unreadMessagesByContact map[string]bool,
	_numOfUnreadThreads int,
	_messagingKeys []*MessagingGroupEntryResponse,
	_err error) {

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUtxoViewForPublicKey(publicKeyBytes, nil)
	if err != nil {
		return nil, nil, nil, 0, nil, errors.Wrapf(
			err, "getMessagesStateless: Error calling GetAugmentedUtxoViewForPublicKey: %v", err)
	}

	// Go through all the MessageEntries and create a MessageEntryResponse for each one.
	// Sort the MessageEntries by their timestamp.
	//
	// TODO: The timestamp is spoofable, but it's not a big deal. See comment on MessageEntry
	// for more insight on this.
	messageEntries, messagingKeys, err := utxoView.GetLimitedMessagesForUser(publicKeyBytes, uint64(lib.MessagesToFetchPerInboxCall))
	if err != nil {
		return nil, nil, nil, 0, nil, errors.Wrapf(
			err, "getMessagesStateless: Problem fetching MessageEntries from augmented UtxoView: ")
	}

	// We sort the messages to be sure they're in the correct order for filtering out selected threads.
	// There could be a faster way to do this, but it preserves pagination properly.
	publicKeyToDESO := make(map[string]uint64)
	publicKeyToNumberOfFollowers := make(map[string]uint64)
	publicKeyToNanosUserHeld := make(map[string]uint64)
	if sortAlgorithm == "deso" {
		for _, messageEntry := range messageEntries {
			otherPartyPublicKeyBytes, otherPartyPublicKeyBase58Check := fes.getOtherPartyInThread(messageEntry, publicKeyBytes)

			if _, alreadySeen := publicKeyToDESO[otherPartyPublicKeyBase58Check]; !alreadySeen {
				otherPartyProfileEntry := utxoView.GetProfileEntryForPublicKey(otherPartyPublicKeyBytes)
				if otherPartyProfileEntry != nil {
					publicKeyToDESO[otherPartyPublicKeyBase58Check] = otherPartyProfileEntry.CreatorCoinEntry.DeSoLockedNanos
				} else {
					publicKeyToDESO[otherPartyPublicKeyBase58Check] = 0
				}
			}
		}

		sort.Slice(messageEntries, func(ii, jj int) bool {
			_, otherPartyPublicKeyiiBase58Check := fes.getOtherPartyInThread(messageEntries[ii], publicKeyBytes)
			_, otherPartyPublicKeyjjBase58Check := fes.getOtherPartyInThread(messageEntries[jj], publicKeyBytes)
			return publicKeyToDESO[otherPartyPublicKeyiiBase58Check] > publicKeyToDESO[otherPartyPublicKeyjjBase58Check]
		})
	} else if sortAlgorithm == "followers" {
		for _, messageEntry := range messageEntries {
			otherPartyPublicKeyBytes, otherPartyPublicKeyBase58Check := fes.getOtherPartyInThread(messageEntry, publicKeyBytes)

			if _, alreadySeen := publicKeyToNumberOfFollowers[otherPartyPublicKeyBase58Check]; !alreadySeen {
				// TODO: Make an index to quickly lookup how many followers a user has
				otherPartyFollowers, err := lib.DbGetPKIDsFollowingYou(utxoView.Handle, lib.PublicKeyToPKID(otherPartyPublicKeyBytes))
				if err != nil {
					return nil, nil, nil, 0, nil, errors.Wrapf(
						err, "getMessagesStateless: Problem getting follows for public key")
				}
				publicKeyToNumberOfFollowers[otherPartyPublicKeyBase58Check] = uint64(len(otherPartyFollowers))
			}
		}

		sort.Slice(messageEntries, func(ii, jj int) bool {
			_, otherPartyPublicKeyiiBase58Check := fes.getOtherPartyInThread(messageEntries[ii], publicKeyBytes)
			_, otherPartyPublicKeyjjBase58Check := fes.getOtherPartyInThread(messageEntries[jj], publicKeyBytes)
			return publicKeyToNumberOfFollowers[otherPartyPublicKeyiiBase58Check] > publicKeyToNumberOfFollowers[otherPartyPublicKeyjjBase58Check]
		})
	} else if sortAlgorithm == "holders" {
		for _, messageEntry := range messageEntries {
			otherPartyPublicKeyBytes, otherPartyPublicKeyBase58Check := fes.getOtherPartyInThread(messageEntry, publicKeyBytes)

			if _, alreadySeen := publicKeyToNanosUserHeld[otherPartyPublicKeyBase58Check]; !alreadySeen {
				otherPartyBalanceEntry, err := lib.GetSingleBalanceEntryFromPublicKeys(
					otherPartyPublicKeyBytes, publicKeyBytes, utxoView, false)
				if err != nil {
					return nil, nil, nil, 0, nil, errors.Wrapf(
						err, "getMessagesStateless: Problem getting balance entry for public key")
				}
				if otherPartyBalanceEntry != nil {
					// CreatorCoins never exceed uint64
					publicKeyToNanosUserHeld[otherPartyPublicKeyBase58Check] = otherPartyBalanceEntry.BalanceNanos.Uint64()
				} else {
					publicKeyToNanosUserHeld[otherPartyPublicKeyBase58Check] = 0
				}
			}
		}

		sort.Slice(messageEntries, func(ii, jj int) bool {
			_, otherPartyPublicKeyiiBase58Check := fes.getOtherPartyInThread(messageEntries[ii], publicKeyBytes)
			_, otherPartyPublicKeyjjBase58Check := fes.getOtherPartyInThread(messageEntries[jj], publicKeyBytes)
			return publicKeyToNanosUserHeld[otherPartyPublicKeyiiBase58Check] > publicKeyToNanosUserHeld[otherPartyPublicKeyjjBase58Check]
		})
	} else {
		sort.Slice(messageEntries, func(ii, jj int) bool {
			return messageEntries[ii].TstampNanos > messageEntries[jj].TstampNanos
		})
	}

	// Setup fetch boolean used for determining if we've already hit the fetchAfterPublicKeyBytes.
	hitFetchAfterPublicKey := len(fetchAfterPublicKeyBytes) == 0

	// Check if we're filtering results, setup maps if so
	filterResults := holdersOnly || holdingsOnly || followersOnly || followingOnly

	// Create maps for checking specific filters
	publicKeyHoldsUser := make(map[string]bool)
	userHoldsPublicKey := make(map[string]bool)
	publicKeyFollowsUser := make(map[string]bool)
	userFollowsPublicKey := make(map[string]bool)
	publicKeyPassedFilters := make(map[string]bool)

	// Filter out paginated messages from messageEntries
	publicKeyInPaginatedSet := make(map[string]bool)
	publicKeyToProfileEntry := make(map[string]*ProfileEntryResponse)
	contactMap := make(map[string]*MessageContactResponse)
	newContactEntries := []*MessageContactResponse{}
	uniqueProfilesInPaginatedSetSeen := uint64(0)
	blockedPubKeysForUser, err := fes.GetBlockedPubKeysForUser(publicKeyBytes)
	if err != nil {
		return nil, nil, nil, 0, nil, errors.Wrapf(
			err, "getMessagesStateless: Problem getting blocked users for public key")
	}
	for _, messageEntry := range messageEntries {
		// Check who the other party in the message is
		otherPartyPublicKeyBytes, otherPartyPublicKeyBase58Check := fes.getOtherPartyInThread(messageEntry, publicKeyBytes)

		// Check if the other party has been seen before and if it needs to be included in the response message
		inPageSet, alreadySeen := publicKeyInPaginatedSet[otherPartyPublicKeyBase58Check]

		// Skip it if it's already been processed
		if alreadySeen && !inPageSet {
			continue
		}

		// Skip if it's a blocked user
		if _, blocked := blockedPubKeysForUser[otherPartyPublicKeyBase58Check]; blocked {
			continue
		}

		// Filter out messages if requested by user
		passedFilters, checkedFilters := publicKeyPassedFilters[otherPartyPublicKeyBase58Check]
		if checkedFilters && !passedFilters {
			continue
		}

		if filterResults && !checkedFilters {
			publicKeyWithinFilters := false

			// Check if the messenger passes the holder check
			if holdersOnly {
				holdsUser, balanceChecked := publicKeyHoldsUser[otherPartyPublicKeyBase58Check]
				if !balanceChecked {
					balanceEntry, err := lib.GetSingleBalanceEntryFromPublicKeys(
						otherPartyPublicKeyBytes, publicKeyBytes, utxoView, false)
					if err != nil {
						return nil, nil, nil, 0, nil, errors.Wrapf(
							err, "getMessagesStateless: Problem getting balance entry for holder public key %v", otherPartyPublicKeyBase58Check)
					}
					// CreatorCoins never exceed Uint64
					holdsUser = balanceEntry != nil && balanceEntry.BalanceNanos.Uint64() > 0
					publicKeyHoldsUser[otherPartyPublicKeyBase58Check] = holdsUser
				}
				if holdsUser {
					publicKeyWithinFilters = true
				}
			}

			// Check if the messenger passes the holding check
			if !publicKeyWithinFilters && holdingsOnly {
				holdsPublicKey, balanceChecked := userHoldsPublicKey[otherPartyPublicKeyBase58Check]
				if !balanceChecked {
					balanceEntry, err := lib.GetSingleBalanceEntryFromPublicKeys(
						publicKeyBytes, otherPartyPublicKeyBytes, utxoView, false)
					if err != nil {
						return nil, nil, nil, 0, nil, errors.Wrapf(
							err, "getMessagesStateless: Problem getting balance entry for holder public key %v", otherPartyPublicKeyBase58Check)
					}
					// CreatorCoins never exceed Uint64
					holdsPublicKey = balanceEntry != nil && balanceEntry.BalanceNanos.Uint64() > 0
					userHoldsPublicKey[otherPartyPublicKeyBase58Check] = holdsPublicKey
				}
				if holdsPublicKey {
					publicKeyWithinFilters = true
				}
			}

			// Check if the messenger passes the followers check
			if !publicKeyWithinFilters && followersOnly {
				followsUser, followChecked := publicKeyFollowsUser[otherPartyPublicKeyBase58Check]
				if !followChecked {
					followEntry := lib.DbGetFollowerToFollowedMapping(utxoView.Handle,
						lib.PublicKeyToPKID(otherPartyPublicKeyBytes),
						lib.PublicKeyToPKID(publicKeyBytes))
					followsUser = followEntry != nil
					publicKeyFollowsUser[otherPartyPublicKeyBase58Check] = followsUser
				}
				if followsUser {
					publicKeyWithinFilters = true
				}
			}

			// Check if the messenger passes the following check
			if !publicKeyWithinFilters && followingOnly {
				followsPublicKey, followChecked := userFollowsPublicKey[otherPartyPublicKeyBase58Check]
				if !followChecked {
					followEntry := lib.DbGetFollowerToFollowedMapping(utxoView.Handle,
						lib.PublicKeyToPKID(publicKeyBytes),
						lib.PublicKeyToPKID(otherPartyPublicKeyBytes))
					followsPublicKey = followEntry != nil
					userFollowsPublicKey[otherPartyPublicKeyBase58Check] = followsPublicKey
				}
				if followsPublicKey {
					publicKeyWithinFilters = true
				}
			}

			// Skip if the user failed the tests and update the map for faster lookup
			publicKeyPassedFilters[otherPartyPublicKeyBase58Check] = publicKeyWithinFilters
			if !publicKeyWithinFilters {
				continue
			}
		}

		// If this passed all the filter's requested by the user, we now check if it's within the requested
		// page parameters.
		if !alreadySeen {
			if hitFetchAfterPublicKey && uniqueProfilesInPaginatedSetSeen < numToFetch {
				inPageSet = true
				publicKeyInPaginatedSet[otherPartyPublicKeyBase58Check] = true

				// We now know the other user's messages are set to be returned for the first time.
				otherProfileEntry := fes._profileEntryToResponse(utxoView.GetProfileEntryForPublicKey(otherPartyPublicKeyBytes), utxoView)
				publicKeyToProfileEntry[otherPartyPublicKeyBase58Check] = otherProfileEntry

				contactEntry := &MessageContactResponse{
					PublicKeyBase58Check: otherPartyPublicKeyBase58Check,
					ProfileEntryResponse: otherProfileEntry,
					Messages:             []*MessageEntryResponse{},
				}
				contactMap[otherPartyPublicKeyBase58Check] = contactEntry
				newContactEntries = append(newContactEntries, contactEntry)

				// Increment the number of profiles in the paginated set to prevent fetching too many profiles.
				uniqueProfilesInPaginatedSetSeen++
			} else {
				publicKeyInPaginatedSet[otherPartyPublicKeyBase58Check] = false

				// Check if we've hit the fetchAfterPublicKey and update accordingly.
				// This means the next unique public key which fits our filter parameters will
				// be put in the paginated set.
				hitFetchAfterPublicKey = reflect.DeepEqual(otherPartyPublicKeyBytes, fetchAfterPublicKeyBytes)

				continue
			}
		}

		// V2 will be true even if message version is 3 or higher, but the version field in MessageEntryResponse
		// will reflect the real message version.
		V2 := false
		if messageEntry.Version == lib.MessagesVersion2 {
			V2 = true
		}

		// By now we know this messageEntry is meant to be included in the response.
		messageEntryRes := &MessageEntryResponse{
			SenderPublicKeyBase58Check:    lib.PkToString(messageEntry.SenderPublicKey[:], fes.Params),
			RecipientPublicKeyBase58Check: lib.PkToString(messageEntry.RecipientPublicKey[:], fes.Params),
			EncryptedText:                 hex.EncodeToString(messageEntry.EncryptedText),
			TstampNanos:                   messageEntry.TstampNanos,
			IsSender:                      !reflect.DeepEqual(messageEntry.RecipientPublicKey[:], publicKeyBytes),
			V2:                            V2, /* DEPRECATED */
			Version:                       uint32(messageEntry.Version),
			SenderMessagingPublicKey:      lib.PkToString(messageEntry.SenderMessagingPublicKey[:], fes.Params),
			SenderMessagingKeyName:        string(lib.MessagingKeyNameDecode(messageEntry.SenderMessagingGroupKeyName)),
			RecipientMessagingPublicKey:   lib.PkToString(messageEntry.RecipientMessagingPublicKey[:], fes.Params),
			RecipientMessagingKeyName:     string(lib.MessagingKeyNameDecode(messageEntry.RecipientMessagingGroupKeyName)),
		}
		contactEntry, _ := contactMap[lib.PkToString(otherPartyPublicKeyBytes, fes.Params)]
		contactEntry.Messages = append(contactEntry.Messages, messageEntryRes)
	}

	// Go through the messages to ensure proper ordering between participant messages.
	for _, contact := range newContactEntries {
		sort.Slice(contact.Messages, func(ii, jj int) bool {
			return contact.Messages[ii].TstampNanos < contact.Messages[jj].TstampNanos
		})
	}

	// Order the messages in the inbox based on the selected sort algorithm.
	if sortAlgorithm == "deso" {
		sort.Slice(newContactEntries, func(ii, jj int) bool {
			return publicKeyToDESO[newContactEntries[ii].PublicKeyBase58Check] >
				publicKeyToDESO[newContactEntries[jj].PublicKeyBase58Check]
		})
	} else if sortAlgorithm == "followers" {
		sort.Slice(newContactEntries, func(ii, jj int) bool {
			return publicKeyToNumberOfFollowers[newContactEntries[ii].PublicKeyBase58Check] >
				publicKeyToNumberOfFollowers[newContactEntries[jj].PublicKeyBase58Check]
		})
	} else if sortAlgorithm == "holders" {
		sort.Slice(newContactEntries, func(ii, jj int) bool {
			return publicKeyToNanosUserHeld[newContactEntries[ii].PublicKeyBase58Check] >
				publicKeyToNanosUserHeld[newContactEntries[jj].PublicKeyBase58Check]
		})
	} else {
		sort.Slice(newContactEntries, func(ii, jj int) bool {
			return newContactEntries[ii].Messages[len(newContactEntries[ii].Messages)-1].TstampNanos >
				newContactEntries[jj].Messages[len(newContactEntries[jj].Messages)-1].TstampNanos
		})
	}

	// We now check if a messages are unread. unreadMessagesBycontact returns true
	// if the contact has new messages for the user.
	unreadMessagesBycontact := make(map[string]bool)
	numOfUnreadThreads := 0
	for _, entry := range newContactEntries {
		otherUserPublicKeyBytes, _, err := lib.Base58CheckDecode(entry.PublicKeyBase58Check)
		if err != nil {
			return nil, nil, nil, 0, nil, errors.Wrapf(err, "getMessagesStateless: Problem decoding "+
				"contact's public key.")
		}

		mostRecentReadTstampNanos, err := fes.getUserContactMostRecentReadTime(publicKeyBytes, otherUserPublicKeyBytes)
		if err != nil {
			return nil, nil, nil, 0, nil, errors.Wrapf(err, "getMessagesStateless: Problem getting "+
				"contact's most recent read state.")
		}

		for ii, msg := range entry.Messages {
			// Check if this is an unread message.
			if !msg.IsSender {
				if msg.TstampNanos > mostRecentReadTstampNanos {
					unreadMessagesBycontact[entry.PublicKeyBase58Check] = true
					numOfUnreadThreads++
					break
				}
			}
			// If we've gone through all the messages and they're all ready, we mark this thread as read.
			if ii == len(entry.Messages)-1 {
				unreadMessagesBycontact[entry.PublicKeyBase58Check] = false
			}
		}
	}

	var userMessagingKeys []*MessagingGroupEntryResponse
	userMessagingKeys = fes.ParseMessagingGroupEntries(publicKeyBytes, messagingKeys)

	return publicKeyToProfileEntry, newContactEntries, unreadMessagesBycontact, numOfUnreadThreads, userMessagingKeys, nil
}

func (fes *APIServer) ParseMessagingGroupEntries(memberPublicKeyBytes []byte, messagingGroupEntries []*lib.MessagingGroupEntry) []*MessagingGroupEntryResponse {
	var userMessagingKeys []*MessagingGroupEntryResponse
	for _, key := range messagingGroupEntries {

		userMessagingKey := MessagingGroupEntryResponse{
			GroupOwnerPublicKeyBase58Check: lib.PkToString(key.GroupOwnerPublicKey[:], fes.Params),
			MessagingPublicKeyBase58Check: lib.PkToString(key.MessagingPublicKey[:], fes.Params),
			MessagingGroupKeyName: string(lib.MessagingKeyNameDecode(key.MessagingGroupKeyName)),
			EncryptedKey: "",
		}

		for _, groupMember := range key.MessagingGroupMembers {
			encryptedKey := hex.EncodeToString(groupMember.EncryptedKey)
			if reflect.DeepEqual(groupMember.GroupMemberPublicKey[:], memberPublicKeyBytes) {
				userMessagingKey.EncryptedKey = encryptedKey
			}
			messagingRecipient := &MessagingGroupMemberResponse{
				GroupMemberPublicKeyBase58Check: lib.PkToString(groupMember.GroupMemberPublicKey[:], fes.Params),
				GroupMemberKeyName: string(lib.MessagingKeyNameDecode(groupMember.GroupMemberKeyName)),
				EncryptedKey: hex.EncodeToString(groupMember.EncryptedKey),
			}
			userMessagingKey.MessagingGroupMembers = append(userMessagingKey.MessagingGroupMembers, messagingRecipient)
		}
		userMessagingKeys = append(userMessagingKeys, &userMessagingKey)
	}
	return userMessagingKeys
}

func (fes *APIServer) getOtherPartyInThread(messageEntry *lib.MessageEntry,
	readerPublicKeyBytes []byte) (otherPartyPublicKeyBytes []byte, otherPartyPublicKeyBase58Check string) {
	if reflect.DeepEqual(messageEntry.RecipientPublicKey[:], readerPublicKeyBytes) {
		otherPartyPublicKeyBytes = messageEntry.SenderPublicKey[:]
	} else {
		otherPartyPublicKeyBytes = messageEntry.RecipientPublicKey[:]
	}
	otherPartyPublicKeyBase58Check = lib.PkToString(otherPartyPublicKeyBytes, fes.Params)
	return
}

// GetMessagesStateless ...
func (fes *APIServer) GetMessagesStateless(ww http.ResponseWriter, rr *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(rr.Body, MaxRequestBodySizeBytes))
	getMessagesRequest := GetMessagesStatelessRequest{}
	if err := decoder.Decode(&getMessagesRequest); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetMessagesStateless: Error parsing request body: %v", err))
		return
	}

	// Decode the public key into bytes.
	publicKeyBytes, _, err := lib.Base58CheckDecode(getMessagesRequest.PublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetMessagesStateless: Problem decoding user public key: %v", err))
		return
	}

	var fetchAfterPublicKeyBytes []byte
	if getMessagesRequest.FetchAfterPublicKeyBase58Check != "" {
		fetchAfterPublicKeyBytes, _, err = lib.Base58CheckDecode(getMessagesRequest.FetchAfterPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetMessagesStateless: Problem decoding fetch after public key: %v", err))
			return
		}
	}

	publicKeyToProfileEntry, orderedContactsWithMessages,
		unreadStateByContact, numOfUnreadThreads, messagingKeys, err := fes.getMessagesStateless(publicKeyBytes, fetchAfterPublicKeyBytes,
		getMessagesRequest.NumToFetch, getMessagesRequest.HoldersOnly, getMessagesRequest.HoldingsOnly,
		getMessagesRequest.FollowersOnly, getMessagesRequest.FollowingOnly, getMessagesRequest.SortAlgorithm)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetMessagesStateless: Problem fetching and decrypting messages: %v", err))
		return
	}

	// =====================================================================================

	res := GetMessagesResponse{
		PublicKeyToProfileEntry:     publicKeyToProfileEntry,
		OrderedContactsWithMessages: orderedContactsWithMessages,
		UnreadStateByContact:        unreadStateByContact,
		NumberOfUnreadThreads:       numOfUnreadThreads,
		MessagingKeys:               messagingKeys,
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetMessages: Problem serializing object to JSON: %v", err))
		return
	}
}

// SendMessageStatelessRequest ...
type SendMessageStatelessRequest struct {
	SenderPublicKeyBase58Check    string `safeForLogging:"true"`
	RecipientPublicKeyBase58Check string `safeForLogging:"true"`
	MessageText                   string
	EncryptedMessageText          string
	SenderMessagingKeyName        string `safeForLogging:"true"`
	RecipientMessagingKeyName     string `safeForLogging:"true"`
	MinFeeRateNanosPerKB          uint64 `safeForLogging:"true"`

	// No need to specify ProfileEntryResponse in each TransactionFee
	TransactionFees []TransactionFee `safeForLogging:"true"`
}

// SendMessageStatelessResponse ...
type SendMessageStatelessResponse struct {
	TstampNanos uint64

	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgDeSoTxn
	TransactionHex    string
}

// SendMessageStateless ...
func (fes *APIServer) SendMessageStateless(ww http.ResponseWriter, req *http.Request) {

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
	senderPublicKey := lib.NewPublicKey(senderPkBytes)

	var senderMessagingKeyNameBytes []byte
	if len(requestData.SenderMessagingKeyName) == 0 {
		senderMessagingKeyNameBytes = lib.DefaultGroupKeyName()[:]
	} else {
		senderMessagingKeyNameBytes = []byte(requestData.SenderMessagingKeyName)
	}
	if err = lib.ValidateGroupPublicKeyAndName(senderPkBytes, senderMessagingKeyNameBytes); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendMessageStateless: Problem validating sender "+
			"messaging key name %s: %v", requestData.SenderMessagingKeyName, err))
		return
	}

	// Decode the recipient's public key.
	recipientPkBytes, _, err := lib.Base58CheckDecode(requestData.RecipientPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendMessageStateless: Problem decoding recipient "+
			"base58 public key %s: %v", requestData.RecipientPublicKeyBase58Check, err))
		return
	}
	recipientPublicKey := lib.NewPublicKey(recipientPkBytes)

	var recipientMessagingKeyNameBytes []byte
	if len(requestData.RecipientMessagingKeyName) == 0 {
		recipientMessagingKeyNameBytes = lib.DefaultGroupKeyName()[:]
	} else {
		recipientMessagingKeyNameBytes = []byte(requestData.RecipientMessagingKeyName)
	}
	if err = lib.ValidateGroupPublicKeyAndName(senderPkBytes, recipientMessagingKeyNameBytes); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendMessageStateless: Problem validating recipient "+
			"messaging key name %s: %v", requestData.RecipientMessagingKeyName, err))
		return
	}

	// Compute the additional transaction fees as specified by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(lib.TxnTypePrivateMessage, senderPkBytes, requestData.TransactionFees)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendMessageStateless: TransactionFees specified in Request body are invalid: %v", err))
		return
	}

	checkPartyMessagingKeysResponse, err := fes.CreateCheckPartyMessagingKeysResponse(senderPublicKey, lib.NewGroupKeyName(senderMessagingKeyNameBytes),
		recipientPublicKey, lib.NewGroupKeyName(recipientMessagingKeyNameBytes))
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendMessageStateless: Problem checking party keys: %v", err))
		return
	}

	if !checkPartyMessagingKeysResponse.IsSenderMessagingKey {
		senderMessagingKeyNameBytes = lib.BaseGroupKeyName()[:]
	}

	if !checkPartyMessagingKeysResponse.IsRecipientMessagingKey {
		recipientMessagingKeyNameBytes = lib.BaseGroupKeyName()[:]
	}


	var senderMessagingPublicKey, recipientMessagingPublicKey []byte
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	senderMessagingGroupKey := lib.NewMessagingGroupKey(senderPublicKey, senderMessagingKeyNameBytes)
	senderMessagingGroupEntry := utxoView.GetMessagingGroupKeyToMessagingGroupEntryMapping(senderMessagingGroupKey)
	senderMessagingPublicKey = senderMessagingGroupEntry.MessagingPublicKey[:]

	recipientMessagingGroupKey := lib.NewMessagingGroupKey(recipientPublicKey, recipientMessagingKeyNameBytes)
	recipientMessagingGroupEntry := utxoView.GetMessagingGroupKeyToMessagingGroupEntryMapping(recipientMessagingGroupKey)
	recipientMessagingPublicKey = recipientMessagingGroupEntry.MessagingPublicKey[:]

	// Try and create the message for the user.
	tstamp := uint64(time.Now().UnixNano())
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreatePrivateMessageTxn(
		senderPkBytes, recipientPkBytes,
		requestData.MessageText, requestData.EncryptedMessageText,
		senderMessagingPublicKey, senderMessagingKeyNameBytes,
		recipientMessagingPublicKey, recipientMessagingKeyNameBytes,
		tstamp,
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool(), additionalOutputs)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendMessageStateless: Problem creating transaction: %v", err))
		return
	}

	// Add node source to txn metadata
	fes.AddNodeSourceToTxnMetadata(txn)

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendMessageStateless: Problem serializing transaction: %v", err))
		return
	}

	// Return all the data associated with the transaction in the response
	res := SendMessageStatelessResponse{
		TstampNanos: tstamp,

		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendMessageStateless: Problem encoding response as JSON: %v", err))
		return
	}
}

type MarkContactMessagesReadRequest struct {
	JWT                         string
	UserPublicKeyBase58Check    string
	ContactPublicKeyBase58Check string
}

func (fes *APIServer) MarkContactMessagesRead(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := MarkContactMessagesReadRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("MarkUserContactMessagesRead: Problem parsing request body: %v", err))
		return
	}

	isValid, err := fes.ValidateJWT(requestData.UserPublicKeyBase58Check, requestData.JWT)
	if !isValid {
		_AddBadRequestError(ww, fmt.Sprintf("MarkUserContactMessagesRead: Invalid token: %v", err))
		return
	}

	userPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.UserPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("MarkUserContactMessagesRead: Problem decoding user public key: %v", err))
		return
	}

	contactPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.ContactPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("MarkUserContactMessagesRead: Problem decoding contact public key: %v", err))
		return
	}

	err = fes.markContactMessagesRead(userPublicKeyBytes, contactPublicKeyBytes)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("MarkUserContactMessagesRead: Problem marking thread as read: %v", err))
		return
	}
}

type MarkAllMessagesReadRequest struct {
	JWT                      string
	UserPublicKeyBase58Check string
}

func (fes *APIServer) MarkAllMessagesRead(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := MarkAllMessagesReadRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("MarkUserContactMessagesRead: Problem parsing request body: %v", err))
		return
	}

	isValid, err := fes.ValidateJWT(requestData.UserPublicKeyBase58Check, requestData.JWT)
	if !isValid {
		_AddBadRequestError(ww, fmt.Sprintf("MarkUserContactMessagesRead: Invalid token: %v", err))
		return
	}

	userPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.UserPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("MarkUserContactMessagesRead: Problem decoding user public key: %v", err))
		return
	}

	err = fes.markAllMessagesRead(userPublicKeyBytes)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("MarkUserContactMessagesRead: Problem marking threads as read: %v", err))
		return
	}
}

// markAllMessagesRead...
func (fes *APIServer) markAllMessagesRead(publicKeyBytes []byte) error {
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUtxoViewForPublicKey(publicKeyBytes, nil)
	if err != nil {
		return errors.Wrapf(err, "markAllMessagesRead: Error calling GetAugmentedUtxoViewForPublicKey: %v", err)
	}

	messageEntries, _, err := utxoView.GetMessagesForUser(publicKeyBytes)
	if err != nil {
		return errors.Wrapf(err, "markAllMessagesRead: Problem fetching MessageEntries from augmented UtxoView: ")
	}

	alreadySeenContactMap := make(map[string]struct{})
	for _, messageEntry := range messageEntries {
		otherPartyPublicKeyBytes, otherPartyPublicKeyBase58Check := fes.getOtherPartyInThread(messageEntry, publicKeyBytes)

		// Check if we've seen this contact before
		_, alreadySeenContact := alreadySeenContactMap[otherPartyPublicKeyBase58Check]

		// Mark messages if this is the first time seeing the contact
		if !alreadySeenContact {
			alreadySeenContactMap[otherPartyPublicKeyBase58Check] = struct{}{}
			err = fes.markContactMessagesRead(publicKeyBytes, otherPartyPublicKeyBytes)
			if err != nil {
				return errors.Wrapf(err, "markAllMessagesRead: Problem marking public key as read: ")
			}
		}
	}

	return nil
}

// markContactMessagesRead...
func (fes *APIServer) markContactMessagesRead(userPublicKeyBytes []byte, contactPublicKeyBytes []byte) (_err error) {
	dbKey := GlobalStateKeyForUserPkContactPkToMostRecentReadTstampNanos(userPublicKeyBytes, contactPublicKeyBytes)

	tStampNanos := uint64(time.Now().UnixNano())
	tStampNanosBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(tStampNanosBytes, tStampNanos)

	err := fes.GlobalState.Put(dbKey, tStampNanosBytes)
	if err != nil {
		return errors.Wrap(fmt.Errorf(
			"putUserContactMostRecentReadTime: Problem putting updated tStampNanosBytes: %v", err), "")
	}

	return nil
}

// getUserContactMostRecentReadTime...
func (fes *APIServer) getUserContactMostRecentReadTime(userPublicKeyBytes []byte, contactPublicKeyBytes []byte) (uint64, error) {
	dbKey := GlobalStateKeyForUserPkContactPkToMostRecentReadTstampNanos(userPublicKeyBytes, contactPublicKeyBytes)
	tStampNanosBytes, err := fes.GlobalState.Get(dbKey)
	if err != nil {
		// If the key errors, we return 0.
		return 0, nil
	}

	var tStampNanos uint64
	if len(tStampNanosBytes) != 0 {
		tStampNanos = binary.LittleEndian.Uint64(tStampNanosBytes)
	}
	return tStampNanos, nil
}

type RegisterMessagingKeysRequest struct {
	OwnerPublicKeyBase58Check     string
	MessagingPublicKeyBase58Check string
	MessagingKeyName              string
	MessagingKeySignatureHex      string

	MinFeeRateNanosPerKB          uint64 `safeForLogging:"true"`

	// No need to specify ProfileEntryResponse in each TransactionFee
	TransactionFees []TransactionFee `safeForLogging:"true"`
}

type RegisterMessagingKeysResponse struct {
	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgDeSoTxn
	TransactionHex    string
}

func (fes *APIServer) RegisterMessagingKeys(ww http.ResponseWriter, req *http.Request) {

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := RegisterMessagingKeysRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("RegisterMessagingKeys: Problem parsing request body: %v", err))
		return
	}

	// Decode the owner public key.
	ownerPkBytes, _, err := lib.Base58CheckDecode(requestData.OwnerPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("RegisterMessagingKeys: Problem decoding sender "+
			"base58 public key %s: %v", requestData.OwnerPublicKeyBase58Check, err))
		return
	}

	// Compute the additional transaction fees as specified by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(lib.TxnTypeMessagingGroup, ownerPkBytes, requestData.TransactionFees)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("RegisterMessagingKeys: TransactionFees specified in Request body are invalid: %v", err))
		return
	}

	messagingPkBytes, _, err := lib.Base58CheckDecode(requestData.MessagingPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("RegisterMessagingKeys: Problem decoding messaging "+
			"base58 public key %s: %v", requestData.MessagingPublicKeyBase58Check, err))
		return
	}
	messagingKeyNameBytes := []byte(requestData.MessagingKeyName)

	err = lib.ValidateGroupPublicKeyAndName(messagingPkBytes, messagingKeyNameBytes)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("RegisterMessagingKeys: Problem validating messaging public key and name %v", err))
		return
	}

	messagingKeySignature, _ := hex.DecodeString(requestData.MessagingKeySignatureHex)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("RegisterMessagingKeys: Problem decoding messaging public key signature %v", err))
		return
	}

	if lib.EqualGroupKeyName(lib.DefaultGroupKeyName(), lib.NewGroupKeyName(messagingKeyNameBytes)) {
		msgBytes := append(messagingPkBytes, messagingKeyNameBytes...)
		if err := VerifyBytesSignature(ownerPkBytes, msgBytes, messagingKeySignature); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("RegisterMessagingKeys: Problem verifying transaction signature: %v", err))
			return
		}
	}

	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateMessagingKeyTxn(
		ownerPkBytes, messagingPkBytes, messagingKeyNameBytes, messagingKeySignature,
		[]*lib.MessagingGroupMember{},
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool(), additionalOutputs)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("RegisterMessagingKeys: Problem creating transaction: %v", err))
		return
	}

	// Add node source to txn metadata
	fes.AddNodeSourceToTxnMetadata(txn)

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("RegisterMessagingKeys: Problem serializing transaction: %v", err))
		return
	}

	res := RegisterMessagingKeysResponse{
		TotalInputNanos: totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos: fees,
		Transaction: txn,
		TransactionHex: hex.EncodeToString(txnBytes),
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("RegisterMessagingKeys: Problem encoding response as JSON: %v", err))
		return
	}
}

func VerifyBytesSignature(signer, data, signature []byte) error {
	bytes := lib.Sha256DoubleHash(data)

	// Convert signature to *btcec.Signature.
	sign, err := btcec.ParseDERSignature(signature, btcec.S256())
	if err != nil {
		return errors.Wrapf(err, "_verifyBytesSignature: Problem parsing access signature: ")
	}

	// Verify signature.
	ownerPk, _ := btcec.ParsePubKey(signer, btcec.S256())
	if !sign.Verify(bytes[:], ownerPk) {
		return fmt.Errorf("_verifyBytesSignature: Invalid signature")
	}
	return nil
}

type GetAllMessagingKeysRequest struct {
	OwnerPublicKeyBase58Check string
}

type GetAllMessagingKeysResponse struct {
	MessagingGroupEntries []*MessagingGroupEntryResponse
}


func (fes *APIServer) GetAllMessagingKeys(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetAllMessagingKeysRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllMessagingKeys: Problem parsing request body: %v", err))
		return
	}

	// Decode the owner public key.
	ownerPkBytes, _, err := lib.Base58CheckDecode(requestData.OwnerPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllMessagingKeys: Problem decoding sender "+
			"base58 public key %s: %v", requestData.OwnerPublicKeyBase58Check, err))
		return
	}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUtxoViewForPublicKey(ownerPkBytes, nil)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllMessagingKeys: Error calling " +
			"GetAugmentedUtxoViewForPublicKey: %s: %v", requestData.OwnerPublicKeyBase58Check, err))
		return
	}

	// First get all messaging keys for a user.
	messagingGroupEntries, err := utxoView.GetMessagingGroupEntriesForUser(ownerPkBytes)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllMessagingKeys: Error calling " +
			"GetAugmentedUtxoViewForPublicKey: %s: %v", requestData.OwnerPublicKeyBase58Check, err))
	}

	var messagingEntryResponses []*MessagingGroupEntryResponse
	messagingEntryResponses = fes.ParseMessagingGroupEntries(ownerPkBytes, messagingGroupEntries)

	res := GetAllMessagingKeysResponse{
		MessagingGroupEntries: messagingEntryResponses,
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllMessagingKeys: Problem serializing object to JSON: %v", err))
		return
	}
}

type CheckPartyMessagingKeysRequest struct {
	SenderPublicKeyBase58Check    string
	SenderMessagingKeyName        string
	RecipientPublicKeyBase58Check string
	RecipientMessagingKeyName     string
}

type CheckPartyMessagingKeysResponse struct {
	SenderMessagingPublicKeyBase58Check    string
	IsSenderMessagingKey                   bool
	SenderMessagingKeyName                 string
	RecipientMessagingPublicKeyBase58Check string
	IsRecipientMessagingKey                bool
	RecipientMessagingKeyName              string
}

func (fes *APIServer) CreateCheckPartyMessagingKeysResponse(senderPublicKey *lib.PublicKey, senderMessagingKeyName *lib.GroupKeyName,
	recipientPublicKey *lib.PublicKey, recipientMessagingKeyName *lib.GroupKeyName) (
	*CheckPartyMessagingKeysResponse, error) {

	response := &CheckPartyMessagingKeysResponse{
		SenderMessagingPublicKeyBase58Check:    lib.Base58CheckEncode(senderPublicKey[:], false, fes.Params),
		IsSenderMessagingKey:                   false,
		SenderMessagingKeyName:                 "",
		RecipientMessagingPublicKeyBase58Check: lib.Base58CheckEncode(recipientPublicKey[:], false, fes.Params),
		IsRecipientMessagingKey:                false,
		RecipientMessagingKeyName:              "",
	}

	// The publicKey Utxo doesn't work currently so doesn't matter if we call it with []byte{}
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return nil, err
	}

	messagingKey := lib.NewMessagingGroupKey(senderPublicKey, senderMessagingKeyName[:])
	messagingEntry := utxoView.GetMessagingGroupKeyToMessagingGroupEntryMapping(messagingKey)

	if messagingEntry != nil {
		response.SenderMessagingPublicKeyBase58Check = lib.Base58CheckEncode(messagingEntry.MessagingPublicKey[:], false, fes.Params)
		response.IsSenderMessagingKey = true
		response.SenderMessagingKeyName = string(lib.MessagingKeyNameDecode(senderMessagingKeyName))
	}

	messagingKey = lib.NewMessagingGroupKey(recipientPublicKey, recipientMessagingKeyName[:])
	messagingEntry = utxoView.GetMessagingGroupKeyToMessagingGroupEntryMapping(messagingKey)

	if messagingEntry != nil {
		response.RecipientMessagingPublicKeyBase58Check = lib.Base58CheckEncode(messagingEntry.MessagingPublicKey[:], false, fes.Params)
		response.IsRecipientMessagingKey = true
		response.RecipientMessagingKeyName = string(lib.MessagingKeyNameDecode(recipientMessagingKeyName))
	}

	return response, nil
}

func (fes *APIServer) CheckPartyMessagingKeys(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := CheckPartyMessagingKeysRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CheckPartyMessagingKeys: Problem parsing request body: %v", err))
		return
	}

	senderPublicKey, _, err := lib.Base58CheckDecode(requestData.SenderPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CheckPartyMessagingKeys: Problem decoding sender public key: %v", err))
		return
	}
	senderKeyName := lib.NewGroupKeyName([]byte(requestData.SenderMessagingKeyName))
	if err = lib.ValidateGroupPublicKeyAndName(senderPublicKey, senderKeyName[:]); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CheckPartyMessagingKeys: Problem validating sender public key and key name: %v", err))
		return
	}

	recipientPublicKey, _, err := lib.Base58CheckDecode(requestData.RecipientPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CheckPartyMessagingKeys: Problem decoding recipient public key: %v", err))
		return
	}
	recipientKeyName := lib.NewGroupKeyName([]byte(requestData.RecipientMessagingKeyName))
	if err = lib.ValidateGroupPublicKeyAndName(recipientPublicKey, recipientKeyName[:]); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CheckPartyMessagingKeys: Problem validating recipient public key and key name: %v", err))
		return
	}

	response, err := fes.CreateCheckPartyMessagingKeysResponse(lib.NewPublicKey(senderPublicKey), senderKeyName,
		lib.NewPublicKey(recipientPublicKey), recipientKeyName)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CheckPartyMessagingKeys: Problem creating party messaging key response: %v", err))
		return
	}
	if err := json.NewEncoder(ww).Encode(response); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CheckPartyMessagingKeys: Problem encoding response as JSON: %v", err))
		return
	}
}
