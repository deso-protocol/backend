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
	// PublicKeyToProfileEntry is a map of profile entries of the message parties. Keys are base58check public keys.
	PublicKeyToProfileEntry map[string]*ProfileEntryResponse

	// OrderedContactsWithMessages is a list of message contacts. Each entry in the list corresponds to a messaging
	// thread and contains the public key and profile entry of the other party in the thread. Entries also contain a
	// list of encrypted messages for the threads.
	OrderedContactsWithMessages []*MessageContactResponse

	// UnreadStateByContact is a map indexed by public key base58check of contacts and with boolean values corresponding
	// to whether the thread has any unread messages. True means there are unread messages.
	UnreadStateByContact map[string]bool

	// NumberOfUnreadThreads is a counter of how many unread threads are there.
	NumberOfUnreadThreads int

	// MessagingGroups are all user's registered messaging keys and group chats that the user is a member of.
	MessagingGroups []*MessagingGroupEntryResponse
}

func (fes *APIServer) getMessagesStateless(publicKeyBytes []byte,
	fetchAfterPublicKeyBytes []byte, numToFetch uint64, holdersOnly bool,
	holdingsOnly bool, followersOnly bool, followingOnly bool, sortAlgorithm string) (
	_publicKeyToProfileEntry map[string]*ProfileEntryResponse,
	_orderedContactsWithMessages []*MessageContactResponse,
	_unreadMessagesByContact map[string]bool,
	_numOfUnreadThreads int,
	_messagingGroups []*MessagingGroupEntryResponse,
	_err error) {

	// Get mempool augmented UtxoView so we can fetch message threads.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUtxoViewForPublicKey(publicKeyBytes, nil)
	if err != nil {
		return nil, nil, nil, 0, nil, errors.Wrapf(
			err, "getMessagesStateless: Error calling GetAugmentedUtxoViewForPublicKey: %v", err)
	}

	// On a high level this function fetches all user's messages and messaging groups and creates a MessageEntryResponse
	// for each one. At the end, sort the MessageEntries by their timestamp.
	//
	// TODO: The timestamp is spoofable, but it's not a big deal. See comment on MessageEntry
	// for more insight on this.

	// Get user's messaging groups and up to lib.MessagesToFetchPerInboxCall messages.
	messageEntries, messagingGroups, err := utxoView.GetLimitedMessagesForUser(publicKeyBytes, uint64(lib.MessagesToFetchPerInboxCall))
	if err != nil {
		return nil, nil, nil, 0, nil, errors.Wrapf(
			err, "getMessagesStateless: Problem fetching MessageEntries and MessagingGroupEntries from augmented UtxoView: ")
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
						fes.blockchain.Snapshot(), lib.PublicKeyToPKID(otherPartyPublicKeyBytes),
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
						fes.blockchain.Snapshot(), lib.PublicKeyToPKID(publicKeyBytes),
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

		// The deprecated V2 field will be true if message version is 2, and the version field in MessageEntryResponse
		// will reflect the real message version.
		V2 := false
		if messageEntry.Version == lib.MessagesVersion2 {
			V2 = true
		}

		// By now we know this messageEntry is meant to be included in the response.
		messageEntryRes := &MessageEntryResponse{
			SenderPublicKeyBase58Check:     lib.PkToString(messageEntry.SenderPublicKey[:], fes.Params),
			RecipientPublicKeyBase58Check:  lib.PkToString(messageEntry.RecipientPublicKey[:], fes.Params),
			EncryptedText:                  hex.EncodeToString(messageEntry.EncryptedText),
			TstampNanos:                    messageEntry.TstampNanos,
			IsSender:                       !reflect.DeepEqual(messageEntry.RecipientPublicKey[:], publicKeyBytes),
			V2:                             V2, /* DEPRECATED */
			Version:                        uint32(messageEntry.Version),
			SenderMessagingPublicKey:       lib.PkToString(messageEntry.SenderMessagingPublicKey[:], fes.Params),
			SenderMessagingGroupKeyName:    string(lib.MessagingKeyNameDecode(messageEntry.SenderMessagingGroupKeyName)),
			RecipientMessagingPublicKey:    lib.PkToString(messageEntry.RecipientMessagingPublicKey[:], fes.Params),
			RecipientMessagingGroupKeyName: string(lib.MessagingKeyNameDecode(messageEntry.RecipientMessagingGroupKeyName)),
			ExtraData:                      DecodeExtraDataMap(fes.Params, utxoView, messageEntry.ExtraData),
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
	userMessagingKeys = fes.ParseMessagingGroupEntries(utxoView, publicKeyBytes, messagingGroups)

	return publicKeyToProfileEntry, newContactEntries, unreadMessagesBycontact, numOfUnreadThreads, userMessagingKeys, nil
}

// ParseMessagingGroupEntries parses a core type []*lib.MessagingGroupEntry to the backend type []*MessagingGroupEntryResponse.
func (fes *APIServer) ParseMessagingGroupEntries(
	utxoView *lib.UtxoView,
	memberPublicKeyBytes []byte,
	messagingGroupEntries []*lib.MessagingGroupEntry,
) []*MessagingGroupEntryResponse {

	var userMessagingGroupEntries []*MessagingGroupEntryResponse
	// Iterate through all messaging group entries.
	for _, key := range messagingGroupEntries {

		// Create an initial MessagingGroupEntryResponse that we will push to our userMessagingGroupEntries list.
		userMessagingGroup := MessagingGroupEntryResponse{
			GroupOwnerPublicKeyBase58Check: lib.PkToString(key.GroupOwnerPublicKey[:], fes.Params),
			MessagingPublicKeyBase58Check:  lib.PkToString(key.MessagingPublicKey[:], fes.Params),
			MessagingGroupKeyName:          string(lib.MessagingKeyNameDecode(key.MessagingGroupKeyName)),
			EncryptedKey:                   "",
			ExtraData:                      DecodeExtraDataMap(fes.Params, utxoView, key.ExtraData),
		}

		// Add all messaging group recipients from the messagingGroupEntries parameter.
		for _, groupMember := range key.MessagingGroupMembers {
			encryptedKey := hex.EncodeToString(groupMember.EncryptedKey)
			if reflect.DeepEqual(groupMember.GroupMemberPublicKey[:], memberPublicKeyBytes) {
				userMessagingGroup.EncryptedKey = encryptedKey
			}
			// Create a MessagingGroupMemberResponse to add to our userMessagingGroup.
			messagingRecipient := &MessagingGroupMemberResponse{
				GroupMemberPublicKeyBase58Check: lib.PkToString(groupMember.GroupMemberPublicKey[:], fes.Params),
				GroupMemberKeyName:              string(lib.MessagingKeyNameDecode(groupMember.GroupMemberKeyName)),
				EncryptedKey:                    hex.EncodeToString(groupMember.EncryptedKey),
			}
			userMessagingGroup.MessagingGroupMembers = append(userMessagingGroup.MessagingGroupMembers, messagingRecipient)
		}
		userMessagingGroupEntries = append(userMessagingGroupEntries, &userMessagingGroup)
	}
	return userMessagingGroupEntries
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

	// Get all contacts profile entries, messages, and group messaging keys.
	publicKeyToProfileEntry, orderedContactsWithMessages,
		unreadStateByContact, numOfUnreadThreads, messagingGroups, err := fes.getMessagesStateless(publicKeyBytes, fetchAfterPublicKeyBytes,
		getMessagesRequest.NumToFetch, getMessagesRequest.HoldersOnly, getMessagesRequest.HoldingsOnly,
		getMessagesRequest.FollowersOnly, getMessagesRequest.FollowingOnly, getMessagesRequest.SortAlgorithm)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetMessagesStateless: Problem fetching and decrypting messages: %v", err))
		return
	}

	// =====================================================================================

	// Now assemble the response.
	res := GetMessagesResponse{
		PublicKeyToProfileEntry:     publicKeyToProfileEntry,
		OrderedContactsWithMessages: orderedContactsWithMessages,
		UnreadStateByContact:        unreadStateByContact,
		NumberOfUnreadThreads:       numOfUnreadThreads,
		MessagingGroups:             messagingGroups,
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetMessages: Problem serializing object to JSON: %v", err))
		return
	}
}

// SendMessageStatelessRequest ...
type SendMessageStatelessRequest struct {
	// SenderPublicKeyBase58Check is the public key in base58check of the message sender.
	SenderPublicKeyBase58Check string `safeForLogging:"true"`

	// RecipientPublicKeyBase58Check is the public key in base58check of the messaging recipient.
	RecipientPublicKeyBase58Check string `safeForLogging:"true"`

	MessageText string // Deprecated

	// EncryptedMessageText is the intended message content. It is recommended to pass actual encrypted message here,
	// although unencrypted message can be passed as well.
	EncryptedMessageText string

	MinFeeRateNanosPerKB uint64 `safeForLogging:"true"`
	// No need to specify ProfileEntryResponse in each TransactionFee
	TransactionFees []TransactionFee `safeForLogging:"true"`

	// ---------------------------------------------------------
	// DeSo V3 Messages Fields
	// ---------------------------------------------------------

	// SenderMessagingGroupKeyName is the messaging group key name of the sender. If left empty, this endpoint
	// will replace it with the base messaging key. If both SenderMessagingGroupKeyName and
	// RecipientMessagingGroupKeyName are left empty, a V2 message will be constructed.
	SenderMessagingGroupKeyName string `safeForLogging:"true"`

	// RecipientMessagingGroupKeyName is the messaging group key name of the recipient. If left empty, this endpoint
	// will replace it with the base messaging key. If both SenderMessagingGroupKeyName and
	// RecipientMessagingGroupKeyName are left empty, a V2 message will be constructed.
	RecipientMessagingGroupKeyName string `safeForLogging:"true"`

	// ExtraData is an arbitrary key value map
	ExtraData map[string]string
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

	// Parse sender public key to lib.PublicKey
	senderPublicKey := lib.NewPublicKey(senderPkBytes)

	// If recipient messaging group key name is passed, we will validate it. Otherwise, just validate sender public key.
	// We will treat empty group messaging keys as lib.BaseGroupKeyName(), which is an empty string key name.
	senderMessagingGroupKeyNameBytes := []byte(requestData.SenderMessagingGroupKeyName)
	if len(requestData.SenderMessagingGroupKeyName) > 0 {
		if err = lib.ValidateGroupPublicKeyAndName(senderPkBytes, senderMessagingGroupKeyNameBytes); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SendMessageStateless: Problem validating sender "+
				"public key and group messaging key name %s: %v", requestData.SenderMessagingGroupKeyName, err))
			return
		}
	} else {
		if err = lib.IsByteArrayValidPublicKey(senderPkBytes); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SendMessageStateless: Problem validating sender "+
				"public key %s: %v", senderPkBytes, err))
			return
		}
	}

	// Decode the recipient's public key.
	recipientPkBytes, _, err := lib.Base58CheckDecode(requestData.RecipientPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendMessageStateless: Problem decoding recipient "+
			"base58 public key %s: %v", requestData.RecipientPublicKeyBase58Check, err))
		return
	}

	// Parse recipient public key to lib.PublicKey
	recipientPublicKey := lib.NewPublicKey(recipientPkBytes)

	// If recipient messaging group key name is passed, we will validate it. Otherwise, just validate sender public key.
	// We will treat empty group messaging keys as lib.BaseGroupKeyName(), which is an empty string key name.
	recipientMessagingGroupKeyNameBytes := []byte(requestData.RecipientMessagingGroupKeyName)
	if len(requestData.RecipientMessagingGroupKeyName) > 0 {
		if err = lib.ValidateGroupPublicKeyAndName(recipientPkBytes, recipientMessagingGroupKeyNameBytes); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SendMessageStateless: Problem validating recipient "+
				"public key and group messaging key name %s: %v", requestData.RecipientMessagingGroupKeyName, err))
			return
		}
	} else {
		if err = lib.IsByteArrayValidPublicKey(recipientPkBytes); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SendMessageStateless: Problem validating recipient "+
				"public key %s: %v", senderPkBytes, err))
			return
		}
	}

	// Validate sender and recipient group messaging keys with UtxoView.
	checkPartyMessagingKeysResponse, err := fes.CreateCheckPartyMessagingKeysResponse(senderPublicKey, lib.NewGroupKeyName(senderMessagingGroupKeyNameBytes),
		recipientPublicKey, lib.NewGroupKeyName(recipientMessagingGroupKeyNameBytes))
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendMessageStateless: Problem checking party keys sender (public key: %v, key name: %v), recipient "+
			"(public key: %v, key name: %v), error: %v", senderPublicKey, lib.NewGroupKeyName(senderMessagingGroupKeyNameBytes),
			recipientPkBytes, lib.NewGroupKeyName(recipientMessagingGroupKeyNameBytes), err))
		return
	}

	// Error if sender group messaging key doesn't exist, because we can't send the intended message.
	if !checkPartyMessagingKeysResponse.IsSenderMessagingKey {
		_AddBadRequestError(ww, fmt.Sprintf("SendMessageStateless: Problem checking party keys; sender messaging key doesn't exist "+
			"(public key: %v, key name: %v)", senderPublicKey, lib.NewGroupKeyName(senderMessagingGroupKeyNameBytes)))
		return
	}

	// Error if recipient group messaging key doesn't exist, because we can't send the intended message.
	if !checkPartyMessagingKeysResponse.IsRecipientMessagingKey {
		_AddBadRequestError(ww, fmt.Sprintf("SendMessageStateless: Problem checking party keys recipient messaging key doesn't exist "+
			"(public key: %v, key name: %v)", recipientPkBytes, lib.NewGroupKeyName(recipientMessagingGroupKeyNameBytes)))
		return
	}

	// Get messaging public key for the sender. If sender group key name is empty, that means we're intending to send
	// a V2 message, so we'll leave the messaging public key empty.
	senderMessagingPublicKey := []byte{}
	if len(requestData.SenderMessagingGroupKeyName) > 0 {
		senderMessagingPublicKey, _, err = lib.Base58CheckDecode(checkPartyMessagingKeysResponse.SenderMessagingPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SendMessageStateless: Problem decoding sender messaging public key "+
				"(public key: %v, key name: %v)", checkPartyMessagingKeysResponse.SenderMessagingPublicKeyBase58Check,
				senderMessagingGroupKeyNameBytes))
			return
		}
	}

	// Get messaging public key for the recipient. If recipient group key name is empty, that means we're intending to
	// send a V2 message, so we'll leave the messaging public key empty.
	recipientMessagingPublicKey := []byte{}
	if len(requestData.RecipientMessagingGroupKeyName) > 0 {
		recipientMessagingPublicKey, _, err = lib.Base58CheckDecode(checkPartyMessagingKeysResponse.RecipientMessagingPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SendMessageStateless: Problem decoding recipient messaging public key "+
				"(public key: %v, key name: %v)", checkPartyMessagingKeysResponse.RecipientMessagingPublicKeyBase58Check,
				recipientMessagingGroupKeyNameBytes))
			return
		}
	}

	// Compute the additional transaction fees as specified by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(lib.TxnTypePrivateMessage, senderPkBytes, requestData.TransactionFees)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendMessageStateless: TransactionFees specified in Request body are invalid: %v", err))
		return
	}

	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendMessageStateless: Problem encoding ExtraData: %v", err))
		return
	}

	// Try and create the message for the user.
	tstamp := uint64(time.Now().UnixNano())
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreatePrivateMessageTxn(
		senderPkBytes, recipientPkBytes,
		requestData.MessageText, requestData.EncryptedMessageText,
		senderMessagingPublicKey, senderMessagingGroupKeyNameBytes,
		recipientMessagingPublicKey, recipientMessagingGroupKeyNameBytes,
		tstamp, extraData,
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

// RegisterMessagingGroupKeyRequest ...
type RegisterMessagingGroupKeyRequest struct {
	// OwnerPublicKeyBase58Check is the public key in base58check of the account we want to register the messaging key for.
	OwnerPublicKeyBase58Check string

	// MessagingPublicKeyBase58Check is the public key in base58check of the messaging group we want to register.
	MessagingPublicKeyBase58Check string

	// MessagingGroupKeyName is the name of the group key.
	MessagingGroupKeyName string

	// MessagingKeySignatureHex is the signature of sha256x2(MessagingPublicKey + MessagingGroupKeyName). Currently,
	// the signature is only needed to register the default key.
	MessagingKeySignatureHex string

	// ExtraData is an arbitrary key value map
	ExtraData map[string]string

	MinFeeRateNanosPerKB uint64 `safeForLogging:"true"`

	// No need to specify ProfileEntryResponse in each TransactionFee
	TransactionFees []TransactionFee `safeForLogging:"true"`
}

// RegisterMessagingGroupKeyResponse ...
type RegisterMessagingGroupKeyResponse struct {
	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgDeSoTxn
	TransactionHex    string
	TxnHashHex        string
}

// RegisterMessagingGroupKey ...
func (fes *APIServer) RegisterMessagingGroupKey(ww http.ResponseWriter, req *http.Request) {

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := RegisterMessagingGroupKeyRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("RegisterMessagingGroupKey: Problem parsing request body: %v", err))
		return
	}

	// Decode the owner public key.
	ownerPkBytes, _, err := lib.Base58CheckDecode(requestData.OwnerPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("RegisterMessagingGroupKey: Problem decoding sender "+
			"base58 public key %s: %v", requestData.OwnerPublicKeyBase58Check, err))
		return
	}

	// Decode the group messaging public key
	messagingPkBytes, _, err := lib.Base58CheckDecode(requestData.MessagingPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("RegisterMessagingGroupKey: Problem decoding messaging "+
			"base58 public key %s: %v", requestData.MessagingPublicKeyBase58Check, err))
		return
	}
	// Parse the messaging group key name from string to bytes
	messagingKeyNameBytes := []byte(requestData.MessagingGroupKeyName)

	// Validate that the group messaging public key and key name have the correct format.
	err = lib.ValidateGroupPublicKeyAndName(messagingPkBytes, messagingKeyNameBytes)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("RegisterMessagingGroupKey: Problem validating messaging public key and name %v", err))
		return
	}

	// Decode the messaging key signature.
	messagingKeySignature, _ := hex.DecodeString(requestData.MessagingKeySignatureHex)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("RegisterMessagingGroupKey: Problem decoding messaging public key signature %v", err))
		return
	}

	// If the messaging key name is the default key name, then we will sanity-check that the signature is valid.
	if lib.EqualGroupKeyName(lib.DefaultGroupKeyName(), lib.NewGroupKeyName(messagingKeyNameBytes)) {
		msgBytes := append(messagingPkBytes, messagingKeyNameBytes...)
		if err := VerifyBytesSignature(ownerPkBytes, msgBytes, messagingKeySignature); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("RegisterMessagingGroupKey: Problem verifying transaction signature: %v", err))
			return
		}
	}

	// Compute the additional transaction fees as specified by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(lib.TxnTypeMessagingGroup, ownerPkBytes, requestData.TransactionFees)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("RegisterMessagingGroupKey: TransactionFees specified in Request body are invalid: %v", err))
		return
	}

	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("RegisterMessagingGroupKey: Problem encoding ExtraData: %v", err))
		return
	}

	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateMessagingKeyTxn(
		ownerPkBytes, messagingPkBytes, messagingKeyNameBytes, messagingKeySignature,
		[]*lib.MessagingGroupMember{}, extraData,
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool(), additionalOutputs)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("RegisterMessagingGroupKey: Problem creating transaction: %v", err))
		return
	}

	// Add node source to txn metadata
	fes.AddNodeSourceToTxnMetadata(txn)

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("RegisterMessagingGroupKey: Problem serializing transaction: %v", err))
		return
	}

	// Assemble and encode the response.
	res := RegisterMessagingGroupKeyResponse{
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
		TxnHashHex:        txn.Hash().String(),
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("RegisterMessagingGroupKey: Problem encoding response as JSON: %v", err))
		return
	}
}

// VerifyBytesSignature checks if signatureBytes is a correct DER signature of data made by signerPk.
func VerifyBytesSignature(signerPk, data, signatureBytes []byte) error {
	bytes := lib.Sha256DoubleHash(data)

	// Convert signatureBytes to *btcec.Signature.
	sign, err := btcec.ParseDERSignature(signatureBytes, btcec.S256())
	if err != nil {
		return errors.Wrapf(err, "VerifyBytesSignature: Problem parsing access signatureBytes: ")
	}

	// Parse signer public key
	ownerPk, err := btcec.ParsePubKey(signerPk, btcec.S256())
	if err != nil {
		return errors.Wrapf(err, "VerifyBytesSignature: Problem parsing signer public key: ")
	}

	// Verify signature.
	if !sign.Verify(bytes[:], ownerPk) {
		return fmt.Errorf("VerifyBytesSignature: Invalid signature")
	}
	return nil
}

// GetAllMessagingGroupKeysRequest ...
type GetAllMessagingGroupKeysRequest struct {
	// OwnerPublicKeyBase58Check is the public key in base58check of the account whose group messaging keys we want to fetch.
	OwnerPublicKeyBase58Check string
}

// GetAllMessagingGroupKeysResponse ...
type GetAllMessagingGroupKeysResponse struct {
	// MessagingGroupEntries is the list of all user's group messaging keys.
	MessagingGroupEntries []*MessagingGroupEntryResponse
}

// GetAllMessagingGroupKeys ...
func (fes *APIServer) GetAllMessagingGroupKeys(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetAllMessagingGroupKeysRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllMessagingGroupKeys: Problem parsing request body: %v", err))
		return
	}

	// Decode the owner public key.
	ownerPkBytes, _, err := lib.Base58CheckDecode(requestData.OwnerPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllMessagingGroupKeys: Problem decoding sender "+
			"base58 public key %s: %v", requestData.OwnerPublicKeyBase58Check, err))
		return
	}

	// Get the augmented UtxoView so that we can fetch user's messaging keys.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUtxoViewForPublicKey(ownerPkBytes, nil)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllMessagingGroupKeys: Error calling "+
			"GetAugmentedUtxoViewForPublicKey: %s: %v", requestData.OwnerPublicKeyBase58Check, err))
		return
	}

	// First get all messaging keys for a user.
	messagingGroupEntries, err := utxoView.GetMessagingGroupEntriesForUser(ownerPkBytes)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllMessagingGroupKeys: Error calling "+
			"GetAugmentedUtxoViewForPublicKey: %s: %v", requestData.OwnerPublicKeyBase58Check, err))
	}

	// Now parse messaging group entries from []*lib.MessagingGroupEntry to []*MessagingGroupEntryResponse.
	// Assemble and encode the response.
	res := GetAllMessagingGroupKeysResponse{
		MessagingGroupEntries: fes.ParseMessagingGroupEntries(utxoView, ownerPkBytes, messagingGroupEntries),
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllMessagingGroupKeys: Problem serializing object to JSON: %v", err))
		return
	}
}

// CheckPartyMessagingKeysRequest ...
type CheckPartyMessagingKeysRequest struct {
	// SenderPublicKeyBase58Check is the main public key of the sender in base58check format.
	SenderPublicKeyBase58Check string

	// SenderMessagingKeyName is the sender's key name the existence of which we want to verify.
	SenderMessagingKeyName string

	// RecipientPublicKeyBase58Check is the public key of the recipient in base58check format.
	RecipientPublicKeyBase58Check string

	// RecipientMessagingKeyName is the recipient's key name the existence of we want to verify.
	RecipientMessagingKeyName string
}

// CheckPartyMessagingKeysResponse ...
type CheckPartyMessagingKeysResponse struct {
	// SenderMessagingPublicKeyBase58Check is the group messaging public key of the sender corresponding to the provided
	// SenderMessagingKeyName. This field will be an empty string if the key name doesn't exist.
	SenderMessagingPublicKeyBase58Check string

	// SenderMessagingKeyName is the key name that was passed in the initial request. It's added to the response for
	// convenience.
	SenderMessagingKeyName string

	// IsSenderMessagingKey determines if the SenderMessagingKeyName existed for the sender.
	IsSenderMessagingKey bool

	// RecipientMessagingPublicKeyBase58Check is the group messaging public key of the recipient corresponding to the provided
	// RecipientMessagingKeyName. This field will be an empty string if the key name doesn't exist.
	RecipientMessagingPublicKeyBase58Check string

	// RecipientMessagingKeyName is the key name that was passed in the initial request. It's added to the response for
	// convenience.
	RecipientMessagingKeyName string

	// IsRecipientMessagingKey determines if the RecipientMessagingKeyName existed for the sender.
	IsRecipientMessagingKey bool
}

func (fes *APIServer) CreateCheckPartyMessagingKeysResponse(senderPublicKey *lib.PublicKey, senderMessagingKeyName *lib.GroupKeyName,
	recipientPublicKey *lib.PublicKey, recipientMessagingKeyName *lib.GroupKeyName) (
	*CheckPartyMessagingKeysResponse, error) {

	// This function is used to verify group messaging keys for a pair of users which we call a sender and a recipient
	// for convenience. We use this function for sanity-checks when sending private messages and in the
	// CheckPartyMessagingKeys endpoint.

	// Create an initial CheckPartyMessagingResponse entry.
	response := &CheckPartyMessagingKeysResponse{
		SenderMessagingPublicKeyBase58Check:    lib.Base58CheckEncode(senderPublicKey[:], false, fes.Params),
		IsSenderMessagingKey:                   false,
		SenderMessagingKeyName:                 "",
		RecipientMessagingPublicKeyBase58Check: lib.Base58CheckEncode(recipientPublicKey[:], false, fes.Params),
		IsRecipientMessagingKey:                false,
		RecipientMessagingKeyName:              "",
	}

	// Get the augmented UtxoView.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return nil, err
	}

	// Check if the messaging group key exists for the sender. First create a group key for the UtxoView mapping and
	// fetch the group entry from it. Add it to the response if the key exists.
	messagingKey := lib.NewMessagingGroupKey(senderPublicKey, senderMessagingKeyName[:])
	messagingEntry := utxoView.GetMessagingGroupKeyToMessagingGroupEntryMapping(messagingKey)
	if messagingEntry != nil || messagingEntry.IsDeleted() {
		response.SenderMessagingPublicKeyBase58Check = lib.Base58CheckEncode(messagingEntry.MessagingPublicKey[:], false, fes.Params)
		response.IsSenderMessagingKey = true
		response.SenderMessagingKeyName = string(lib.MessagingKeyNameDecode(senderMessagingKeyName))
	}

	// Check if the messaging group key exists for the recipient. First create a group key for the UtxoView mapping and
	// fetch the group entry from it. Add it to the response if the key exists.
	messagingKey = lib.NewMessagingGroupKey(recipientPublicKey, recipientMessagingKeyName[:])
	messagingEntry = utxoView.GetMessagingGroupKeyToMessagingGroupEntryMapping(messagingKey)
	if messagingEntry != nil || messagingEntry.IsDeleted() {
		response.RecipientMessagingPublicKeyBase58Check = lib.Base58CheckEncode(messagingEntry.MessagingPublicKey[:], false, fes.Params)
		response.IsRecipientMessagingKey = true
		response.RecipientMessagingKeyName = string(lib.MessagingKeyNameDecode(recipientMessagingKeyName))
	}

	return response, nil
}

// CheckPartyMessagingKeys ...
func (fes *APIServer) CheckPartyMessagingKeys(ww http.ResponseWriter, req *http.Request) {

	// Decode the request.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := CheckPartyMessagingKeysRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CheckPartyMessagingKeys: Problem parsing request body: %v", err))
		return
	}

	// Decode the sender public key.
	senderPublicKey, _, err := lib.Base58CheckDecode(requestData.SenderPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CheckPartyMessagingKeys: Problem decoding sender public key: %v", err))
		return
	}
	// Parse the sender's messaging key name from string to a byte array.
	senderKeyName := lib.NewGroupKeyName([]byte(requestData.SenderMessagingKeyName))
	// Validate that the sender's public key and key name have the correct format.
	if err = lib.ValidateGroupPublicKeyAndName(senderPublicKey, senderKeyName[:]); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CheckPartyMessagingKeys: Problem validating sender public key and key name: %v", err))
		return
	}

	// Decode the recipient public key.
	recipientPublicKey, _, err := lib.Base58CheckDecode(requestData.RecipientPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CheckPartyMessagingKeys: Problem decoding recipient public key: %v", err))
		return
	}
	// Parse the recipient's messaging key name from string to a byte array.
	recipientKeyName := lib.NewGroupKeyName([]byte(requestData.RecipientMessagingKeyName))
	// Validate that the recipient's public key and key name have the correct format.
	if err = lib.ValidateGroupPublicKeyAndName(recipientPublicKey, recipientKeyName[:]); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CheckPartyMessagingKeys: Problem validating recipient public key and key name: %v", err))
		return
	}

	// Verify whether sender's and recipient's  public keys and key names are registered on the blockchain.
	response, err := fes.CreateCheckPartyMessagingKeysResponse(lib.NewPublicKey(senderPublicKey), senderKeyName,
		lib.NewPublicKey(recipientPublicKey), recipientKeyName)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CheckPartyMessagingKeys: Problem creating party messaging key response: %v", err))
		return
	}

	// Encode the response.
	if err := json.NewEncoder(ww).Encode(response); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CheckPartyMessagingKeys: Problem encoding response as JSON: %v", err))
		return
	}
}

// GetBulkMessagingPublicKeysRequest ...
type GetBulkMessagingPublicKeysRequest struct {
	// GroupOwnerPublicKeysBase58Check is a list of public keys of the group owners.
	GroupOwnerPublicKeysBase58Check []string `safeForLogging:"true"`
	// MessagingGroupKeyNames is a list of messaging key names in hex.
	MessagingGroupKeyNames []string `safeForLogging:"true"`
}

// GetBulkMessagingPublicKeysResponse ...
type GetBulkMessagingPublicKeysResponse struct {
	// MessagingPublicKeysBase58Check is a list of messaging public keys in base58check of the corresponding groups
	// identified by the <GroupOwnerPublicKeysBase58Check, MessagingGroupKeyNames> pairs.
	MessagingPublicKeysBase58Check []string `safeForLogging:"true"`
}

// GetBulkMessagingPublicKeys endpoint will check if the messaging group keys exist for the given messaging groups
// identified by <GroupOwnerPublicKeysBase58Check, MessagingGroupKeyNames>. If all the groups exist, it will return
// the messaging public keys of the groups.
func (fes *APIServer) GetBulkMessagingPublicKeys(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetBulkMessagingPublicKeysRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetBulkMessagingPublicKeys: Problem parsing request body: %v", err))
		return
	}

	if len(requestData.GroupOwnerPublicKeysBase58Check) != len(requestData.MessagingGroupKeyNames) {
		_AddBadRequestError(ww, fmt.Sprintf("GetBulkMessagingPublicKeys: GroupOwnerPublicKeysBase58Check and MessagingGroupKeyNames must be the same length"))
		return
	}

	// Decode the group owner public keys.
	groupOwnerPublicKeys := []*lib.PublicKey{}
	for _, groupOwnerPublicKeyBase58Check := range requestData.GroupOwnerPublicKeysBase58Check {
		groupOwnerPublicKeyBytes, _, err := lib.Base58CheckDecode(groupOwnerPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetBulkMessagingPublicKeys: Problem decoding group owner public key: %v", err))
			return
		}
		groupOwnerPublicKey := lib.NewPublicKey(groupOwnerPublicKeyBytes)
		groupOwnerPublicKeys = append(groupOwnerPublicKeys, groupOwnerPublicKey)
	}

	// Decode the messaging group key names.
	messagingGroupKeyNames := []*lib.GroupKeyName{}
	for _, messagingGroupKeyNameString := range requestData.MessagingGroupKeyNames {
		messagingGroupKeyName := lib.NewGroupKeyName([]byte(messagingGroupKeyNameString))
		messagingGroupKeyNames = append(messagingGroupKeyNames, messagingGroupKeyName)
	}

	// Check if the group owner public keys and messaging group key names are registered, if so fetch their messaging public keys.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetBulkMessagingPublicKeys: Problem fetching utxoView: %v", err))
		return
	}

	messagingPublicKeys := []*lib.PublicKey{}
	for ii, groupOwnerPublicKey := range groupOwnerPublicKeys {
		messagingGroupKey := lib.NewMessagingGroupKey(groupOwnerPublicKey, messagingGroupKeyNames[ii].ToBytes())
		messagingGroupEntry := utxoView.GetMessagingGroupKeyToMessagingGroupEntryMapping(messagingGroupKey)
		if messagingGroupEntry == nil || messagingGroupEntry.IsDeleted() {
			_AddBadRequestError(ww, fmt.Sprintf("GetBulkMessagingPublicKeys: Messaging group key not found for "+
				"public key %v and key name %v: %v", requestData.GroupOwnerPublicKeysBase58Check[ii],
				requestData.MessagingGroupKeyNames[ii], err))
			return
		}
		if messagingGroupEntry.MessagingPublicKey == nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetBulkMessagingPublicKeys: Messaging public key is nil for "+
				"public key %v and key name %v. This member can't be added: %v", requestData.GroupOwnerPublicKeysBase58Check[ii],
				requestData.MessagingGroupKeyNames[ii], err))
			return
		}
		messagingPublicKeys = append(messagingPublicKeys, messagingGroupEntry.MessagingPublicKey)
	}

	// Encode the response.
	messagingPublicKeysString := []string{}
	for _, messagingPublicKey := range messagingPublicKeys {
		messagingPublicKeysString = append(messagingPublicKeysString, lib.PkToString(messagingPublicKey.ToBytes(), fes.Params))
	}
	response := GetBulkMessagingPublicKeysResponse{
		MessagingPublicKeysBase58Check: messagingPublicKeysString,
	}
	if err := json.NewEncoder(ww).Encode(response); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetBulkMessagingPublicKeys: Problem encoding response as JSON: %v", err))
		return
	}
}
