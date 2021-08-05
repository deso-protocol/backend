package routes

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/bitclout/core/lib"
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
	// it support time, clout, and followers based sorting.
	SortAlgorithm string `safeForLogging:"true"`
}

// GetMessagesResponse ...
type GetMessagesResponse struct {
	PublicKeyToProfileEntry     map[string]*ProfileEntryResponse
	OrderedContactsWithMessages []*MessageContactResponse
	UnreadStateByContact        map[string]bool
	NumberOfUnreadThreads       int
}

func (fes *APIServer) getMessagesStateless(publicKeyBytes []byte,
	fetchAfterPublicKeyBytes []byte, numToFetch uint64, holdersOnly bool,
	holdingsOnly bool, followersOnly bool, followingOnly bool, sortAlgorithm string) (
	_publicKeyToProfileEntry map[string]*ProfileEntryResponse,
	_orderedContactsWithMessages []*MessageContactResponse,
	_unreadMessagesByContact map[string]bool,
	_numOfUnreadThreads int, _err error) {

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUtxoViewForPublicKey(publicKeyBytes, nil)
	if err != nil {
		return nil, nil, nil, 0, errors.Wrapf(
			err, "getMessagesStateless: Error calling GetAugmentedUtxoViewForPublicKey: %v", err)
	}

	// Grab verified username map pointer
	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
	if err != nil {
		return nil, nil, nil, 0, errors.Wrapf(
			err, "getMessagesStateless: Error fetching verifiedMap: %v", err)
	}

	// Go through all the MessageEntries and create a MessageEntryResponse for each one.
	// Sort the MessageEntries by their timestamp.
	//
	// TODO: The timestamp is spoofable, but it's not a big deal. See comment on MessageEntry
	// for more insight on this.
	messageEntries, err := utxoView.GetLimitedMessagesForUser(publicKeyBytes)
	if err != nil {
		return nil, nil, nil, 0, errors.Wrapf(
			err, "getMessagesStateless: Problem fetching MessageEntries from augmented UtxoView: ")
	}

	// We sort the messages to be sure they're in the correct order for filtering out selected threads.
	// There could be a faster way to do this, but it preserves pagination properly.
	publicKeyToClout := make(map[string]uint64)
	publicKeyToNumberOfFollowers := make(map[string]uint64)
	publicKeyToNanosUserHeld := make(map[string]uint64)
	if sortAlgorithm == "clout" {
		for _, messageEntry := range messageEntries {
			otherPartyPublicKeyBytes, otherPartyPublicKeyBase58Check := fes.getOtherPartyInThread(messageEntry, publicKeyBytes)

			if _, alreadySeen := publicKeyToClout[otherPartyPublicKeyBase58Check]; !alreadySeen {
				otherPartyProfileEntry := utxoView.GetProfileEntryForPublicKey(otherPartyPublicKeyBytes)
				if otherPartyProfileEntry != nil {
					publicKeyToClout[otherPartyPublicKeyBase58Check] = otherPartyProfileEntry.BitCloutLockedNanos
				} else {
					publicKeyToClout[otherPartyPublicKeyBase58Check] = 0
				}
			}
		}

		sort.Slice(messageEntries, func(ii, jj int) bool {
			_, otherPartyPublicKeyiiBase58Check := fes.getOtherPartyInThread(messageEntries[ii], publicKeyBytes)
			_, otherPartyPublicKeyjjBase58Check := fes.getOtherPartyInThread(messageEntries[jj], publicKeyBytes)
			return publicKeyToClout[otherPartyPublicKeyiiBase58Check] > publicKeyToClout[otherPartyPublicKeyjjBase58Check]
		})
	} else if sortAlgorithm == "followers" {
		for _, messageEntry := range messageEntries {
			otherPartyPublicKeyBytes, otherPartyPublicKeyBase58Check := fes.getOtherPartyInThread(messageEntry, publicKeyBytes)

			if _, alreadySeen := publicKeyToNumberOfFollowers[otherPartyPublicKeyBase58Check]; !alreadySeen {
				// TODO: Make an index to quickly lookup how many followers a user has
				otherPartyFollowers, err := lib.DbGetPKIDsFollowingYou(utxoView.Handle, lib.PublicKeyToPKID(otherPartyPublicKeyBytes))
				if err != nil {
					return nil, nil, nil, 0, errors.Wrapf(
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
				otherPartyBalanceEntry, err := lib.GetSingleBalanceEntryFromPublicKeys(otherPartyPublicKeyBytes, publicKeyBytes, utxoView)
				if err != nil {
					return nil, nil, nil, 0, errors.Wrapf(
						err, "getMessagesStateless: Problem getting balance entry for public key")
				}
				if otherPartyBalanceEntry != nil {
					publicKeyToNanosUserHeld[otherPartyPublicKeyBase58Check] = otherPartyBalanceEntry.BalanceNanos
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
		return nil, nil, nil, 0, errors.Wrapf(
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
					balanceEntry, err := lib.GetSingleBalanceEntryFromPublicKeys(otherPartyPublicKeyBytes, publicKeyBytes, utxoView)
					if err != nil {
						return nil, nil, nil, 0, errors.Wrapf(
							err, "getMessagesStateless: Problem getting balance entry for holder public key %v", otherPartyPublicKeyBase58Check)
					}
					holdsUser = balanceEntry != nil && balanceEntry.BalanceNanos > 0
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
					balanceEntry, err := lib.GetSingleBalanceEntryFromPublicKeys(publicKeyBytes, otherPartyPublicKeyBytes, utxoView)
					if err != nil {
						return nil, nil, nil, 0, errors.Wrapf(
							err, "getMessagesStateless: Problem getting balance entry for holder public key %v", otherPartyPublicKeyBase58Check)
					}
					holdsPublicKey = balanceEntry != nil && balanceEntry.BalanceNanos > 0
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
				otherProfileEntry := _profileEntryToResponse(utxoView.GetProfileEntryForPublicKey(otherPartyPublicKeyBytes), fes.Params, verifiedMap, utxoView)
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

		V2 := false
		if messageEntry.Version == 2 {
			V2 = true
		}

		// By now we know this messageEntry is meant to be included in the response.
		messageEntryRes := &MessageEntryResponse{
			SenderPublicKeyBase58Check:    lib.PkToString(messageEntry.SenderPublicKey, fes.Params),
			RecipientPublicKeyBase58Check: lib.PkToString(messageEntry.RecipientPublicKey, fes.Params),
			EncryptedText:                 hex.EncodeToString(messageEntry.EncryptedText),
			TstampNanos:                   messageEntry.TstampNanos,
			IsSender:                      !reflect.DeepEqual(messageEntry.RecipientPublicKey, publicKeyBytes),
			V2:                            V2,
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
	if sortAlgorithm == "clout" {
		sort.Slice(newContactEntries, func(ii, jj int) bool {
			return publicKeyToClout[newContactEntries[ii].PublicKeyBase58Check] >
				publicKeyToClout[newContactEntries[jj].PublicKeyBase58Check]
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
			return nil, nil, nil, 0, errors.Wrapf(err, "getMessagesStateless: Problem decoding "+
				"contact's public key.")
		}

		mostRecentReadTstampNanos, err := fes.getUserContactMostRecentReadTime(publicKeyBytes, otherUserPublicKeyBytes)
		if err != nil {
			return nil, nil, nil, 0, errors.Wrapf(err, "getMessagesStateless: Problem getting "+
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

	return publicKeyToProfileEntry, newContactEntries, unreadMessagesBycontact, numOfUnreadThreads, nil
}

func (fes *APIServer) getOtherPartyInThread(messageEntry *lib.MessageEntry,
	readerPublicKeyBytes []byte) (otherPartyPublicKeyBytes []byte, otherPartyPublicKeyBase58Check string) {
	if reflect.DeepEqual(messageEntry.RecipientPublicKey, readerPublicKeyBytes) {
		otherPartyPublicKeyBytes = messageEntry.SenderPublicKey
	} else {
		otherPartyPublicKeyBytes = messageEntry.RecipientPublicKey
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
		unreadStateByContact, numOfUnreadThreads, err := fes.getMessagesStateless(publicKeyBytes, fetchAfterPublicKeyBytes,
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
	MinFeeRateNanosPerKB          uint64 `safeForLogging:"true"`
}

// SendMessageStatelessResponse ...
type SendMessageStatelessResponse struct {
	TstampNanos uint64

	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgBitCloutTxn
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

	// Decode the recipient's public key.
	recipientPkBytes, _, err := lib.Base58CheckDecode(requestData.RecipientPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendMessageStateless: Problem decoding recipient "+
			"base58 public key %s: %v", requestData.RecipientPublicKeyBase58Check, err))
		return
	}

	// Try and create the message for the user.
	tstamp := uint64(time.Now().UnixNano())
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreatePrivateMessageTxn(
		senderPkBytes, recipientPkBytes,
		requestData.MessageText, requestData.EncryptedMessageText,
		tstamp,
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool())
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendMessageStateless: Problem creating transaction: %v", err))
		return
	}

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendBitClout: Problem serializing transaction: %v", err))
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

	messageEntries, err := utxoView.GetMessagesForUser(publicKeyBytes)
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

	err := fes.GlobalStatePut(dbKey, tStampNanosBytes)
	if err != nil {
		return errors.Wrap(fmt.Errorf(
			"putUserContactMostRecentReadTime: Problem putting updated tStampNanosBytes: %v", err), "")
	}

	return nil
}

// getUserContactMostRecentReadTime...
func (fes *APIServer) getUserContactMostRecentReadTime(userPublicKeyBytes []byte, contactPublicKeyBytes []byte) (uint64, error) {
	dbKey := GlobalStateKeyForUserPkContactPkToMostRecentReadTstampNanos(userPublicKeyBytes, contactPublicKeyBytes)
	tStampNanosBytes, err := fes.GlobalStateGet(dbKey)
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
