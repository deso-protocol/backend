package routes

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/deso-protocol/core/lib"

	"github.com/dgraph-io/badger/v3"
	"github.com/nyaruka/phonenumbers"
	"github.com/pkg/errors"
)

const (
	GlobalStateSharedSecretParam = "shared_secret"

	RoutePathGlobalStatePutRemote      = "/api/v1/global-state/put"
	RoutePathGlobalStateGetRemote      = "/api/v1/global-state/get"
	RoutePathGlobalStateBatchGetRemote = "/api/v1/global-state/batch-get"
	RoutePathGlobalStateDeleteRemote   = "/api/v1/global-state/delete"
	RoutePathGlobalStateSeekRemote     = "/api/v1/global-state/seek"
)

// GlobalStateRoutes returns the routes for managing global state.
// Note that these routes are generally protected by a shared_secret
func (fes *APIServer) GlobalStateRoutes() []Route {
	var GlobalStateRoutes = []Route{
		{
			"GlobalStatePutRemote",
			[]string{"POST", "OPTIONS"},
			RoutePathGlobalStatePutRemote,
			fes.GlobalStatePutRemote,
			AdminAccess, // CheckSecret
		},
		{
			"GlobalStateGetRemote",
			[]string{"POST", "OPTIONS"},
			RoutePathGlobalStateGetRemote,
			fes.GlobalStateGetRemote,
			AdminAccess, // CheckSecret
		},
		{
			"GlobalStateBatchGetRemote",
			[]string{"POST", "OPTIONS"},
			RoutePathGlobalStateBatchGetRemote,
			fes.GlobalStateBatchGetRemote,
			AdminAccess, // CheckSecret
		},
		{
			"GlobalStateDeleteRemote",
			[]string{"POST", "OPTIONS"},
			RoutePathGlobalStateDeleteRemote,
			fes.GlobalStateDeleteRemote,
			AdminAccess, // CheckSecret
		},
		{
			"GlobalStateSeekRemote",
			[]string{"POST", "OPTIONS"},
			RoutePathGlobalStateSeekRemote,
			fes.GlobalStateSeekRemote,
			AdminAccess, // CheckSecret
		},
	}

	return GlobalStateRoutes
}

var (
	// The key prefixes for the  global state key-value database.

	// The prefix for accessing a user's metadata (e.g. email, blacklist status, etc.):
	// <prefix,  ProfilePubKey [33]byte> -> <UserMetadata>
	_GlobalStatePrefixPublicKeyToUserMetadata = []byte{0}

	// The prefix for accessing whitelisted posts for the global feed:
	// Unlike in db_utils here, we use a single byte as a value placeholder.  This is a
	// result of the way global state handles when a key is not present.
	// <prefix, tstampNanos uint64, PostHash> -> <[]byte{1}>
	_GlobalStatePrefixTstampNanosPostHash = []byte{1}

	// The prefix for accessing a phone number's metadata
	// <prefix,  PhoneNumber [variableLength]byte> -> <PhoneNumberMetadata>
	_GlobalStatePrefixPhoneNumberToPhoneNumberMetadata = []byte{2}

	// The prefix for accessing the verified users map.
	// The resulting map takes a username and returns a PKID.
	// <prefix> -> <map[string]*PKID>
	_GlobalStatePrefixForVerifiedMap = []byte{3}

	// The prefix for accessing the pinned posts on the global feed:
	// <prefix, tstampNanos uint64, PostHash> -> <[]byte{4}>
	_GlobalStatePrefixTstampNanosPinnedPostHash = []byte{4}

	// The prefix for accessing the audit log of verification badges
	// <prefix, username string> -> <VerificationAuditLog>
	_GlobalStatePrefixUsernameVerificationAuditLog = []byte{5}

	// The prefix for accessing the graylisted users.
	// <prefix, public key> -> <IsGraylisted>
	_GlobalStatePrefixPublicKeyToGraylistState = []byte{6}

	// The prefix for accesing the blacklisted users.
	// <prefix, public key> -> <IsBlacklisted>
	_GlobalStatePrefixPublicKeyToBlacklistState = []byte{7}

	// The prefix for checking the most recent read time stamp for a user reading
	// a contact's private message.
	// <prefix, user public key, contact's public key> -> <tStampNanos>
	_GlobalStatePrefixUserPublicKeyContactPublicKeyToMostRecentReadTstampNanos = []byte{8}

	// The prefix for checking the state of a user's wyre order.
	_GlobalStatePrefixUserPublicKeyWyreOrderIdToWyreOrderMetadata = []byte{9}

	// The prefix for checking whether or not deso has been sent for a given a wyre order
	_GlobalStatePrefixWyreOrderIdProcessed = []byte{10}

	// Keeps a record of all wyre orders so we can see what has been processed or not.
	_GlobalStatePrefixWyreOrderId = []byte{11}

	// The prefix for accessing the white list audit log of a user.
	// <prefix, username string> -> <WhitelistAudiLog>
	_GlobalStatePrefixWhitelistAuditLog = []byte{12}

	// The prefix for accessing the graylist audit log of a user.
	// <prefix, username string> -> <GraylistAudiLog>
	_GlobalStatePrefixGraylistAuditLog = []byte{13}

	// The prefix for accessing the blacklist audit log of a user.
	// <prefix, username string> -> <BlacklistAudiLog>
	_GlobalStatePrefixBlacklistAuditLog = []byte{14}

	// Stores the current USD Cents per DeSo reserve exchange rate.
	// If rate received from exchanges goes below this value, use this value instead.
	_GlobalStatePrefixUSDCentsToDeSoReserveExchangeRate = []byte{15}

	_GlobalStatePrefixBuyDeSoFeeBasisPoints = []byte{16}

	// NFT drop info.
	_GlobalStatePrefixNFTDropNumberToNFTDropEntry = []byte{17}

	// Jumio global state indexes
	_GlobalStatePrefixPKIDTstampNanosToJumioTransaction = []byte{20}

	_GlobalStatePrefixCountryIDDocumentTypeSubTypeDocumentNumber = []byte{19}

	// Jumio DeSoNanos
	_GlobalStatePrefixJumioDeSoNanos = []byte{21}

	// Tutorial featured well-known creators
	_GlobalStateKeyWellKnownTutorialCreators = []byte{22}

	// Tutorial featured up and coming creators
	_GlobalStateKeyUpAndComingTutorialCreators = []byte{23}

	// Referral program indexes.
	// 	- <prefix, referral hash (8 bytes)> -> <ReferralInfo>
	_GlobalStatePrefixReferralHashToReferralInfo = []byte{24}
	// 	- <prefix, PKID, referral hash (8 bytes)> -> <IsActive bool>
	_GlobalStatePrefixPKIDReferralHashToIsActive = []byte{25}

	// - <prefix, PKID, referral hash (6-8 bytes), Referred PKID
	_GlobalStatePrefixPKIDReferralHashRefereePKID = []byte{26}

	// ETH purchases <prefix, ETH Txn Hash> -> <Complete bool>
	_GlobalStatePrefixForETHPurchases = []byte{27}

	// This prefix allows nodes to construct an in-memory map of the posthashes that are
	// approved to be shown on the Hot Feed. We store approvals and removals as individual
	// "ops" in this index so that nodes don't need to regularly download the entire list
	// of approved post hashes from global state. HotFeedOps can also include "multipliers",
	// which serve to multiply the hotness score of a given post hash.
	//
	// <prefix, OperationTimestampNanos, PostHash> -> <HotFeedOp>
	_GlobalStatePrefixForHotFeedOps = []byte{28}

	// Prefix for accessing hot feed score constants.  <prefix> -> <uint64>
	_GlobalStatePrefixForHotFeedInteractionCap  = []byte{29}
	_GlobalStatePrefixForHotFeedTimeDecayBlocks = []byte{30}

	// - <prefix, lib.TxnType> -> []*lib.DeSoOutput
	_GlobalStatePrefixTxnTypeToDeSoOutputs = []byte{28}

	// Public keys exempt from node fees
	// - <prefix, public key> -> void
	_GlobalStatePrefixExemptPublicKeys = []byte{29}

	// TODO: This process is a bit error-prone. We should come up with a test or
	// something to at least catch cases where people have two prefixes with the
	// same ID.
	//

	// NEXT_TAG: 31
)

type HotFeedOp struct {
	IsRemoval  bool
	Multiplier float64 // Negatives are ignored, 1 has no effect.
}

// A ReferralInfo struct holds all of the params and stats for a referral link/hash.
type ReferralInfo struct {
	ReferralHashBase58     string
	ReferrerPKID           *lib.PKID
	ReferrerAmountUSDCents uint64
	RefereeAmountUSDCents  uint64
	MaxReferrals           uint64 // If set to zero, there is no cap on referrals.
	RequiresJumio          bool

	// Stats
	NumJumioAttempts       uint64
	NumJumioSuccesses      uint64
	TotalReferrals         uint64
	TotalReferrerDeSoNanos uint64
	TotalRefereeDeSoNanos  uint64
	DateCreatedTStampNanos uint64
}

type SimpleReferralInfo struct {
	ReferralHashBase58    string
	RefereeAmountUSDCents uint64
	MaxReferrals          uint64 // If set to zero, there is no cap on referrals.
	TotalReferrals        uint64
}

type NFTDropEntry struct {
	IsActive        bool
	DropNumber      uint64
	DropTstampNanos uint64
	NFTHashes       []*lib.BlockHash
}

// This struct contains all the metadata associated with a user's public key.
type UserMetadata struct {
	// The PublicKey of the user this metadata is associated with.
	PublicKey []byte

	// True if this user should be hidden from all data returned to the app.
	RemoveEverywhere bool

	// True if this user should be hidden from the creator leaderboard.
	RemoveFromLeaderboard bool

	// Email address for a user to receive email notifications at.
	Email string

	// Has the email been verified
	EmailVerified bool

	// E.164 format phone number for a user to receive text notifications at.
	PhoneNumber string

	// Country code associated with the user's phone number. This is a string like "US"
	PhoneNumberCountryCode string

	// This map stores the number of messages that a user has read from a specific contact.
	// The map is indexed with the contact's PublicKeyBase58Check and maps to an integer
	// number of messages that the user has read.
	MessageReadStateByContact map[string]int

	// Store the index of the last notification that the user saw
	NotificationLastSeenIndex int64

	// Amount of Bitcoin that users have burned so far via the Buy DeSo UI
	//
	// We track this so that, if the user does multiple burns,
	// we can set HasBurnedEnoughSatoshisToCreateProfile based on the total
	//
	// This tracks the "total input satoshis" (i.e. it includes fees the user spends).
	// Including fees makes it less expensive for a user to make a profile. We're cutting
	// users a break, but we could change this later.
	SatoshisBurnedSoFar uint64

	// True if the user has burned enough satoshis to create a profile. This can be
	// set to true from the BurnBitcoinStateless endpoint or canUserCreateProfile.
	//
	// We store this (instead of computing it when the user loads the page) to avoid issues
	// where the user burns the required amount, and then we reboot the node and change the min
	// satoshis required, and then the user hasn't burned enough. Once a user has burned enough,
	// we want him to be allowed to create a profile forever.
	HasBurnedEnoughSatoshisToCreateProfile bool

	// Map of public keys of profiles this user has blocked.  The map here functions as a hashset to make look ups more
	// efficient.  Values are empty structs to keep memory usage down.
	BlockedPublicKeys map[string]struct{}

	// If true, this user's posts will automatically be added to the global whitelist (max 5 per day).
	WhitelistPosts bool

	// JumioInternalReference = internal tracking reference for user's experience in Jumio
	JumioInternalReference string
	// JumioFinishedTime = has user completed flow in Jumio
	JumioFinishedTime uint64
	// JumioVerified = user was verified from Jumio flow
	JumioVerified bool
	// JumioReturned = jumio webhook called
	JumioReturned bool
	// JumioTransactionID = jumio's tracking number for the transaction in which this user was verified.
	JumioTransactionID string
	// JumioDocumentKey = Country - Document Type - Document SubType - Document Number. Helps uniquely identify users
	// and allows us to reset Jumio for a given user.
	// DEPRECATED
	JumioDocumentKey []byte
	// RedoJumio = boolean which allows user to skip the duplicate ID check in JumioCallback
	RedoJumio bool
	// JumioStarterDeSoTxnHashHex = Txn hash hex of the transaction in which the user was paid for
	// going through the Jumio flow
	JumioStarterDeSoTxnHashHex string
	// JumioShouldCompProfileCreation = True if we should comp the create profile fee because the user went through the
	// Jumio flow.
	JumioShouldCompProfileCreation bool

	// User must complete tutorial if they have been jumio verified.
	MustCompleteTutorial bool

	// If user is featured as a well known creator in the tutorial.
	IsFeaturedTutorialWellKnownCreator bool
	// If user is featured as an up and coming creator in the tutorial.
	// Note: a user should not be both featured as well known and up and coming
	IsFeaturedTutorialUpAndComingCreator bool

	TutorialStatus                  TutorialStatus
	CreatorPurchasedInTutorialPKID  *lib.PKID
	CreatorCoinsPurchasedInTutorial uint64

	// ReferralHashBase58Check with which user signed up
	ReferralHashBase58Check string

	// Txn hash in which the referrer was paid
	ReferrerDeSoTxnHash string
}

type TutorialStatus string

const (
	EMPTY              TutorialStatus = ""
	STARTED            TutorialStatus = "TutorialStarted"
	SKIPPED            TutorialStatus = "TutorialSkipped"
	INVEST_OTHERS_BUY  TutorialStatus = "InvestInOthersBuyComplete"
	INVEST_OTHERS_SELL TutorialStatus = "InvestInOthersSellComplete"
	CREATE_PROFILE     TutorialStatus = "TutorialCreateProfileComplete"
	INVEST_SELF        TutorialStatus = "InvestInYourselfComplete"
	DIAMOND            TutorialStatus = "GiveADiamondComplete"
	COMPLETE           TutorialStatus = "TutorialComplete"
)

// This struct contains all the metadata associated with a user's phone number.
type PhoneNumberMetadata struct {
	// The PublicKey of the user that this phone number belongs to.
	PublicKey []byte

	// E.164 format phone number for a user to receive text notifications at.
	PhoneNumber string

	// Country code associated with the user's phone number.
	PhoneNumberCountryCode string

	// if true, when the public key associated with this metadata tries to create a profile, we will comp their fee.
	ShouldCompProfileCreation bool
}

type WyreWalletOrderMetadata struct {
	// Last payload received from Wyre webhook
	LatestWyreWalletOrderWebhookPayload WyreWalletOrderWebhookPayload

	// Track Wallet Order response received based on the last payload received from Wyre Webhook
	LatestWyreTrackWalletOrderResponse *WyreTrackOrderResponse

	// Amount of DeSo that was sent for this WyreWalletOrder
	DeSoPurchasedNanos uint64

	// BlockHash of the transaction for sending the DeSo
	BasicTransferTxnBlockHash *lib.BlockHash
}

func GlobalStateKeyForNFTDropEntry(dropNumber uint64) []byte {
	dropNumBytes := lib.EncodeUint64(uint64(dropNumber))
	keyBytes := _GlobalStatePrefixNFTDropNumberToNFTDropEntry
	keyBytes = append(keyBytes, dropNumBytes...)
	return keyBytes
}

// countryCode is a string like 'US' (Note: the phonenumbers lib calls this a "region code")
func GlobalStateKeyForPhoneNumberStringToPhoneNumberMetadata(phoneNumber string) (_key []byte, _err error) {
	parsedNumber, err := phonenumbers.Parse(phoneNumber, "")
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf(
			"GlobalStateKeyForPhoneNumberStringToPhoneNumberMetadata: Problem with phonenumbers.Parse: %v", err), "")
	}
	formattedNumber := phonenumbers.Format(parsedNumber, phonenumbers.E164)

	// Get the key for the formatted number
	return globalStateKeyForPhoneNumberBytesToPhoneNumberMetadata([]byte(formattedNumber)), nil
}

// Key for accessing a user's global metadata.
// External callers should use GlobalStateKeyForPhoneNumberStringToPhoneNumberMetadata, not this function,
// to ensure that the phone number key is formatted in a standard way
func globalStateKeyForPhoneNumberBytesToPhoneNumberMetadata(phoneNumberBytes []byte) []byte {
	prefixCopy := append([]byte{}, _GlobalStatePrefixPhoneNumberToPhoneNumberMetadata...)
	key := append(prefixCopy, phoneNumberBytes[:]...)
	return key
}

// Key for accessing a user's global metadata.
func GlobalStateKeyForPublicKeyToUserMetadata(profilePubKey []byte) []byte {
	prefixCopy := append([]byte{}, _GlobalStatePrefixPublicKeyToUserMetadata...)
	key := append(prefixCopy, profilePubKey[:]...)
	return key
}

// Key for accessing the referral info for a specific referral hash.
func GlobalStateKeyForReferralHashToReferralInfo(referralHashBytes []byte) []byte {
	prefixCopy := append([]byte{}, _GlobalStatePrefixReferralHashToReferralInfo...)
	key := append(prefixCopy, referralHashBytes[:]...)
	return key
}

// Key for getting a pub key's referral hashes and "IsActive" status.
func GlobalStateKeyForPKIDReferralHashToIsActive(pkid *lib.PKID, referralHashBytes []byte) []byte {
	prefixCopy := append([]byte{}, _GlobalStatePrefixPKIDReferralHashToIsActive...)
	key := append(prefixCopy, pkid[:]...)
	key = append(key, referralHashBytes[:]...)
	return key
}

// Key for seeking the DB for hot feed operations based on timestamp.
func GlobalStateSeekKeyForHotFeedOps(startTimestampNanos uint64) []byte {
	prefixCopy := append([]byte{}, _GlobalStatePrefixForHotFeedOps...)
	key := append(prefixCopy, lib.EncodeUint64(startTimestampNanos)...)
	return key
}

// Key for seeking the DB for all hot feed operations.
func GlobalStateKeyForHotFeedOp(
	opTimestampNanos uint64,
	postHash *lib.BlockHash,
) []byte {
	prefixCopy := append([]byte{}, _GlobalStatePrefixForHotFeedOps...)
	key := append(prefixCopy, lib.EncodeUint64(opTimestampNanos)...)
	key = append(key, postHash[:]...)
	return key
}

// Key for seeking the DB for all referral hashes with a specific PKID.
func GlobalStateSeekKeyForPKIDReferralHashes(pkid *lib.PKID) []byte {
	prefixCopy := append([]byte{}, _GlobalStatePrefixPKIDReferralHashToIsActive...)
	key := append(prefixCopy, pkid[:]...)
	return key
}

func GlobalStateKeyForPKIDReferralHashRefereePKID(pkid *lib.PKID, referralHash []byte, refereePKID *lib.PKID) []byte {
	prefixCopy := append([]byte{}, _GlobalStatePrefixPKIDReferralHashRefereePKID...)
	key := append(prefixCopy, pkid[:]...)
	key = append(key, referralHash[:]...)
	key = append(key, refereePKID[:]...)
	return key
}

// Key for accessing a whitelised post in the global feed index.
func GlobalStateKeyForTstampPostHash(tstampNanos uint64, postHash *lib.BlockHash) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	key := append([]byte{}, _GlobalStatePrefixTstampNanosPostHash...)
	key = append(key, lib.EncodeUint64(tstampNanos)...)
	key = append(key, postHash[:]...)
	return key
}

// Key for accessing a pinned post.
func GlobalStateKeyForTstampPinnedPostHash(tstampNanos uint64, postHash *lib.BlockHash) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	key := append([]byte{}, _GlobalStatePrefixTstampNanosPinnedPostHash...)
	key = append(key, lib.EncodeUint64(tstampNanos)...)
	key = append(key, postHash[:]...)
	return key
}

// Key for accessing verification audit logs for a given username
func GlobalStateKeyForUsernameVerificationAuditLogs(username string) []byte {
	key := append([]byte{}, _GlobalStatePrefixUsernameVerificationAuditLog...)
	key = append(key, []byte(strings.ToLower(username))...)
	return key
}

// Key for accessing the whitelist audit logs associated with a user.
func GlobalStateKeyForWhitelistAuditLogs(username string) []byte {
	key := append([]byte{}, _GlobalStatePrefixWhitelistAuditLog...)
	key = append(key, []byte(strings.ToLower(username))...)
	return key
}

// Key for accessing a graylisted user.
func GlobalStateKeyForGraylistedProfile(profilePubKey []byte) []byte {
	key := append([]byte{}, _GlobalStatePrefixPublicKeyToGraylistState...)
	key = append(key, profilePubKey...)
	return key
}

// Key for accessing the graylist audit logs associated with a user.
func GlobalStateKeyForGraylistAuditLogs(username string) []byte {
	key := append([]byte{}, _GlobalStatePrefixGraylistAuditLog...)
	key = append(key, []byte(strings.ToLower(username))...)
	return key
}

// Key for accessing a blacklisted user.
func GlobalStateKeyForBlacklistedProfile(profilePubKey []byte) []byte {
	key := append([]byte{}, _GlobalStatePrefixPublicKeyToBlacklistState...)
	key = append(key, profilePubKey...)
	return key
}

// Key for accessing the blacklist audit logs associated with a user.
func GlobalStateKeyForBlacklistAuditLogs(username string) []byte {
	key := append([]byte{}, _GlobalStatePrefixBlacklistAuditLog...)
	key = append(key, []byte(strings.ToLower(username))...)
	return key
}

// Key for accessing a user's global metadata.
func GlobalStateKeyForUserPkContactPkToMostRecentReadTstampNanos(userPubKey []byte, contactPubKey []byte) []byte {
	prefixCopy := append([]byte{}, _GlobalStatePrefixUserPublicKeyContactPublicKeyToMostRecentReadTstampNanos...)
	key := append(prefixCopy, userPubKey[:]...)
	key = append(key, contactPubKey[:]...)
	return key
}

// Key for accessing a public key's wyre order metadata.
func GlobalStateKeyForUserPublicKeyTstampNanosToWyreOrderMetadata(userPublicKeyBytes []byte, timestampNanos uint64) []byte {
	prefixCopy := append([]byte{}, _GlobalStatePrefixUserPublicKeyWyreOrderIdToWyreOrderMetadata...)
	key := append(prefixCopy, userPublicKeyBytes...)
	key = append(key, lib.EncodeUint64(timestampNanos)...)
	return key
}

func GlobalStateKeyForWyreOrderIDProcessed(orderIdBytes []byte) []byte {
	prefixCopy := append([]byte{}, _GlobalStatePrefixWyreOrderIdProcessed...)
	key := append(prefixCopy, orderIdBytes...)
	return key
}

func GlobalStateKeyForWyreOrderID(orderIdBytes []byte) []byte {
	prefixCopy := append([]byte{}, _GlobalStatePrefixWyreOrderId...)
	key := append(prefixCopy, orderIdBytes...)
	return key
}

func GlobalStateKeyForUSDCentsToDeSoReserveExchangeRate() []byte {
	prefixCopy := append([]byte{}, _GlobalStatePrefixUSDCentsToDeSoReserveExchangeRate...)
	return prefixCopy
}

func GlobalStateKeyForBuyDeSoFeeBasisPoints() []byte {
	prefixCopy := append([]byte{}, _GlobalStatePrefixBuyDeSoFeeBasisPoints...)
	return prefixCopy
}

func GlobalStateKeyForPKIDTstampnanosToJumioTransaction(pkid *lib.PKID, timestampNanos uint64) []byte {
	prefixCopy := append([]byte{}, _GlobalStatePrefixPKIDTstampNanosToJumioTransaction...)
	key := append(prefixCopy, pkid[:]...)
	key = append(key, lib.EncodeUint64(timestampNanos)...)
	return key
}

func GlobalStatePrefixforPKIDTstampnanosToJumioTransaction(pkid *lib.PKID) []byte {
	prefixCopy := append([]byte{}, _GlobalStatePrefixPKIDTstampNanosToJumioTransaction...)
	key := append(prefixCopy, pkid[:]...)
	return key
}

func GlobalStateKeyForCountryIDDocumentTypeSubTypeDocumentNumber(countryID string, documentType string, subType string, documentNumber string) []byte {
	prefixCopy := append([]byte{}, _GlobalStatePrefixCountryIDDocumentTypeSubTypeDocumentNumber...)
	key := append(prefixCopy, []byte(countryID)...)
	key = append(key, []byte(documentType)...)
	key = append(key, []byte(subType)...)
	key = append(key, []byte(documentNumber)...)
	return key
}

func GlobalStateKeyForJumioDeSoNanos() []byte {
	prefixCopy := append([]byte{}, _GlobalStatePrefixJumioDeSoNanos...)
	return prefixCopy
}

func GlobalStateKeyWellKnownTutorialCreators(pkid *lib.PKID) []byte {
	prefixCopy := append([]byte{}, _GlobalStateKeyWellKnownTutorialCreators...)
	key := append(prefixCopy, pkid[:]...)
	return key
}

func GlobalStateKeyUpAndComingTutorialCreators(pkid *lib.PKID) []byte {
	prefixCopy := append([]byte{}, _GlobalStateKeyUpAndComingTutorialCreators...)
	key := append(prefixCopy, pkid[:]...)
	return key
}

func GlobalStateKeyETHPurchases(txnHash string) []byte {
	prefixCopy := append([]byte{}, _GlobalStatePrefixForETHPurchases...)
	key := append(prefixCopy, txnHash[:]...)
	return key
}

func GlobalStateKeyTransactionFeeOutputsFromTxnType(txnType lib.TxnType) []byte {
	prefixCopy := append([]byte{}, _GlobalStatePrefixTxnTypeToDeSoOutputs...)
	key := append(prefixCopy, lib.UintToBuf(uint64(txnType))...)
	return key
}

func GlobalStateKeyExemptPublicKey(publicKey []byte) []byte {
	prefixCopy := append([]byte{}, _GlobalStatePrefixExemptPublicKeys...)
	key := append(prefixCopy, publicKey[:]...)
	return key
}

type GlobalStatePutRemoteRequest struct {
	Key   []byte
	Value []byte
}

type GlobalStatePutRemoteResponse struct {
}

func (fes *APIServer) GlobalStatePutRemote(ww http.ResponseWriter, rr *http.Request) {
	// Parse the request.
	decoder := json.NewDecoder(io.LimitReader(rr.Body, MaxRequestBodySizeBytes))
	requestData := GlobalStatePutRemoteRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GlobalStatePutRemote: Problem parsing request body: %v", err))
		return
	}

	// Call the put function. Note that this may also proxy to another node.
	if err := fes.GlobalStatePut(requestData.Key, requestData.Value); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GlobalStatePutRemote: Error processing GlobalStatePut: %v", err))
		return
	}

	// Return
	res := GlobalStatePutRemoteResponse{}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GlobalStatePutRemote: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) CreateGlobalStatePutRequest(key []byte, value []byte) (
	_url string, _json_data []byte, _err error) {

	req := GlobalStatePutRemoteRequest{
		Key:   key,
		Value: value,
	}
	json_data, err := json.Marshal(req)
	if err != nil {
		return "", nil, fmt.Errorf("GlobalStatePut: Could not marshal JSON: %v", err)
	}

	url := fmt.Sprintf("%s%s?%s=%s",
		fes.Config.GlobalStateRemoteNode, RoutePathGlobalStatePutRemote,
		GlobalStateSharedSecretParam, fes.Config.GlobalStateRemoteSecret)

	return url, json_data, nil
}

func (fes *APIServer) GlobalStatePut(key []byte, value []byte) error {
	// If we have a remote node then use that node to fulfill this request.
	if fes.Config.GlobalStateRemoteNode != "" {
		// TODO: This codepath is hard to exercise in a test.

		url, json_data, err := fes.CreateGlobalStatePutRequest(key, value)
		if err != nil {
			return fmt.Errorf("GlobalStatePut: Error constructing request: %v", err)
		}
		res, err := http.Post(
			url,
			"application/json", /*contentType*/
			bytes.NewBuffer(json_data))
		if err != nil {
			return fmt.Errorf("GlobalStatePut: Error processing remote request")
		}
		res.Body.Close()

		//res := GlobalStatePutRemoteResponse{}
		//json.NewDecoder(resReturned.Body).Decode(&res)

		// No error means nothing to return.
		return nil
	}

	// If we get here, it means we don't have a remote node so store the
	// data in our local db.
	return fes.GlobalStateDB.Update(func(txn *badger.Txn) error {
		return txn.Set(key, value)
	})
}

type GlobalStateGetRemoteRequest struct {
	Key []byte
}

type GlobalStateGetRemoteResponse struct {
	Value []byte
}

func (fes *APIServer) GlobalStateGetRemote(ww http.ResponseWriter, rr *http.Request) {
	// Parse the request.
	decoder := json.NewDecoder(io.LimitReader(rr.Body, MaxRequestBodySizeBytes))
	requestData := GlobalStateGetRemoteRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GlobalStateGetRemote: Problem parsing request body: %v", err))
		return
	}

	// Call the get function. Note that this may also proxy to another node.
	val, err := fes.GlobalStateGet(requestData.Key)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GlobalStateGetRemote: Error processing GlobalStateGet: %v", err))
		return
	}

	// Return
	res := GlobalStateGetRemoteResponse{
		Value: val,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GlobalStateGetRemote: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) CreateGlobalStateGetRequest(key []byte) (
	_url string, _json_data []byte, _err error) {

	req := GlobalStateGetRemoteRequest{
		Key: key,
	}
	json_data, err := json.Marshal(req)
	if err != nil {
		return "", nil, fmt.Errorf("GlobalStateGet: Could not marshal JSON: %v", err)
	}

	url := fmt.Sprintf("%s%s?%s=%s",
		fes.Config.GlobalStateRemoteNode, RoutePathGlobalStateGetRemote,
		GlobalStateSharedSecretParam, fes.Config.GlobalStateRemoteSecret)

	return url, json_data, nil
}

func (fes *APIServer) GlobalStateGet(key []byte) (value []byte, _err error) {
	// If we have a remote node then use that node to fulfill this request.
	if fes.Config.GlobalStateRemoteNode != "" {
		// TODO: This codepath is currently annoying to test.

		url, json_data, err := fes.CreateGlobalStateGetRequest(key)
		if err != nil {
			return nil, fmt.Errorf(
				"GlobalStateGet: Error constructing request: %v", err)
		}

		resReturned, err := http.Post(
			url,
			"application/json", /*contentType*/
			bytes.NewBuffer(json_data))
		if err != nil {
			return nil, fmt.Errorf("GlobalStateGet: Error processing remote request")
		}

		res := GlobalStateGetRemoteResponse{}
		json.NewDecoder(resReturned.Body).Decode(&res)
		resReturned.Body.Close()

		return res.Value, nil
	}

	// If we get here, it means we don't have a remote node so get the
	// data from our local db.
	var retValue []byte
	err := fes.GlobalStateDB.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return nil
		}
		retValue, err = item.ValueCopy(nil)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("GlobalStateGet: Error copying value into new slice: %v", err)
	}

	return retValue, nil
}

type GlobalStateBatchGetRemoteRequest struct {
	KeyList [][]byte
}

type GlobalStateBatchGetRemoteResponse struct {
	ValueList [][]byte
}

func (fes *APIServer) GlobalStateBatchGetRemote(ww http.ResponseWriter, rr *http.Request) {
	// Parse the request.
	decoder := json.NewDecoder(io.LimitReader(rr.Body, MaxRequestBodySizeBytes))
	requestData := GlobalStateBatchGetRemoteRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GlobalStateBatchGetRemote: Problem parsing request body: %v", err))
		return
	}

	// Call the get function. Note that this may also proxy to another node.
	values, err := fes.GlobalStateBatchGet(requestData.KeyList)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GlobalStateBatchGetRemote: Error processing GlobalStateBatchGet: %v", err))
		return
	}

	// Return
	res := GlobalStateBatchGetRemoteResponse{
		ValueList: values,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GlobalStateBatchGetRemote: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) CreateGlobalStateBatchGetRequest(keyList [][]byte) (
	_url string, _json_data []byte, _err error) {

	req := GlobalStateBatchGetRemoteRequest{
		KeyList: keyList,
	}
	json_data, err := json.Marshal(req)
	if err != nil {
		return "", nil, fmt.Errorf("GlobalStateBatchGet: Could not marshal JSON: %v", err)
	}

	url := fmt.Sprintf("%s%s?%s=%s",
		fes.Config.GlobalStateRemoteNode, RoutePathGlobalStateBatchGetRemote,
		GlobalStateSharedSecretParam, fes.Config.GlobalStateRemoteSecret)

	return url, json_data, nil
}

func (fes *APIServer) GlobalStateBatchGet(keyList [][]byte) (value [][]byte, _err error) {
	// If we have a remote node then use that node to fulfill this request.
	if fes.Config.GlobalStateRemoteNode != "" {
		// TODO: This codepath is currently annoying to test.

		url, json_data, err := fes.CreateGlobalStateBatchGetRequest(keyList)
		if err != nil {
			return nil, fmt.Errorf(
				"GlobalStateBatchGet: Error constructing request: %v", err)
		}

		resReturned, err := http.Post(
			url,
			"application/json", /*contentType*/
			bytes.NewBuffer(json_data))
		if err != nil {
			return nil, fmt.Errorf("GlobalStateBatchGet: Error processing remote request")
		}

		res := GlobalStateBatchGetRemoteResponse{}
		json.NewDecoder(resReturned.Body).Decode(&res)
		resReturned.Body.Close()

		return res.ValueList, nil
	}

	// If we get here, it means we don't have a remote node so get the
	// data from our local db.
	var retValueList [][]byte
	err := fes.GlobalStateDB.View(func(txn *badger.Txn) error {
		for _, key := range keyList {
			item, err := txn.Get(key)
			if err != nil {
				retValueList = append(retValueList, []byte{})
				continue
			}
			value, err := item.ValueCopy(nil)
			if err != nil {
				return err
			} else {
				retValueList = append(retValueList, value)
			}
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("GlobalStateBatchGet: Error copying value into new slice: %v", err)
	}

	return retValueList, nil
}

type GlobalStateDeleteRemoteRequest struct {
	Key []byte
}

type GlobalStateDeleteRemoteResponse struct {
}

func (fes *APIServer) CreateGlobalStateDeleteRequest(key []byte) (
	_url string, _json_data []byte, _err error) {

	req := GlobalStateDeleteRemoteRequest{
		Key: key,
	}
	json_data, err := json.Marshal(req)
	if err != nil {
		return "", nil, fmt.Errorf("GlobalStateDelete: Could not marshal JSON: %v", err)
	}

	url := fmt.Sprintf("%s%s?%s=%s",
		fes.Config.GlobalStateRemoteNode, RoutePathGlobalStateDeleteRemote,
		GlobalStateSharedSecretParam, fes.Config.GlobalStateRemoteSecret)

	return url, json_data, nil
}

func (fes *APIServer) GlobalStateDeleteRemote(ww http.ResponseWriter, rr *http.Request) {
	// Parse the request.
	decoder := json.NewDecoder(io.LimitReader(rr.Body, MaxRequestBodySizeBytes))
	requestData := GlobalStateDeleteRemoteRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GlobalStateDeleteRemote: Problem parsing request body: %v", err))
		return
	}

	// Call the Delete function. Note that this may also proxy to another node.
	if err := fes.GlobalStateDelete(requestData.Key); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GlobalStateDeleteRemote: Error processing GlobalStateDelete: %v", err))
		return
	}

	// Return
	res := GlobalStateDeleteRemoteResponse{}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GlobalStateDeleteRemote: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) GlobalStateDelete(key []byte) error {
	// If we have a remote node then use that node to fulfill this request.
	if fes.Config.GlobalStateRemoteNode != "" {
		// TODO: This codepath is currently annoying to test.

		url, json_data, err := fes.CreateGlobalStateDeleteRequest(key)
		if err != nil {
			return fmt.Errorf("GlobalStateDelete: Could not construct request: %v", err)
		}

		res, err := http.Post(
			url,
			"application/json", /*contentType*/
			bytes.NewBuffer(json_data))
		if err != nil {
			return fmt.Errorf("GlobalStateDelete: Error processing remote request")
		}

		res.Body.Close()
		//res := GlobalStateDeleteRemoteResponse{}
		//json.NewDecoder(resReturned.Body).Decode(&res)

		// No error means nothing to return.
		return nil
	}

	// If we get here, it means we don't have a remote node so store the
	// data in our local db.
	return fes.GlobalStateDB.Update(func(txn *badger.Txn) error {
		return txn.Delete(key)
	})
}

type GlobalStateSeekRemoteRequest struct {
	StartPrefix    []byte
	ValidForPrefix []byte
	MaxKeyLen      int
	NumToFetch     int
	Reverse        bool
	FetchValues    bool
}
type GlobalStateSeekRemoteResponse struct {
	KeysFound [][]byte
	ValsFound [][]byte
}

func (fes *APIServer) CreateGlobalStateSeekRequest(startPrefix []byte, validForPrefix []byte,
	maxKeyLen int, numToFetch int, reverse bool, fetchValues bool) (
	_url string, _json_data []byte, _err error) {

	req := GlobalStateSeekRemoteRequest{
		StartPrefix:    startPrefix,
		ValidForPrefix: validForPrefix,
		MaxKeyLen:      maxKeyLen,
		NumToFetch:     numToFetch,
		Reverse:        reverse,
		FetchValues:    fetchValues,
	}
	json_data, err := json.Marshal(req)
	if err != nil {
		return "", nil, fmt.Errorf("GlobalStateSeek: Could not marshal JSON: %v", err)
	}

	url := fmt.Sprintf("%s%s?%s=%s",
		fes.Config.GlobalStateRemoteNode, RoutePathGlobalStateSeekRemote,
		GlobalStateSharedSecretParam, fes.Config.GlobalStateRemoteSecret)

	return url, json_data, nil
}
func (fes *APIServer) GlobalStateSeekRemote(ww http.ResponseWriter, rr *http.Request) {
	// Parse the request.
	decoder := json.NewDecoder(io.LimitReader(rr.Body, MaxRequestBodySizeBytes))
	requestData := GlobalStateSeekRemoteRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GlobalStateSeekRemote: Problem parsing request body: %v", err))
		return
	}

	// Call the get function. Note that this may also proxy to another node.
	keys, values, err := fes.GlobalStateSeek(
		requestData.StartPrefix,
		requestData.ValidForPrefix,
		requestData.MaxKeyLen,
		requestData.NumToFetch,
		requestData.Reverse,
		requestData.FetchValues,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GlobalStateSeekRemote: Error processing GlobalStateSeek: %v", err))
		return
	}

	// Return
	res := GlobalStateSeekRemoteResponse{
		KeysFound: keys,
		ValsFound: values,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GlobalStateSeekRemote: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) GlobalStateSeek(startPrefix []byte, validForPrefix []byte,
	maxKeyLen int, numToFetch int, reverse bool, fetchValues bool) (
	_keysFound [][]byte, _valsFound [][]byte, _err error) {

	// If we have a remote node then use that node to fulfill this request.
	if fes.Config.GlobalStateRemoteNode != "" {
		// TODO: This codepath is currently annoying to test.

		url, json_data, err := fes.CreateGlobalStateSeekRequest(
			startPrefix,
			validForPrefix,
			maxKeyLen,
			numToFetch,
			reverse,
			fetchValues)
		if err != nil {
			return nil, nil, fmt.Errorf(
				"GlobalStateSeek: Error constructing request: %v", err)
		}

		resReturned, err := http.Post(
			url,
			"application/json", /*contentType*/
			bytes.NewBuffer(json_data))
		if err != nil {
			return nil, nil, fmt.Errorf("GlobalStateSeek: Error processing remote request")
		}

		res := GlobalStateSeekRemoteResponse{}
		json.NewDecoder(resReturned.Body).Decode(&res)
		resReturned.Body.Close()

		return res.KeysFound, res.ValsFound, nil
	}

	// If we get here, it means we don't have a remote node so get the
	// data from our local db.
	retKeys, retVals, err := lib.DBGetPaginatedKeysAndValuesForPrefix(fes.GlobalStateDB, startPrefix,
		validForPrefix, maxKeyLen, numToFetch, reverse, fetchValues)
	if err != nil {
		return nil, nil, fmt.Errorf("GlobalStateSeek: Error getting paginated keys and values: %v", err)
	}

	return retKeys, retVals, nil
}
