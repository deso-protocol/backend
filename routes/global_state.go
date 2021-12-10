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

type GlobalState struct {
	GlobalStateRemoteNode   string
	GlobalStateRemoteSecret string
	GlobalStateDB           *badger.DB
}

// GlobalStateRoutes returns the routes for managing global state.
// Note that these routes are generally protected by a shared_secret
func (gs *GlobalState) GlobalStateRoutes() []Route {
	var GlobalStateRoutes = []Route{
		{
			"PutRemote",
			[]string{"POST", "OPTIONS"},
			RoutePathGlobalStatePutRemote,
			gs.PutRemote,
			AdminAccess, // CheckSecret
		},
		{
			"GetRemote",
			[]string{"POST", "OPTIONS"},
			RoutePathGlobalStateGetRemote,
			gs.GetRemote,
			AdminAccess, // CheckSecret
		},
		{
			"BatchGetRemote",
			[]string{"POST", "OPTIONS"},
			RoutePathGlobalStateBatchGetRemote,
			gs.BatchGetRemote,
			AdminAccess, // CheckSecret
		},
		{
			"DeleteRemote",
			[]string{"POST", "OPTIONS"},
			RoutePathGlobalStateDeleteRemote,
			gs.DeleteRemote,
			AdminAccess, // CheckSecret
		},
		{
			"GlobalStateSeekRemote",
			[]string{"POST", "OPTIONS"},
			RoutePathGlobalStateSeekRemote,
			gs.GlobalStateSeekRemote,
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
	// - <prefix, PKID, referral hash (8 bytes), Referred PKID
	_GlobalStatePrefixPKIDReferralHashRefereePKID = []byte{26}
	// - <prefix, TimestampNanos, PKID, referral hash (8 bytes), Referred PKID
	_GlobalStatePrefixTimestampPKIDReferralHashRefereePKID = []byte{37}

	// ETH purchases <prefix, ETH Txn Hash> -> <Complete bool>
	_GlobalStatePrefixForETHPurchases = []byte{27}

	// DO NOT USE: prefixes 28-30. At one point, these prefixes were used for multiple indexes.
	// In order to prevent future issues with either index, these indexes were moved to start at 31.

	// This prefix allows nodes to construct an in-memory map of the posthashes that are
	// approved to be shown on the Hot Feed. We store approvals and removals as individual
	// "ops" in this index so that nodes don't need to regularly download the entire list
	// of approved post hashes from global state. HotFeedOps can also include "multipliers",
	// which serve to multiply the hotness score of a given post hash.
	//
	// <prefix, OperationTimestampNanos, PostHash> -> <HotFeedOp>
	_GlobalStatePrefixForHotFeedApprovedPostOps = []byte{31}

	// Prefix for accessing hot feed score constants.  <prefix> -> <uint64>
	_GlobalStatePrefixForHotFeedInteractionCap  = []byte{32}
	_GlobalStatePrefixForHotFeedTimeDecayBlocks = []byte{33}

	// - <prefix, lib.TxnType> -> []*lib.DeSoOutput
	_GlobalStatePrefixTxnTypeToDeSoOutputs = []byte{34}

	// Public keys exempt from node fees
	// - <prefix, public key> -> void
	_GlobalStatePrefixExemptPublicKeys = []byte{35}

	// This key is used in a similar way to the _GlobalStatePrefixForHotFeedApprovedPostOps
	// above except it is used to track changes to the HotFeedPKIDMultiplier map.
	// <prefix, OperationTimestampNanos, PKID> -> <HotFeedPKIDMultiplierOp>
	_GlobalStatePrefixForHotFeedPKIDMultiplierOps = []byte{36}

	// TODO: This process is a bit error-prone. We should come up with a test or
	// something to at least catch cases where people have two prefixes with the
	// same ID.
	//

	// NEXT_TAG: 38
)

type HotFeedApprovedPostOp struct {
	IsRemoval  bool
	Multiplier float64 // Negatives are ignored when updating the ApprovedPosts map.
}

type HotFeedPKIDMultiplierOp struct {
	InteractionMultiplier float64 // Negatives are ignored when updating the PKIDMultiplier map.
	PostsMultiplier       float64 // Negatives are ignored when updating the PKIDMultiplier map.
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

	// The number of unread notifications stored in the db.
	UnreadNotifications uint64
	// The most recently scanned notification transaction index in the database. Stored in order to prevent unnecessary re-scanning.
	LatestUnreadNotificationIndex int64
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
	FOLLOW_CREATORS    TutorialStatus = "FollowCreatorsComplete"
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

	// True if user deleted PII. Since users can
	PublicKeyDeleted bool
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

func GlobalStateSeekKeyForHotFeedApprovedPostOps(startTimestampNanos uint64) []byte {
	prefixCopy := append([]byte{}, _GlobalStatePrefixForHotFeedApprovedPostOps...)
	key := append(prefixCopy, lib.EncodeUint64(startTimestampNanos)...)
	return key
}

func GlobalStateKeyForHotFeedApprovedPostOp(
	opTimestampNanos uint64,
	postHash *lib.BlockHash,
) []byte {
	prefixCopy := append([]byte{}, _GlobalStatePrefixForHotFeedApprovedPostOps...)
	key := append(prefixCopy, lib.EncodeUint64(opTimestampNanos)...)
	key = append(key, postHash[:]...)
	return key
}

func GlobalStateSeekKeyForHotFeedPKIDMultiplierOps(startTimestampNanos uint64) []byte {
	prefixCopy := append([]byte{}, _GlobalStatePrefixForHotFeedPKIDMultiplierOps...)
	key := append(prefixCopy, lib.EncodeUint64(startTimestampNanos)...)
	return key
}

func GlobalStateKeyForHotFeedPKIDMultiplierOp(
	opTimestampNanos uint64,
	opPKID *lib.PKID,
) []byte {
	prefixCopy := append([]byte{}, _GlobalStatePrefixForHotFeedPKIDMultiplierOps...)
	key := append(prefixCopy, lib.EncodeUint64(opTimestampNanos)...)
	key = append(key, opPKID[:]...)
	return key
}

// Key for seeking the DB for all referral hashes with a specific PKID.
func GlobalStateSeekKeyForPKIDReferralHashes(pkid *lib.PKID) []byte {
	prefixCopy := append([]byte{}, _GlobalStatePrefixPKIDReferralHashToIsActive...)
	key := append(prefixCopy, pkid[:]...)
	return key
}

func GlobalStateSeekKeyForPKIDReferralHashRefereePKIDs(pkid *lib.PKID, referralHash []byte) []byte {
	prefixCopy := append([]byte{}, _GlobalStatePrefixPKIDReferralHashRefereePKID...)
	key := append(prefixCopy, pkid[:]...)
	key = append(key, referralHash[:]...)
	return key
}

func GlobalStateKeyForPKIDReferralHashRefereePKID(pkid *lib.PKID, referralHash []byte, refereePKID *lib.PKID) []byte {
	prefixCopy := append([]byte{}, _GlobalStatePrefixPKIDReferralHashRefereePKID...)
	key := append(prefixCopy, pkid[:]...)
	key = append(key, referralHash[:]...)
	key = append(key, refereePKID[:]...)
	return key
}

func GlobalStateKeyForTimestampPKIDReferralHashRefereePKID(
	tstampNanos uint64, pkid *lib.PKID, referralHash []byte, refereePKID *lib.PKID) []byte {
	prefixCopy := append([]byte{}, _GlobalStatePrefixTimestampPKIDReferralHashRefereePKID...)
	key := append(prefixCopy, lib.EncodeUint64(tstampNanos)...)
	key = append(key, pkid[:]...)
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

func GlobalStateSeekKeyForTstampPostHash(tstampNanos uint64) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	key := append([]byte{}, _GlobalStatePrefixTstampNanosPostHash...)
	key = append(key, lib.EncodeUint64(tstampNanos)...)
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

type PutRemoteRequest struct {
	Key   []byte
	Value []byte
}

type PutRemoteResponse struct {
}

func (gs *GlobalState) PutRemote(ww http.ResponseWriter, rr *http.Request) {
	// Parse the request.
	decoder := json.NewDecoder(io.LimitReader(rr.Body, MaxRequestBodySizeBytes))
	requestData := PutRemoteRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("PutRemote: Problem parsing request body: %v", err))
		return
	}

	// Call the put function. Note that this may also proxy to another node.
	if err := gs.Put(requestData.Key, requestData.Value); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"PutRemote: Error processing Put: %v", err))
		return
	}

	// Return
	res := PutRemoteResponse{}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("PutRemote: Problem encoding response as JSON: %v", err))
		return
	}
}

func (gs *GlobalState) CreatePutRequest(key []byte, value []byte) (
	_url string, _json_data []byte, _err error) {

	req := PutRemoteRequest{
		Key:   key,
		Value: value,
	}
	json_data, err := json.Marshal(req)
	if err != nil {
		return "", nil, fmt.Errorf("Put: Could not marshal JSON: %v", err)
	}

	url := fmt.Sprintf("%s%s?%s=%s",
		gs.GlobalStateRemoteNode, RoutePathGlobalStatePutRemote,
		GlobalStateSharedSecretParam, gs.GlobalStateRemoteSecret)

	return url, json_data, nil
}

func (gs *GlobalState) Put(key []byte, value []byte) error {
	// If we have a remote node then use that node to fulfill this request.
	if gs.GlobalStateRemoteNode != "" {
		// TODO: This codepath is hard to exercise in a test.

		url, json_data, err := gs.CreatePutRequest(key, value)
		if err != nil {
			return fmt.Errorf("Put: Error constructing request: %v", err)
		}
		res, err := http.Post(
			url,
			"application/json", /*contentType*/
			bytes.NewBuffer(json_data))
		if err != nil {
			return fmt.Errorf("Put: Error processing remote request")
		}
		res.Body.Close()

		//res := PutRemoteResponse{}
		//json.NewDecoder(resReturned.Body).Decode(&res)

		// No error means nothing to return.
		return nil
	}

	// If we get here, it means we don't have a remote node so store the
	// data in our local db.
	return gs.GlobalStateDB.Update(func(txn *badger.Txn) error {
		return txn.Set(key, value)
	})
}

type GetRemoteRequest struct {
	Key []byte
}

type GetRemoteResponse struct {
	Value []byte
}

func (gs *GlobalState) GetRemote(ww http.ResponseWriter, rr *http.Request) {
	// Parse the request.
	decoder := json.NewDecoder(io.LimitReader(rr.Body, MaxRequestBodySizeBytes))
	requestData := GetRemoteRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetRemote: Problem parsing request body: %v", err))
		return
	}

	// Call the get function. Note that this may also proxy to another node.
	val, err := gs.Get(requestData.Key)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetRemote: Error processing Get: %v", err))
		return
	}

	// Return
	res := GetRemoteResponse{
		Value: val,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetRemote: Problem encoding response as JSON: %v", err))
		return
	}
}

func (gs *GlobalState) CreateGetRequest(key []byte) (
	_url string, _json_data []byte, _err error) {

	req := GetRemoteRequest{
		Key: key,
	}
	json_data, err := json.Marshal(req)
	if err != nil {
		return "", nil, fmt.Errorf("Get: Could not marshal JSON: %v", err)
	}

	url := fmt.Sprintf("%s%s?%s=%s",
		gs.GlobalStateRemoteNode, RoutePathGlobalStateGetRemote,
		GlobalStateSharedSecretParam, gs.GlobalStateRemoteSecret)

	return url, json_data, nil
}

func (gs *GlobalState) Get(key []byte) (value []byte, _err error) {
	// If we have a remote node then use that node to fulfill this request.
	if gs.GlobalStateRemoteNode != "" {
		// TODO: This codepath is currently annoying to test.

		url, json_data, err := gs.CreateGetRequest(key)
		if err != nil {
			return nil, fmt.Errorf(
				"Get: Error constructing request: %v", err)
		}

		resReturned, err := http.Post(
			url,
			"application/json", /*contentType*/
			bytes.NewBuffer(json_data))
		if err != nil {
			return nil, fmt.Errorf("Get: Error processing remote request")
		}

		res := GetRemoteResponse{}
		json.NewDecoder(resReturned.Body).Decode(&res)
		resReturned.Body.Close()

		return res.Value, nil
	}

	// If we get here, it means we don't have a remote node so get the
	// data from our local db.
	var retValue []byte
	err := gs.GlobalStateDB.View(func(txn *badger.Txn) error {
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
		return nil, fmt.Errorf("Get: Error copying value into new slice: %v", err)
	}

	return retValue, nil
}

type BatchGetRemoteRequest struct {
	KeyList [][]byte
}

type BatchGetRemoteResponse struct {
	ValueList [][]byte
}

func (gs *GlobalState) BatchGetRemote(ww http.ResponseWriter, rr *http.Request) {
	// Parse the request.
	decoder := json.NewDecoder(io.LimitReader(rr.Body, MaxRequestBodySizeBytes))
	requestData := BatchGetRemoteRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("BatchGetRemote: Problem parsing request body: %v", err))
		return
	}

	// Call the get function. Note that this may also proxy to another node.
	values, err := gs.BatchGet(requestData.KeyList)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"BatchGetRemote: Error processing BatchGet: %v", err))
		return
	}

	// Return
	res := BatchGetRemoteResponse{
		ValueList: values,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("BatchGetRemote: Problem encoding response as JSON: %v", err))
		return
	}
}

func (gs *GlobalState) CreateBatchGetRequest(keyList [][]byte) (
	_url string, _json_data []byte, _err error) {

	req := BatchGetRemoteRequest{
		KeyList: keyList,
	}
	json_data, err := json.Marshal(req)
	if err != nil {
		return "", nil, fmt.Errorf("BatchGet: Could not marshal JSON: %v", err)
	}

	url := fmt.Sprintf("%s%s?%s=%s",
		gs.GlobalStateRemoteNode, RoutePathGlobalStateBatchGetRemote,
		GlobalStateSharedSecretParam, gs.GlobalStateRemoteSecret)

	return url, json_data, nil
}

func (gs *GlobalState) BatchGet(keyList [][]byte) (value [][]byte, _err error) {
	// If we have a remote node then use that node to fulfill this request.
	if gs.GlobalStateRemoteNode != "" {
		// TODO: This codepath is currently annoying to test.

		url, json_data, err := gs.CreateBatchGetRequest(keyList)
		if err != nil {
			return nil, fmt.Errorf(
				"BatchGet: Error constructing request: %v", err)
		}

		resReturned, err := http.Post(
			url,
			"application/json", /*contentType*/
			bytes.NewBuffer(json_data))
		if err != nil {
			return nil, fmt.Errorf("BatchGet: Error processing remote request")
		}

		res := BatchGetRemoteResponse{}
		json.NewDecoder(resReturned.Body).Decode(&res)
		resReturned.Body.Close()

		return res.ValueList, nil
	}

	// If we get here, it means we don't have a remote node so get the
	// data from our local db.
	var retValueList [][]byte
	err := gs.GlobalStateDB.View(func(txn *badger.Txn) error {
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
		return nil, fmt.Errorf("BatchGet: Error copying value into new slice: %v", err)
	}

	return retValueList, nil
}

type DeleteRemoteRequest struct {
	Key []byte
}

type DeleteRemoteResponse struct {
}

func (gs *GlobalState) CreateDeleteRequest(key []byte) (
	_url string, _json_data []byte, _err error) {

	req := DeleteRemoteRequest{
		Key: key,
	}
	json_data, err := json.Marshal(req)
	if err != nil {
		return "", nil, fmt.Errorf("Delete: Could not marshal JSON: %v", err)
	}

	url := fmt.Sprintf("%s%s?%s=%s",
		gs.GlobalStateRemoteNode, RoutePathGlobalStateDeleteRemote,
		GlobalStateSharedSecretParam, gs.GlobalStateRemoteSecret)

	return url, json_data, nil
}

func (gs *GlobalState) DeleteRemote(ww http.ResponseWriter, rr *http.Request) {
	// Parse the request.
	decoder := json.NewDecoder(io.LimitReader(rr.Body, MaxRequestBodySizeBytes))
	requestData := DeleteRemoteRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("DeleteRemote: Problem parsing request body: %v", err))
		return
	}

	// Call the Delete function. Note that this may also proxy to another node.
	if err := gs.Delete(requestData.Key); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"DeleteRemote: Error processing Delete: %v", err))
		return
	}

	// Return
	res := DeleteRemoteResponse{}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("DeleteRemote: Problem encoding response as JSON: %v", err))
		return
	}
}

func (gs *GlobalState) Delete(key []byte) error {
	// If we have a remote node then use that node to fulfill this request.
	if gs.GlobalStateRemoteNode != "" {
		// TODO: This codepath is currently annoying to test.

		url, json_data, err := gs.CreateDeleteRequest(key)
		if err != nil {
			return fmt.Errorf("Delete: Could not construct request: %v", err)
		}

		res, err := http.Post(
			url,
			"application/json", /*contentType*/
			bytes.NewBuffer(json_data))
		if err != nil {
			return fmt.Errorf("Delete: Error processing remote request")
		}

		res.Body.Close()
		//res := DeleteRemoteResponse{}
		//json.NewDecoder(resReturned.Body).Decode(&res)

		// No error means nothing to return.
		return nil
	}

	// If we get here, it means we don't have a remote node so store the
	// data in our local db.
	return gs.GlobalStateDB.Update(func(txn *badger.Txn) error {
		return txn.Delete(key)
	})
}

type SeekRemoteRequest struct {
	StartPrefix    []byte
	ValidForPrefix []byte
	MaxKeyLen      int
	NumToFetch     int
	Reverse        bool
	FetchValues    bool
}
type SeekRemoteResponse struct {
	KeysFound [][]byte
	ValsFound [][]byte
}

func (gs *GlobalState) CreateSeekRequest(startPrefix []byte, validForPrefix []byte,
	maxKeyLen int, numToFetch int, reverse bool, fetchValues bool) (
	_url string, _json_data []byte, _err error) {

	req := SeekRemoteRequest{
		StartPrefix:    startPrefix,
		ValidForPrefix: validForPrefix,
		MaxKeyLen:      maxKeyLen,
		NumToFetch:     numToFetch,
		Reverse:        reverse,
		FetchValues:    fetchValues,
	}
	json_data, err := json.Marshal(req)
	if err != nil {
		return "", nil, fmt.Errorf("Seek: Could not marshal JSON: %v", err)
	}

	url := fmt.Sprintf("%s%s?%s=%s",
		gs.GlobalStateRemoteNode, RoutePathGlobalStateSeekRemote,
		GlobalStateSharedSecretParam, gs.GlobalStateRemoteSecret)

	return url, json_data, nil
}

func (gs *GlobalState) GlobalStateSeekRemote(ww http.ResponseWriter, rr *http.Request) {
	// Parse the request.
	decoder := json.NewDecoder(io.LimitReader(rr.Body, MaxRequestBodySizeBytes))
	requestData := SeekRemoteRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GlobalStateSeekRemote: Problem parsing request body: %v", err))
		return
	}

	// Call the get function. Note that this may also proxy to another node.
	keys, values, err := gs.Seek(
		requestData.StartPrefix,
		requestData.ValidForPrefix,
		requestData.MaxKeyLen,
		requestData.NumToFetch,
		requestData.Reverse,
		requestData.FetchValues,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GlobalStateSeekRemote: Error processing Seek: %v", err))
		return
	}

	// Return
	res := SeekRemoteResponse{
		KeysFound: keys,
		ValsFound: values,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GlobalStateSeekRemote: Problem encoding response as JSON: %v", err))
		return
	}
}

func (gs *GlobalState) Seek(startPrefix []byte, validForPrefix []byte,
	maxKeyLen int, numToFetch int, reverse bool, fetchValues bool) (
	_keysFound [][]byte, _valsFound [][]byte, _err error) {

	// If we have a remote node then use that node to fulfill this request.
	if gs.GlobalStateRemoteNode != "" {
		// TODO: This codepath is currently annoying to test.

		url, json_data, err := gs.CreateSeekRequest(
			startPrefix,
			validForPrefix,
			maxKeyLen,
			numToFetch,
			reverse,
			fetchValues)
		if err != nil {
			return nil, nil, fmt.Errorf(
				"Seek: Error constructing request: %v", err)
		}

		resReturned, err := http.Post(
			url,
			"application/json", /*contentType*/
			bytes.NewBuffer(json_data))
		if err != nil {
			return nil, nil, fmt.Errorf("Seek: Error processing remote request")
		}

		res := SeekRemoteResponse{}
		json.NewDecoder(resReturned.Body).Decode(&res)
		resReturned.Body.Close()

		return res.KeysFound, res.ValsFound, nil
	}

	// If we get here, it means we don't have a remote node so get the
	// data from our local db.
	retKeys, retVals, err := lib.DBGetPaginatedKeysAndValuesForPrefix(gs.GlobalStateDB, startPrefix,
		validForPrefix, maxKeyLen, numToFetch, reverse, fetchValues)
	if err != nil {
		return nil, nil, fmt.Errorf("Seek: Error getting paginated keys and values: %v", err)
	}

	return retKeys, retVals, nil
}
