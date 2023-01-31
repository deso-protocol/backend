package routes

import (
	"bytes"
	"encoding/json"
	fmt "fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/btcsuite/btcd/btcec"
	"github.com/deso-protocol/backend/config"
	"github.com/golang-jwt/jwt/v4"
	"github.com/tyler-smith/go-bip39"

	"github.com/deso-protocol/core/lib"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/kevinburke/twilio-go"
	muxtrace "gopkg.in/DataDog/dd-trace-go.v1/contrib/gorilla/mux"
)

const (
	// MaxRequestBodySizeBytes is the maximum size of a request body we will
	// generally be willing to process.
	MaxRequestBodySizeBytes        = 10 * 1e6 // 10M
	SeedInfoCookieKey              = "seed_info_cookie_key"
	TwilioVoipCarrierType          = "voip"
	TwilioCheckPhoneNumberApproved = "approved"
	SafeForLoggingKey              = `safeForLogging`
	SafeForLoggingValue            = "true"
)

const (
	RoutePathSendBitClout            = "/api/v0/send-bitclout"               // Deprecated
	RoutePathGetRecloutsForPost      = "/api/v0/get-reclouts-for-post"       // Deprecated
	RoutePathGetQuoteRecloutsForPost = "/api/v0/get-quote-reclouts-for-post" // Deprecated

	// base.go
	RoutePathHealthCheck      = "/api/v0/health-check"
	RoutePathGetExchangeRate  = "/api/v0/get-exchange-rate"
	RoutePathGetAppState      = "/api/v0/get-app-state"
	RoutePathGetIngressCookie = "/api/v0/get-ingress-cookie"

	// transaction.go
	RoutePathGetTxn                   = "/api/v0/get-txn"
	RoutePathSubmitTransaction        = "/api/v0/submit-transaction"
	RoutePathUpdateProfile            = "/api/v0/update-profile"
	RoutePathExchangeBitcoin          = "/api/v0/exchange-bitcoin"
	RoutePathSendDeSo                 = "/api/v0/send-deso"
	RoutePathSubmitPost               = "/api/v0/submit-post"
	RoutePathCreateFollowTxnStateless = "/api/v0/create-follow-txn-stateless"
	RoutePathCreateLikeStateless      = "/api/v0/create-like-stateless"
	RoutePathBuyOrSellCreatorCoin     = "/api/v0/buy-or-sell-creator-coin"
	RoutePathTransferCreatorCoin      = "/api/v0/transfer-creator-coin"
	RoutePathSendDiamonds             = "/api/v0/send-diamonds"
	RoutePathAuthorizeDerivedKey      = "/api/v0/authorize-derived-key"
	RoutePathDAOCoin                  = "/api/v0/dao-coin"
	RoutePathTransferDAOCoin          = "/api/v0/transfer-dao-coin"
	RoutePathCreateDAOCoinLimitOrder  = "/api/v0/create-dao-coin-limit-order"
	RoutePathCreateDAOCoinMarketOrder = "/api/v0/create-dao-coin-market-order"
	RoutePathCancelDAOCoinLimitOrder  = "/api/v0/cancel-dao-coin-limit-order"
	RoutePathAppendExtraData          = "/api/v0/append-extra-data"
	RoutePathGetTransactionSpending   = "/api/v0/get-transaction-spending"

	RoutePathGetUsersStateless                          = "/api/v0/get-users-stateless"
	RoutePathDeleteIdentities                           = "/api/v0/delete-identities"
	RoutePathGetProfiles                                = "/api/v0/get-profiles"
	RoutePathGetSingleProfile                           = "/api/v0/get-single-profile"
	RoutePathGetSingleProfilePicture                    = "/api/v0/get-single-profile-picture"
	RoutePathGetHodlersForPublicKey                     = "/api/v0/get-hodlers-for-public-key"
	RoutePathGetHodlersCountForPublicKeys               = "/api/v0/get-hodlers-count-for-public-keys"
	RoutePathGetDiamondsForPublicKey                    = "/api/v0/get-diamonds-for-public-key"
	RoutePathGetFollowsStateless                        = "/api/v0/get-follows-stateless"
	RoutePathGetUserGlobalMetadata                      = "/api/v0/get-user-global-metadata"
	RoutePathUpdateUserGlobalMetadata                   = "/api/v0/update-user-global-metadata"
	RoutePathGetNotifications                           = "/api/v0/get-notifications"
	RoutePathGetUnreadNotificationsCount                = "/api/v0/get-unread-notifications-count"
	RoutePathSetNotificationMetadata                    = "/api/v0/set-notification-metadata"
	RoutePathBlockPublicKey                             = "/api/v0/block-public-key"
	RoutePathIsFollowingPublicKey                       = "/api/v0/is-following-public-key"
	RoutePathIsHodlingPublicKey                         = "/api/v0/is-hodling-public-key"
	RoutePathGetUserDerivedKeys                         = "/api/v0/get-user-derived-keys"
	RoutePathGetSingleDerivedKey                        = "/api/v0/get-single-derived-key"
	RoutePathGetTransactionSpendingLimitHexString       = "/api/v0/get-transaction-spending-limit-hex-string"
	RoutePathGetAccessBytes                             = "/api/v0/get-access-bytes"
	RoutePathGetTransactionSpendingLimitResponseFromHex = "/api/v0/get-transaction-spending-limit-response-from-hex"
	RoutePathDeletePII                                  = "/api/v0/delete-pii"
	RoutePathGetUserMetadata                            = "/api/v0/get-user-metadata"
	RoutePathGetUsernameForPublicKey                    = "/api/v0/get-user-name-for-public-key"
	RoutePathGetPublicKeyForUsername                    = "/api/v0/get-public-key-for-user-name"

	// dao_coin_exchange.go
	RoutePathGetDaoCoinLimitOrders           = "/api/v0/get-dao-coin-limit-orders"
	RoutePathGetTransactorDaoCoinLimitOrders = "/api/v0/get-transactor-dao-coin-limit-orders"

	// post.go
	RoutePathGetPostsHashHexList    = "/api/v0/get-posts-hashhexlist"
	RoutePathGetPostsStateless      = "/api/v0/get-posts-stateless"
	RoutePathGetSinglePost          = "/api/v0/get-single-post"
	RoutePathGetLikesForPost        = "/api/v0/get-likes-for-post"
	RoutePathGetDiamondsForPost     = "/api/v0/get-diamonds-for-post"
	RoutePathGetRepostsForPost      = "/api/v0/get-reposts-for-post"
	RoutePathGetQuoteRepostsForPost = "/api/v0/get-quote-reposts-for-post"
	RoutePathGetPostsForPublicKey   = "/api/v0/get-posts-for-public-key"
	RoutePathGetDiamondedPosts      = "/api/v0/get-diamonded-posts"

	// hot_feed.go
	RoutePathGetHotFeed = "/api/v0/get-hot-feed"

	// nft.go
	RoutePathCreateNFT                 = "/api/v0/create-nft"
	RoutePathUpdateNFT                 = "/api/v0/update-nft"
	RoutePathGetNFTsForUser            = "/api/v0/get-nfts-for-user"
	RoutePathGetNFTBidsForUser         = "/api/v0/get-nft-bids-for-user"
	RoutePathCreateNFTBid              = "/api/v0/create-nft-bid"
	RoutePathAcceptNFTBid              = "/api/v0/accept-nft-bid"
	RoutePathGetNFTBidsForNFTPost      = "/api/v0/get-nft-bids-for-nft-post"
	RoutePathGetNFTShowcase            = "/api/v0/get-nft-showcase"
	RoutePathGetNextNFTShowcase        = "/api/v0/get-next-nft-showcase"
	RoutePathGetNFTCollectionSummary   = "/api/v0/get-nft-collection-summary"
	RoutePathGetNFTEntriesForPostHash  = "/api/v0/get-nft-entries-for-nft-post"
	RoutePathGetNFTsCreatedByPublicKey = "/api/v0/get-nfts-created-by-public-key"
	RoutePathTransferNFT               = "/api/v0/transfer-nft"
	RoutePathAcceptNFTTransfer         = "/api/v0/accept-nft-transfer"
	RoutePathBurnNFT                   = "/api/v0/burn-nft"
	RoutePathGetAcceptedBidHistory     = "/api/v0/accepted-bid-history"

	// media.go
	RoutePathUploadImage         = "/api/v0/upload-image"
	RoutePathGetFullTikTokURL    = "/api/v0/get-full-tiktok-url"
	RoutePathUploadVideo         = "/api/v0/upload-video"
	RoutePathGetVideoStatus      = "/api/v0/get-video-status"
	RoutePathGetVideoDimensions  = "/api/v0/get-video-dimensions"
	RoutePathEnableVideoDownload = "/api/v0/enable-video-download"

	// message.go
	RoutePathSendMessageStateless       = "/api/v0/send-message-stateless"
	RoutePathGetMessagesStateless       = "/api/v0/get-messages-stateless"
	RoutePathMarkContactMessagesRead    = "/api/v0/mark-contact-messages-read"
	RoutePathMarkAllMessagesRead        = "/api/v0/mark-all-messages-read"
	RoutePathRegisterMessagingGroupKey  = "/api/v0/register-messaging-group-key"
	RoutePathGetAllMessagingGroupKeys   = "/api/v0/get-all-messaging-group-keys"
	RoutePathCheckPartyMessagingKeys    = "/api/v0/check-party-messaging-keys"
	RoutePathGetBulkMessagingPublicKeys = "/api/v0/get-bulk-messaging-public-keys"

	// verify.go
	RoutePathSendPhoneNumberVerificationText   = "/api/v0/send-phone-number-verification-text"
	RoutePathSubmitPhoneNumberVerificationCode = "/api/v0/submit-phone-number-verification-code"
	RoutePathResendVerifyEmail                 = "/api/v0/resend-verify-email"
	RoutePathVerifyEmail                       = "/api/v0/verify-email"
	RoutePathJumioBegin                        = "/api/v0/jumio-begin"
	RoutePathJumioCallback                     = "/api/v0/jumio-callback"
	RoutePathJumioFlowFinished                 = "/api/v0/jumio-flow-finished"
	RoutePathGetJumioStatusForPublicKey        = "/api/v0/get-jumio-status-for-public-key"

	// tutorial.go
	RoutePathGetTutorialCreators  = "/api/v0/get-tutorial-creators"
	RoutePathStartOrSkipTutorial  = "/api/v0/start-or-skip-tutorial"
	RoutePathUpdateTutorialStatus = "/api/v0/update-tutorial-status"

	// eth.go
	RoutePathSubmitETHTx       = "/api/v0/submit-eth-tx"
	RoutePathMetamaskSignIn    = "/api/v0/send-starter-deso-for-metamask-account"
	RoutePathQueryETHRPC       = "/api/v0/query-eth-rpc"
	RoutePathAdminProcessETHTx = "/api/v0/admin/process-eth-tx"

	// wyre.go
	RoutePathGetWyreWalletOrderQuotation     = "/api/v0/get-wyre-wallet-order-quotation"
	RoutePathGetWyreWalletOrderReservation   = "/api/v0/get-wyre-wallet-order-reservation"
	RoutePathWyreWalletOrderSubscription     = "/api/v0/wyre-wallet-order-subscription"
	RoutePathGetWyreWalletOrdersForPublicKey = "/api/v0/admin/get-wyre-wallet-orders-for-public-key"

	// miner.go
	RoutePathGetBlockTemplate = "/api/v0/get-block-template"
	RoutePathSubmitBlock      = "/api/v0/submit-block"

	// Admin route paths can only be accessed if a user's public key is whitelisted as an admin.

	// admin_node.go
	RoutePathNodeControl          = "/api/v0/admin/node-control"
	RoutePathAdminGetMempoolStats = "/api/v0/admin/get-mempool-stats"

	// admin_buy_deso.go
	RoutePathSetUSDCentsToDeSoReserveExchangeRate = "/api/v0/admin/set-usd-cents-to-deso-reserve-exchange-rate"
	RoutePathGetUSDCentsToDeSoReserveExchangeRate = "/api/v0/admin/get-usd-cents-to-deso-reserve-exchange-rate"
	RoutePathSetBuyDeSoFeeBasisPoints             = "/api/v0/admin/set-buy-deso-fee-basis-points"
	RoutePathGetBuyDeSoFeeBasisPoints             = "/api/v0/admin/get-buy-deso-fee-basis-points"

	// admin_transaction.go
	RoutePathGetGlobalParams                   = "/api/v0/get-global-params"
	RoutePathTestSignTransactionWithDerivedKey = "/api/v0/admin/test-sign-transaction-with-derived-key"

	// Eventually we will deprecate the admin endpoint since it does not need to be protected.
	RoutePathAdminGetGlobalParams = "/api/v0/admin/get-global-params"
	RoutePathUpdateGlobalParams   = "/api/v0/admin/update-global-params"
	RoutePathSwapIdentity         = "/api/v0/admin/swap-identity"

	// admin_user.go
	RoutePathAdminUpdateUserGlobalMetadata         = "/api/v0/admin/update-user-global-metadata"
	RoutePathAdminGetAllUserGlobalMetadata         = "/api/v0/admin/get-all-user-global-metadata"
	RoutePathAdminGetUserGlobalMetadata            = "/api/v0/admin/get-user-global-metadata"
	RoutePathAdminGrantVerificationBadge           = "/api/v0/admin/grant-verification-badge"
	RoutePathAdminRemoveVerificationBadge          = "/api/v0/admin/remove-verification-badge"
	RoutePathAdminGetVerifiedUsers                 = "/api/v0/admin/get-verified-users"
	RoutePathAdminGetUsernameVerificationAuditLogs = "/api/v0/admin/get-username-verification-audit-logs"
	RoutePathAdminGetUserAdminData                 = "/api/v0/admin/get-user-admin-data"
	RoutePathAdminResetPhoneNumber                 = "/api/v0/admin/reset-phone-number"

	// admin_feed.go
	RoutePathAdminUpdateGlobalFeed = "/api/v0/admin/update-global-feed"
	RoutePathAdminPinPost          = "/api/v0/admin/pin-post"
	RoutePathAdminRemoveNilPosts   = "/api/v0/admin/remove-nil-posts"

	// hot_feed.go
	RoutePathAdminGetUnfilteredHotFeed        = "/api/v0/admin/get-unfiltered-hot-feed"
	RoutePathAdminGetHotFeedAlgorithm         = "/api/v0/admin/get-hot-feed-algorithm"
	RoutePathAdminUpdateHotFeedAlgorithm      = "/api/v0/admin/update-hot-feed-algorithm"
	RoutePathAdminUpdateHotFeedPostMultiplier = "/api/v0/admin/update-hot-feed-post-multiplier"
	RoutePathAdminUpdateHotFeedUserMultiplier = "/api/v0/admin/update-hot-feed-user-multiplier"
	RoutePathAdminGetHotFeedUserMultiplier    = "/api/v0/admin/get-hot-feed-user-multiplier"

	// admin_fees.go
	RoutePathAdminSetTransactionFeeForTransactionType = "/api/v0/admin/set-txn-fee-for-txn-type"
	RoutePathAdminSetAllTransactionFees               = "/api/v0/admin/set-all-txn-fees"
	RoutePathAdminGetTransactionFeeMap                = "/api/v0/admin/get-transaction-fee-map"
	RoutePathAdminAddExemptPublicKey                  = "/api/v0/admin/add-exempt-public-key"
	RoutePathAdminGetExemptPublicKeys                 = "/api/v0/admin/get-exempt-public-keys"

	// admin_nft.go
	RoutePathAdminGetNFTDrop    = "/api/v0/admin/get-nft-drop"
	RoutePathAdminUpdateNFTDrop = "/api/v0/admin/update-nft-drop"

	// admin_jumio.go
	RoutePathAdminResetJumioForPublicKey          = "/api/v0/admin/reset-jumio-for-public-key"
	RoutePathAdminUpdateJumioDeSo                 = "/api/v0/admin/update-jumio-deso"
	RoutePathAdminUpdateJumioUSDCents             = "/api/v0/admin/update-jumio-usd-cents"
	RoutePathAdminUpdateJumioKickbackUSDCents     = "/api/v0/admin/update-jumio-kickback-usd-cents"
	RoutePathAdminJumioCallback                   = "/api/v0/admin/jumio-callback"
	RoutePathAdminUpdateJumioCountrySignUpBonus   = "/api/v0/admin/update-jumio-country-sign-up-bonus"
	RoutePathAdminGetAllCountryLevelSignUpBonuses = "/api/v0/admin/get-all-country-level-sign-up-bonuses"

	// admin_referrals.go
	RoutePathAdminCreateReferralHash        = "/api/v0/admin/create-referral-hash"
	RoutePathAdminGetAllReferralInfoForUser = "/api/v0/admin/get-all-referral-info-for-user"
	RoutePathAdminUpdateReferralHash        = "/api/v0/admin/update-referral-hash"
	RoutePathAdminUploadReferralCSV         = "/api/v0/admin/upload-referral-csv"
	RoutePathAdminDownloadReferralCSV       = "/api/v0/admin/download-referral-csv"
	RoutePathAdminDownloadRefereeCSV        = "/api/v0/admin/download-referee-csv"

	// referrals.go
	RoutePathGetReferralInfoForUser         = "/api/v0/get-referral-info-for-user"
	RoutePathGetReferralInfoForReferralHash = "/api/v0/get-referral-info-for-referral-hash"

	// admin_tutorial.go
	RoutePathAdminUpdateTutorialCreators = "/api/v0/admin/update-tutorial-creators"
	RoutePathAdminResetTutorialStatus    = "/api/v0/admin/reset-tutorial-status"
	RoutePathAdminGetTutorialCreators    = "/api/v0/admin/get-tutorial-creators"

	// expose_global_state.go
	RoutePathGetVerifiedUsernames     = "/api/v0/get-verified-usernames"
	RoutePathGetBlacklistedPublicKeys = "/api/v0/get-blacklisted-public-keys"
	RoutePathGetGraylistedPublicKeys  = "/api/v0/get-graylisted-public-keys"
	RoutePathGetGlobalFeed            = "/api/v0/get-global-feed"

	// supply.go
	RoutePathGetTotalSupply       = "/api/v0/total-supply"
	RoutePathGetRichList          = "/api/v0/rich-list"
	RoutePathGetCountKeysWithDESO = "/api/v0/count-keys-with-deso"

	// access_group.go
	RoutePathCreateAccessGroup                = "/api/v0/create-access-group"
	RoutePathUpdateAccessGroup                = "/api/v0/update-access-group"
	RoutePathAddAccessGroupMembers            = "/api/v0/add-access-group-members"
	RoutePathRemoveAccessGroupMembers         = "/api/v0/remove-access-group-members"
	RoutePathUpdateAccessGroupMembers         = "/api/v0/update-access-group-members"
	RoutePathGetAllUserAccessGroups           = "/api/v0/get-all-user-access-groups"
	RoutePathGetAllUserAccessGroupsOwned      = "/api/v0/get-all-user-access-groups-owned"
	RoutePathGetAllUserAccessGroupsMemberOnly = "/api/v0/get-all-user-access-groups-member-only"
	RoutePathCheckPartyAccessGroups           = "/api/v0/check-party-access-groups"
	RoutePathGetAccessGroupInfo               = "/api/v0/get-access-group-info"
	RoutePathGetAccessGroupMemberInfo         = "/api/v0/get-access-group-member-info"
	RoutePathGetPaginatedAccessGroupMembers   = "/api/v0/get-paginated-access-group-members"
	RoutePathGetBulkAccessGroupEntries        = "/api/v0/get-bulk-access-group-entries"

	// new_message.go
	RoutePathSendDmMessage                             = "/api/v0/send-dm-message"
	RoutePathUpdateDmMessage                           = "/api/v0/update-dm-message"
	RoutePathSendGroupChatMessage                      = "/api/v0/send-group-chat-message"
	RoutePathUpdateGroupChatMessage                    = "/api/v0/update-group-chat-message"
	RoutePathGetUserDmThreadsOrderedByTimestamp        = "/api/v0/get-user-dm-threads-ordered-by-timestamp"
	RoutePathGetPaginatedMessagesForDmThread           = "/api/v0/get-paginated-messages-for-dm-thread"
	RoutePathGetUserGroupChatThreadsOrderedByTimestamp = "/api/v0/get-user-group-chat-threads-ordered-by-timestamp"
	RoutePathGetPaginatedMessagesForGroupChatThread    = "/api/v0/get-paginated-messages-for-group-chat-thread"
	RoutePathGetAllUserMessageThreads                  = "/api/v0/get-all-user-message-threads"

	// associations.go
	RoutePathUserAssociations = "/api/v0/user-associations"
	RoutePathPostAssociations = "/api/v0/post-associations"

	// snapshot.go
	RoutePathSnapshotEpochMetadata = "/api/v0/snapshot-epoch-metadata"
	RoutePathStateChecksum         = "/api/v0/state-checksum"
)

// APIServer provides the interface between the blockchain and things like the
// web UI. In particular, it exposes a JSON API that can be used to do everything the
// frontend cares about, from posts to profiles to purchasing DeSo with Bitcoin.
type APIServer struct {
	backendServer *lib.Server
	mempool       *lib.DeSoMempool
	blockchain    *lib.Blockchain
	blockProducer *lib.DeSoBlockProducer
	Params        *lib.DeSoParams
	Config        *config.Config

	MinFeeRateNanosPerKB uint64

	// A pointer to the router that handles all requests.
	router *muxtrace.Router

	TXIndex *lib.TXIndex

	// Used for getting/setting the global state. Usually either a db is set OR
	// a remote node is set-- not both. When a remote node is set, global state
	// is set and fetched from that node. Otherwise, it is set/fetched from the
	// db. This makes it easy to run a local node in development.
	GlobalState *GlobalState

	// Optional, may be empty. Used for Twilio integration
	Twilio *twilio.Client

	// When set, BlockCypher is used to add extra security to BitcoinExchange
	// transactions.
	BlockCypherAPIKey string

	// This lock is used when sending seed DeSo to avoid a race condition
	// in which two calls to sending the seed DeSo use the same UTXO,
	// causing one to error.
	mtxSeedDeSo sync.RWMutex

	UsdCentsPerDeSoExchangeRate    uint64
	UsdCentsPerBitCoinExchangeRate float64
	UsdCentsPerETHExchangeRate     uint64

	// List of prices retrieved.  This is culled everytime we update the current price.
	LastTradeDeSoPriceHistory []LastTradePriceHistoryItem
	// How far back do we consider trade prices when we set the current price of $DESO in nanoseconds
	LastTradePriceLookback uint64

	// most recent exchange prices fetched
	MostRecentCoinbasePriceUSDCents         uint64
	MostRecentBlockchainDotComPriceUSDCents uint64

	// Base-58 prefix to check for to determine if a string could be a public key.
	PublicKeyBase58Prefix string

	// A list of posts from the specified look-back period ordered by hotness score.
	HotFeedOrderedList []*HotFeedEntry
	// A map version of HotFeedOrderedList mapping each post to its hotness score for the tag feed and post age.
	HotFeedPostHashToTagScoreMap map[lib.BlockHash]*HotnessPostInfo
	// An in-memory map from post hash to post tags. This is used to cache tags to prevent hot feed algorithm from
	// continuously parsing the text body from already processed posts.
	PostHashToPostTagsMap map[lib.BlockHash][]string
	// An in-memory map from post tag to post hash. This allows us to
	// quickly get all the posts for a particular group.
	// This is represented as a map of strings to a set of post hashes. A set is used instead of an array to allow for
	// quicker de-duplication checks.
	PostTagToPostHashesMap map[string]map[lib.BlockHash]bool
	// For each tag, store ordered slice of post hashes based on hot feed ranking.
	PostTagToOrderedHotFeedEntries map[string][]*HotFeedEntry
	// For each tag, store ordered slice of post hashes based on newness.
	PostTagToOrderedNewestEntries map[string][]*HotFeedEntry
	// The height of the last block evaluated by the hotness routine.
	HotFeedBlockHeight uint32
	// A cache to store blocks for the block feed - in order to reduce processing time.
	HotFeedBlockCache map[lib.BlockHash]*lib.MsgDeSoBlock
	// Map of whitelisted post hashes used for serving the hot feed.
	// The float64 value is a multiplier than can be modified and used in scoring.
	HotFeedApprovedPostsToMultipliers             map[lib.BlockHash]float64
	LastHotFeedApprovedPostOpProcessedTstampNanos uint64
	// Multipliers applied to individual PKIDs to help node operators better fit their
	// hot feed to the type of content they would like to display.
	HotFeedPKIDMultipliers                          map[lib.PKID]*HotFeedPKIDMultiplier
	LastHotFeedPKIDMultiplierOpProcessedTstampNanos uint64
	// Constants for the hotness score algorithm.
	HotFeedInteractionCap        uint64
	HotFeedTagInteractionCap     uint64
	HotFeedTimeDecayBlocks       uint64
	HotFeedTagTimeDecayBlocks    uint64
	HotFeedTxnTypeMultiplierMap  map[lib.TxnType]uint64
	HotFeedPostMultiplierUpdated bool
	HotFeedPKIDMultiplierUpdated bool

	//Map of transaction type to []*lib.DeSoOutput that represent fees assessed on each transaction of that type.
	TransactionFeeMap map[lib.TxnType][]*lib.DeSoOutput

	// Map of public keys that are exempt from node fees
	ExemptPublicKeyMap map[string]interface{}

	// Global State cache

	// VerifiedUsernameToPKIDMap is a map of lowercase usernames to PKIDs representing the current state of
	// verifications this node is recognizing.
	VerifiedUsernameToPKIDMap map[string]*lib.PKID
	// BlacklistedPKIDMap is a map of PKID to a byte slice representing the PKID of a user as the key and the current
	// blacklist state of that user as the key. If a PKID is not present in this map, then the user is NOT blacklisted.
	BlacklistedPKIDMap map[lib.PKID][]byte
	// BlacklistedResponseMap is a map of PKIDs converted to base58-encoded string to a byte slice. This is computed
	// from the BlacklistedPKIDMap above and is a JSON-encodable version of that map. This map is only used when
	// responding to requests for this node's blacklist. A JSON-encoded response is easier for any language to digest
	// than a gob-encoded one.
	BlacklistedResponseMap map[string][]byte
	// GraylistedPKIDMap is a map of PKID to a byte slice representing the PKID of a user as the key and the current
	// graylist state of that user as the key. If a PKID is not present in this map, then the user is NOT graylisted.
	GraylistedPKIDMap map[lib.PKID][]byte
	// GraylistedResponseMap is a map of PKIDs converted to base58-encoded string to a byte slice. This is computed
	// from the GraylistedPKIDMap above and is a JSON-encodable version of that map. This map is only used when
	// responding to requests for this node's graylist. A JSON-encoded response is easier for any language to digest
	// than a gob-encoded one.
	GraylistedResponseMap map[string][]byte
	// GlobalFeedPostHashes is a slice of BlockHashes representing an ordered state of post hashes on the global feed on
	// this node.
	GlobalFeedPostHashes []*lib.BlockHash
	// GlobalFeedPostEntries is a slice of PostEntries representing an ordered state of PostEntries on the global feed
	// on this node. It is computed from the GlobalFeedPostHashes above.
	GlobalFeedPostEntries []*lib.PostEntry

	// Cache of Total Supply and Rich List
	TotalSupplyNanos  uint64
	TotalSupplyDESO   float64
	RichList          []RichListEntryResponse
	CountKeysWithDESO uint64

	// map of country name to sign up bonus data
	AllCountryLevelSignUpBonuses map[string]CountrySignUpBonusResponse

	// Frequently accessed data from global state
	USDCentsToDESOReserveExchangeRate uint64
	BuyDESOFeeBasisPoints             uint64
	JumioUSDCents                     uint64
	JumioKickbackUSDCents             uint64

	// Public keys that need their balances monitored. Map of Label to Public key
	PublicKeyBalancesToMonitor map[string]string

	// Signals that the frontend server is in a stopped state
	quit chan struct{}
}

type LastTradePriceHistoryItem struct {
	LastTradePrice uint64
	Timestamp      uint64
}

// NewAPIServer ...
func NewAPIServer(
	_backendServer *lib.Server,
	_mempool *lib.DeSoMempool,
	_blockchain *lib.Blockchain,
	_blockProducer *lib.DeSoBlockProducer,
	txIndex *lib.TXIndex,
	params *lib.DeSoParams,
	config *config.Config,
	minFeeRateNanosPerKB uint64,
	globalStateDB *badger.DB,
	twilio *twilio.Client,
	blockCypherAPIKey string,
) (*APIServer, error) {

	globalState := &GlobalState{
		GlobalStateRemoteSecret: config.GlobalStateRemoteSecret,
		GlobalStateRemoteNode:   config.GlobalStateRemoteNode,
		GlobalStateDB:           globalStateDB,
	}

	if globalStateDB == nil && globalState.GlobalStateRemoteNode == "" {
		return nil, fmt.Errorf(
			"NewAPIServer: Error: A globalStateDB or a globalStateRemoteNode is required")
	}

	publicKeyBase58Prefix := lib.Base58CheckEncode(make([]byte, btcec.PubKeyBytesLenCompressed), false, params)[0:3]

	fes := &APIServer{
		// TODO: It would be great if we could eliminate the dependency on
		// the backendServer. Right now it's here because it was the easiest
		// way to give the APIServer the ability to add transactions
		// to the mempool and relay them to peers.
		backendServer:             _backendServer,
		mempool:                   _mempool,
		blockchain:                _blockchain,
		blockProducer:             _blockProducer,
		TXIndex:                   txIndex,
		Params:                    params,
		Config:                    config,
		Twilio:                    twilio,
		BlockCypherAPIKey:         blockCypherAPIKey,
		GlobalState:               globalState,
		LastTradeDeSoPriceHistory: []LastTradePriceHistoryItem{},
		PublicKeyBase58Prefix:     publicKeyBase58Prefix,
		// We consider last trade prices from the last hour when determining the current price of DeSo.
		// This helps prevents attacks that attempt to purchase $DESO at below market value.
		LastTradePriceLookback:       uint64(time.Hour.Nanoseconds()),
		AllCountryLevelSignUpBonuses: make(map[string]CountrySignUpBonusResponse),
		quit:                         make(chan struct{}),
	}

	fes.StartSeedBalancesMonitoring()

	// Call this once upon starting server to ensure we have a good initial value
	fes.UpdateUSDCentsToDeSoExchangeRate()
	fes.UpdateUSDToBTCPrice()
	fes.UpdateUSDToETHPrice()

	// Get the transaction fee map from global state if it exists
	fes.TransactionFeeMap = fes.GetTransactionFeeMapFromGlobalState()

	fes.ExemptPublicKeyMap = fes.GetExemptPublicKeyMapFromGlobalState()

	// Then monitor them
	fes.StartExchangePriceMonitoring()

	if fes.Config.RunHotFeedRoutine {
		fes.StartHotFeedRoutine()
	}

	if fes.Config.RunSupplyMonitoringRoutine {
		fes.StartSupplyMonitoring()
		fes.UpdateSupplyStats()
	}

	fes.SetGlobalStateCache()
	// Kick off Global State Monitoring to set up cache of Verified Username, Blacklist, and Graylist.
	fes.StartGlobalStateMonitoring()

	return fes, nil
}

type AccessLevel int

const (
	PublicAccess AccessLevel = iota
	AdminAccess
	SuperAdminAccess
)

// Route ...
type Route struct {
	Name        string
	Method      []string
	Pattern     string
	HandlerFunc http.HandlerFunc
	AccessLevel AccessLevel
}

// InitRoutes ...
// Note: Be very careful when editing existing routes in this list.
// This *must* be kept in-sync with the backend-api.service.ts file in the
// frontend code. If not, then requests will fail.
func (fes *APIServer) NewRouter() *muxtrace.Router {
	var FrontendRoutes = []Route{
		// Deprecated
		{
			"SendBitClout",
			[]string{"POST", "OPTIONS"},
			RoutePathSendBitClout,
			fes.SendDeSo,
			PublicAccess,
		},
		{
			"GetRecloutsForPost",
			[]string{"POST", "OPTIONS"},
			RoutePathGetRecloutsForPost,
			fes.GetRepostsForPost,
			PublicAccess,
		},
		{
			"GetQuoteRecloutsForPost",
			[]string{"POST", "OPTIONS"},
			RoutePathGetQuoteRecloutsForPost,
			fes.GetQuoteRepostsForPost,
			PublicAccess,
		},

		{
			"Index",
			[]string{"GET"},
			"/",
			fes.Index,
			PublicAccess,
		},

		{
			"HealthCheck",
			[]string{"GET"},
			RoutePathHealthCheck,
			fes.HealthCheck,
			PublicAccess,
		},

		// Routes for populating various UI elements.
		{
			"GetExchangeRate",
			[]string{"GET"},
			RoutePathGetExchangeRate,
			fes.GetExchangeRate,
			PublicAccess,
		},
		{
			"GetGlobalParams",
			[]string{"POST", "OPTIONS"},
			RoutePathGetGlobalParams,
			fes.GetGlobalParams,
			PublicAccess,
		},
		// Route for sending DeSo
		{
			"SendDeSo",
			[]string{"POST", "OPTIONS"},
			RoutePathSendDeSo,
			fes.SendDeSo,
			PublicAccess,
		},
		// Route for exchanging Bitcoin for DeSo
		{
			"ExchangeBitcoin",
			[]string{"POST", "OPTIONS"},
			RoutePathExchangeBitcoin,
			fes.ExchangeBitcoinStateless,
			PublicAccess,
		},

		// Route for submitting signed transactions for network broadcast
		{
			"SubmitTransaction",
			[]string{"POST", "OPTIONS"},
			RoutePathSubmitTransaction,
			fes.SubmitTransaction,
			PublicAccess,
		},

		// Temporary route to wipe seedinfo cookies
		{
			"DeleteIdentities",
			[]string{"POST", "OPTIONS"},
			RoutePathDeleteIdentities,
			fes.DeleteIdentities,
			PublicAccess,
		},
		// Endpoint to trigger granting a user a verified badge

		// The new DeSo endpoints start here.
		{
			"GetUsersStateless",
			[]string{"POST", "OPTIONS"},
			RoutePathGetUsersStateless,
			fes.GetUsersStateless,
			PublicAccess,
		},
		{
			"SendPhoneNumberVerificationText",
			[]string{"POST", "OPTIONS"},
			RoutePathSendPhoneNumberVerificationText,
			fes.SendPhoneNumberVerificationText,
			PublicAccess,
		},
		{
			"SubmitPhoneNumberVerificationCode",
			[]string{"POST", "OPTIONS"},
			RoutePathSubmitPhoneNumberVerificationCode,
			fes.SubmitPhoneNumberVerificationCode,
			PublicAccess,
		},
		{
			"UploadImage",
			[]string{"POST", "OPTIONS"},
			RoutePathUploadImage,
			fes.UploadImage,
			PublicAccess,
		},
		{
			"SubmitPost",
			[]string{"POST", "OPTIONS"},
			RoutePathSubmitPost,
			fes.SubmitPost,
			PublicAccess,
		},
		{
			"PostsHashHexList",
			[]string{"POST", "OPTIONS"},
			RoutePathGetPostsHashHexList,
			fes.GetPostsHashHexList,
			PublicAccess,
		},
		{
			"GetPostsStateless",
			[]string{"POST", "OPTIONS"},
			RoutePathGetPostsStateless,
			fes.GetPostsStateless,
			// CheckSecret: No need to check the secret since this is a read-only endpoint.
			PublicAccess,
		},
		{
			"UpdateProfile",
			[]string{"POST", "OPTIONS"},
			RoutePathUpdateProfile,
			fes.UpdateProfile,
			PublicAccess,
		},
		{
			"GetProfiles",
			[]string{"POST", "OPTIONS"},
			RoutePathGetProfiles,
			fes.GetProfiles,
			// CheckSecret: No need to check the secret since this is a read-only endpoint.
			PublicAccess,
		},
		{
			"GetSingleProfile",
			[]string{"POST", "OPTIONS"},
			RoutePathGetSingleProfile,
			fes.GetSingleProfile,
			PublicAccess,
		},
		{
			"GetSingleProfilePicture",
			[]string{"GET"},
			RoutePathGetSingleProfilePicture + "/{publicKeyBase58Check:[0-9a-zA-Z]{54,55}}",
			fes.GetSingleProfilePicture,
			PublicAccess,
		},
		{
			"GetPostsForPublicKey",
			[]string{"POST", "OPTIONS"},
			RoutePathGetPostsForPublicKey,
			fes.GetPostsForPublicKey,
			PublicAccess,
		},
		{
			"GetDiamondsForPublicKey",
			[]string{"POST", "OPTIONS"},
			RoutePathGetDiamondsForPublicKey,
			fes.GetDiamondsForPublicKey,
			PublicAccess,
		},
		{
			"GetDiamondedPosts",
			[]string{"POST", "OPTIONS"},
			RoutePathGetDiamondedPosts,
			fes.GetDiamondedPosts,
			PublicAccess,
		},
		{
			"GetHotFeed",
			[]string{"POST", "OPTIONS"},
			RoutePathGetHotFeed,
			fes.GetHotFeed,
			PublicAccess,
		},
		{
			"CreateNFT",
			[]string{"POST", "OPTIONS"},
			RoutePathCreateNFT,
			fes.CreateNFT,
			PublicAccess,
		},
		{
			"TransferNFT",
			[]string{"POST", "OPTIONS"},
			RoutePathTransferNFT,
			fes.TransferNFT,
			PublicAccess,
		},
		{
			"AcceptNFTTransfer",
			[]string{"POST", "OPTIONS"},
			RoutePathAcceptNFTTransfer,
			fes.AcceptNFTTransfer,
			PublicAccess,
		},
		{
			"BurnNFT",
			[]string{"POST", "OPTIONS"},
			RoutePathBurnNFT,
			fes.BurnNFT,
			PublicAccess,
		},
		{
			"GetAcceptedBidHistory",
			[]string{"GET"},
			RoutePathGetAcceptedBidHistory + "/{postHashHex:[0-9a-zA-Z]{64}}",
			fes.GetAcceptedBidHistory,
			PublicAccess,
		},
		{
			"UpdateNFT",
			[]string{"POST", "OPTIONS"},
			RoutePathUpdateNFT,
			fes.UpdateNFT,
			PublicAccess,
		},
		{
			"CreateNFTBid",
			[]string{"POST", "OPTIONS"},
			RoutePathCreateNFTBid,
			fes.CreateNFTBid,
			PublicAccess,
		},
		{
			"AcceptNFTBid",
			[]string{"POST", "OPTIONS"},
			RoutePathAcceptNFTBid,
			fes.AcceptNFTBid,
			PublicAccess,
		},
		{
			"GetNFTBidsForNFTPost",
			[]string{"POST", "OPTIONS"},
			RoutePathGetNFTBidsForNFTPost,
			fes.GetNFTBidsForNFTPost,
			PublicAccess,
		},
		{
			"GetNFTShowcase",
			[]string{"POST", "OPTIONS"},
			RoutePathGetNFTShowcase,
			fes.GetNFTShowcase,
			PublicAccess,
		},
		{
			"GetNextNFTShowcase",
			[]string{"POST", "OPTIONS"},
			RoutePathGetNextNFTShowcase,
			fes.GetNextNFTShowcase,
			PublicAccess,
		},
		{
			"GetNFTsForUser",
			[]string{"POST", "OPTIONS"},
			RoutePathGetNFTsForUser,
			fes.GetNFTsForUser,
			PublicAccess,
		},
		{
			"GetNFTBidsForUser",
			[]string{"POST", "OPTIONS"},
			RoutePathGetNFTBidsForUser,
			fes.GetNFTBidsForUser,
			PublicAccess,
		},
		{
			"GetNFTCollectionSummary",
			[]string{"POST", "OPTIONS"},
			RoutePathGetNFTCollectionSummary,
			fes.GetNFTCollectionSummary,
			PublicAccess,
		},
		{
			"GetNFTEntriesForPostHash",
			[]string{"POST", "OPTIONS"},
			RoutePathGetNFTEntriesForPostHash,
			fes.GetNFTEntriesForPostHash,
			PublicAccess,
		},
		{
			"GetNFTsCreatedByPublicKey",
			[]string{"POST", "OPTIONS"},
			RoutePathGetNFTsCreatedByPublicKey,
			fes.GetNFTsCreatedByPublicKey,
			PublicAccess,
		},
		{
			"GetHodlersForPublicKey",
			[]string{"POST", "OPTIONS"},
			RoutePathGetHodlersForPublicKey,
			fes.GetHodlersForPublicKey,
			PublicAccess,
		},
		{
			"GetHodlersCountForPublicKeys",
			[]string{"POST", "OPTIONS"},
			RoutePathGetHodlersCountForPublicKeys,
			fes.GetHodlersCountForPublicKeys,
			PublicAccess,
		},
		{
			"GetFollowsStateless",
			[]string{"POST", "OPTIONS"},
			RoutePathGetFollowsStateless,
			fes.GetFollowsStateless,
			PublicAccess,
		},
		{
			"CreateFollowTxnStateless",
			[]string{"POST", "OPTIONS"},
			RoutePathCreateFollowTxnStateless,
			fes.CreateFollowTxnStateless,
			PublicAccess,
		},
		{
			"CreateLikeStateless",
			[]string{"POST", "OPTIONS"},
			RoutePathCreateLikeStateless,
			fes.CreateLikeStateless,
			PublicAccess,
		},
		{
			"BuyOrSellCreatorCoin",
			[]string{"POST", "OPTIONS"},
			RoutePathBuyOrSellCreatorCoin,
			fes.BuyOrSellCreatorCoin,
			PublicAccess,
		},
		{
			"TransferCreatorCoin",
			[]string{"POST", "OPTIONS"},
			RoutePathTransferCreatorCoin,
			fes.TransferCreatorCoin,
			PublicAccess,
		},
		{
			"SendDiamonds",
			[]string{"POST", "OPTIONS"},
			RoutePathSendDiamonds,
			fes.SendDiamonds,
			PublicAccess,
		},
		{
			"AuthorizeDerivedKey",
			[]string{"POST", "OPTIONS"},
			RoutePathAuthorizeDerivedKey,
			fes.AuthorizeDerivedKey,
			PublicAccess,
		},
		{
			"DAOCoin",
			[]string{"POST", "OPTIONS"},
			RoutePathDAOCoin,
			fes.DAOCoin,
			PublicAccess,
		},
		{
			"TransferDAOCoin",
			[]string{"POST", "OPTIONS"},
			RoutePathTransferDAOCoin,
			fes.TransferDAOCoin,
			PublicAccess,
		},
		{
			"CreateDAOCoinLimitOrder",
			[]string{"POST", "OPTIONS"},
			RoutePathCreateDAOCoinLimitOrder,
			fes.CreateDAOCoinLimitOrder,
			PublicAccess,
		},
		{
			"CreateDAOCoinMarketOrder",
			[]string{"POST", "OPTIONS"},
			RoutePathCreateDAOCoinMarketOrder,
			fes.CreateDAOCoinMarketOrder,
			PublicAccess,
		},
		{
			"CancelDAOCoinLimitOrder",
			[]string{"POST", "OPTIONS"},
			RoutePathCancelDAOCoinLimitOrder,
			fes.CancelDAOCoinLimitOrder,
			PublicAccess,
		},
		{
			"AppendExtraData",
			[]string{"POST", "OPTIONS"},
			RoutePathAppendExtraData,
			fes.AppendExtraData,
			PublicAccess,
		},
		{
			"GetTransactionSpending",
			[]string{"POST", "OPTIONS"},
			RoutePathGetTransactionSpending,
			fes.GetTransactionSpending,
			PublicAccess,
		},
		{
			"GetNotifications",
			[]string{"POST", "OPTIONS"},
			RoutePathGetNotifications,
			fes.GetNotifications,
			PublicAccess,
		},
		{
			"GetUnreadNotificationsCount",
			[]string{"POST", "OPTIONS"},
			RoutePathGetUnreadNotificationsCount,
			fes.GetNotificationsCount,
			PublicAccess,
		},
		{
			"SetNotificationMetadata",
			[]string{"POST", "OPTIONS"},
			RoutePathSetNotificationMetadata,
			fes.SetNotificationMetadata,
			PublicAccess,
		},
		{
			"GetAppState",
			[]string{"POST", "OPTIONS"},
			RoutePathGetAppState,
			fes.GetAppState,
			PublicAccess,
		},
		{
			"GetIngressCookie",
			[]string{"GET"},
			RoutePathGetIngressCookie,
			fes.GetIngressCookie,
			PublicAccess,
		},
		{
			"UpdateUserGlobalMetadata",
			[]string{"POST", "OPTIONS"},
			RoutePathUpdateUserGlobalMetadata,
			fes.UpdateUserGlobalMetadata,
			PublicAccess,
		},
		{
			"GetUserGlobalMetadata",
			[]string{"POST", "OPTIONS"},
			RoutePathGetUserGlobalMetadata,
			fes.GetUserGlobalMetadata,
			PublicAccess,
		},
		{
			"GetSinglePost",
			[]string{"POST", "OPTIONS"},
			RoutePathGetSinglePost,
			fes.GetSinglePost,
			PublicAccess,
		},
		{
			"BlockPublicKey",
			[]string{"POST", "OPTIONS"},
			RoutePathBlockPublicKey,
			fes.BlockPublicKey,
			PublicAccess,
		},
		{
			"BlockGetTxn",
			[]string{"POST", "OPTIONS"},
			RoutePathGetTxn,
			fes.GetTxn,
			PublicAccess,
		},
		{
			"IsFollowingPublicKey",
			[]string{"POST", "OPTIONS"},
			RoutePathIsFollowingPublicKey,
			fes.IsFollowingPublicKey,
			PublicAccess,
		},
		{
			"IsHodlingPublicKey",
			[]string{"POST", "OPTIONS"},
			RoutePathIsHodlingPublicKey,
			fes.IsHodlingPublicKey,
			PublicAccess,
		},
		{
			"StartOrSkipTutorial",
			[]string{"POST", "OPTIONS"},
			RoutePathStartOrSkipTutorial,
			fes.StartOrSkipTutorial,
			PublicAccess,
		},
		{
			"ResendVerifyEmail",
			[]string{"POST", "OPTIONS"},
			RoutePathResendVerifyEmail,
			fes.ResendVerifyEmail,
			PublicAccess,
		},
		{
			"VerifyEmail",
			[]string{"POST", "OPTIONS"},
			RoutePathVerifyEmail,
			fes.VerifyEmail,
			PublicAccess,
		},
		{
			"GetUserDerivedKeys",
			[]string{"POST", "OPTIONS"},
			RoutePathGetUserDerivedKeys,
			fes.GetUserDerivedKeys,
			PublicAccess,
		},
		{
			"GetSingleDerivedKey",
			[]string{"GET"},
			RoutePathGetSingleDerivedKey + "/{ownerPublicKeyBase58Check:[0-9a-zA-Z]{54,55}}/{derivedPublicKeyBase58Check:[0-9a-zA-Z]{54,55}}",
			fes.GetSingleDerivedKey,
			PublicAccess,
		},
		{
			"GetTransactionSpendingLimitHexString",
			[]string{"POST", "OPTIONS"},
			RoutePathGetTransactionSpendingLimitHexString,
			fes.GetTransactionSpendingLimitHexString,
			PublicAccess,
		},
		{
			"GetAccessBytes",
			[]string{"POST", "OPTIONS"},
			RoutePathGetAccessBytes,
			fes.GetAccessBytes,
			PublicAccess,
		},
		{
			"GetTransactionSpendingLimitResponseFromHex",
			[]string{"GET"},
			RoutePathGetTransactionSpendingLimitResponseFromHex + "/{transactionSpendingLimitHex:[a-fA-F0-9]+$}",
			fes.GetTransactionSpendingLimitResponseFromHex,
			PublicAccess,
		},
		{
			"DeletePII",
			[]string{"POST", "OPTIONS"},
			RoutePathDeletePII,
			fes.DeletePII,
			PublicAccess,
		},
		{
			"GetUserMetadata",
			[]string{"GET"},
			RoutePathGetUserMetadata + "/{publicKeyBase58Check:[0-9a-zA-Z]{54,55}}",
			fes.GetUserMetadata,
			PublicAccess,
		},
		{
			"GetUsernameForPublicKey",
			[]string{"GET"},
			RoutePathGetUsernameForPublicKey + "/{publicKeyBase58Check:[0-9a-zA-Z]{54,55}}",
			fes.GetUsernameForPublicKey,
			PublicAccess,
		},
		{
			"GetPublicKeyForUsername",
			[]string{"GET"},
			RoutePathGetPublicKeyForUsername + "/{username:[a-zA-Z0-9_]{1,26}",
			fes.GetPublicKeyForUsername,
			PublicAccess,
		},
		{
			"GetDAOCoinLimitOrders",
			[]string{"POST", "OPTIONS"},
			RoutePathGetDaoCoinLimitOrders,
			fes.GetDAOCoinLimitOrders,
			PublicAccess,
		},
		{
			"GetTransactorDAOCoinLimitOrders",
			[]string{"POST", "OPTIONS"},
			RoutePathGetTransactorDaoCoinLimitOrders,
			fes.GetTransactorDAOCoinLimitOrders,
			PublicAccess,
		},
		{
			"CreateUserAssociation",
			[]string{"POST", "OPTIONS"},
			RoutePathUserAssociations + "/create",
			fes.CreateUserAssociation,
			PublicAccess,
		},
		{
			"DeleteUserAssociation",
			[]string{"POST", "OPTIONS"},
			RoutePathUserAssociations + "/delete",
			fes.DeleteUserAssociation,
			PublicAccess,
		},
		{
			"GetUserAssociationByID",
			[]string{"GET"},
			RoutePathUserAssociations + "/{associationID:[a-fA-F0-9]+$}",
			fes.GetUserAssociationByID,
			PublicAccess,
		},
		{
			"GetUserAssociations",
			[]string{"POST", "OPTIONS"},
			RoutePathUserAssociations + "/query",
			fes.GetUserAssociations,
			PublicAccess,
		},
		{
			"CountUserAssociations",
			[]string{"POST", "OPTIONS"},
			RoutePathUserAssociations + "/count",
			fes.CountUserAssociations,
			PublicAccess,
		},
		{
			"CountUserAssociationsByValue",
			[]string{"POST", "OPTIONS"},
			RoutePathUserAssociations + "/counts",
			fes.CountUserAssociationsByValue,
			PublicAccess,
		},
		{
			"CreatePostAssociation",
			[]string{"POST", "OPTIONS"},
			RoutePathPostAssociations + "/create",
			fes.CreatePostAssociation,
			PublicAccess,
		},
		{
			"DeletePostAssociation",
			[]string{"POST", "OPTIONS"},
			RoutePathPostAssociations + "/delete",
			fes.DeletePostAssociation,
			PublicAccess,
		},
		{
			"GetPostAssociationByID",
			[]string{"GET"},
			RoutePathPostAssociations + "/{associationID:[a-fA-F0-9]+$}",
			fes.GetPostAssociationByID,
			PublicAccess,
		},
		{
			"GetPostAssociations",
			[]string{"POST", "OPTIONS"},
			RoutePathPostAssociations + "/query",
			fes.GetPostAssociations,
			PublicAccess,
		},
		{
			"CountPostAssociations",
			[]string{"POST", "OPTIONS"},
			RoutePathPostAssociations + "/count",
			fes.CountPostAssociations,
			PublicAccess,
		},
		{
			"CountPostAssociationsByValue",
			[]string{"POST", "OPTIONS"},
			RoutePathPostAssociations + "/counts",
			fes.CountPostAssociationsByValue,
			PublicAccess,
		},
		// Jumio Routes
		{
			"JumioBegin",
			[]string{"POST", "OPTIONS"},
			RoutePathJumioBegin,
			fes.JumioBegin,
			PublicAccess,
		},
		{
			"JumioCallback",
			[]string{"POST", "OPTIONS"},
			RoutePathJumioCallback,
			fes.JumioCallback,
			PublicAccess,
		},
		{
			"JumioFlowFinished",
			[]string{"POST", "OPTIONS"},
			RoutePathJumioFlowFinished,
			fes.JumioFlowFinished,
			PublicAccess,
		},
		{
			"GetJumioStatusForPublicKey",
			[]string{"POST", "OPTIONS"},
			RoutePathGetJumioStatusForPublicKey,
			fes.GetJumioStatusForPublicKey,
			PublicAccess,
		},
		{
			"GetReferralInfoForUser",
			[]string{"POST", "OPTIONS"},
			RoutePathGetReferralInfoForUser,
			fes.GetReferralInfoForUser,
			PublicAccess,
		},
		{
			"GetReferralInfoForReferralHash",
			[]string{"POST", "OPTIONS"},
			RoutePathGetReferralInfoForReferralHash,
			fes.GetReferralInfoForReferralHash,
			PublicAccess,
		},
		// Tutorial Routes
		{
			"GetTutorialCreators",
			[]string{"POST", "OPTIONS"},
			RoutePathGetTutorialCreators,
			fes.GetTutorialCreators,
			PublicAccess,
		},
		{
			"UpdateTutorialStatus",
			[]string{"POST", "OPTIONS"},
			RoutePathUpdateTutorialStatus,
			fes.UpdateTutorialStatus,
			PublicAccess,
		},

		// ETH Routes
		{
			"SubmitETHTx",
			[]string{"POST", "OPTIONS"},
			RoutePathSubmitETHTx,
			fes.SubmitETHTx,
			PublicAccess,
		},
		{
			"AdminProcessETHTx",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminProcessETHTx,
			fes.AdminProcessETHTx,
			SuperAdminAccess,
		},
		{
			"QueryETHRPC",
			[]string{"POST", "OPTIONS"},
			RoutePathQueryETHRPC,
			fes.QueryETHRPC,
			PublicAccess,
		},
		{
			"SendStarterDesoForMetamaskAccount",
			[]string{"POST", "OPTIONS"},
			RoutePathMetamaskSignIn,
			fes.MetamaskSignIn,
			PublicAccess,
		},

		// Begin all /admin routes
		{
			// Route for all low-level node operations.
			"NodeControl",
			[]string{"POST", "OPTIONS"},
			RoutePathNodeControl,
			fes.NodeControl,
			AdminAccess,
		},
		{
			"AdminUpdateUserGlobalMetadata",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminUpdateUserGlobalMetadata,
			fes.AdminUpdateUserGlobalMetadata,
			AdminAccess,
		},
		{
			"AdminGetVerifiedUsers",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminGetVerifiedUsers,
			fes.AdminGetVerifiedUsers,
			AdminAccess, // Check Secret
		},
		{
			"AdminGetAllUserGlobalMetadata",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminGetAllUserGlobalMetadata,
			fes.AdminGetAllUserGlobalMetadata,
			AdminAccess,
		},
		{
			"AdminGetUserGlobalMetadata",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminGetUserGlobalMetadata,
			fes.AdminGetUserGlobalMetadata,
			AdminAccess,
		},
		{
			"AdminUpdateGlobalFeed",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminUpdateGlobalFeed,
			fes.AdminUpdateGlobalFeed,
			AdminAccess,
		},
		{
			"AdminPinPost",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminPinPost,
			fes.AdminPinPost,
			AdminAccess, // CheckSecret
		},
		{
			"AdminGetMempoolStats",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminGetMempoolStats,
			fes.AdminGetMempoolStats,
			AdminAccess,
		},
		{
			"AdminGetGlobalParams",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminGetGlobalParams,
			fes.GetGlobalParams,
			AdminAccess,
		},
		{
			"GetWyreWalletOrdersForPublicKey",
			[]string{"POST", "OPTIONS"},
			RoutePathGetWyreWalletOrdersForPublicKey,
			fes.GetWyreWalletOrdersForPublicKey,
			AdminAccess,
		},
		{
			"AdminGetNFTDrop",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminGetNFTDrop,
			fes.AdminGetNFTDrop,
			AdminAccess,
		},
		{
			"AdminUpdateNFTDrop",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminUpdateNFTDrop,
			fes.AdminUpdateNFTDrop,
			AdminAccess,
		},
		{
			"AdminResetTutorialStatus",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminResetTutorialStatus,
			fes.AdminResetTutorialStatus,
			AdminAccess,
		},
		{
			"AdminGetTutorialCreators",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminGetTutorialCreators,
			fes.AdminGetTutorialCreators,
			AdminAccess,
		},
		{
			"AdminGetUnfilteredHotFeed",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminGetUnfilteredHotFeed,
			fes.AdminGetUnfilteredHotFeed,
			AdminAccess,
		},
		// Super Admin routes
		{
			"AdminGetHotFeedAlgorithm",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminGetHotFeedAlgorithm,
			fes.AdminGetHotFeedAlgorithm,
			SuperAdminAccess,
		},
		{
			"AdminUpdateHotFeedAlgorithm",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminUpdateHotFeedAlgorithm,
			fes.AdminUpdateHotFeedAlgorithm,
			SuperAdminAccess,
		},
		{
			"AdminUpdateHotFeedPostMultiplier",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminUpdateHotFeedPostMultiplier,
			fes.AdminUpdateHotFeedPostMultiplier,
			SuperAdminAccess,
		},
		{
			"AdminUpdateHotFeedUserMultiplier",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminUpdateHotFeedUserMultiplier,
			fes.AdminUpdateHotFeedUserMultiplier,
			SuperAdminAccess,
		},
		{
			"AdminGetHotFeedUserMultiplier",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminGetHotFeedUserMultiplier,
			fes.AdminGetHotFeedUserMultiplier,
			SuperAdminAccess,
		},
		{
			"AdminGetUserAdminData",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminGetUserAdminData,
			fes.AdminGetUserAdminData,
			SuperAdminAccess,
		},
		{
			"AdminGetUsernameVerificationAuditLogs",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminGetUsernameVerificationAuditLogs,
			fes.AdminGetUsernameVerificationAuditLogs,
			SuperAdminAccess,
		},
		{
			"AdminGrantVerificationBadge",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminGrantVerificationBadge,
			fes.AdminGrantVerificationBadge,
			SuperAdminAccess,
		},
		{
			"AdminRemoveVerificationBadge",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminRemoveVerificationBadge,
			fes.AdminRemoveVerificationBadge,
			SuperAdminAccess,
		},
		{
			"SwapIdentity",
			[]string{"POST", "OPTIONS"},
			RoutePathSwapIdentity,
			fes.SwapIdentity,
			SuperAdminAccess,
		},
		{
			"UpdateGlobalParams",
			[]string{"POST", "OPTIONS"},
			RoutePathUpdateGlobalParams,
			fes.UpdateGlobalParams,
			SuperAdminAccess,
		},
		{
			"AdminRemoveNilPosts",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminRemoveNilPosts,
			fes.AdminRemoveNilPosts,
			SuperAdminAccess,
		},
		{
			"SetUSDCentsToDeSoReserveExchangeRate",
			[]string{"POST", "OPTIONS"},
			RoutePathSetUSDCentsToDeSoReserveExchangeRate,
			fes.SetUSDCentsToDeSoReserveExchangeRate,
			SuperAdminAccess,
		},
		{
			"SetBuyDeSoFeeBasisPoints",
			[]string{"POST", "OPTIONS"},
			RoutePathSetBuyDeSoFeeBasisPoints,
			fes.SetBuyDeSoFeeBasisPoints,
			SuperAdminAccess,
		},
		{
			"AdminResetJumioForPublicKey",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminResetJumioForPublicKey,
			fes.AdminResetJumioForPublicKey,
			SuperAdminAccess,
		},
		{
			"AdminUpdateJumioDeSo",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminUpdateJumioDeSo,
			fes.AdminUpdateJumioDeSo,
			SuperAdminAccess,
		},
		{
			"AdminUpdateJumioUSDCents",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminUpdateJumioUSDCents,
			fes.AdminUpdateJumioUSDCents,
			SuperAdminAccess,
		},
		{
			"AdminUpdateJumioKickbackUSDCents",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminUpdateJumioKickbackUSDCents,
			fes.AdminUpdateJumioKickbackUSDCents,
			SuperAdminAccess,
		},
		{
			"AdminTestSignTransactionWithDerivedKey",
			[]string{"POST", "OPTIONS"},
			RoutePathTestSignTransactionWithDerivedKey,
			fes.TestSignTransactionWithDerivedKey,
			SuperAdminAccess,
		},
		{
			"AdminJumioCallback",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminJumioCallback,
			fes.AdminJumioCallback,
			SuperAdminAccess,
		},
		{
			"AdminUpdateJumioCountrySignUpBonus",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminUpdateJumioCountrySignUpBonus,
			fes.AdminUpdateJumioCountrySignUpBonus,
			SuperAdminAccess,
		},
		{
			"AdminGetAllCountryLevelSignUpBonuses",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminGetAllCountryLevelSignUpBonuses,
			fes.AdminGetAllCountryLevelSignUpBonuses,
			AdminAccess,
		},
		{
			"AdminCreateReferralHash",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminCreateReferralHash,
			fes.AdminCreateReferralHash,
			SuperAdminAccess,
		},
		{
			"AdminGetAllReferralInfoForUser",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminGetAllReferralInfoForUser,
			fes.AdminGetAllReferralInfoForUser,
			SuperAdminAccess,
		},
		{
			"AdminUpdateReferralHash",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminUpdateReferralHash,
			fes.AdminUpdateReferralHash,
			SuperAdminAccess,
		},
		{
			"AdminUploadReferralCSV",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminUploadReferralCSV,
			fes.AdminUploadReferralCSV,
			// Although this says public access here, we validate that the user is indeed a super admin in the handler.
			// This is to avoid making changes to the existing CheckAdminPublicKey function to support multipart form
			// content types.
			PublicAccess,
		},
		{
			"AdminDownloadReferralCSV",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminDownloadReferralCSV,
			fes.AdminDownloadReferralCSV,
			SuperAdminAccess,
		},
		{
			"AdminDownloadReferralCSV",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminDownloadRefereeCSV,
			fes.AdminDownloadRefereeCSV,
			SuperAdminAccess,
		},
		{
			"AdminUpdateTutorialCreators",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminUpdateTutorialCreators,
			fes.AdminUpdateTutorialCreator,
			SuperAdminAccess,
		},
		{
			"AdminSetTransactionFeeForTransactionType",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminSetTransactionFeeForTransactionType,
			fes.AdminSetTransactionFeeForTransactionType,
			SuperAdminAccess,
		},
		{
			"AdminSetAllTransactionFees",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminSetAllTransactionFees,
			fes.AdminSetAllTransactionFees,
			SuperAdminAccess,
		},
		{
			"AdminGetTransactionFeeMap",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminGetTransactionFeeMap,
			fes.AdminGetTransactionFeeMap,
			SuperAdminAccess,
		},
		{
			"AdminAddExemptPublicKey",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminAddExemptPublicKey,
			fes.AdminAddExemptPublicKey,
			SuperAdminAccess,
		},
		{
			"AdminGetExemptPublicKeys",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminGetExemptPublicKeys,
			fes.AdminGetExemptPublicKeys,
			SuperAdminAccess,
		},
		{
			"AdminResetPhoneNumber",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminResetPhoneNumber,
			fes.AdminResetPhoneNumber,
			SuperAdminAccess,
		},
		// End all /admin routes
		// GET endpoints for managing parameters related to Buying DeSo
		{
			"GetUSDCentsToDeSoReserveExchangeRate",
			[]string{"GET"},
			RoutePathGetUSDCentsToDeSoReserveExchangeRate,
			fes.GetUSDCentsToDeSoReserveExchangeRate,
			PublicAccess,
		},
		{
			"GetBuyDeSoFeeBasisPoints",
			[]string{"GET"},
			RoutePathGetBuyDeSoFeeBasisPoints,
			fes.GetBuyDeSoFeeBasisPoints,
			PublicAccess,
		},
		{
			"GetLikesForPost",
			[]string{"POST", "OPTIONS"},
			RoutePathGetLikesForPost,
			fes.GetLikesForPost,
			PublicAccess,
		},
		{
			"GetDiamondsForPost",
			[]string{"POST", "OPTIONS"},
			RoutePathGetDiamondsForPost,
			fes.GetDiamondsForPost,
			PublicAccess,
		},
		{
			"GetRepostsForPost",
			[]string{"POST", "OPTIONS"},
			RoutePathGetRepostsForPost,
			fes.GetRepostsForPost,
			PublicAccess,
		},
		{
			"GetQuoteRepostsForPost",
			[]string{"POST", "OPTIONS"},
			RoutePathGetQuoteRepostsForPost,
			fes.GetQuoteRepostsForPost,
			PublicAccess,
		},
		{
			"BlockPublicKey",
			[]string{"POST", "OPTIONS"},
			RoutePathBlockPublicKey,
			fes.BlockPublicKey,
			PublicAccess,
		},
		// message.go
		{
			"SendMessageStateless",
			[]string{"POST", "OPTIONS"},
			RoutePathSendMessageStateless,
			fes.SendMessageStateless,
			PublicAccess,
		},
		{
			"GetMessagesStateless",
			[]string{"POST", "OPTIONS"},
			RoutePathGetMessagesStateless,
			fes.GetMessagesStateless,
			PublicAccess,
		},
		{
			"MarkContactMessagesRead",
			[]string{"POST", "OPTIONS"},
			RoutePathMarkContactMessagesRead,
			fes.MarkContactMessagesRead,
			PublicAccess,
		},
		{
			"MarkAllMessagesRead",
			[]string{"POST", "OPTIONS"},
			RoutePathMarkAllMessagesRead,
			fes.MarkAllMessagesRead,
			PublicAccess,
		},
		{
			"RegisterMessagingGroupKey",
			[]string{"POST", "OPTIONS"},
			RoutePathRegisterMessagingGroupKey,
			fes.RegisterMessagingGroupKey,
			PublicAccess,
		},
		{
			"GetAllMessagingGroupKeys",
			[]string{"POST", "OPTIONS"},
			RoutePathGetAllMessagingGroupKeys,
			fes.GetAllMessagingGroupKeys,
			PublicAccess,
		},
		{
			"CheckPartyMessagingKeys",
			[]string{"POST", "OPTIONS"},
			RoutePathCheckPartyMessagingKeys,
			fes.CheckPartyMessagingKeys,
			PublicAccess,
		},
		{
			"GetBulkMessagingPublicKeys",
			[]string{"POST", "OPTIONS"},
			RoutePathGetBulkMessagingPublicKeys,
			fes.GetBulkMessagingPublicKeys,
			PublicAccess,
		},
		// Snapshot endpoints
		{
			"SnapshotEpochMetadata",
			[]string{"GET"},
			RoutePathSnapshotEpochMetadata,
			fes.GetSnapshotEpochMetadata,
			PublicAccess,
		},
		{
			"StateChecksum",
			[]string{"GET"},
			RoutePathStateChecksum,
			fes.GetStateChecksum,
			PublicAccess,
		},

		// Paths for the mining pool
		{
			"GetBlockTemplate",
			[]string{"POST", "OPTIONS"},
			RoutePathGetBlockTemplate,
			fes.GetBlockTemplate,
			PublicAccess,
		},
		{
			"SubmitBlock",
			[]string{"POST", "OPTIONS"},
			RoutePathSubmitBlock,
			fes.SubmitBlock,
			PublicAccess,
		},

		{
			"GetFullTikTokURL",
			[]string{"POST", "OPTIONS"},
			RoutePathGetFullTikTokURL,
			fes.GetFullTikTokURL,
			PublicAccess,
		},
		{
			"UploadVideo",
			[]string{"POST", "OPTIONS"},
			RoutePathUploadVideo,
			fes.UploadVideo,
			PublicAccess,
		},
		{
			"GetVideoStatus",
			[]string{"GET"},
			RoutePathGetVideoStatus + "/{videoId:[0-9a-z]{25,35}}",
			fes.GetVideoStatus,
			PublicAccess,
		},
		{
			"EnableVideoDownload",
			[]string{"POST", "OPTIONS"},
			RoutePathEnableVideoDownload + "/{videoId:[0-9a-z]{25,35}}",
			fes.EnableVideoDownload,
			PublicAccess,
		},
		{
			"GetVideoDimensions",
			[]string{"GET"},
			RoutePathGetVideoDimensions + "/{videoId:[0-9a-z]{25,35}}",
			fes.GetVideoDimensions,
			PublicAccess,
		},
		// Paths for wyre
		{
			"GetWyreWalletOrderQuotation",
			[]string{"POST", "OPTIONS"},
			RoutePathGetWyreWalletOrderQuotation,
			fes.GetWyreWalletOrderQuotation,
			PublicAccess,
		},
		{
			"GetWyreWalletOrderReservation",
			[]string{"POST", "OPTIONS"},
			RoutePathGetWyreWalletOrderReservation,
			fes.GetWyreWalletOrderReservation,
			PublicAccess,
		},
		{
			// Make sure you only allow access to Wyre IPs for this endpoint, otherwise anybody can take all the funds from
			// the public key that sends DeSo. WHITELIST WYRE IPs.
			"WyreWalletOrderSubscription",
			[]string{"POST", "OPTIONS"},
			RoutePathWyreWalletOrderSubscription,
			fes.WyreWalletOrderSubscription,
			PublicAccess,
		},
		{
			"GetVerifiedUsernameMap",
			[]string{"GET"},
			RoutePathGetVerifiedUsernames,
			fes.GetVerifiedUsernames,
			PublicAccess,
		},
		{
			"GetBlacklistedPublicKeys",
			[]string{"GET"},
			RoutePathGetBlacklistedPublicKeys,
			fes.GetBlacklistedPublicKeys,
			PublicAccess,
		},
		{
			"GetGraylistedPublicKeys",
			[]string{"GET"},
			RoutePathGetGraylistedPublicKeys,
			fes.GetGraylistedPublicKeys,
			PublicAccess,
		},
		{
			"GetGlobalFeed",
			[]string{"GET"},
			RoutePathGetGlobalFeed,
			fes.GetGlobalFeed,
			PublicAccess,
		},
		{
			"GetTotalSupply",
			[]string{"GET"},
			RoutePathGetTotalSupply,
			fes.GetTotalSupply,
			PublicAccess,
		},
		{
			"GetRichList",
			[]string{"GET"},
			RoutePathGetRichList,
			fes.GetRichList,
			PublicAccess,
		},
		{
			"GetCountKeysWithDESO",
			[]string{"GET"},
			RoutePathGetCountKeysWithDESO,
			fes.GetCountKeysWithDESO,
			PublicAccess,
		},
		// registering the routes related to access groups
		{
			"CreateAccessGroup",
			[]string{"POST", "OPTIONS"},
			RoutePathCreateAccessGroup,
			fes.CreateAccessGroup,
			PublicAccess,
		},
		{
			"UpdateAccessGroup",
			[]string{"POST", "OPTIONS"},
			RoutePathUpdateAccessGroup,
			fes.UpdateAccessGroup,
			PublicAccess,
		},
		{
			"AddAccessGroupMembers",
			[]string{"POST", "OPTIONS"},
			RoutePathAddAccessGroupMembers,
			fes.AddAccessGroupMembers,
			PublicAccess,
		},
		{
			"RemoveAccessGroupMembers",
			[]string{"POST", "OPTIONS"},
			RoutePathRemoveAccessGroupMembers,
			fes.RemoveAccessGroupMembers,
			PublicAccess,
		},
		{
			"UpdateAccessGroupMembers",
			[]string{"POST", "OPTIONS"},
			RoutePathUpdateAccessGroupMembers,
			fes.UpdateAccessGroupMembers,
			PublicAccess,
		},
		{
			"GetAllUserAccessGroups",
			[]string{"POST", "OPTIONS"},
			RoutePathGetAllUserAccessGroups,
			fes.GetAllUserAccessGroups,
			PublicAccess,
		},
		{
			"GetAllUserAccessGroupsOwned",
			[]string{"POST", "OPTIONS"},
			RoutePathGetAllUserAccessGroupsOwned,
			fes.GetAllUserAccessGroupsOwned,
			PublicAccess,
		},
		{
			"GetAllUserAccessGroupsMemberOnly",
			[]string{"POST", "OPTIONS"},
			RoutePathGetAllUserAccessGroupsMemberOnly,
			fes.GetAllUserAccessGroupsMemberOnly,
			PublicAccess,
		},
		{
			"CheckPartyAccessGroups",
			[]string{"POST", "OPTIONS"},
			RoutePathCheckPartyAccessGroups,
			fes.CheckPartyAccessGroups,
			PublicAccess,
		},
		{
			"GetAccessGroupInfo",
			[]string{"POST", "OPTIONS"},
			RoutePathGetAccessGroupInfo,
			fes.GetAccessGroupInfo,
			PublicAccess,
		},
		{
			"GetAccessGroupMemberInfo",
			[]string{"POST", "OPTIONS"},
			RoutePathGetAccessGroupMemberInfo,
			fes.GetAccessGroupMemberInfo,
			PublicAccess,
		},
		{
			"GetPaginatedAccessGroupMembers",
			[]string{"POST", "OPTIONS"},
			RoutePathGetPaginatedAccessGroupMembers,
			fes.GetPaginatedAccessGroupMembers,
			PublicAccess,
		},
		{
			"GetBulkAccessGroupEntries",
			[]string{"POST", "OPTIONS"},
			RoutePathGetBulkAccessGroupEntries,
			fes.GetBulkAccessGroupEntries,
			PublicAccess,
		},
		// access group message APIs.
		{
			"SendDmMessage",
			[]string{"POST", "OPTIONS"},
			RoutePathSendDmMessage,
			fes.SendDmMessage,
			PublicAccess,
		},
		{
			"UpdateDmMessage",
			[]string{"POST", "OPTIONS"},
			RoutePathUpdateDmMessage,
			fes.UpdateDmMessage,
			PublicAccess,
		},
		{
			"SendGroupChatMessage",
			[]string{"POST", "OPTIONS"},
			RoutePathSendGroupChatMessage,
			fes.SendGroupChatMessage,
			PublicAccess,
		},
		{
			"UpdateGroupChatMessage",
			[]string{"POST", "OPTIONS"},
			RoutePathUpdateGroupChatMessage,
			fes.UpdateGroupChatMessage,
			PublicAccess,
		},
		{
			"GetUserDmThreadsOrderedByTimestamp",
			[]string{"POST", "OPTIONS"},
			RoutePathGetUserDmThreadsOrderedByTimestamp,
			fes.GetUserDmThreadsOrderedByTimestamp,
			PublicAccess,
		},
		{
			"GetPaginatedMessagesForDmThread",
			[]string{"POST", "OPTIONS"},
			RoutePathGetPaginatedMessagesForDmThread,
			fes.GetPaginatedMessagesForDmThread,
			PublicAccess,
		},
		{
			"GetUserGroupChatThreadsOrderedByTimestamp",
			[]string{"POST", "OPTIONS"},
			RoutePathGetUserGroupChatThreadsOrderedByTimestamp,
			fes.GetUserGroupChatThreadsOrderedByTimestamp,
			PublicAccess,
		},
		{
			"GetPaginatedMessagesForGroupChatThread",
			[]string{"POST", "OPTIONS"},
			RoutePathGetPaginatedMessagesForGroupChatThread,
			fes.GetPaginatedMessagesForGroupChatThread,
			PublicAccess,
		},
		{
			"GetAllUserMessageThreads",
			[]string{"POST", "OPTIONS"},
			RoutePathGetAllUserMessageThreads,
			fes.GetAllUserMessageThreads,
			PublicAccess,
		},
	}

	router := muxtrace.NewRouter().StrictSlash(true)

	// Set secure headers
	secureMiddleware := lib.InitializeSecureMiddleware(
		fes.Config.SecureHeaderAllowHosts,
		fes.Config.SecureHeaderDevelopment,
		lib.SECURE_MIDDLEWARE_RESTRICTIVE_CONTENT_SECURITY_POLICY,
	)
	router.Use(secureMiddleware.Handler)

	// We serve multiple groups of routes from this endpoint.
	fullRouteList := append([]Route{}, FrontendRoutes...)
	fullRouteList = append(fullRouteList, fes.APIRoutes()...)
	fullRouteList = append(fullRouteList, fes.GlobalState.GlobalStateRoutes()...)

	for _, route := range fullRouteList {
		var handler http.Handler

		handler = route.HandlerFunc
		// Note that the wrapper that is applied last is actually called first. For
		// example if you have:
		// - handler = C(handler)
		// - handler = B(handler)
		// - handler = A(handler)
		// then A will be called first B will be called second, and C will be called
		// last.

		// If the route is not "PublicAccess" we wrap it in a function to check that the caller
		// has the correct permissions before calling its handler.
		if route.AccessLevel != PublicAccess {
			handler = fes.CheckAdminPublicKey(handler, route.AccessLevel)
		}
		handler = Logger(handler, route.Name)
		handler = AddHeaders(handler, fes.Config.AccessControlAllowOrigins)

		router.
			Methods(route.Method...).
			Path(route.Pattern).
			Name(route.Name).
			Handler(handler)

		// Support legacy frontend server routes that weren't prefixed
		if strings.HasPrefix(route.Pattern, "/api/v0") {
			router.
				Methods(route.Method...).
				Path(strings.ReplaceAll(route.Pattern, "/api/v0", "")).
				Name(route.Name).
				Handler(handler)
		}
	}

	return router
}

// Logger ...
func Logger(inner http.Handler, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		inner.ServeHTTP(w, r)

		glog.V(2).Infof(
			"%s\t%s\t%s\t%s",
			r.Method,
			r.RequestURI,
			name,
			time.Since(start),
		)
	})
}

var publicRoutes = map[string]interface{}{
	RoutePathGetJumioStatusForPublicKey:     nil,
	RoutePathUploadVideo:                    nil,
	RoutePathEnableVideoDownload:            nil,
	RoutePathGetReferralInfoForReferralHash: nil,
	RoutePathGetReferralInfoForUser:         nil,
	RoutePathGetVerifiedUsernames:           nil,
	RoutePathGetBlacklistedPublicKeys:       nil,
	RoutePathGetGraylistedPublicKeys:        nil,
	RoutePathGetGlobalFeed:                  nil,
	RoutePathDeletePII:                      nil,
	RoutePathGetUserMetadata:                nil,
	RoutePathSubmitTransaction:              nil,
	RoutePathGetTxn:                         nil,
	RoutePathUpdateProfile:                  nil,
}

// AddHeaders ...
func AddHeaders(inner http.Handler, allowedOrigins []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// We have to add Access-Control-Allow-Origin headers so that bitclout.com can make
		// cross-origin requests to the node (which is running on a different port than bitclout.com).
		//
		// We have to allow multiple origins, since both bitclout.com and explorer.bitclout.com
		// hit the node.

		// Test whether the actual origin matches any of the allowedOrigins. If so, set
		// the Access-Control-Allow-Origin header to the origin in the request.
		actualOrigin := r.Header.Get("Origin")
		match := false
		for _, allowedOrigin := range allowedOrigins {
			// Match wildcard
			if allowedOrigin == "*" {
				match = true
				break
			}

			// Exact match including protocol and subdomain e.g. https://my.domain.com
			if allowedOrigin == actualOrigin {
				match = true
				break
			}

			// Match any domain excluding protocol and subdomain e.g. domain.com
			actualDomain := strings.Split(actualOrigin, "://")
			if len(actualDomain) >= 2 {
				actualDomain = strings.Split(actualDomain[1], ".")
				actualDomainLen := len(actualDomain)
				if actualDomainLen >= 2 {
					actualDomainStr := fmt.Sprintf("%s.%s", actualDomain[actualDomainLen-2], actualDomain[actualDomainLen-1])
					if actualDomainStr == allowedOrigin {
						match = true
						break
					}
				}
			}
		}

		// Note Content-Type header contains the media type, as well as some additional directives based on media type
		// (such as boundary for multipart media types and charset to indicate string encoding).
		contentType := r.Header.Get("Content-Type")
		mediaType := strings.SplitN(contentType, ";", 2)[0]

		invalidPostRequest := false
		// upload-image endpoint is the only one allowed to use multipart/form-data
		if (r.RequestURI == RoutePathUploadImage || r.RequestURI == RoutePathAdminUploadReferralCSV) &&
			mediaType == "multipart/form-data" {
			match = true
		} else if _, exists := publicRoutes[r.RequestURI]; exists {
			// We set the headers for all requests to public routes.
			// This allows third-party frontends to access this endpoint
			match = true
		} else if strings.HasPrefix(r.RequestURI, RoutePathGetVideoStatus) || strings.HasPrefix(r.RequestURI, RoutePathGetUserMetadata) {
			// We don't match the RoutePathGetVideoStatus and RoutePathGetUserMetadata paths exactly since there is a
			// variable param. Check for the prefix instead.
			match = true
		} else if r.Method == "POST" && mediaType != "application/json" && r.RequestURI != RoutePathJumioCallback {
			invalidPostRequest = true
		}

		if match {
			// Needed in order for the user's browser to set a cookie
			w.Header().Add("Access-Control-Allow-Credentials", "true")

			if r.RequestURI != RoutePathUploadVideo {
				w.Header().Set("Access-Control-Allow-Origin", actualOrigin)
				w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
			} else {
				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.Header().Set("Access-Control-Allow-Headers", "*")
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, OPTIONS")
		}

		// Otherwise, don't add any headers. This should make a CORS request fail.

		// If it's an options request stop at the CORS headers.
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// If this is a POST request, only accept the application/json content type. This should help
		// mitigate CSRF vulnerabilities (since our CORS policy will reject application/json
		// POST requests from a non-deso domain)
		if invalidPostRequest {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// For all normal requests, add the JSON header and run the business
		// logic handlers.
		w.Header().Set("Content-Type", "application/json")
		inner.ServeHTTP(w, r)
	})
}

type AdminRequest struct {
	JWT            string
	AdminPublicKey string
}

// CheckSecret ...
func (fes *APIServer) CheckAdminPublicKey(inner http.Handler, AccessLevel AccessLevel) http.Handler {
	return http.HandlerFunc(func(ww http.ResponseWriter, req *http.Request) {
		// If the only entry is a "*" we exit immediately
		if (len(fes.Config.AdminPublicKeys) == 1 && fes.Config.AdminPublicKeys[0] == "*") ||
			(len(fes.Config.SuperAdminPublicKeys) == 1 && fes.Config.SuperAdminPublicKeys[0] == "*") {
			inner.ServeHTTP(ww, req)
			return
		}

		requestData := AdminRequest{}

		if req.Body == nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"CheckAdminPublicKey: Request has no Body attribute"))
			return
		}

		// We read the entire body and then create a new ReadCloser Body object
		// from the bytes we read because you can only read the body once
		bodyBytes, err := ioutil.ReadAll(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("CheckAdminPublicKey: %v", err))
			return
		}

		req.Body = ioutil.NopCloser(bytes.NewReader(bodyBytes))
		decoder := json.NewDecoder(bytes.NewReader(bodyBytes))
		err = decoder.Decode(&requestData)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"CheckAdminPublicKey: Problem parsing request body: %v", err))
			return
		}

		if requestData.AdminPublicKey == "" {
			_AddBadRequestError(ww, "CheckAdminPublicKey: Missing AdminPublicKey param")
			return
		}

		isValid, err := fes.ValidateJWT(requestData.AdminPublicKey, requestData.JWT)
		if !isValid {
			_AddBadRequestError(ww, fmt.Sprintf(
				"CheckAdminPublicKey: Invalid token: %v", err))
			return
		}

		// If this a regular admin endpoint, we iterate through all the admin public keys.
		if AccessLevel == AdminAccess {
			for _, adminPubKey := range fes.Config.AdminPublicKeys {
				if adminPubKey == requestData.AdminPublicKey {
					// We found a match, serve the request
					inner.ServeHTTP(ww, req)
					return
				}
			}
		}

		// We also check super admins, as they have a superset of capabilities.
		for _, superAdminPubKey := range fes.Config.SuperAdminPublicKeys {
			if superAdminPubKey == requestData.AdminPublicKey {
				// We found a match, serve the request
				inner.ServeHTTP(ww, req)
				return
			}
		}

		adminType := "an admin"
		if AccessLevel == SuperAdminAccess {
			adminType = "a superadmin"
		}
		_AddBadRequestError(ww, fmt.Sprintf("CheckAdminPublicKey: Not %v", adminType))
		return
	})
}

const JwtDerivedPublicKeyClaim = "derivedPublicKeyBase58Check"

func (fes *APIServer) ValidateJWT(publicKey string, jwtToken string) (bool, error) {
	pubKeyBytes, _, err := lib.Base58CheckDecode(publicKey)
	if err != nil {
		return false, errors.Wrapf(err, "Problem decoding public key")
	}

	pubKey, err := btcec.ParsePubKey(pubKeyBytes, btcec.S256())
	if err != nil {
		return false, errors.Wrapf(err, "Problem parsing public key")
	}

	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		// Do not check token issued at time. We still check expiration time.
		mapClaims := token.Claims.(jwt.MapClaims)
		delete(mapClaims, "iat")

		// We accept JWT signed by derived keys. To accommodate this, the JWT claims payload should contain the key
		// "derivedPublicKeyBase58Check" with the derived public key in base58 as value.
		if derivedPublicKeyBase58Check, isDerived := mapClaims[JwtDerivedPublicKeyClaim]; isDerived {
			// Parse the derived public key.
			derivedPublicKeyBytes, _, err := lib.Base58CheckDecode(derivedPublicKeyBase58Check.(string))
			if err != nil {
				return nil, errors.Wrapf(err, "Problem decoding derived public key")
			}
			derivedPublicKey, err := btcec.ParsePubKey(derivedPublicKeyBytes, btcec.S256())
			if err != nil {
				return nil, errors.Wrapf(err, "Problem parsing derived public key bytes")
			}
			// Validate the derived public key.
			utxoView, err := fes.mempool.GetAugmentedUniversalView()
			if err != nil {
				return nil, errors.Wrapf(err, "Problem getting utxoView")
			}
			blockHeight := uint64(fes.blockchain.BlockTip().Height)
			if err := utxoView.ValidateDerivedKey(pubKeyBytes, derivedPublicKeyBytes, blockHeight); err != nil {
				return nil, errors.Wrapf(err, "Derived key is not authorize")
			}

			return derivedPublicKey.ToECDSA(), nil
		}

		return pubKey.ToECDSA(), nil
	})

	if err != nil {
		return false, errors.Wrapf(err, "Problem verifying JWT token")
	}

	return token.Valid, nil
}

// Start ...
func (fes *APIServer) Start() {
	fes.initState()

	glog.Infof("Listening to NON-SSL JSON API connections on port :%d", fes.Config.APIPort)
	glog.Error(http.ListenAndServe(fmt.Sprintf(":%d", fes.Config.APIPort), fes.router))
}

// A helper function to initialize the APIServer. Useful for testing.
func (fes *APIServer) initState() {
	glog.Info("APIServer.Start: Starting APIServer")
	fes.router = fes.NewRouter()
}

// Stop...
func (fes *APIServer) Stop() {
	glog.Info("APIServer.Stop: Gracefully shutting down APIServer")
	close(fes.quit)
}

// Amplitude Logging
type AmplitudeUploadRequestBody struct {
	ApiKey string           `json:"api_key"`
	Events []AmplitudeEvent `json:"events"`
}

type AmplitudeEvent struct {
	UserId          string                 `json:"user_id"`
	EventType       string                 `json:"event_type"`
	EventProperties map[string]interface{} `json:"event_properties"`
}

func (fes *APIServer) logAmplitudeEvent(publicKey string, event string, eventData map[string]interface{}) error {
	if fes.Config.AmplitudeKey == "" {
		return nil
	}
	headers := map[string][]string{
		"Content-Type": {"application/json"},
		"Accept":       {"*/*"},
	}
	events := []AmplitudeEvent{{UserId: publicKey, EventType: event, EventProperties: eventData}}
	ampBody := AmplitudeUploadRequestBody{ApiKey: fes.Config.AmplitudeKey, Events: events}
	payload, err := json.Marshal(ampBody)
	if err != nil {
		return err
	}
	data := bytes.NewBuffer(payload)
	req, err := http.NewRequest("POST", "https://api2.amplitude.com/2/httpapi", data)
	if err != nil {
		return err
	}
	req.Header = headers

	client := &http.Client{}
	_, err = client.Do(req)
	if err != nil {
		return err
	}
	return nil
}

// StartExchangePriceMonitoring gives every exchange rate update
// its own go routine so a blocked routine doesn't impede others
func (fes *APIServer) StartExchangePriceMonitoring() {
	go func() {
	out:
		for {
			select {
			case <-time.After(10 * time.Second):
				fes.UpdateUSDCentsToDeSoExchangeRate()
			case <-fes.quit:
				break out
			}
		}
	}()

	go func() {
	out:
		for {
			select {
			case <-time.After(10 * time.Second):
				fes.UpdateUSDToBTCPrice()
			case <-fes.quit:
				break out
			}
		}
	}()

	go func() {
	out:
		for {
			select {
			case <-time.After(10 * time.Second):
				fes.UpdateUSDToETHPrice()
			case <-fes.quit:
				break out
			}
		}
	}()
}

// Monitor balances for starter deso seed and buy deso seed
func (fes *APIServer) StartSeedBalancesMonitoring() {
	go func() {
	out:
		for {
			select {
			case <-time.After(1 * time.Minute):
				if fes.backendServer == nil || fes.backendServer.GetStatsdClient() == nil {
					return
				}
				tags := []string{}
				fes.logBalanceForSeed(fes.Config.StarterDESOSeed, "STARTER_DESO", tags)
				fes.logBalanceForSeed(fes.Config.BuyDESOSeed, "BUY_DESO", tags)
				for label, publicKey := range fes.Config.PublicKeyBalancesToMonitor {
					fes.logBalanceForPublicKey(publicKey, label, tags)
				}
			case <-fes.quit:
				break out
			}
		}
	}()
}

func (fes *APIServer) logBalanceForSeed(seed string, seedName string, tags []string) {
	if seed == "" {
		return
	}
	balance, err := fes.getBalanceForSeed(seed)
	if err != nil {
		glog.Errorf("LogBalanceForSeed: Error getting balance for %v seed", seedName)
		return
	}
	if err = fes.backendServer.GetStatsdClient().Gauge(fmt.Sprintf("%v_BALANCE", seedName), float64(balance), tags, 1); err != nil {
		glog.Errorf("LogBalanceForSeed: Error logging balance to datadog for %v seed", seedName)
	}
}

func (fes *APIServer) logBalanceForPublicKey(publicKey []byte, label string, tags []string) {
	if len(publicKey) != btcec.PubKeyBytesLenCompressed {
		glog.Errorf("logBalanceForPublicKey: Invalid pub key length for pub key with label %v", label)
		return
	}
	balance, err := fes.getBalanceForPubKey(publicKey)
	if err != nil {
		glog.Errorf("logBalanceForPublicKey: Error getting balance for label %v, public key %v: %v", label, lib.PkToString(publicKey, fes.Params), err)
		return
	}
	if err = fes.backendServer.GetStatsdClient().Gauge(fmt.Sprintf("%v_BALANCE", label), float64(balance), tags, 1); err != nil {
		glog.Errorf("logBalanceForPublicKey: Error logging balance to datadog for label %v, public key %v: %v", label, lib.PkToString(publicKey, fes.Params), err)
	}
}

func (fes *APIServer) getBalanceForSeed(seedPhrase string) (uint64, error) {
	seedBytes, err := bip39.NewSeedWithErrorChecking(seedPhrase, "")
	if err != nil {
		return 0, fmt.Errorf("GetBalanceForSeed: Error converting mnemonic: %+v", err)
	}

	pubKey, _, _, err := lib.ComputeKeysFromSeed(seedBytes, 0, fes.Params)
	if err != nil {
		return 0, fmt.Errorf("GetBalanceForSeed: Error computing keys from seed: %+v", err)
	}
	return fes.getBalanceForPubKey(pubKey.SerializeCompressed())
}

func (fes *APIServer) getBalanceForPubKey(pubKey []byte) (uint64, error) {
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return 0, fmt.Errorf("getBalanceForPubKey: Error getting UtxoView: %v", err)
	}
	currentBalanceNanos, err := GetBalanceForPublicKeyUsingUtxoView(pubKey, utxoView)
	if err != nil {
		return 0, fmt.Errorf("getBalanceForPubKey: Error getting balance: %v", err)
	}
	return currentBalanceNanos, nil
}

// StartGlobalStateMonitoring begins monitoring Verified, Blacklisted, and Graylisted users and Global Feed Posts
func (fes *APIServer) StartGlobalStateMonitoring() {
	go func() {
	out:
		for {
			select {
			case <-time.After(1 * time.Minute):
				fes.SetGlobalStateCache()
			case <-fes.quit:
				break out
			}
		}
	}()
}

func (fes *APIServer) SetGlobalStateCache() {
	if fes.backendServer == nil {
		return
	}
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		glog.Errorf("SetGlobalStateCache: problem with GetAugmentedUniversalView: %v", err)
		return
	}
	fes.SetVerifiedUsernameMap()
	fes.SetBlacklistedPKIDMap(utxoView)
	fes.SetGraylistedPKIDMap(utxoView)
	fes.SetGlobalFeedPostHashes(utxoView)
	fes.SetAllCountrySignUpBonusMetadata()
	fes.SetUSDCentsToDeSoReserveExchangeRateFromGlobalState()
	fes.SetBuyDeSoFeeBasisPointsResponseFromGlobalState()
	fes.SetJumioUSDCents()
	fes.SetJumioKickbackUSDCents()
}

func (fes *APIServer) SetVerifiedUsernameMap() {
	verifiedPKIDMap, err := fes.GetVerifiedUsernameMap()
	if err != nil {
		glog.Errorf("SetVerifiedUsernameMap: Error getting verified username map: %v", err)
	} else {
		fes.VerifiedUsernameToPKIDMap = verifiedPKIDMap
	}
}

func (fes *APIServer) SetBlacklistedPKIDMap(utxoView *lib.UtxoView) {
	blacklistMap, err := fes.GetBlacklist(utxoView)
	if err != nil {
		glog.Errorf("SetBlacklistedPKIDMap: Error getting blacklist: %v", err)
	} else {
		fes.BlacklistedPKIDMap = blacklistMap
		// We keep a JSON-encodable version of the blacklist map ready to send to nodes that wish to connect to this
		// node's global state. Sending a JSON-encoded version is preferable over a gob-encoded one so that any
		// language can easily decode the response.
		fes.BlacklistedResponseMap = fes.makePKIDMapJSONEncodable(blacklistMap)
	}
}

func (fes *APIServer) SetGraylistedPKIDMap(utxoView *lib.UtxoView) {
	graylistMap, err := fes.GetGraylist(utxoView)
	if err != nil {
		glog.Errorf("SetGraylistedPKIDMap: Error getting graylist: %v", err)
	} else {
		fes.GraylistedPKIDMap = graylistMap
		// We keep a JSON-encodable version of the graylist map ready to send to nodes that wish to connect to this
		// node's global state. Sending a JSON-encoded version is preferable over a gob-encoded one so that any
		// language can easily decode the response.
		fes.GraylistedResponseMap = fes.makePKIDMapJSONEncodable(graylistMap)
	}
}

func (fes *APIServer) SetGlobalFeedPostHashes(utxoView *lib.UtxoView) {
	postHashes, postEntries, err := fes.GetGlobalFeedCache(utxoView)

	if err != nil {
		glog.Errorf("SetGlobalFeedPostHashes: Error getting global feed post hashes: %v", err)
	} else {
		fes.GlobalFeedPostHashes = postHashes
		fes.GlobalFeedPostEntries = postEntries
	}
}

// makePKIDMapJSONEncodable converts a map that has PKID keys into Base58-encoded strings.
// Using gob-encoding when sending responses would make using this API difficult to interact with when using any
// language other than go.
func (fes *APIServer) makePKIDMapJSONEncodable(restrictedKeysMap map[lib.PKID][]byte) map[string][]byte {
	outputMap := make(map[string][]byte)
	for k, v := range restrictedKeysMap {
		outputMap[lib.PkToString(k.ToBytes(), fes.Params)] = v
	}
	return outputMap
}
