package routes

import (
	"bytes"
	"encoding/json"
	fmt "fmt"
	"github.com/bitclout/backend/config"
	"github.com/tyler-smith/go-bip39"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/dgrijalva/jwt-go/v4"

	"github.com/bitclout/core/lib"
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
	// base.go
	RoutePathHealthCheck     = "/api/v0/health-check"
	RoutePathGetExchangeRate = "/api/v0/get-exchange-rate"
	RoutePathGetAppState     = "/api/v0/get-app-state"

	// transaction.go
	RoutePathGetTxn                   = "/api/v0/get-txn"
	RoutePathSubmitTransaction        = "/api/v0/submit-transaction"
	RoutePathUpdateProfile            = "/api/v0/update-profile"
	RoutePathExchangeBitcoin          = "/api/v0/exchange-bitcoin"
	RoutePathSendBitClout             = "/api/v0/send-bitclout"
	RoutePathSubmitPost               = "/api/v0/submit-post"
	RoutePathCreateFollowTxnStateless = "/api/v0/create-follow-txn-stateless"
	RoutePathCreateLikeStateless      = "/api/v0/create-like-stateless"
	RoutePathBuyOrSellCreatorCoin     = "/api/v0/buy-or-sell-creator-coin"
	RoutePathTransferCreatorCoin      = "/api/v0/transfer-creator-coin"
	RoutePathSendDiamonds             = "/api/v0/send-diamonds"

	// user.go
	RoutePathGetUsersStateless        = "/api/v0/get-users-stateless"
	RoutePathDeleteIdentities         = "/api/v0/delete-identities"
	RoutePathGetProfiles              = "/api/v0/get-profiles"
	RoutePathGetSingleProfile         = "/api/v0/get-single-profile"
	RoutePathGetSingleProfilePicture  = "/api/v0/get-single-profile-picture"
	RoutePathGetHodlersForPublicKey   = "/api/v0/get-hodlers-for-public-key"
	RoutePathGetDiamondsForPublicKey  = "/api/v0/get-diamonds-for-public-key"
	RoutePathGetFollowsStateless      = "/api/v0/get-follows-stateless"
	RoutePathGetUserGlobalMetadata    = "/api/v0/get-user-global-metadata"
	RoutePathUpdateUserGlobalMetadata = "/api/v0/update-user-global-metadata"
	RoutePathGetNotifications         = "/api/v0/get-notifications"
	RoutePathBlockPublicKey           = "/api/v0/block-public-key"
	RoutePathIsFollowingPublicKey     = "/api/v0/is-following-public-key"
	RoutePathIsHodlingPublicKey       = "/api/v0/is-hodling-public-key"

	// post.go
	RoutePathGetPostsStateless       = "/api/v0/get-posts-stateless"
	RoutePathGetSinglePost           = "/api/v0/get-single-post"
	RoutePathGetLikesForPost         = "/api/v0/get-likes-for-post"
	RoutePathGetDiamondsForPost      = "/api/v0/get-diamonds-for-post"
	RoutePathGetRecloutsForPost      = "/api/v0/get-reclouts-for-post"
	RoutePathGetQuoteRecloutsForPost = "/api/v0/get-quote-reclouts-for-post"
	RoutePathGetPostsForPublicKey    = "/api/v0/get-posts-for-public-key"
	RoutePathGetDiamondedPosts       = "/api/v0/get-diamonded-posts"

	// media.go
	RoutePathUploadImage      = "/api/v0/upload-image"
	RoutePathGetFullTikTokURL = "/api/v0/get-full-tiktok-url"

	// message.go
	RoutePathSendMessageStateless    = "/api/v0/send-message-stateless"
	RoutePathGetMessagesStateless    = "/api/v0/get-messages-stateless"
	RoutePathMarkContactMessagesRead = "/api/v0/mark-contact-messages-read"
	RoutePathMarkAllMessagesRead     = "/api/v0/mark-all-messages-read"

	// verify.go
	RoutePathSendPhoneNumberVerificationText   = "/api/v0/send-phone-number-verification-text"
	RoutePathSubmitPhoneNumberVerificationCode = "/api/v0/submit-phone-number-verification-code"
	RoutePathResendVerifyEmail                 = "/api/v0/resend-verify-email"
	RoutePathVerifyEmail                       = "/api/v0/verify-email"

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
	RoutePathNodeControl             = "/api/v0/admin/node-control"
	RoutePathReprocessBitcoinBlock   = "/api/v0/admin/reprocess-bitcoin-block"
	RoutePathAdminGetMempoolStats    = "/api/v0/admin/get-mempool-stats"
	RoutePathEvictUnminedBitcoinTxns = "/api/v0/admin/evict-unmined-bitcoin-txns"

	// admin_buy_bitclout.go
	RoutePathSetUSDCentsToBitCloutReserveExchangeRate = "/api/v0/admin/set-usd-cents-to-bitclout-reserve-exchange-rate"
	RoutePathGetUSDCentsToBitCloutReserveExchangeRate = "/api/v0/admin/get-usd-cents-to-bitclout-reserve-exchange-rate"
	RoutePathSetBuyBitCloutFeeBasisPoints             = "/api/v0/admin/set-buy-bitclout-fee-basis-points"
	RoutePathGetBuyBitCloutFeeBasisPoints             = "/api/v0/admin/get-buy-bitclout-fee-basis-points"

	// admin_transaction.go
	RoutePathGetGlobalParams    = "/api/v0/admin/get-global-params"
	RoutePathUpdateGlobalParams = "/api/v0/admin/update-global-params"
	RoutePathSwapIdentity       = "/api/v0/admin/swap-identity"

	// admin_user.go
	RoutePathAdminUpdateUserGlobalMetadata         = "/api/v0/admin/update-user-global-metadata"
	RoutePathAdminGetAllUserGlobalMetadata         = "/api/v0/admin/get-all-user-global-metadata"
	RoutePathAdminGetUserGlobalMetadata            = "/api/v0/admin/get-user-global-metadata"
	RoutePathAdminGrantVerificationBadge           = "/api/v0/admin/grant-verification-badge"
	RoutePathAdminRemoveVerificationBadge          = "/api/v0/admin/remove-verification-badge"
	RoutePathAdminGetVerifiedUsers                 = "/api/v0/admin/get-verified-users"
	RoutePathAdminGetUsernameVerificationAuditLogs = "/api/v0/admin/get-username-verification-audit-logs"
	RoutePathAdminGetUserAdminData                 = "/api/v0/admin/get-user-admin-data"

	// admin_feed.go
	RoutePathAdminUpdateGlobalFeed = "/api/v0/admin/update-global-feed"
	RoutePathAdminPinPost          = "/api/v0/admin/pin-post"
	RoutePathAdminRemoveNilPosts   = "/api/v0/admin/remove-nil-posts"
)

// APIServer provides the interface between the blockchain and things like the
// web UI. In particular, it exposes a JSON API that can be used to do everything the
// frontend cares about, from posts to profiles to purchasing BitClout with Bitcoin.
type APIServer struct {
	backendServer *lib.Server
	mempool       *lib.BitCloutMempool
	blockchain    *lib.Blockchain
	blockProducer *lib.BitCloutBlockProducer
	Params        *lib.BitCloutParams
	Config        *config.Config

	MinFeeRateNanosPerKB uint64

	// A pointer to the router that handles all requests.
	router *muxtrace.Router

	TXIndex *lib.TXIndex

	// Used for getting/setting the global state. Usually either a db is set OR
	// a remote node is set-- not both. When a remote node is set, global state
	// is set and fetched from that node. Otherwise, it is set/fetched from the
	// db. This makes it easy to run a local node in development.
	GlobalStateDB *badger.DB

	// Optional, may be empty. Used for Twilio integration
	Twilio *twilio.Client

	// When set, BlockCypher is used to add extra security to BitcoinExchange
	// transactions.
	BlockCypherAPIKey string

	// This lock is used when sending seed BitClout to avoid a race condition
	// in which two calls to sending the seed BitClout use the same UTXO,
	// causing one to error.
	mtxSeedBitClout sync.RWMutex

	UsdCentsPerBitCloutExchangeRate uint64

	// List of prices retrieved.  This is culled everytime we update the current price.
	LastTradeBitCloutPriceHistory []LastTradePriceHistoryItem
	// How far back do we consider trade prices when we set the current price of $CLOUT in nanoseconds
	LastTradePriceLookback uint64
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
	_mempool *lib.BitCloutMempool,
	_blockchain *lib.Blockchain,
	_blockProducer *lib.BitCloutBlockProducer,
	txIndex *lib.TXIndex,
	params *lib.BitCloutParams,
	config *config.Config,
	minFeeRateNanosPerKB uint64,
	globalStateDB *badger.DB,
	twilio *twilio.Client,
	blockCypherAPIKey string,
) (*APIServer, error) {

	if globalStateDB == nil && config.GlobalStateRemoteNode == "" {
		return nil, fmt.Errorf(
			"NewAPIServer: Error: A globalStateDB or a globalStateRemoteNode is required")
	}

	fes := &APIServer{
		// TODO: It would be great if we could eliminate the dependency on
		// the backendServer. Right now it's here because it was the easiest
		// way to give the APIServer the ability to add transactions
		// to the mempool and relay them to peers.
		backendServer:                 _backendServer,
		mempool:                       _mempool,
		blockchain:                    _blockchain,
		blockProducer:                 _blockProducer,
		TXIndex:                       txIndex,
		Params:                        params,
		Config:                        config,
		GlobalStateDB:                 globalStateDB,
		Twilio:                        twilio,
		BlockCypherAPIKey:             blockCypherAPIKey,
		LastTradeBitCloutPriceHistory: []LastTradePriceHistoryItem{},
		// We consider last trade prices from the last hour when determining the current price of BitClout.
		// This helps prevents attacks that attempt to purchase $CLOUT at below market value.
		LastTradePriceLookback: uint64(time.Hour.Nanoseconds()),
	}

	fes.StartSeedBalancesMonitoring()
	// Call this once upon starting server to ensure we have a good initial value
	fes.UpdateUSDCentsToBitCloutExchangeRate()
	fes.StartExchangePriceMonitoring()
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
		// Route for sending BitClout
		{
			"SendBitClout",
			[]string{"POST", "OPTIONS"},
			RoutePathSendBitClout,
			fes.SendBitClout,
			PublicAccess,
		},
		// Route for exchanging Bitcoin for BitClout
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

		// Endpoint to trigger the reprocessing of a particular Bitcoin block.
		{
			"ReprocessBitcoinBlock",
			[]string{"GET", "POST", "OPTIONS"},
			RoutePathReprocessBitcoinBlock + "/{blockHashHexOrblockHeight:[0-9abcdefABCDEF]+}",
			fes.ReprocessBitcoinBlock,
			PublicAccess,
		},
		// Endpoint to trigger granting a user a verified badge

		// The new BitClout endpoints start here.
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
			"GetHodlersForPublicKey",
			[]string{"POST", "OPTIONS"},
			RoutePathGetHodlersForPublicKey,
			fes.GetHodlersForPublicKey,
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
			"GetNotifications",
			[]string{"POST", "OPTIONS"},
			RoutePathGetNotifications,
			fes.GetNotifications,
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
			"GetGlobalParams",
			[]string{"POST", "OPTIONS"},
			RoutePathGetGlobalParams,
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
		// Super Admin routes
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
			"EvictUnminedBitcoinTxns",
			[]string{"POST", "OPTIONS"},
			RoutePathEvictUnminedBitcoinTxns,
			fes.EvictUnminedBitcoinTxns,
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
			"SetUSDCentsToBitCloutReserveExchangeRate",
			[]string{"POST", "OPTIONS"},
			RoutePathSetUSDCentsToBitCloutReserveExchangeRate,
			fes.SetUSDCentsToBitCloutReserveExchangeRate,
			SuperAdminAccess,
		},
		{
			"SetBuyBitCloutFeeBasisPoints",
			[]string{"POST", "OPTIONS"},
			RoutePathSetBuyBitCloutFeeBasisPoints,
			fes.SetBuyBitCloutFeeBasisPoints,
			SuperAdminAccess,
		},
		// End all /admin routes
		// GET endpoints for managing parameters related to Buying BitClout
		{
			"GetUSDCentsToBitCloutReserveExchangeRate",
			[]string{"GET"},
			RoutePathGetUSDCentsToBitCloutReserveExchangeRate,
			fes.GetUSDCentsToBitCloutReserveExchangeRate,
			PublicAccess,
		},
		{
			"GetBuyBitCloutFeeBasisPoints",
			[]string{"GET"},
			RoutePathGetBuyBitCloutFeeBasisPoints,
			fes.GetBuyBitCloutFeeBasisPoints,
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
			"GetRecloutsForPost",
			[]string{"POST", "OPTIONS"},
			RoutePathGetRecloutsForPost,
			fes.GetRecloutsForPost,
			PublicAccess,
		},
		{
			"GetQuoteRecloutsForPost",
			[]string{"POST", "OPTIONS"},
			RoutePathGetQuoteRecloutsForPost,
			fes.GetQuoteRecloutsForPost,
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
			// the public key that sends BitClout. WHITELIST WYRE IPs.
			"WyreWalletOrderSubscription",
			[]string{"POST", "OPTIONS"},
			RoutePathWyreWalletOrderSubscription,
			fes.WyreWalletOrderSubscription,
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
	fullRouteList = append(fullRouteList, fes.GlobalStateRoutes()...)

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

		// Anyone can access the admin panel if no public keys exist
		if route.AccessLevel != PublicAccess && (len(fes.Config.AdminPublicKeys) > 0 || len(fes.Config.SuperAdminPublicKeys) > 0) {
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

		glog.Tracef(
			"%s\t%s\t%s\t%s",
			r.Method,
			r.RequestURI,
			name,
			time.Since(start),
		)
	})
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
			// Note: Prior versions of this code used a regex, but I changed it to a literal match,
			// since I didn't want to risk a security vulnerability with a broken regex
			if allowedOrigin == actualOrigin || allowedOrigin == "*" {
				match = true
				break
			}
		}

		contentType := r.Header.Get("Content-Type")

		invalidPostRequest := false
		// upload-image endpoint is the only one allowed to use multipart/form-data
		if r.RequestURI == RoutePathUploadImage && strings.HasPrefix(contentType, "multipart/form-data") {
			match = true
			actualOrigin = "*"
		} else if r.Method == "POST" && contentType != "application/json" {
			invalidPostRequest = true
		}

		if match {
			// Needed in order for the user's browser to set a cookie
			w.Header().Add("Access-Control-Allow-Credentials", "true")

			w.Header().Set("Access-Control-Allow-Origin", actualOrigin)
			w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
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
		// POST requests from a non-bitclout domain)
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

func (fes *APIServer) ValidateJWT(publicKey string, jwtToken string) (bool, error) {
	pubKeyBytes, _, err := lib.Base58CheckDecode(publicKey)
	if err != nil {
		return false, err
	}

	pubKey, err := btcec.ParsePubKey(pubKeyBytes, btcec.S256())
	if err != nil {
		return false, err
	}

	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		return pubKey.ToECDSA(), nil
	})

	if err != nil {
		return false, err
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

func (fes *APIServer) logAmplitudeEvent(publicKeyBytes string, event string, eventData map[string]interface{}) error {
	if fes.Config.AmplitudeKey == "" {
		return nil
	}
	headers := map[string][]string{
		"Content-Type": {"application/json"},
		"Accept":       {"*/*"},
	}
	events := []AmplitudeEvent{{UserId: publicKeyBytes, EventType: event, EventProperties: eventData}}
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

func (fes *APIServer) StartExchangePriceMonitoring() {
	go func() {
	out:
		for {
			select {
			case <-time.After(10 * time.Second):
				fes.UpdateUSDCentsToBitCloutExchangeRate()
			case <-fes.quit:
				break out
			}
		}
	}()
}

// Monitor balances for starter bitclout seed and buy bitclout seed
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
				fes.logBalanceForSeed(fes.Config.StarterBitcloutSeed, "STARTER_BITCLOUT", tags)
				fes.logBalanceForSeed(fes.Config.BuyBitCloutSeed, "BUY_BITCLOUT", tags)
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

func (fes *APIServer) getBalanceForSeed(seedPhrase string) (uint64, error) {
	seedBytes, err := bip39.NewSeedWithErrorChecking(seedPhrase, "")
	if err != nil {
		return 0, fmt.Errorf("GetBalanceForSeed: Error converting mnemonic: %+v", err)
	}

	pubKey, _, _, err := lib.ComputeKeysFromSeed(seedBytes, 0, fes.Params)
	if err != nil {
		return 0, fmt.Errorf("GetBalanceForSeed: Error computing keys from seed: %+v", err)
	}
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return 0, fmt.Errorf("GetBalanceForSeed: Error getting UtxoView: %v", err)
	}
	currentBalanceNanos, err := GetBalanceForPublicKeyUsingUtxoView(pubKey.SerializeCompressed(), utxoView)
	if err != nil {
		return 0, fmt.Errorf("GetBalanceForSeed: Error getting balance: %v", err)
	}
	return currentBalanceNanos, nil
}
