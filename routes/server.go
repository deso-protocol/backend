package routes

import (
	"bytes"
	"encoding/json"
	fmt "fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/dgrijalva/jwt-go/v4"
	"github.com/tyler-smith/go-bip39"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

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
	RoutePathHealthCheck              = "/api/v0/health-check"
	RoutePathGetExchangeRate          = "/api/v0/get-exchange-rate"
	RoutePathGetAppState              = "/api/v0/get-app-state"

	// transaction.go
	RoutePathGetTxn                   = "/api/v0/get-txn"
	RoutePathSubmitTransaction        = "/api/v0/submit-transaction"
	RoutePathUpdateProfile            = "/api/v0/update-profile"
	RoutePathBurnBitcoin              = "/api/v0/burn-bitcoin"
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
	RoutePathGetHodlersForPublicKey   = "/api/v0/get-hodlers-for-public-key"
	RoutePathGetDiamondsForPublicKey  = "/api/v0/get-diamonds-for-public-key"
	RoutePathGetFollowsStateless      = "/api/v0/get-follows-stateless"
	RoutePathGetUserGlobalMetadata    = "/api/v0/get-user-global-metadata"
	RoutePathUpdateUserGlobalMetadata = "/api/v0/update-user-global-metadata"
	RoutePathGetNotifications         = "/api/v0/get-notifications"
	RoutePathBlockPublicKey           = "/api/v0/block-public-key"

	// post.go
	RoutePathGetPostsStateless        = "/api/v0/get-posts-stateless"
	RoutePathGetSinglePost            = "/api/v0/get-single-post"
	RoutePathGetPostsForPublicKey     = "/api/v0/get-posts-for-public-key"
	RoutePathGetDiamondedPosts        = "/api/v0/get-diamonded-posts"

	// media.go
	RoutePathUploadImage              = "/api/v0/upload-image"
	RoutePathGetFullTikTokURL         = "/api/v0/get-full-tiktok-url"

	// message.go
	RoutePathSendMessageStateless     = "/api/v0/send-message-stateless"
	RoutePathGetMessagesStateless     = "/api/v0/get-messages-stateless"
	RoutePathMarkContactMessagesRead  = "/api/v0/mark-contact-messages-read"
	RoutePathMarkAllMessagesRead 	  = "/api/v0/mark-all-messages-read"

	// verify.go
	RoutePathSendPhoneNumberVerificationText   = "/api/v0/send-phone-number-verification-text"
	RoutePathSubmitPhoneNumberVerificationCode = "/api/v0/submit-phone-number-verification-code"

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
	RoutePathNodeControl                           = "/api/v0/admin/node-control"
	RoutePathReprocessBitcoinBlock                 = "/api/v0/admin/reprocess-bitcoin-block"
	RoutePathAdminGetMempoolStats                  = "/api/v0/admin/get-mempool-stats"
	RoutePathEvictUnminedBitcoinTxns               = "/api/v0/admin/evict-unmined-bitcoin-txns"

	// admin_transaction.go
	RoutePathGetGlobalParams                       = "/api/v0/admin/get-global-params"
	RoutePathUpdateGlobalParams                    = "/api/v0/admin/update-global-params"
	RoutePathSwapIdentity                          = "/api/v0/admin/swap-identity"

	// admin_user.go
	RoutePathAdminUpdateUserGlobalMetadata         = "/api/v0/admin/update-user-global-metadata"
	RoutePathAdminGetAllUserGlobalMetadata         = "/api/v0/admin/get-all-user-global-metadata"
	RoutePathAdminGetUserGlobalMetadata            = "/api/v0/admin/get-user-global-metadata"
	RoutePathAdminGrantVerificationBadge           = "/api/v0/admin/grant-verification-badge"
	RoutePathAdminRemoveVerificationBadge          = "/api/v0/admin/remove-verification-badge"
	RoutePathAdminGetVerifiedUsers                 = "/api/v0/admin/get-verified-users"
	RoutePathAdminGetUsernameVerificationAuditLogs = "/api/v0/admin/get-username-verification-audit-logs"

	// admin_feed.go
	RoutePathAdminUpdateGlobalFeed                 = "/api/v0/admin/update-global-feed"
	RoutePathAdminPinPost                          = "/api/v0/admin/pin-post"
	RoutePathAdminRemoveNilPosts                   = "/api/v0/admin/remove-nil-posts"
)

// APIServer provides the interface between the blockchain and things like the
// web UI. In particular, it exposes a JSON API that can be used to do everything the
// frontend cares about, from posts to profiles to purchasing BitClout with Bitcoin.
type APIServer struct {
	backendServer *lib.Server
	mempool       *lib.BitCloutMempool
	blockchain    *lib.Blockchain
	blockProducer *lib.BitCloutBlockProducer

	Params               *lib.BitCloutParams
	SharedSecret         string
	JSONPort             uint16
	MinFeeRateNanosPerKB uint64

	// This info is used to send "starter" BitClout to newly-created accounts.
	// This allows them to create profiles, among other things, without having
	// to buy BitClout first.
	StarterBitCloutSeed        string
	StarterBitCloutAmountNanos uint64

	// Map of country code strings to the amount of start BitClout to issue.
	StarterBitCloutPrefixExceptionMap map[string]uint64

	// A pointer to the router that handles all requests.
	router *muxtrace.Router

	TXIndex *lib.TXIndex

	// Used for getting/setting the global state. Usually either a db is set OR
	// a remote node is set-- not both. When a remote node is set, global state
	// is set and fetched from that node. Otherwise, it is set/fetched from the
	// db. This makes it easy to run a local node in development.
	GlobalStateDB                     *badger.DB
	GlobalStateRemoteNode             string
	GlobalStateRemoteNodeSharedSecret string

	AccessControlAllowOrigins           []string
	SecureHeaderMiddlewareIsDevelopment bool
	SecureHeaderMiddlewareAllowedHost   []string

	// Optional, may be empty. Used for client-side user instrumentation
	AmplitudeKey    string
	AmplitudeDomain string

	// Whether or not to show processing spinners for unmined transactions in the UI.
	ShowProcessingSpinners bool

	// Optional, may be empty. Used for Twilio integration
	Twilio                *twilio.Client
	TwilioVerifyServiceId string

	// Optional. Used for gating profile creation.
	MinSatoshisBurnedForProfileCreation uint64

	// Optional. Show a support email to end users
	SupportEmail string

	// When set, BlockCypher is used to add extra security to BitcoinExchange
	// transactions.
	BlockCypherAPIKey string

	// Google image storage environment variables
	GoogleApplicationCredentials string
	GoogleBucketName             string

	// Optional. If true and twilio and starter bitclout seed configured, node will comp profile creation.
	IsCompProfileCreation bool

	// Optional, restricts access to the admin panel to these public keys
	AdminPublicKeys []string

	// Wyre
	WyreUrl string
	WyreAccountId string
	WyreApiKey string
	WyreSecretKey string
	WyreBTCAddress string
	BuyBitCloutSeed string

	// Signals that the frontend server is in a stopped state
	quit chan struct{}
}

// NewAPIServer ...
func NewAPIServer(_backendServer *lib.Server,
	_mempool *lib.BitCloutMempool,
	_blockchain *lib.Blockchain,
	_blockProducer *lib.BitCloutBlockProducer,
	txIndex *lib.TXIndex,
	params *lib.BitCloutParams,
	jsonPort uint16,
	_minFeeRateNanosPerKB uint64,
	_starterBitCloutSeed string,
	_starterBitCloutAmountNanos uint64,
	_starterBitCloutPrefixExceptionMap map[string]uint64,
	globalStateDB *badger.DB,
	globalStateRemoteNode string,
	globalStateRemoteNodeSharedSecret string,
	accessControlAllowOrigins []string,
	secureHeaderMiddlewareIsDevelopment bool,
	secureHeaderMiddlewareAllowedHost []string,
	amplitudeKey string,
	amplitudeDomain string,
	showProcessingSpinners bool,
	twilio *twilio.Client,
	twilioVerifyServiceId string,
	minSatoshisBurnedForProfileCreation uint64,
	supportEmail string,
	blockCypherAPIKey string,
	googleApplicationCredentials string,
	googleBucketName string,
	compProfileCreation bool,
	adminPublicKeys []string,
	wyreUrl string,
	wyreAccountId string,
	wyreApiKey string,
	wyreSecretKey string,
	wyreBTCAddress string,
	buyBitCloutSeed string,
) (*APIServer, error) {

	if globalStateDB == nil && globalStateRemoteNode == "" {
		return nil, fmt.Errorf(
			"NewAPIServer: Error: A globalStateDB or a globalStateRemoteNode is required")
	}

	fes := &APIServer{
		// TODO: It would be great if we could eliminate the dependency on
		// the backendServer. Right now it's here because it was the easiest
		// way to give the APIServer the ability to add transactions
		// to the mempool and relay them to peers.
		backendServer:                       _backendServer,
		mempool:                             _mempool,
		blockchain:                          _blockchain,
		blockProducer:                       _blockProducer,
		TXIndex:                             txIndex,
		Params:                              params,
		JSONPort:                            jsonPort,
		MinFeeRateNanosPerKB:                _minFeeRateNanosPerKB,
		StarterBitCloutSeed:                 _starterBitCloutSeed,
		StarterBitCloutAmountNanos:          _starterBitCloutAmountNanos,
		StarterBitCloutPrefixExceptionMap:   _starterBitCloutPrefixExceptionMap,
		GlobalStateDB:                       globalStateDB,
		GlobalStateRemoteNode:               globalStateRemoteNode,
		GlobalStateRemoteNodeSharedSecret:   globalStateRemoteNodeSharedSecret,
		AccessControlAllowOrigins:           accessControlAllowOrigins,
		SecureHeaderMiddlewareIsDevelopment: secureHeaderMiddlewareIsDevelopment,
		SecureHeaderMiddlewareAllowedHost:   secureHeaderMiddlewareAllowedHost,
		AmplitudeKey:                        amplitudeKey,
		AmplitudeDomain:                     amplitudeDomain,
		ShowProcessingSpinners:              showProcessingSpinners,
		Twilio:                              twilio,
		TwilioVerifyServiceId:               twilioVerifyServiceId,
		MinSatoshisBurnedForProfileCreation: minSatoshisBurnedForProfileCreation,
		SupportEmail:                        supportEmail,
		BlockCypherAPIKey:                   blockCypherAPIKey,
		GoogleApplicationCredentials:        googleApplicationCredentials,
		GoogleBucketName:                    googleBucketName,
		IsCompProfileCreation:               compProfileCreation,
		AdminPublicKeys:                     adminPublicKeys,
		WyreUrl:                             wyreUrl,
		WyreAccountId:                       wyreAccountId,
		WyreApiKey:                          wyreApiKey,
		WyreSecretKey:                       wyreSecretKey,
		WyreBTCAddress:                      wyreBTCAddress,
		BuyBitCloutSeed:                     buyBitCloutSeed,
	}

	fes.StartSeedBalancesMonitoring()

	return fes, nil
}

// Route ...
type Route struct {
	Name           string
	Method         []string
	Pattern        string
	HandlerFunc    http.HandlerFunc
	CheckPublicKey bool
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
			false,
		},

		{
			"HealthCheck",
			[]string{"GET"},
			RoutePathHealthCheck,
			fes.HealthCheck,
			false,
		},

		// Routes for populating various UI elements.
		{
			"GetExchangeRate",
			[]string{"GET"},
			RoutePathGetExchangeRate,
			fes.GetExchangeRate,
			false,
		},

		// Route for sending BitClout
		{
			"SendBitClout",
			[]string{"POST", "OPTIONS"},
			RoutePathSendBitClout,
			fes.SendBitClout,
			false,
		},

		// Route for burning Bitcoin for BitClout
		{
			"BurnBitcoin",
			[]string{"POST", "OPTIONS"},
			RoutePathBurnBitcoin,
			fes.BurnBitcoinStateless,
			false,
		},

		// Route for submitting signed transactions for network broadcast
		{
			"SubmitTransaction",
			[]string{"POST", "OPTIONS"},
			RoutePathSubmitTransaction,
			fes.SubmitTransaction,
			false,
		},

		// Temporary route to wipe seedinfo cookies
		{
			"DeleteIdentities",
			[]string{"POST", "OPTIONS"},
			RoutePathDeleteIdentities,
			fes.DeleteIdentities,
			false,
		},

		// Endpoint to trigger the reprocessing of a particular Bitcoin block.
		{
			"ReprocessBitcoinBlock",
			[]string{"GET", "POST", "OPTIONS"},
			RoutePathReprocessBitcoinBlock + "/{blockHashHexOrblockHeight:[0-9abcdefABCDEF]+}",
			fes.ReprocessBitcoinBlock,
			false,
		},
		// Endpoint to trigger granting a user a verified badge

		// The new BitClout endpoints start here.
		{
			"GetUsersStateless",
			[]string{"POST", "OPTIONS"},
			RoutePathGetUsersStateless,
			fes.GetUsersStateless,
			false,
		},
		{
			"SendPhoneNumberVerificationText",
			[]string{"POST", "OPTIONS"},
			RoutePathSendPhoneNumberVerificationText,
			fes.SendPhoneNumberVerificationText,
			false,
		},
		{
			"SubmitPhoneNumberVerificationCode",
			[]string{"POST", "OPTIONS"},
			RoutePathSubmitPhoneNumberVerificationCode,
			fes.SubmitPhoneNumberVerificationCode,
			false,
		},
		{
			"UploadImage",
			[]string{"POST", "OPTIONS"},
			RoutePathUploadImage,
			fes.UploadImage,
			false,
		},
		{
			"SubmitPost",
			[]string{"POST", "OPTIONS"},
			RoutePathSubmitPost,
			fes.SubmitPost,
			false,
		},
		{
			"GetPostsStateless",
			[]string{"POST", "OPTIONS"},
			RoutePathGetPostsStateless,
			fes.GetPostsStateless,
			// CheckSecret: No need to check the secret since this is a read-only endpoint.
			false,
		},
		{
			"UpdateProfile",
			[]string{"POST", "OPTIONS"},
			RoutePathUpdateProfile,
			fes.UpdateProfile,
			false,
		},
		{
			"GetProfiles",
			[]string{"POST", "OPTIONS"},
			RoutePathGetProfiles,
			fes.GetProfiles,
			// CheckSecret: No need to check the secret since this is a read-only endpoint.
			false,
		},
		{
			"GetSingleProfile",
			[]string{"POST", "OPTIONS"},
			RoutePathGetSingleProfile,
			fes.GetSingleProfile,
			false,
		},
		{
			"GetPostsForPublicKey",
			[]string{"POST", "OPTIONS"},
			RoutePathGetPostsForPublicKey,
			fes.GetPostsForPublicKey,
			false,
		},
		{
			"GetDiamondsForPublicKey",
			[]string{"POST", "OPTIONS"},
			RoutePathGetDiamondsForPublicKey,
			fes.GetDiamondsForPublicKey,
			false,
		},
		{
			"GetDiamondedPosts",
			[]string{"POST", "OPTIONS"},
			RoutePathGetDiamondedPosts,
			fes.GetDiamondedPosts,
			false,
		},
		{
			"GetHodlersForPublicKey",
			[]string{"POST", "OPTIONS"},
			RoutePathGetHodlersForPublicKey,
			fes.GetHodlersForPublicKey,
			false,
		},
		{
			"GetFollowsStateless",
			[]string{"POST", "OPTIONS"},
			RoutePathGetFollowsStateless,
			fes.GetFollowsStateless,
			false,
		},
		{
			"CreateFollowTxnStateless",
			[]string{"POST", "OPTIONS"},
			RoutePathCreateFollowTxnStateless,
			fes.CreateFollowTxnStateless,
			false,
		},
		{
			"CreateLikeStateless",
			[]string{"POST", "OPTIONS"},
			RoutePathCreateLikeStateless,
			fes.CreateLikeStateless,
			false,
		},
		{
			"BuyOrSellCreatorCoin",
			[]string{"POST", "OPTIONS"},
			RoutePathBuyOrSellCreatorCoin,
			fes.BuyOrSellCreatorCoin,
			false,
		},
		{
			"TransferCreatorCoin",
			[]string{"POST", "OPTIONS"},
			RoutePathTransferCreatorCoin,
			fes.TransferCreatorCoin,
			false,
		},
		{
			"SendDiamonds",
			[]string{"POST", "OPTIONS"},
			RoutePathSendDiamonds,
			fes.SendDiamonds,
			false,
		},
		{
			"GetNotifications",
			[]string{"POST", "OPTIONS"},
			RoutePathGetNotifications,
			fes.GetNotifications,
			false,
		},
		{
			"GetAppState",
			[]string{"POST", "OPTIONS"},
			RoutePathGetAppState,
			fes.GetAppState,
			false,
		},
		{
			"UpdateUserGlobalMetadata",
			[]string{"POST", "OPTIONS"},
			RoutePathUpdateUserGlobalMetadata,
			fes.UpdateUserGlobalMetadata,
			false,
		},
		{
			"GetUserGlobalMetadata",
			[]string{"POST", "OPTIONS"},
			RoutePathGetUserGlobalMetadata,
			fes.GetUserGlobalMetadata,
			false,
		},

		// Begin all /admin routes

		{
			// Route for all low-level node operations.
			"NodeControl",
			[]string{"POST", "OPTIONS"},
			RoutePathNodeControl,
			fes.NodeControl,
			true,
		},
		{
			"AdminUpdateUserGlobalMetadata",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminUpdateUserGlobalMetadata,
			fes.AdminUpdateUserGlobalMetadata,
			true,
		},
		{
			"AdminGetVerifiedUsers",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminGetVerifiedUsers,
			fes.AdminGetVerifiedUsers,
			true, // Check Secret
		},
		{
			"AdminGetUsernameVerificationAuditLogs",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminGetUsernameVerificationAuditLogs,
			fes.AdminGetUsernameVerificationAuditLogs,
			true, // Check Secret
		},
		{
			"AdminGrantVerificationBadge",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminGrantVerificationBadge,
			fes.AdminGrantVerificationBadge,
			true, // Check Secret
		},
		{
			"AdminRemoveVerificationBadge",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminRemoveVerificationBadge,
			fes.AdminRemoveVerificationBadge,
			true, // Check Secret
		},
		{
			"AdminGetAllUserGlobalMetadata",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminGetAllUserGlobalMetadata,
			fes.AdminGetAllUserGlobalMetadata,
			true,
		},
		{
			"AdminGetUserGlobalMetadata",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminGetUserGlobalMetadata,
			fes.AdminGetUserGlobalMetadata,
			true,
		},
		{
			"AdminUpdateGlobalFeed",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminUpdateGlobalFeed,
			fes.AdminUpdateGlobalFeed,
			true,
		},
		{
			"AdminPinPost",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminPinPost,
			fes.AdminPinPost,
			true, // CheckSecret
		},
		{
			"AdminRemoveNilPosts",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminRemoveNilPosts,
			fes.AdminRemoveNilPosts,
			true,
		},
		{
			"AdminGetMempoolStats",
			[]string{"POST", "OPTIONS"},
			RoutePathAdminGetMempoolStats,
			fes.AdminGetMempoolStats,
			true,
		},
		{
			"SwapIdentity",
			[]string{"POST", "OPTIONS"},
			RoutePathSwapIdentity,
			fes.SwapIdentity,
			true,
		},
		{
			"UpdateGlobalParams",
			[]string{"POST", "OPTIONS"},
			RoutePathUpdateGlobalParams,
			fes.UpdateGlobalParams,
			true,
		},
		{
			"GetGlobalParams",
			[]string{"POST", "OPTIONS"},
			RoutePathGetGlobalParams,
			fes.GetGlobalParams,
			true,
		},
		{
			"EvictUnminedBitcoinTxns",
			[]string{"POST", "OPTIONS"},
			RoutePathEvictUnminedBitcoinTxns,
			fes.EvictUnminedBitcoinTxns,
			true,
		},
		{
			"GetWyreWalletOrdersForPublicKey",
			[]string{"POST", "OPTIONS"},
			RoutePathGetWyreWalletOrdersForPublicKey,
			fes.GetWyreWalletOrdersForPublicKey,
			true,
		},
		// End all /admin routes

		{
			"GetSinglePost",
			[]string{"POST", "OPTIONS"},
			RoutePathGetSinglePost,
			fes.GetSinglePost,
			false,
		},
		{
			"BlockPublicKey",
			[]string{"POST", "OPTIONS"},
			RoutePathBlockPublicKey,
			fes.BlockPublicKey,
			false,
		},
		{
			"BlockGetTxn",
			[]string{"POST", "OPTIONS"},
			RoutePathGetTxn,
			fes.GetTxn,
			false,
		},

		// message.go
		{
			"SendMessageStateless",
			[]string{"POST", "OPTIONS"},
			RoutePathSendMessageStateless,
			fes.SendMessageStateless,
			false,
		},
		{
			"GetMessagesStateless",
			[]string{"POST", "OPTIONS"},
			RoutePathGetMessagesStateless,
			fes.GetMessagesStateless,
			false,
		},
		{
			"MarkContactMessagesRead",
			[]string{"POST", "OPTIONS"},
			RoutePathMarkContactMessagesRead,
			fes.MarkContactMessagesRead,
			false,
		},
		{
			"MarkAllMessagesRead",
			[]string{"POST", "OPTIONS"},
			RoutePathMarkAllMessagesRead,
			fes.MarkAllMessagesRead,
			false,
		},

		// Paths for the mining pool
		{
			"GetBlockTemplate",
			[]string{"POST", "OPTIONS"},
			RoutePathGetBlockTemplate,
			fes.GetBlockTemplate,
			false,
		},
		{
			"SubmitBlock",
			[]string{"POST", "OPTIONS"},
			RoutePathSubmitBlock,
			fes.SubmitBlock,
			false,
		},

		{
			"GetFullTikTokURL",
			[]string{"POST", "OPTIONS"},
			RoutePathGetFullTikTokURL,
			fes.GetFullTikTokURL,
			false,
		},

		// Paths for wyre
		{
			"GetWyreWalletOrderQuotation",
			[]string{"POST", "OPTIONS"},
			RoutePathGetWyreWalletOrderQuotation,
			fes.GetWyreWalletOrderQuotation,
			false,
		},
		{
			"GetWyreWalletOrderReservation",
			[]string{"POST", "OPTIONS"},
			RoutePathGetWyreWalletOrderReservation,
			fes.GetWyreWalletOrderReservation,
			false,
		},
		{
			// Make sure you only allow access to Wyre IPs for this endpoint, otherwise anybody can take all the funds from
			// the public key that sends BitClout. WHITELIST WYRE IPs.
			"WyreWalletOrderSubscription",
			[]string{"POST", "OPTIONS"},
			RoutePathWyreWalletOrderSubscription,
			fes.WyreWalletOrderSubscription,
			false,
		},
	}

	router := muxtrace.NewRouter().StrictSlash(true)

	// Set secure headers
	secureMiddleware := lib.InitializeSecureMiddleware(
		fes.SecureHeaderMiddlewareAllowedHost,
		fes.SecureHeaderMiddlewareIsDevelopment,
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
		if route.CheckPublicKey && len(fes.AdminPublicKeys) > 0 {
			handler = fes.CheckAdminPublicKey(handler)
		}
		handler = Logger(handler, route.Name)
		handler = AddHeaders(handler, fes.AccessControlAllowOrigins)

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
func (fes *APIServer) CheckAdminPublicKey(inner http.Handler) http.Handler {
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

		for _, adminPubKey := range fes.AdminPublicKeys {
			if adminPubKey == requestData.AdminPublicKey {
				// We found a match, serve the request
				inner.ServeHTTP(ww, req)
				return
			}
		}

		_AddBadRequestError(ww, "CheckAdminPublicKey: Not an admin")
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

	return token.Valid, err
}

// Start ...
func (fes *APIServer) Start() {
	fes.initState()

	glog.Infof("Listening to NON-SSL JSON API connections on port :%d", fes.JSONPort)
	glog.Error(http.ListenAndServe(fmt.Sprintf(":%d", fes.JSONPort), fes.router))
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
	ApiKey string `json:"api_key"`
	Events []AmplitudeEvent `json:"events"`
}

type AmplitudeEvent struct {
	UserId          string `json:"user_id"`
	EventType       string `json:"event_type"`
	EventProperties map[string]interface{} `json:"event_properties"`
}

func (fes *APIServer) logAmplitudeEvent(publicKeyBytes string, event string, eventData map[string]interface{})  error {
	if fes.AmplitudeKey == "" {
		return nil
	}
	headers := map[string][]string{
		"Content-Type": {"application/json"},
		"Accept":       {"*/*"},
	}
	events := []AmplitudeEvent{{UserId: publicKeyBytes, EventType: event, EventProperties: eventData}}
	ampBody := AmplitudeUploadRequestBody{ApiKey: fes.AmplitudeKey, Events: events}
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

// Monitor balances for starter bitclout seed and buy bitclout seed
func (fes *APIServer) StartSeedBalancesMonitoring() {
	go func() {
	out:
		for {
			select {
			case <- time.After(1 * time.Minute):
				if fes.backendServer.GetStatsdClient() == nil {
					return
				}
				tags := []string{}
				fes.logBalanceForSeed(fes.StarterBitCloutSeed, "STARTER_BITCLOUT", tags)
				fes.logBalanceForSeed(fes.BuyBitCloutSeed, "BUY_BITCLOUT", tags)
			case <- fes.quit:
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

func (fes *APIServer) getBalanceForSeed(seedPhrase string) (uint64, error){
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

