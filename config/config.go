package config

import (
	"fmt"
	"github.com/holiman/uint256"
	"math/big"
	"strconv"
	"strings"

	"github.com/deso-protocol/core/lib"

	coreCmd "github.com/deso-protocol/core/cmd"
	"github.com/spf13/viper"
)

type Config struct {
	// Core
	APIPort uint16

	// Onboarding
	StarterDESOSeed         string
	StarterDESONanos        uint64
	StarterPrefixNanosMap   map[string]uint64
	TwilioAccountSID        string
	TwilioAuthToken         string
	TwilioVerifyServiceID   string
	CompProfileCreation     bool
	MinSatoshisForProfile   uint64
	PhoneNumberUseThreshold uint64

	// Global State
	GlobalStateRemoteNode   string
	GlobalStateRemoteSecret string

	// Hot Feed
	RunHotFeedRoutine    bool
	HotFeedMediaRequired bool

	// Web Security
	AccessControlAllowOrigins []string
	SecureHeaderDevelopment   bool
	SecureHeaderAllowHosts    []string
	AdminPublicKeys           []string
	SuperAdminPublicKeys      []string

	// Analytics
	AmplitudeKey string

	// Images
	GCPCredentialsPath string
	GCPBucketName      string

	// Wyre
	WyreUrl           string
	WyreAccountId     string
	WyreApiKey        string
	WyreSecretKey     string
	BuyDESOBTCAddress string
	BuyDESOETHAddress string
	BuyDESOSeed       string
	InfuraProjectID   string
	EtherscanAPIKey   string

	// Emails
	SendgridApiKey         string
	SendgridDomain         string
	SendgridSalt           string
	SendgridFromName       string
	SendgridFromEmail      string
	SendgridConfirmEmailId string

	// Jumio
	JumioToken  string
	JumioSecret string

	// Video Upload
	CloudflareStreamToken string
	CloudflareAccountId   string

	// Global State
	ExposeGlobalState bool
	GlobalStateAPIUrl string

	// Supply Monitoring Routine
	RunSupplyMonitoringRoutine bool

	// ID to tag node source
	NodeSource uint64

	// Public keys that need their balances monitored. Map of Label to Public key
	PublicKeyBalancesToMonitor map[string][]byte

	// Metamask minimal Eth in Wei required to receive an airdrop.
	MetamaskAirdropEthMinimum *uint256.Int
	// Amount of DESO in nanos metamask users receive as an airdrop
	MetamaskAirdropDESONanosAmount uint64
}

func LoadConfig(coreConfig *coreCmd.Config) *Config {
	config := Config{}

	config.APIPort = uint16(viper.GetUint64("api-port"))
	if config.APIPort <= 0 {
		// TODO: pull this out of core. we shouldn't need core's config here
		config.APIPort = coreConfig.Params.DefaultJSONPort
	}

	// Onboarding
	config.StarterDESOSeed = viper.GetString("starter-deso-seed")
	config.StarterDESONanos = viper.GetUint64("starter-deso-nanos")
	starterPrefixNanosMap := viper.GetString("starter-prefix-nanos-map")
	if len(starterPrefixNanosMap) > 0 {
		config.StarterPrefixNanosMap = make(map[string]uint64)
		for _, pair := range strings.Split(starterPrefixNanosMap, ",") {
			entry := strings.Split(pair, "=")
			nanos, err := strconv.Atoi(entry[1])
			if err != nil {
				fmt.Printf("invalid nanos: %s", entry[1])
			}
			config.StarterPrefixNanosMap[entry[0]] = uint64(nanos)
		}
	}
	config.TwilioAccountSID = viper.GetString("twilio-account-sid")
	config.TwilioAuthToken = viper.GetString("twilio-auth-token")
	config.TwilioVerifyServiceID = viper.GetString("twilio-verify-service-id")
	config.CompProfileCreation = viper.GetBool("comp-profile-creation")
	config.MinSatoshisForProfile = viper.GetUint64("min-satoshis-for-profile")
	config.PhoneNumberUseThreshold = viper.GetUint64("phone-number-use-threshold")

	// Global State
	config.GlobalStateRemoteNode = viper.GetString("global-state-remote-node")
	config.GlobalStateRemoteSecret = viper.GetString("global-state-remote-secret")

	// Hot Feed
	config.RunHotFeedRoutine = viper.GetBool("run-hot-feed-routine")
	config.HotFeedMediaRequired = viper.GetBool("hot-feed-media-required")

	// Web Security
	config.AccessControlAllowOrigins = viper.GetStringSlice("access-control-allow-origins")
	config.SecureHeaderDevelopment = viper.GetBool("secure-header-development")
	config.SecureHeaderAllowHosts = viper.GetStringSlice("secure-header-allow-hosts")
	config.AdminPublicKeys = viper.GetStringSlice("admin-public-keys")
	config.SuperAdminPublicKeys = viper.GetStringSlice("super-admin-public-keys")

	// Analytics
	config.AmplitudeKey = viper.GetString("amplitude-key")

	// Images
	config.GCPCredentialsPath = viper.GetString("gcp-credentials-path")
	config.GCPBucketName = viper.GetString("gcp-bucket-name")

	// Wyre
	config.WyreUrl = viper.GetString("wyre-url")
	config.WyreAccountId = viper.GetString("wyre-account-id")
	config.WyreApiKey = viper.GetString("wyre-api-key")
	config.WyreSecretKey = viper.GetString("wyre-secret-key")

	// BTC address to send all Bitcoin received from Wyre purchases and "Buy With BTC" purchases.
	config.BuyDESOBTCAddress = viper.GetString("buy-deso-btc-address")

	// ETH address to send all ETH received from "Buy With ETH" purchases.
	config.BuyDESOETHAddress = viper.GetString("buy-deso-eth-address")
	// Project ID for Infura requests
	config.InfuraProjectID = viper.GetString("infura-project-id")
	// Etherscan API Key
	config.EtherscanAPIKey = viper.GetString("etherscan-api-key")

	// Seed from which DeSo will be sent for orders placed through Wyre and "Buy With BTC" purchases
	config.BuyDESOSeed = viper.GetString("buy-deso-seed")

	// Email
	config.SendgridApiKey = viper.GetString("sendgrid-api-key")
	config.SendgridDomain = viper.GetString("sendgrid-domain")
	config.SendgridSalt = viper.GetString("sendgrid-salt")
	config.SendgridFromName = viper.GetString("sendgrid-from-name")
	config.SendgridFromEmail = viper.GetString("sendgrid-from-email")
	config.SendgridConfirmEmailId = viper.GetString("sendgrid-confirm-email-id")

	// Jumio
	config.JumioToken = viper.GetString("jumio-token")
	config.JumioSecret = viper.GetString("jumio-secret")

	// Video Upload
	config.CloudflareStreamToken = viper.GetString("cloudflare-stream-token")
	config.CloudflareAccountId = viper.GetString("cloudflare-account-id")

	// Global State
	config.ExposeGlobalState = viper.GetBool("expose-global-state")
	config.GlobalStateAPIUrl = viper.GetString("global-state-api-url")

	// Supply Monitoring Routine
	config.RunSupplyMonitoringRoutine = viper.GetBool("run-supply-monitoring-routine")

	// Node source ID
	config.NodeSource = viper.GetUint64("node-source")

	// Public keys that need their balances monitored. Map of Label to Public key
	labelsToPublicKeys := viper.GetString("public-key-balances-to-monitor")
	if len(labelsToPublicKeys) > 0 {
		config.PublicKeyBalancesToMonitor = make(map[string][]byte)
		for _, pair := range strings.Split(labelsToPublicKeys, ",") {
			entry := strings.Split(pair, "=")
			pubKeyBytes, _, err := lib.Base58CheckDecode(entry[1])
			if err != nil {
				fmt.Printf("Invalid public key: %v", entry[1])
				continue
			}
			config.PublicKeyBalancesToMonitor[entry[0]] = pubKeyBytes
		}
	}

	// Metamask minimal Eth in Wei required to receive an airdrop.
	metamaskAirdropMinStr := viper.GetString("metamask-airdrop-eth-minimum")
	if metamaskAirdropMinStr != "" {
		metamaskAirdropMinBigint, ok := big.NewInt(0).SetString(metamaskAirdropMinStr, 10)
		if !ok {
			panic(fmt.Sprintf("Error parsing metamask-airdrop-eth-minimum into bigint: %v", metamaskAirdropMinStr))
		}
		var overflow bool
		config.MetamaskAirdropEthMinimum, overflow = uint256.FromBig(metamaskAirdropMinBigint)
		if overflow {
			panic(fmt.Sprintf("metamask-airdrop-eth-minimum value %v overflows uint256", metamaskAirdropMinStr))
		}
	} else {
		config.MetamaskAirdropEthMinimum = uint256.NewInt()
	}
	config.MetamaskAirdropDESONanosAmount = viper.GetUint64("metamask-airdrop-deso-nanos-amount")

	return &config
}
