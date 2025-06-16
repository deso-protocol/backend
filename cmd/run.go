package cmd

import (
	"github.com/deso-protocol/backend/config"
	coreCmd "github.com/deso-protocol/core/cmd"
	"github.com/golang/glog"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the server",
	Long:  `...`,
	Run:   Run,
}

func Run(cmd *cobra.Command, args []string) {
	shutdownListener := make(chan struct{})

	// Start the core node
	coreConfig := coreCmd.LoadConfig()
	coreNode := coreCmd.NewNode(coreConfig)
	coreNode.Start(&shutdownListener)

	// Start the backend node
	nodeConfig := config.LoadConfig(coreConfig)
	node := NewNode(nodeConfig, coreNode)
	node.Start()

	defer func() {
		coreNode.Stop()
		node.Stop()
		glog.Info("Shutdown complete")
	}()

	if shutdownListener != nil {
		<-shutdownListener
	}
}

func init() {
	// Add all the core node flags
	coreCmd.SetupRunFlags(runCmd)

	// Add all the backend flags
	runCmd.PersistentFlags().Uint64("api-port", 0,
		"When set, determines the port on which this node will listen for json "+
			"requests. If unset, the port will default to what is present in the DeSoParams set.")
	runCmd.PersistentFlags().String("amm-metadata-public-key", "",
		"The base58-encoded public key for the AMM_METADATA user, which is "+
			"used to set the trading fees on users' coins.")
	// Onboarding
	runCmd.PersistentFlags().String("starter-deso-seed", "",
		"Send a small amount of DeSo from this seed to new users.")
	runCmd.PersistentFlags().Uint64("starter-deso-nanos", 1000000,
		"The amount of DeSo given to new accounts to get them started. Only "+
			"active if --starter-deso-seed is set and funded.")
	runCmd.PersistentFlags().String("starter-prefix-nanos-map", "",
		"A comma-separated list of 'prefix=nanos' mappings, where prefix is a phone "+
			"number prefix such as \"+1\". These mappings allow the "+
			"node operator to specify custom amounts of DeSo to users verifying their phone "+
			"numbers based on the country they're in. This is useful as it is more expensive "+
			"for attackers to get phone numbers from certain countries. An example string would "+
			"be '+1=2000000,+2=2000000', which would double the default nanos for users with "+
			"with those prefixes.")
	runCmd.PersistentFlags().String("twilio-account-sid", "",
		"Twilio account SID (string id). Twilio is used for sending verification texts. See twilio documentation for more info.")
	runCmd.PersistentFlags().String("twilio-auth-token", "",
		"Twilio authentication token. See twilio documentation for more info.")
	runCmd.PersistentFlags().String("twilio-verify-service-id", "",
		"ID for a verify service configured within Twilio (used for verification texts)")
	runCmd.PersistentFlags().Bool("comp-profile-creation", false, "Comp profile creation")
	runCmd.PersistentFlags().Uint64("min-satoshis-for-profile", 50000,
		"Users won't be able to create a profile unless they buy this "+
			"amount of satoshis or provide a phone number.")
	// How many times can a phone number be used to receive starter DESO.
	runCmd.PersistentFlags().Uint64("phone-number-use-threshold", 10, "A phone number will "+
		"be allowed to be used this many times to receive starter DESO. Set this to a higher value "+
		"if you want users to be able to create multiple accounts more easily.")

	// Global State
	runCmd.PersistentFlags().String("global-state-remote-node", "",
		"The IP:PORT or DOMAIN:PORT corresponding to a node that can be used to "+
			"set/get global state. When this is not provided, global state is set/fetched "+
			"from a local DB. Global state is used to manage things like user data, e.g. "+
			"emails, that should not be duplicated across multiple nodes.")
	runCmd.PersistentFlags().String("global-state-remote-secret", "",
		"When a remote node is being used to set/fetch global state, a secret "+
			"is also required to restrict access.")

	// Hot Feed
	runCmd.PersistentFlags().Bool("run-hot-feed-routine", false,
		"If set, runs a go routine that accumulates 'hotness' scores for posts  in the "+
			"last 24hrs.  This can be used to serve a 'hot' feed.")
	runCmd.PersistentFlags().Bool("hot-feed-media-required", false,
		"If set, hot feed excludes posts without media.")

	// Web Security
	runCmd.PersistentFlags().StringSlice("access-control-allow-origins", []string{"*"},
		"Accepts a comma-separated lists of origin domains that will be allowed as the "+
			"Access-Control-Allow-Origin HTTP header. Defaults to * if not set.")
	runCmd.PersistentFlags().StringSlice("secure-header-allow-hosts", []string{},
		"This is the domain that our secure middleware will accept requests from. We also set the "+
			"HTTP Access-Control-Allow-Origin")
	runCmd.PersistentFlags().Bool("secure-header-development", true,
		"If set, runs our secure header middleware in development mode, which disables some "+
			"of the options. The default is true to make it easy to run a node locally. "+
			"See https://github.com/unrolled/secure for more info. Note that")

	// Analytics + Profiling
	runCmd.PersistentFlags().String("amplitude-key", "", "Client-side amplitude key for instrumenting user behavior.")
	runCmd.PersistentFlags().String("amplitude-domain", "api.amplitude.com", "Client-side amplitude API Endpoint.")

	// Transactions
	runCmd.PersistentFlags().Int("max-optional-preceding-transactions", 0,
		"If set, enables certain transaction construction "+
			"endpoints to accept transactions that should be connected "+
			"before constructing the specified transaction. "+
			"Setting this flag can aid in workflows that deal with atomic transaction construction.")

	// User Interface
	runCmd.PersistentFlags().String("support-email", "", "Show a support email to users of this node")
	runCmd.PersistentFlags().Bool("show-processing-spinners", false,
		"Show processing spinners for unmined posts / DeSo / creator coins")

	// Images
	runCmd.PersistentFlags().String("gcp-credentials-path", "", "Google credentials to images bucket")
	runCmd.PersistentFlags().String("gcp-bucket-name", "", "Name of bucket to store images")

	// Admin
	runCmd.PersistentFlags().StringSlice("admin-public-keys", []string{},
		"A list of public keys which gives users access to the admin panel. "+
			"If '*' is specified as a key, anyone can access the admin panel. You can add a space "+
			"and a comment after every public key and leave a note about who the public key belongs to.")
	runCmd.PersistentFlags().StringSlice("super-admin-public-keys", []string{},
		"A list of public keys which gives users access to the super admin panel. "+
			"If '*' is specified as a key, anyone can access the super admin panel. You can add a space "+
			"and a comment after every public key and leave a note about who the public key belongs to.")

	// Wyre
	runCmd.PersistentFlags().String("wyre-account-id", "", "Wyre Account ID")
	runCmd.PersistentFlags().String("wyre-url", "", "Wyre API URL")
	runCmd.PersistentFlags().String("wyre-api-key", "", "Wyre API Key")
	runCmd.PersistentFlags().String("wyre-secret-key", "", "Wyre Secret Key")
	runCmd.PersistentFlags().String("buy-deso-btc-address", "", "BTC Address for all Wyre Wallet Orders and 'Buy With BTC' purchases")
	runCmd.PersistentFlags().String("buy-deso-seed", "", "Seed phrase from which DeSo will be sent for orders placed through Wyre and 'Buy With BTC' purchases")
	runCmd.PersistentFlags().String("buy-deso-eth-address", "", "ETH Address for all 'Buy With ETH' purchases")
	runCmd.PersistentFlags().String("infura-project-id", "", "Project ID for Infura requests")
	runCmd.PersistentFlags().String("etherscan-api-key", "", "Etherscan API Key")

	// Email
	runCmd.PersistentFlags().String("sendgrid-api-key", "", "Sendgrid API key")
	runCmd.PersistentFlags().String("sendgrid-domain", "", "Sendgrid domain")
	runCmd.PersistentFlags().String("sendgrid-salt", "", "Sendgrid salt for encoding data in emails")
	runCmd.PersistentFlags().String("sendgrid-from-name", "", "Sendgrid from name")
	runCmd.PersistentFlags().String("sendgrid-from-email", "", "Sendgrid from email")
	runCmd.PersistentFlags().String("sendgrid-confirm-email-id", "", "Sendgrid confirmation email template ID")

	// Jumio
	runCmd.PersistentFlags().String("jumio-token", "", "Jumio Token")
	runCmd.PersistentFlags().String("jumio-secret", "", "Jumio Secret Key")

	// Video Upload
	runCmd.PersistentFlags().String("cloudflare-stream-token", "", "API Token with Edit access to Cloudflare's stream service")
	runCmd.PersistentFlags().String("cloudflare-account-id", "", "Cloudflare Account ID")

	// Global State
	runCmd.PersistentFlags().Bool("expose-global-state", false, "Expose global state data to all origins")
	runCmd.PersistentFlags().String("global-state-api-url", "", "URL to use to fetch global state data. Only used if expose-global-state is false. If not provided, use own global state.")

	// Run Supply Monitoring Routine
	runCmd.PersistentFlags().Bool("run-supply-monitoring-routine", false, "Run a goroutine to monitor total supply and rich list")

	// Tag transaction with node source
	runCmd.PersistentFlags().Uint64("node-source", 0, "Node ID to tag transaction with. Maps to ../core/lib/nodes.go")

	// Public keys that need their balances monitored. Map of Label to Public key
	runCmd.PersistentFlags().String("public-key-balances-to-monitor", "",
		"Comma-separated string of 'label=publicKey'. These balances of the public key provided will be logged in DataDog with the label provided.")

	// Metamask minimal Eth in Wei required to receive an airdrop.
	// The default 100000000000000 is equal to .0001 Eth.
	runCmd.PersistentFlags().String("metamask-airdrop-eth-minimum", "100000000000000",
		"In Wei, amount of Eth required to receive an airdrop during Metamask signup.")
	runCmd.PersistentFlags().Uint64("metamask-airdrop-deso-nanos-amount", 0, "Amount of DESO in nanos to send to metamask users as an airdrop")
	runCmd.PersistentFlags().String("hcaptcha-secret", "", "Secret key for hcaptcha service. Used to verify captcha token verifications.")
	runCmd.PersistentFlags().StringSlice("peers-to-monitor", []string{}, "List of peer URLs to monitor for networking connectivity while the node is running.")
	runCmd.PersistentFlags().VisitAll(func(flag *pflag.Flag) {
		viper.BindPFlag(flag.Name, flag)
	})

	rootCmd.AddCommand(runCmd)
}
