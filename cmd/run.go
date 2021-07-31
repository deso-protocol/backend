package cmd

import (
	"github.com/bitclout/backend/config"
	coreCmd "github.com/bitclout/core/cmd"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"os"
	"os/signal"
	"syscall"

	"github.com/golang/glog"
)

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the server",
	Long:  `...`,
	Run:   Run,
}

func Run(cmd *cobra.Command, args []string) {
	// Start the core node
	coreConfig := coreCmd.LoadConfig()
	coreNode := coreCmd.NewNode(coreConfig)
	coreNode.Start()

	// Start the backend node
	nodeConfig := config.LoadConfig(coreConfig)
	node := NewNode(nodeConfig, coreNode)
	node.Start()

	shutdownListener := make(chan os.Signal)
	signal.Notify(shutdownListener, syscall.SIGINT, syscall.SIGTERM)
	defer func() {
		node.Stop()
		glog.Info("Shutdown complete")
	}()

	<-shutdownListener
}

func init() {
	// Add all the core node flags
	coreCmd.SetupRunFlags(runCmd)

	// Add all the backend flags
	runCmd.PersistentFlags().Uint64("api-port", 0,
		"When set, determines the port on which this node will listen for json "+
			"requests. If unset, the port will default to what is present in the BitCloutParams set.")

	// Onboarding
	runCmd.PersistentFlags().String("starter-bitclout-seed", "",
		"Send a small amount of BitClout from this seed to new users.")
	runCmd.PersistentFlags().Uint64("starter-bitclout-nanos", 1000000,
		"The amount of BitClout given to new accounts to get them started. Only "+
			"active if --starter-bitclout-seed is set and funded.")
	runCmd.PersistentFlags().String("starter-prefix-nanos-map", "",
		"A comma-separated list of 'prefix=nanos' mappings, where prefix is a phone "+
			"number prefix such as \"+1\". These mappings allow the "+
			"node operator to specify custom amounts of BitClout to users verifying their phone "+
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

	// Global State
	runCmd.PersistentFlags().String("global-state-remote-node", "",
		"The IP:PORT or DOMAIN:PORT corresponding to a node that can be used to "+
			"set/get global state. When this is not provided, global state is set/fetched "+
			"from a local DB. Global state is used to manage things like user data, e.g. "+
			"emails, that should not be duplicated across multiple nodes.")
	runCmd.PersistentFlags().String("global-state-remote-secret", "",
		"When a remote node is being used to set/fetch global state, a secret "+
			"is also required to restrict access.")

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

	// User Interface
	runCmd.PersistentFlags().String("support-email", "", "Show a support email to users of this node")
	runCmd.PersistentFlags().Bool("show-processing-spinners", false,
		"Show processing spinners for unmined posts / BitClout / creator coins")

	// Images
	runCmd.PersistentFlags().String("gcp-credentials-path", "", "Google credentials to images bucket")
	runCmd.PersistentFlags().String("gcp-bucket-name", "", "Name of bucket to store images")

	// Admin
	runCmd.PersistentFlags().StringSlice("admin-public-keys", []string{},
		"A list of public keys which gives users access to the admin panel. "+
			"If no keys are specified anyone can access the admin panel. You can add a space "+
			"and a comment after every public key and leave a note about who the public key belongs to.")
	runCmd.PersistentFlags().StringSlice("super-admin-public-keys", []string{},
		"A list of public keys which gives users access to the super admin panel. "+
			"If no keys are specified anyone can access the super admin panel. You can add a space "+
			"and a comment after every public key and leave a note about who the public key belongs to.")

	// Wyre
	runCmd.PersistentFlags().String("wyre-account-id", "", "Wyre Account ID")
	runCmd.PersistentFlags().String("wyre-url", "", "Wyre API URL")
	runCmd.PersistentFlags().String("wyre-api-key", "", "Wyre API Key")
	runCmd.PersistentFlags().String("wyre-secret-key", "", "Wyre Secret Key")
	runCmd.PersistentFlags().String("buy-bitclout-btc-address", "", "BTC Address for all Wyre Wallet Orders and 'Buy With BTC' purchases")
	runCmd.PersistentFlags().String("buy-bitclout-seed", "", "Seed phrase from which BitClout will be sent for orders placed through Wyre and 'Buy With BTC' purchases")

	// Email
	runCmd.PersistentFlags().String("sendgrid-api-key", "", "Sendgrid API key")
	runCmd.PersistentFlags().String("sendgrid-domain", "", "Sendgrid domain")
	runCmd.PersistentFlags().String("sendgrid-salt", "", "Sendgrid salt for encoding data in emails")
	runCmd.PersistentFlags().String("sendgrid-from-name", "", "Sendgrid from name")
	runCmd.PersistentFlags().String("sendgrid-from-email", "", "Sendgrid from email")
	runCmd.PersistentFlags().String("sendgrid-confirm-email-id", "", "Sendgrid confirmation email template ID")

	runCmd.PersistentFlags().String("jumio-token", "", "Jumio Token")
	runCmd.PersistentFlags().String("jumio-secret", "", "Jumio Secret Key")

	runCmd.PersistentFlags().VisitAll(func(flag *pflag.Flag) {
		viper.BindPFlag(flag.Name, flag)
	})

	rootCmd.AddCommand(runCmd)
}
