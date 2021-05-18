package cmd

import (
	"github.com/bitclout/backend/routes"
	coreCmd "github.com/bitclout/core/cmd"
	"github.com/bitclout/core/lib"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/kevinburke/twilio-go"
	"path/filepath"
)


type Node struct {
	APIServer   *routes.APIServer
	TXIndex     *badger.DB
	GlobalState *badger.DB
	Config      *Config

	CoreNode    *coreCmd.Node
}

func NewNode(config *Config, coreNode *coreCmd.Node) *Node {
	result := Node{}
	result.Config = config
	result.CoreNode = coreNode

	return &result
}

func (node *Node) Start() {
	var err error

	// Create a transaction index as a separate db that's managed by the APIServer.
	// This makes it easy to delete manually if it gets too large.
	if node.Config.TXIndex {
		txindexDir := filepath.Join(lib.GetBadgerDbPath(node.CoreNode.Config.DataDirectory), "txindex")
		txindexOpts := badger.DefaultOptions(txindexDir)
		txindexOpts.ValueDir = lib.GetBadgerDbPath(txindexDir)
		txindexOpts.MemTableSize = 1024 << 20
		glog.Infof("TxIndex BadgerDB Dir: %v", txindexOpts.Dir)
		glog.Infof("TxIndex BadgerDB ValueDir: %v", txindexOpts.ValueDir)
		node.TXIndex, err = badger.Open(txindexOpts)
		if err != nil {
			glog.Fatal(err)
		}
	}

	// For the global state, we use a local db unless a remote node is set in
	// which case all global state set/fetch calls will proxy to the remote.
	if node.Config.GlobalStateRemoteNode == "" {
		globalStateDir := filepath.Join(lib.GetBadgerDbPath(node.CoreNode.Config.DataDirectory), "global_state")
		globalStateOpts := badger.DefaultOptions(globalStateDir)
		globalStateOpts.MemTableSize = 1024 << 20
		globalStateOpts.ValueDir = lib.GetBadgerDbPath(globalStateDir)
		glog.Infof("GlobalState BadgerDB Dir: %v", globalStateOpts.Dir)
		glog.Infof("GlobalState BadgerDB ValueDir: %v", globalStateOpts.ValueDir)
		node.GlobalState, err = badger.Open(globalStateOpts)
		if err != nil {
			glog.Fatal(err)
		}
	}

	var twilioClient *twilio.Client
	if node.Config.TwilioAccountSID != "" {
		twilioClient = twilio.NewClient(node.Config.TwilioAccountSID, node.Config.TwilioAuthToken, nil)
	}

	apiServer, err := routes.NewAPIServer(
		node.CoreNode.Server,
		node.CoreNode.Server.GetMempool(),
		node.CoreNode.Server.GetBlockchain(),
		node.CoreNode.Server.GetBlockProducer(),
		node.TXIndex,
		node.CoreNode.Params,
		node.Config.APIPort,
		node.CoreNode.Config.MinFeerate,
		node.Config.StarterBitcloutSeed,
		node.Config.StarterBitcloutNanos,
		node.Config.StarterPrefixNanosMap,
		node.GlobalState,
		node.Config.GlobalStateRemoteNode,
		node.Config.GlobalStateRemoteSecret,
		node.Config.AccessControlAllowOrigins,
		node.Config.SecureHeaderDevelopment,
		node.Config.SecureHeaderAllowHosts,
		node.Config.AmplitudeKey,
		node.Config.AmplitudeDomain,
		node.Config.ShowProcessingSpinners,
		twilioClient,
		node.Config.TwilioVerifyServiceID,
		node.Config.MinSatoshisForProfile,
		node.Config.SupportEmail,
		node.CoreNode.Config.BlockCypherAPIKey,
		node.Config.GCPCredentialsPath,
		node.Config.GCPBucketName,
		node.Config.CompProfileCreation,
		node.CoreNode.Config.AdminPublicKeys,
	)
	if err != nil {
		glog.Fatal(err)
	}

	go apiServer.Start()
}

func (node *Node) Stop() {
	node.APIServer.Stop()

	if node.GlobalState != nil {
		_ = node.GlobalState.Close()
	}

	if node.TXIndex != nil {
		_ = node.TXIndex.Close()
	}
}
