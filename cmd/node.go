package cmd

import (
	"path/filepath"

	"github.com/deso-protocol/backend/config"
	"github.com/deso-protocol/backend/routes"
	coreCmd "github.com/deso-protocol/core/cmd"
	"github.com/deso-protocol/core/lib"
	"github.com/dgraph-io/badger/v4"
	"github.com/golang/glog"
	"github.com/kevinburke/twilio-go"
)

type Node struct {
	APIServer   *routes.APIServer
	GlobalState *badger.DB
	Config      *config.Config
	CoreNode    *coreCmd.Node
}

func NewNode(config *config.Config, coreNode *coreCmd.Node) *Node {
	result := Node{}
	result.Config = config
	result.CoreNode = coreNode

	return &result
}

func (node *Node) Start() {
	var err error

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

	if node.CoreNode.Config.HyperSync == true && node.Config.RunHotFeedRoutine == true {
		if !lib.IsNodeArchival(node.CoreNode.Config.SyncType) {
			node.Config.RunHotFeedRoutine = false
			glog.Errorf(lib.CLog(lib.Red, "Hot feed is not compatible with non-archival mode. You need "+
				"to set --archival-mode=true if you want to run hot feed with hypersync."))
		}
	}

	node.APIServer, err = routes.NewAPIServer(
		node.CoreNode.Server,
		node.CoreNode.Server.GetMempool(),
		node.CoreNode.Server.GetBlockchain(),
		node.CoreNode.Server.GetBlockProducer(),
		node.CoreNode.TXIndex,
		node.CoreNode.Params,
		node.Config,
		node.CoreNode.Config.MinFeerate,
		node.GlobalState,
		twilioClient,
		node.CoreNode.Config.BlockCypherAPIKey,
	)
	if err != nil {
		glog.Fatal(err)
	}

	go node.APIServer.Start()
}

func (node *Node) Stop() {
	node.APIServer.Stop()

	if node.GlobalState != nil {
		_ = node.GlobalState.Close()
	}
}
