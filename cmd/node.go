package cmd

import (
	"github.com/bitclout/backend/config"
	"github.com/bitclout/backend/globaldb"
	"github.com/bitclout/backend/migrate"
	"github.com/bitclout/backend/routes"
	coreCmd "github.com/bitclout/core/cmd"
	"github.com/bitclout/core/lib"
	"github.com/dgraph-io/badger/v3"
	"github.com/go-pg/pg/v10"
	"github.com/golang/glog"
	"github.com/kevinburke/twilio-go"
	migrations "github.com/robinjoseph08/go-pg-migrations/v3"
	"path/filepath"
)

type Node struct {
	APIServer   *routes.APIServer
	GlobalState *badger.DB
	GlobalDB    *globaldb.GlobalDB
	Config      *config.Config

	CoreNode *coreCmd.Node
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

	// Default to core node postgres once fully transitioned
	//if node.Config.GlobalStatePostgresURI == "" {
	//	node.Config.GlobalStatePostgresURI = node.CoreNode.Config.PostgresURI
	//}

	// Connect to global DB postgres
	if node.Config.GlobalStatePostgresURI != "" {
		options, err := pg.ParseURL(node.Config.GlobalStatePostgresURI)
		if err != nil {
			panic(err)
		}

		db := pg.Connect(options)

		// Make sure we're migrated
		migrate.LoadMigrations()
		err = migrations.Run(db, "migrate", []string{"", "migrate"})
		if err != nil {
			panic(err)
		}

		node.GlobalDB = globaldb.NewGlobalDB(db)
	}

	var twilioClient *twilio.Client
	if node.Config.TwilioAccountSID != "" {
		twilioClient = twilio.NewClient(node.Config.TwilioAccountSID, node.Config.TwilioAuthToken, nil)
	}

	node.APIServer, err = routes.NewAPIServer(
		node.CoreNode.Server,
		node.CoreNode.Server.GetMempool(),
		node.CoreNode.Server.GetBlockchain(),
		node.CoreNode.Server.GetBlockProducer(),
		node.CoreNode.TXIndex,
		node.CoreNode.Postgres,
		node.GlobalDB,
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
