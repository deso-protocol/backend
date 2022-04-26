package secondary_indexes

import (
	"context"
	"github.com/deso-protocol/backend/secondary_indexes/migrations"
	coreCmd "github.com/deso-protocol/core/cmd"
	"github.com/deso-protocol/core/lib"
	"database/sql"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/spf13/viper"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
	"github.com/uptrace/bun/extra/bundebug"
	"github.com/uptrace/bun/migrate"
)

type SecondaryIndex struct {
	Node *coreCmd.Node

	ForceRecomputeOnStartup bool
	PostgresDB *bun.DB
}

func NewSecondaryIndex(
	coreNode *coreCmd.Node, pgURI string, forceRecomputeOnStartup bool) *SecondaryIndex {

	// FIXME: Provide an easy path for testing locally. See how daodao does it.
	//if pgURI == "" {
	//	pgURI = "postgresql://postgres:postgres@localhost:5432/postgres?sslmode=disable"
	//}

	// Open a PostgreSQL database.
	pgdb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(pgURI)))
	if pgdb == nil {
		glog.Fatalf("Error connecting to postgres db at URI: %v", pgURI)
	}

	// Create a Bun db on top of postgres for querying.
	db := bun.NewDB(pgdb, pgdialect.New())

	// Print all queries to stdout for debugging.
	db.AddQueryHook(bundebug.NewQueryHook(bundebug.WithVerbose(true)))

	// Apply db migrations
	ctx := context.Background()
	glog.Info("Applying migrations...")
	migrator := migrate.NewMigrator(db, migrations.Migrations)
	if err := migrator.Init(ctx); err != nil {
		glog.Fatal(err)
	}
	group, err := migrator.Migrate(ctx)
	if err != nil {
		glog.Fatal(err)
	}
	glog.Infof("Migrated to %s\n", group)

	return &SecondaryIndex{
		Node: coreNode,
		PostgresDB: db,
		ForceRecomputeOnStartup: forceRecomputeOnStartup,
	}
}


func (secondaryindex *SecondaryIndex) BuildSecondaryIndexesAfterSyncCompleted(
	event *lib.BlockEvent) {

	// FIXME: Store a variable in the DB to indicate whether or not we have built the
	// "initial" indexes yet. Set this variable the first time we have built these initial
	// indexes.
	hasBuiltInitialIndexes := false
	coreBlockchain := secondaryindex.Node.Server.GetBlockchain()
	isFullySynced := coreBlockchain.ChainState() != lib.SyncStateFullyCurrent
	if !hasBuiltInitialIndexes && isFullySynced {
		// FIXME: To support DAODAO, do the following here:
		// - Iterate through all posts in the node's "consensus" db. The inefficient function below
		//   is fine, but you have to fill it in:
		//   * DBGetAllPostsInefficient(coreBlockchain.DB())
		// - For each post, store it in Postgres with an index on the following fields PLUS
		//   indexed on timestamp AND amount of DAO coin held AND follower/following AND CommentCount,
		//   which comes standard on the PostEntry (will tell you how to look up DAO coin held in a second):
		//   * Parse the tags in the post and see if any of them correspond to a DAO.
		//   * PostApp (will be DAODAO for DAODAO)
		// - To compute the amount of DAO coin held, use the function below and use the profile of
		//   the username in the PostGroup as the creatorPKID to look it up:
		//   * DBGetBalanceEntryForHODLerAndCreatorPKIDsWithTxn

		// You're done once you've indexed all of the above.
		return
	}
	// If we get here, it means we already did the initial index build, and just need to
	// process this one new block. This is pretty chill.

	// FIXME: Implement the following:
	// - For each txn in the block that is a SubmitPost or a like or a Diamond, update
	//   the post in our DB. You don't need to do anything fancy here, just set the post
	//   in postgres to be whatever consensus has computed.

	// If you've done all of the above, you should be able to support queries of the following form,
	// which is the whole point:
	// - DAODAO subreddit default sort:
	//   * Give me all posts made in the last day/week/month filtered to a particular PostGroup and
	//     sorted by {CommentCount, DAO coin holdings of the poster}
	//

	// Check a variable in the DB to determine if we need to do an "initial" build
	// of secondary indexes or not. If yes, then build. Otherwise, don't. If we
	// have ForceRecomputeOnStartup, then dump the entire database and build the
	// indexes from scratch once sync is complete.
	// Check to see if we're supposed to actually build secondary indexes.
	// Check to see if we've run this function before.


	// If you do the above, you'll be able to service the following queries, which is the goal
	// of all this:
	// - Give me all the posts made in the last 24 hours sorted by
	// - Give me all the posts for a particular PostGroup ordered by WHEN they were posted. This
	//   will support the NEW sort on a DAODAO subreddit.
	// - Give me all the posts for a particular PostGroup ordered by largest DAO coin holders first.
	//   We will need to filter this a bit to show unique posts, ut
	// - Give me all the posts for a particular (user,  app) ordered by WHEN they were posted

	isCurrent := event.Server.blockchain.ChainState() == SyncStateFullyCurrent
	if event. {

	}
}
