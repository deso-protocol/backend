package main

import (
	"fmt"
	"github.com/deso-protocol/backend/scripts/tools/toolslib"
	"github.com/deso-protocol/core/lib"
	"github.com/dgraph-io/badger/v3"
	"github.com/pkg/errors"
)

func main() {
	dbDir := "$HOME/data_dirs/hypersync/runner"

	db, err := toolslib.OpenDataDir(dbDir)
	if err != nil {
		fmt.Printf("Error reading db1 err: %v", err)
		return
	}
	snap, err, _ := lib.NewSnapshot(db, dbDir, lib.SnapshotBlockHeightPeriod, false, false, &lib.DeSoMainnetParams, false, lib.HypersyncDefaultMaxQueueSize)
	if err != nil {
		fmt.Printf("Error reading snap err: %v", err)
		return
	}
	snap.CurrentEpochSnapshotMetadata.SnapshotBlockHeight = 114000
	snap.Checksum.ResetChecksum()
	for _, prefixByte := range []byte{0, 1, 2} {
		prefix := []byte{prefixByte}
		startKey := prefix
		fetchingPrefix := true

		// We will delete all records for a prefix step by step. We do this in chunks of 8MB,
		// to make sure we don't overload badger DB with the size of our queries. Whenever a
		// chunk is not full, that is isChunkFull = false, it means that we've exhausted all
		// entries for a prefix.
		for fetchingPrefix {
			// Fetch a chunk of data from the DB.
			dbEntries, isChunkFull, err := lib.DBIteratePrefixKeys(db, prefix, startKey, lib.SnapshotBatchSize)
			fetchingPrefix = isChunkFull
			if err != nil {
				panic(errors.Wrapf(err, "Problem fetching entries from the db at prefix (%v)", prefix))
			}

			// Now delete all these keys.
			err = db.Update(func(txn *badger.Txn) error {
				for _, dbEntry := range dbEntries {
					err := txn.Delete(dbEntry.Key)
					if err != nil {
						return errors.Wrapf(err, "Problem deleting key (%v)", dbEntry.Key)
					}
				}
				return nil
			})
			if err != nil {
				panic(err)
			}
		}
	}
}
