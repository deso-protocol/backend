package main

import (
	"bytes"
	"fmt"
	"github.com/deso-protocol/backend/scripts/tools/toolslib"
	"github.com/deso-protocol/core/lib"
	"github.com/dgraph-io/badger/v3"
	"github.com/pkg/errors"
	"sort"
)

func ancestralRecordToDBEntry(ancestralEntry *lib.DBEntry) *lib.DBEntry {
	var dbKey, dbVal []byte
	// Trim the prefix and the block height from the ancestral record key.
	dbKey = ancestralEntry.Key[9:]

	// Trim the existence_byte from the ancestral record value.
	if len(ancestralEntry.Value) > 0 {
		dbVal = ancestralEntry.Value[:len(ancestralEntry.Value)-1]
	}
	return &lib.DBEntry{
		Key:   dbKey,
		Value: dbVal,
	}
}

func getAncestralRecordsKey(key []byte) []byte {
	var prefix []byte

	// Append the ancestral records prefix.
	prefix = append(prefix, []byte{0}...)

	// Append block height, which is the current snapshot identifier.
	prefix = append(prefix, lib.EncodeUint64(114200)...)

	// Finally, append the main DB key.
	prefix = append(prefix, key...)
	return prefix
}

func checkAnceststralRecordExistenceByte(value []byte) bool {
	if len(value) > 0 {
		return value[len(value)-1] == 1
	}
	return false
}

func getSnapshotChunk(mainDb *badger.DB, snapDb *badger.DB, prefix []byte, startKey []byte) (
	_snapshotEntriesBatch []*lib.DBEntry, _snapshotEntriesFilled bool, _concurrencyFault bool, _err error) {

	// This the list of fetched DB entries.
	var snapshotEntriesBatch []*lib.DBEntry

	// Fetch the batch from main DB records with a batch size of about snap.BatchSize.
	mainDbBatchEntries, mainDbFilled, err := lib.DBIteratePrefixKeys(mainDb, prefix, startKey, lib.SnapshotBatchSize)
	if err != nil {
		return nil, false, false, errors.Wrapf(err, "Snapshot.GetSnapshotChunk: Problem fetching main Db records: ")
	}
	// Fetch the batch from the ancestral DB records with a batch size of about snap.BatchSize.
	ancestralDbBatchEntries, ancestralDbFilled, err := lib.DBIteratePrefixKeys(snapDb,
		getAncestralRecordsKey(prefix), getAncestralRecordsKey(startKey), lib.SnapshotBatchSize)
	if err != nil {
		return nil, false, false, errors.Wrapf(err, "Snapshot.GetSnapshotChunk: Problem fetching main Db records: ")
	}

	// To combine the main DB entries and the ancestral records DB entries, we iterate through the
	// ancestral records and for each key we add all the main DB keys that are smaller than the
	// currently processed key. The ancestral records entries have priority over the main DB entries,
	// so whenever there are entries with the same key among the two DBs, we will only add the
	// ancestral record entry to our snapshot batch. Also, the loop below might appear like O(n^2)
	// but it's actually O(n) because the inside loop iterates at most O(n) times in total.

	// Index to keep track of how many main DB entries we've already processed.
	indexChunk := 0
	for _, ancestralEntry := range ancestralDbBatchEntries {
		//var entriesToAppend []*DBEntry

		dbEntry := ancestralRecordToDBEntry(ancestralEntry)

		for jj := indexChunk; jj < len(mainDbBatchEntries); {
			if bytes.Compare(mainDbBatchEntries[jj].Key, dbEntry.Key) == -1 {
				snapshotEntriesBatch = append(snapshotEntriesBatch, mainDbBatchEntries[jj])
			} else if bytes.Compare(mainDbBatchEntries[jj].Key, dbEntry.Key) == 1 {
				break
			}
			// if keys are equal we just skip
			jj++
			indexChunk = jj
		}

		//for _, entry := range entriesToAppend {
		//	snapshotEntriesBatch = append(snapshotEntriesBatch, entry)
		//}

		// If we filled the chunk for main db records, we will return so that there is no
		// gap between the most recently added DBEntry and the next ancestral record. Otherwise,
		// we will keep going with the loop and add all the ancestral records.
		if mainDbFilled && indexChunk == len(mainDbBatchEntries) {
			break
		}
		if checkAnceststralRecordExistenceByte(ancestralEntry.Value) {
			snapshotEntriesBatch = append(snapshotEntriesBatch, dbEntry)
		}
	}

	// If we got all ancestral records, but there are still some main DB entries that we can add,
	// we will do that now.
	if !ancestralDbFilled {
		for jj := indexChunk; jj < len(mainDbBatchEntries); jj++ {
			indexChunk = jj
			snapshotEntriesBatch = append(snapshotEntriesBatch, mainDbBatchEntries[jj])
		}
	}

	// If no records are present in the db for the provided prefix and startKey, return an empty db entry.
	if len(snapshotEntriesBatch) == 0 {
		if ancestralDbFilled {
			// This can happen in a rare case where all ancestral records were non-existent records and
			// no record from the main DB was added.
			lastAncestralEntry := ancestralDbBatchEntries[len(ancestralDbBatchEntries)-1]
			dbEntry := ancestralRecordToDBEntry(lastAncestralEntry)
			return getSnapshotChunk(mainDb, snapDb, prefix, dbEntry.Key)
		} else {
			snapshotEntriesBatch = append(snapshotEntriesBatch, lib.EmptyDBEntry())
			return snapshotEntriesBatch, false, false, nil
		}
	}

	// If either of the chunks is full, we should return true.
	return snapshotEntriesBatch, mainDbFilled || ancestralDbFilled, false, nil
}

func main() {
	//dirSnap := "/Users/piotr/data_dirs/n1_10/badgerdb/snapshot/"
	dirSnap := "/Users/piotr/data_dirs/hypersync/sentry"
	//dirDB := "/tmp/n0_test_10000"

	dbSnap, err := toolslib.OpenDataDir(dirSnap)
	if err != nil {
		fmt.Printf("Error reading db1 err: %v", err)
		return
	}
	snap, err := lib.NewSnapshot(dirSnap, lib.SnapshotBlockHeightPeriod, false, false)
	if err != nil {
		fmt.Printf("Error reading snap err: %v", err)
		return
	}
	snap.CurrentEpochSnapshotMetadata.SnapshotBlockHeight = 114000
	snap.Checksum.Initialize()

	//optsDb := badger.DefaultOptions(dirDB)
	//optsDb.ValueDir = lib.GetBadgerDbPath(dirDB)
	//optsDb.MemTableSize = 2000 << 20
	//db, err := badger.Open(optsDb)
	//if err != nil {
	//	fmt.Printf("Error reading db err: %v", err)
	//	return
	//}
	//db, err := toolslib.OpenDataDir(dirDB)
	//if err != nil {
	//	fmt.Printf("Error reading db1 err: %v", err)
	//	return
	//}

	//snap, _ := lib.NewSnapshot(100000)
	//fmt.Println(snap.GetSnapshotChunk(db0, []byte{5}, []byte{5}))
	//fmt.Println(snap.GetSnapshotChunk(db1, []byte{5}, []byte{5}))
	//maxBytes := uint32(8 << 20)
	maxBytes := uint32(8 << 20)
	var prefixes [][]byte
	for prefix, _ := range lib.StatePrefixes.StatePrefixesMap {
		if prefix == 14 || prefix == 15 || prefix == 16 || prefix == 42 {
			continue
		}
		//if !isState {
		//	continue
		//}
		prefixes = append(prefixes, []byte{prefix})
	}
	sort.Slice(prefixes, func(ii, jj int) bool {
		return prefixes[ii][0] < prefixes[jj][0]
	})
	fmt.Println(prefixes)
	//prefixes = append(prefixes, []byte{1})
	//prefixes = append(prefixes, []byte{2})
	err = func() error {
		fmt.Printf("Checking prefixes: ")
		for _, prefix := range prefixes {
			existingEntries := make(map[string]bool)
			fmt.Printf("%v \n", prefix)
			lastPrefix := prefix
			var recurr func()
			//snap.Checksum.Initialize()
			recurr = func() {
				//ancestralEntries, fullSnap := getMostRecentSnapshot(snap, dbSnap, prefix, lastPrefix, maxBytes)
				//fmt.Printf("Found snap (%v) entries and full is (%v)\n", len(ancestralEntries), fullSnap)
				//for _, entry := range ancestralEntries {
				//	//if entry.Key == "1703420bfd00431747618ea5231a7637e61c491510b30f5101265d6d5e9d0038b63c" {
				//	//	fmt.Println("GOT HERE BUT SHOULDN'T")
				//	//}
				//	keyHex := hex.EncodeToString(entry.Key)
				//	valueHex := hex.EncodeToString(entry.Value)
				//	existingKeysSnap[keyHex] = valueHex
				//}
				//ancestralEntries, fullSnap, _, err := snap.GetSnapshotChunk(dbSnap, prefix, lastPrefix)
				entries, fullDb, err := lib.DBIteratePrefixKeys(dbSnap, prefix, lastPrefix, maxBytes)
				if err != nil {
					panic(fmt.Errorf("Problem fetching snapshot chunk (%v)", err))
				}
				for _, entry := range entries {
					encode := lib.EncodeKeyValue(entry.Key, entry.Value)
					dHash := string(lib.Sha256DoubleHash(encode)[:])
					if _, exists := existingEntries[dHash]; exists {
						continue
					} else {
						existingEntries[dHash] = true
					}
					snap.AddChecksumBytes(encode)
				}

				//entries, fullDb, err := lib.DBIteratePrefixKeys(db, prefix, lastPrefix, maxBytes)
				//for _, entry := range entries {
				//	//if (*k0)[ii] == "05000000000000000000000000000000000000000000000000000000000000000000000083" {
				//	//	fmt.Println("YES IT EXISTS BUD")
				//	//}
				//	keyHex := hex.EncodeToString(entry.Key)
				//	valueHex := hex.EncodeToString(entry.Value)
				//	existingKeysDb[keyHex] = valueHex
				//}
				//fmt.Printf("prefix: %v, len: %v\n", prefix, len(entries))
				//if err != nil {
				//	fmt.Printf("Error reading db0 err: %v", err)
				//	return
				//}
				//fmt.Printf("Found db (%v) entries and full is (%v)\n", len(ancestralEntries), fullSnap)
				if len(entries) != 0 {
					lastPrefix = entries[len(entries)-1].Key
				} else if fullDb {
					panic("Number of ancestral records should not be zero")
				}
				//if fullSnap || fullDb {
				//	recurr()
				//}
				snap.WaitForAllOperationsToFinish()
				checksumBytes, _ := snap.Checksum.ToBytes()
				fmt.Println("prefix", prefix, "checksum:", checksumBytes)
				if fullDb {
					recurr()
				}
			}
			recurr()
			snap.WaitForAllOperationsToFinish()
			checksumBytes, _ := snap.Checksum.ToBytes()
			fmt.Println("prefix", prefix, "checksum:", checksumBytes)

			//fmt.Println("Number of entries: ", len(*k0))
			//for ii, _ := range(*k0) {
			//	fmt.Printf("Iterating prefix (%v) key (%v) value (%v)\n", prefix, (*k0)[ii], 0)//(*v0)[ii])
			//}
		}
		fmt.Println("Finished iterating all prefixes")
		snap.WaitForAllOperationsToFinish()
		checksumBytes, _ := snap.Checksum.ToBytes()
		fmt.Println("Final checksum:", checksumBytes)
		//fmt.Println("how many snap keys:", len(existingKeysSnap))
		//fmt.Println("how many db keys:", len(existingKeysDb))
		//for key, value := range existingKeysSnap {
		//	if dbVal, exists := existingKeysDb[key]; exists {
		//		if value != dbVal {
		//			fmt.Printf("Error on key (%v); values don't match\n snap value: (%v)\n db value: (%v)\n",
		//				key, value, dbVal)
		//		}
		//	} else {
		//		fmt.Printf("Error value doesn't exist in db for key (%v)\n", key)
		//	}
		//}
		return nil
	}()

}
