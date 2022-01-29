package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/deso-protocol/backend/scripts/tools/toolslib"
	"github.com/deso-protocol/core/lib"
	"github.com/dgraph-io/badger/v3"
)

func getMostRecentSnapshot(snap *lib.Snapshot, handle *badger.DB, prefix []byte, lastKey []byte, chunkSize uint32) (
	[]*lib.DBEntry, bool) {

	var snapshotEntriesBatch []*lib.DBEntry
	//for ii := 0; ii < len(StatePrefixes); ii++ {
	//	prefix := StatePrefixes[ii]
	//for {
	fmt.Printf("Prefix (%v)\n", prefix)
	mainDbBatchEntries, mainDbFilled, _ := lib.DBIteratePrefixKeys(handle, prefix, lastKey, chunkSize)
	//ancestralChunk, chunkFullA, _ := lib.DBIteratePrefixKeys(snap.Db, snap.GetSeekPrefix(prefix),
	//	snap.GetSeekPrefix(lastKey), chunkSize)
	ancestralDbBatchEntries, ancestralDbFilled, _ := lib.DBIteratePrefixKeys(snap.Db,
		snap.GetSeekPrefix(prefix), snap.GetSeekPrefix(lastKey), chunkSize)
	//fmt.Printf("# seek prefix (%v)\n lastKey trimmed (%v)\n last key (%v)\n", snap.GetSeekPrefix(prefix), snap.GetSeekPrefix(lastKey),
	//	lastKey)
	fmt.Println("Number of snap original db keys", len(mainDbBatchEntries), "full?", mainDbFilled)
	for _, key := range mainDbBatchEntries {

		if hex.EncodeToString(key.Key) == "05cc52430f378922b792cfe7506d90d1df0adaf04871dda70a43f51126c8fd0bc400000000" {
			fmt.Println("#It's in the main DB")
		}
	}
	fmt.Println("How many snap keys? ", len(ancestralDbBatchEntries), "full?", ancestralDbFilled)
	numExisted := 0
	numNotExisted := 0
	for _, entry := range ancestralDbBatchEntries {
		if snap.CheckPrefixExists(entry.Value) {
			numExisted ++
		} else {
			numNotExisted ++
		}

		keyString := hex.EncodeToString(snap.SnapKeyToDBEntryKey(entry.Key))
		if keyString == "05cc52430f378922b792cfe7506d90d1df0adaf04871dda70a43f51126c8fd0bc400000000" {
			fmt.Println("#It's in the snap DB")
		}
	}
	fmt.Println("How many snap keys existed:", numExisted, "; and how many did not exist:", numNotExisted)

	indexChunk := 0
	for _, ancestralEntry := range ancestralDbBatchEntries {
		dbEntry := snap.AncestralRecordToDBEntry(ancestralEntry)
		if snap.CheckPrefixExists(ancestralEntry.Value) {
			snapshotEntriesBatch = append(snapshotEntriesBatch, dbEntry)
		}

		for jj := indexChunk; jj < len(mainDbBatchEntries); {
			if bytes.Compare(mainDbBatchEntries[jj].Key, dbEntry.Key) == -1 {
					snapshotEntriesBatch = append(snapshotEntriesBatch, mainDbBatchEntries[jj])
			} else if bytes.Compare(mainDbBatchEntries[jj].Key, dbEntry.Key) == 1 {
				break
			}
			// if keys are equal we just skip
			jj ++
			indexChunk = jj
		}
		// If we filled the chunk for main db records, we will return so that there is no
		// gap between the most recently added DBEntry and the next ancestral record. Otherwise,
		// we will keep going with the loop and add all the ancestral records.
		if mainDbFilled && indexChunk == len(mainDbBatchEntries) {
			break
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

	if len(snapshotEntriesBatch) == 0 {
		snapshotEntriesBatch = append(snapshotEntriesBatch, lib.EmptyDBEntry())
		return snapshotEntriesBatch, false
	}

	// If either of the chunks is full, we should return true.
	return snapshotEntriesBatch, mainDbFilled || ancestralDbFilled
}

func main() {
	//dirSnap := "/Users/piotr/data_dirs/n1_10/badgerdb/snapshot/"
	dirSnap := "/Users/piotr/data_dirs/n1_19/"
	dirDB := "/Users/piotr/data_dirs/n5_19/"

	dbSnap, err := toolslib.OpenDataDir(dirSnap)
	if err != nil {
		fmt.Printf("Error reading db1 err: %v", err)
		return
	}
	snap, err := lib.NewSnapshot(100000, dirSnap)
	if err != nil {
		fmt.Printf("Error reading snap err: %v", err)
		return
	}
	snap.BlockHeight = 1800

	//optsDb := badger.DefaultOptions(dirDB)
	//optsDb.ValueDir = lib.GetBadgerDbPath(dirDB)
	//optsDb.MemTableSize = 2000 << 20
	//db, err := badger.Open(optsDb)
	//if err != nil {
	//	fmt.Printf("Error reading db err: %v", err)
	//	return
	//}
	db, err := toolslib.OpenDataDir(dirDB)
	if err != nil {
		fmt.Printf("Error reading db1 err: %v", err)
		return
	}

	//snap, _ := lib.NewSnapshot(100000)
	//fmt.Println(snap.GetSnapshotChunk(db0, []byte{5}, []byte{5}))
	//fmt.Println(snap.GetSnapshotChunk(db1, []byte{5}, []byte{5}))
	maxBytes := uint32(8<<20)
	var prefixes [][]byte
	prefixes = append(prefixes, []byte{5})
	//prefixes = append(prefixes, []byte{1})
	//prefixes = append(prefixes, []byte{2})
	err = func() error {
		fmt.Printf("Checking prefixes: ")
		existingKeysSnap := make(map[string]string)
		existingKeysDb := make(map[string]string)
		for _, prefix := range prefixes {
			fmt.Printf("%v \n", prefix)
			lastPrefix := prefix
			var recurr func()
			recurr = func(){
				ancestralEntries, fullSnap := getMostRecentSnapshot(snap, dbSnap, prefix, lastPrefix, maxBytes)
				fmt.Printf("Found snap (%v) entries and full is (%v)\n", len(ancestralEntries), fullSnap)
				for _, entry := range ancestralEntries {
					//if entry.Key == "1703420bfd00431747618ea5231a7637e61c491510b30f5101265d6d5e9d0038b63c" {
					//	fmt.Println("GOT HERE BUT SHOULDN'T")
					//}
					keyHex := hex.EncodeToString(entry.Key)
					valueHex := hex.EncodeToString(entry.Value)
					existingKeysSnap[keyHex] = valueHex
				}

				entries, fullDb, err := lib.DBIteratePrefixKeys(db, prefix, lastPrefix, maxBytes)
				for _, entry := range entries {
					//if (*k0)[ii] == "05000000000000000000000000000000000000000000000000000000000000000000000083" {
					//	fmt.Println("YES IT EXISTS BUD")
					//}
					keyHex := hex.EncodeToString(entry.Key)
					valueHex := hex.EncodeToString(entry.Value)
					existingKeysDb[keyHex] = valueHex
				}
				if err != nil {
					fmt.Printf("Error reading db0 err: %v", err)
					return
				}
				fmt.Printf("Found db (%v) entries and full is (%v)\n", len(entries), fullDb)
				lastPrefix = ancestralEntries[len(ancestralEntries)-1].Key
				if fullSnap || fullDb {
					recurr()
				}
			}
			recurr()

			//fmt.Println("Number of entries: ", len(*k0))
			//for ii, _ := range(*k0) {
			//	fmt.Printf("Iterating prefix (%v) key (%v) value (%v)\n", prefix, (*k0)[ii], 0)//(*v0)[ii])
			//}
		}
		fmt.Println("how many snap keys:", len(existingKeysSnap))
		fmt.Println("how many db keys:", len(existingKeysDb))
		for key, value := range existingKeysSnap {
			if dbVal, exists := existingKeysDb[key]; exists {
				if value != dbVal {
					fmt.Printf("Error on key (%v); values don't match\n snap value: (%v)\n db value: (%v)\n",
						key, value, dbVal)
				}
			} else {
				fmt.Printf("Error value doesn't exist in db for key (%v)\n", key)
			}
		}
		return nil
	}()
	fmt.Println()
	if err == nil {
		fmt.Println("Databases identical!")
	} else {
		fmt.Println("Error! Databases not equal: ", err)
	}
	//for _, prefix := range lib.StatePrefixes {
	//	k0, v0, full0, err := lib.DBIteratePrefixKeys(db0, prefix, prefix, maxBytes)
	//	if err != nil {
	//		fmt.Printf("Error reading db0 err: %v", err)
	//		return
	//	}
	//	k1, v1, full1, err := lib.DBIteratePrefixKeys(db1, prefix, prefix, maxBytes)
	//	if err != nil {
	//		fmt.Printf("Error reading db1 err: %v", err)
	//		return
	//	}
	//}
}