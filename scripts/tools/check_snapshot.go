package main

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/deso-protocol/backend/scripts/tools/toolslib"
	"github.com/deso-protocol/core/lib"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
)

// FIXME: Delete this file if it's not needed or at least clean it up a little...
func main() {
	//dirSnap := "/Users/piotr/data_dirs/n1_10/badgerdb/snapshot/"
	dirSnap := "/Users/piotr/data_dirs/n1_19/"
	dirDB := "/tmp/n0_test_10000"
	txIndexDir := filepath.Join(lib.GetBadgerDbPath(dirDB), "txindex")
	txIndexOpts := badger.DefaultOptions(txIndexDir)
	txIndexOpts.ValueDir = lib.GetBadgerDbPath(txIndexDir)
	txIndexOpts.MemTableSize = 1024 << 20
	glog.Infof("TxIndex BadgerDB Dir: %v", txIndexOpts.Dir)
	glog.Infof("TxIndex BadgerDB ValueDir: %v", txIndexOpts.ValueDir)
	db, err := badger.Open(txIndexOpts)
	if err != nil {
		glog.Fatal(err)
	}

	dbSnap, err := toolslib.OpenDataDir(dirSnap)
	_ = dbSnap
	if err != nil {
		fmt.Printf("Error reading db1 err: %v", err)
		return
	}
	snap, err := lib.NewSnapshot(dirSnap, lib.SnapshotBlockHeightPeriod, false, false)
	if err != nil {
		fmt.Printf("Error reading snap err: %v", err)
		return
	}
	snap.CurrentEpochSnapshotMetadata.SnapshotBlockHeight = 1000

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
	maxBytes := uint32(8 << 20)
	var prefixes [][]byte
	for prefix, _ := range lib.StatePrefixes.StatePrefixesMap {
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
		existingKeysSnap := make(map[string]string)
		existingKeysDb := make(map[string]string)
		for _, prefix := range prefixes {
			fmt.Printf("%v \n", prefix)
			lastPrefix := prefix
			var recurr func()
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

				entries, fullDb, err := lib.DBIteratePrefixKeys(db, prefix, lastPrefix, maxBytes)
				for _, entry := range entries {
					//if (*k0)[ii] == "05000000000000000000000000000000000000000000000000000000000000000000000083" {
					//	fmt.Println("YES IT EXISTS BUD")
					//}
					keyHex := hex.EncodeToString(entry.Key)
					valueHex := hex.EncodeToString(entry.Value)
					existingKeysDb[keyHex] = valueHex
				}
				fmt.Printf("prefix: %v, len: %v\n", prefix, len(entries))
				if err != nil {
					fmt.Printf("Error reading db0 err: %v", err)
					return
				}
				fmt.Printf("Found db (%v) entries and full is (%v)\n", len(entries), fullDb)
				//lastPrefix = ancestralEntries[len(ancestralEntries)-1].Key
				//if fullSnap || fullDb {
				//	recurr()
				//}
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
