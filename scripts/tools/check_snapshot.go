package main

import (
	"fmt"
	"github.com/deso-protocol/backend/scripts/tools/toolslib"
	"github.com/deso-protocol/core/lib"
	"sort"
)

func main() {
	dirSnap := "/Users/piotr/data_dirs/hypersync/sentry"

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

	maxBytes := uint32(8 << 20)
	var prefixes [][]byte
	for prefix, _ := range lib.StatePrefixes.StatePrefixesMap {
		if prefix == 14 || prefix == 15 || prefix == 16 || prefix == 42 {
			continue
		}

		prefixes = append(prefixes, []byte{prefix})
	}
	sort.Slice(prefixes, func(ii, jj int) bool {
		return prefixes[ii][0] < prefixes[jj][0]
	})
	fmt.Println(prefixes)
	err = func() error {
		fmt.Printf("Checking prefixes: ")
		for _, prefix := range prefixes {
			existingEntries := make(map[string]bool)
			fmt.Printf("%v \n", prefix)
			lastPrefix := prefix
			var recurr func()
			recurr = func() {
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

				if len(entries) != 0 {
					lastPrefix = entries[len(entries)-1].Key
				} else if fullDb {
					panic("Number of ancestral records should not be zero")
				}

				if fullDb {
					recurr()
				}
			}
			recurr()
			snap.WaitForAllOperationsToFinish()
			checksumBytes, _ := snap.Checksum.ToBytes()
			fmt.Println("prefix", prefix, "checksum:", checksumBytes)

		}
		fmt.Println("Finished iterating all prefixes")
		snap.WaitForAllOperationsToFinish()
		checksumBytes, _ := snap.Checksum.ToBytes()
		fmt.Println("Final checksum:", checksumBytes)

		return nil
	}()

}
