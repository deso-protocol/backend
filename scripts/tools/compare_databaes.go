package main

import (
	"fmt"
	"github.com/deso-protocol/backend/scripts/tools/toolslib"
	"github.com/deso-protocol/core/lib"
	"reflect"
	"sort"
)

func main() {
	dir0 := "/Users/piotr/data_dirs/n69_5"
	dir1 := "/Users/piotr/data_dirs/n69_2"

	db0, err := toolslib.OpenDataDir(dir0)
	if err != nil {
		fmt.Printf("Error reading db0 err: %v", err)
		return
	}
	db1, err := toolslib.OpenDataDir(dir1)
	if err != nil {
		fmt.Printf("Error reading db1 err: %v", err)
		return
	}

	maxBytes := uint32(8 << 22)
	broken := false
	var prefixes, brokenPrefixes [][]byte
	for prefix, isState := range lib.StatePrefixes.StatePrefixesMap {
		if !isState {
			continue
		}

		prefixes = append(prefixes, []byte{prefix})
	}
	sort.Slice(prefixes, func(ii, jj int) bool {
		return prefixes[ii][0] < prefixes[jj][0]
	})
	err = func() error {
		for _, prefix := range prefixes {
			fmt.Printf("Checking prefix: (%v)\n", prefix)
			lastPrefix := prefix
			invalidLengths := false
			invalidKeys := false
			invalidValues := false
			invalidFull := false
			for {
				db0Entries, full0, err := lib.DBIteratePrefixKeys(db0, prefix, lastPrefix, maxBytes)
				if err != nil {
					return fmt.Errorf("Error reading db0 err: %v\n", err)
				}

				db1Entries, full1, err := lib.DBIteratePrefixKeys(db1, prefix, lastPrefix, maxBytes)

				if err != nil {
					return fmt.Errorf("Error reading db1 err: %v\n", err)
				}
				if len(db0Entries) != len(db1Entries) {
					invalidLengths = true
					fmt.Printf("Databases not equal on prefix: %v, and lastPrefix: %v;"+
						"varying lengths (db0, db1) : (%v, %v)\n", prefix, lastPrefix, len(db0Entries), len(db1Entries))
					break
				}
				for ii, entry := range db0Entries {
					if !reflect.DeepEqual(entry.Key, db1Entries[ii].Key) {
						if !invalidKeys {
							fmt.Printf("Databases not equal on prefix: %v, and lastPrefix: %v; unequal keys "+
								"(db0, db1) : (%v, %v)\n", prefix, lastPrefix, entry.Key, db1Entries[ii].Key)
							invalidKeys = true
						}
					}
				}
				for ii, entry := range db0Entries {
					if !reflect.DeepEqual(entry.Value, db1Entries[ii].Value) {
						if !invalidValues {
							fmt.Printf("Databases not equal on prefix: %v, and lastPrefix: %v; the key is (%v); "+
								"unequal values (db0, db1) : (%v, %v)\n", prefix, lastPrefix, entry.Key,
								entry.Value, db1Entries[ii].Value)
							invalidValues = true
						}
					}
				}
				if full0 != full1 {
					if !invalidFull {
						fmt.Printf("Databases not equal on prefix: %v, and lastPrefix: %v;"+
							"unequal fulls (db0, db1) : (%v, %v)\n", prefix, lastPrefix, full0, full1)
						invalidFull = true
					}
				}

				if len(db0Entries) > 0 {
					lastPrefix = db0Entries[len(db0Entries)-1].Key
				} else {
					break
				}

				if !full0 {
					break
				}
			}
			status := "PASS"
			if invalidLengths || invalidKeys || invalidValues || invalidFull {
				status = "FAIL"
				brokenPrefixes = append(brokenPrefixes, prefix)
				broken = true
			}

			fmt.Printf("Status for prefix (%v): (%s)\n invalidLengths: (%v); invalidKeys: (%v); invalidValues: "+
				"(%v); invalidFull: (%v)\n\n", prefix, status, invalidLengths, invalidKeys, invalidValues, invalidFull)
		}
		return nil
	}()

	if err == nil {
		if broken {
			fmt.Println("Databases differ! Broken prefixes:", brokenPrefixes)
		} else {
			fmt.Println("Databases identical!")
		}
	} else {
		fmt.Println("Error! Databases not equal: ", err)
	}
}
