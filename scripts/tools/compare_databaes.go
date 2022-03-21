package main

import (
	"encoding/hex"
	"fmt"
	"github.com/deso-protocol/backend/scripts/tools/toolslib"
	"github.com/deso-protocol/core/lib"
	"reflect"
	"time"
)

func main() {
	dir0 := "/Users/piotr/data_dirs/n69_3"
	dir1 := "/Users/piotr/data_dirs/n69_2"
	//dir2 := "/Users/piotr/data_dirs/n7_1"

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
	//db2, err := toolslib.OpenDataDir(dir2)
	//if err != nil {
	//	fmt.Printf("Error reading db2 err: %v", err)
	//	return
	//}

	//snap, _ := lib.NewSnapshot(100000)
	//fmt.Println(snap.GetSnapshotChunk(db0, []byte{5}, []byte{5}))
	//fmt.Println(snap.GetSnapshotChunk(db1, []byte{5}, []byte{5}))
	maxBytes := uint32(8 << 22)
	totalLen := 0
	var timeElapsed float64
	var currentTime time.Time
	timeElapsed = 0.0
	currentTime = time.Now()
	broken := false
	err = func() error {
		for prefixByte, isState := range lib.StatePrefixes.StatePrefixesMap {
			if !isState {
				continue
			}
			prefix := []byte{prefixByte}
			fmt.Printf("Checking prefix: (%v)\n", prefix)
			lastPrefix := prefix
			invalidLengths := false
			invalidKeys := false
			invalidValues := false
			invalidFull := false
			for {
				existingKeysSnap := make(map[string]string)
				existingKeysDb := make(map[string]string)
				timeElapsed += time.Since(currentTime).Seconds()
				currentTime = time.Now()
				//fmt.Println("Starting the fetch time elapsed (%v) current time (%v)", timeElapsed, currentTime)
				//timeElapsed += time.Since(currentTime).Seconds()
				//currentTime = time.Now()
				//fmt.Println("Starting the fetch time elapsed (%v) current time (%v)", timeElapsed, currentTime)
				//if err != nil {
				//	return fmt.Errorf("Error reading db0 err: %v\n", err)
				//}
				//fmt.Println("Current key %v", (*k0)[0])
				//db2.Update(func(txn *badger.Txn) error {
				//	for i, _ := range *k0 {
				//		keyBytes, _ := hex.DecodeString((*k0)[i])
				//		valueBytes, _ := hex.DecodeString((*v0)[i])
				//		lib.DBSetWithTxn(txn, nil, keyBytes, valueBytes)
				//	}
				//	return nil
				//})
				//lapsed += time.Since(currentTime).Seconds()
				//currentTime = time.Now()
				//fmt.Println("Finished writing data time elapsed (%v) current time (%v)", timeElapsed, currentTime)
				db0Entries, full0, err := lib.DBIteratePrefixKeys(db0, prefix, lastPrefix, maxBytes)
				_ = err
				for _, entry := range db0Entries {
					keyHex := hex.EncodeToString(entry.Key)
					valueHex := hex.EncodeToString(entry.Value)
					existingKeysSnap[keyHex] = valueHex
				}
				db1Entries, full1, err := lib.DBIteratePrefixKeys(db1, prefix, lastPrefix, maxBytes)
				for _, entry := range db1Entries {
					keyHex := hex.EncodeToString(entry.Key)
					valueHex := hex.EncodeToString(entry.Value)
					existingKeysDb[keyHex] = valueHex
				}

				if err != nil {
					return fmt.Errorf("Error reading db1 err: %v\n", err)
				}
				fmt.Printf("Number of snap keys (%v) number of db keys (%v)\n", len(db0Entries), len(db1Entries))
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
							fmt.Printf("Databases not equal on prefix: %v, and lastPrefix: %v; unequal values "+
								"(db0, db1) : (%v, %v)\n", prefix, lastPrefix, entry.Value, db1Entries[ii].Value)
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
				//fmt.Println("lastPrefix", lastPrefix, "full", full0, len(*k0))
				totalLen += len(db0Entries) - 1
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
				broken = true
			}

			fmt.Printf("Status for prefix (%v): (%s)\n invalidLengths: (%v); invalidKeys: (%v); invalidValues: "+
				"(%v); invalidFull: (%v)\n\n", prefix, status, invalidLengths, invalidKeys, invalidValues, invalidFull)
		}
		return nil
	}()
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
	fmt.Println()
	if err == nil {
		if broken {
			fmt.Println("Databases differ!")
		} else {
			fmt.Println("Databases identical!")
		}
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
