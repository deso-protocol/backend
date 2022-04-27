package main

import (
	"encoding/hex"
	"fmt"
	"github.com/deso-protocol/backend/scripts/tools/toolslib"
	"github.com/deso-protocol/core/lib"
)

func main() {
	dir0 := "/Users/piotr/data_dirs/n69_5"
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
	prefixList := []byte{54}
	err = func() error {
		for _, prefixByte := range prefixList {
			prefix := []byte{prefixByte}
			fmt.Printf("Checking prefix: (%v)\n", prefix)
			lastPrefix := prefix
			existingKeysDb0 := make(map[string]string)
			existingKeysDb1 := make(map[string]string)
			for {
				db0Entries, full, err := lib.DBIteratePrefixKeys(db0, prefix, lastPrefix, maxBytes)
				if err != nil {
					panic(fmt.Errorf("Error reading db0 err: %v\n", err))
				}
				for _, entry := range db0Entries {
					keyHex := hex.EncodeToString(entry.Key)
					valueHex := hex.EncodeToString(entry.Value)
					existingKeysDb0[keyHex] = valueHex
				}
				fmt.Printf("Iterating Db0 got (%v) entries\n", len(db0Entries))
				if len(db0Entries) > 0 {
					lastPrefix = db0Entries[len(db0Entries)-1].Key
				} else {
					break
				}
				if !full {
					break
				}
			}
			lastPrefix = prefix
			for {
				db1Entries, full, err := lib.DBIteratePrefixKeys(db1, prefix, lastPrefix, maxBytes)
				if err != nil {
					panic(fmt.Errorf("Error reading db1 err: %v\n", err))
				}
				for _, entry := range db1Entries {
					keyHex := hex.EncodeToString(entry.Key)
					valueHex := hex.EncodeToString(entry.Value)
					existingKeysDb1[keyHex] = valueHex
				}
				fmt.Printf("Iterating Db1 got (%v) entries\n", len(db1Entries))
				if len(db1Entries) > 0 {
					lastPrefix = db1Entries[len(db1Entries)-1].Key
				} else {
					break
				}
				if !full {
					break
				}
			}
			fmt.Println("Iterating existingKeysDb0, number of entries:", len(existingKeysDb0))
			for key, value := range existingKeysDb0 {
				if dbVal, exists := existingKeysDb1[key]; exists {
					if value != dbVal {
						fmt.Printf("Error on key (%v); values don't match\n db0 value: (%v)\n db1 value: (%v)\n",
							key, value, dbVal)
					}
				} else {
					fmt.Printf("Error value doesn't exist in db1 for key (%v)\n", key)
				}
			}
			fmt.Println("Passed iterating existingKeysDb0")
			fmt.Println("Iterating existingKeysDb1, number of entries:", len(existingKeysDb1))
			for key, value := range existingKeysDb1 {
				if dbVal, exists := existingKeysDb0[key]; exists {
					if value != dbVal {
						fmt.Printf("Error on key (%v); values don't match\n db1 value: (%v)\n db0 value: (%v)\n",
							key, value, dbVal)
					}
				} else {
					fmt.Printf("Error value doesn't exist in db0 for key (%v)\n", key)
				}
			}
			fmt.Println("Passed iterating existingKeysDb1")
		}
		return nil
	}()

}
