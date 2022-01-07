package main

import (
	"encoding/hex"
	"fmt"
	"github.com/deso-protocol/backend/scripts/tools/toolslib"
	"github.com/deso-protocol/core/lib"
)

func main() {
	dir0 := "/Users/piotr/data_dirs/n0_1"
	dir1 := "/Users/piotr/data_dirs/n1_1"

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

	//snap, _ := lib.NewSnapshot(100000)
	//fmt.Println(snap.GetMostRecentSnapshot(db0, []byte{5}, []byte{5}))
	//fmt.Println(snap.GetMostRecentSnapshot(db1, []byte{5}, []byte{5}))
	maxBytes := uint32(8<<20)
	totalLen := 0
	err = func() error {
		fmt.Printf("Checking prefixes: ")
		for _, prefix := range lib.StatePrefixes {
			fmt.Printf("%v ", prefix)
			lastPrefix := prefix
			for {
				k0, v0, full0, err := lib.DBIteratePrefixKeys(db0, prefix, lastPrefix, maxBytes)
				if err != nil {
					return fmt.Errorf("Error reading db0 err: %v\n", err)
				}
				k1, v1, full1, err := lib.DBIteratePrefixKeys(db1, prefix, lastPrefix, maxBytes)
				if err != nil {
					return fmt.Errorf("Error reading db1 err: %v\n", err)
				}
				if len(*k0) != len(*k1) {
					return fmt.Errorf("Databases not equal on prefix: %v, and lastPrefix: %v;" +
						"varying lengths (db0, db1) : (%v, %v)\n", prefix, lastPrefix, len(*k0), len(*k1))
				}
				for ii, key := range *k1 {
					if key != (*k1)[ii] {
						return fmt.Errorf("Databases not equal on prefix: %v, and lastPrefix: %v;" +
							"unequal keys (db0, db1) : (%v, %v)\n", prefix, lastPrefix, key, (*k1)[ii])
					}
				}
				for ii, value := range *v1 {
					if value != (*v1)[ii] {
						return fmt.Errorf("Databases not equal on prefix: %v, and lastPrefix: %v;" +
							"unequal values (db0, db1) : (%v, %v)\n", prefix, lastPrefix, value, (*v1)[ii])
					}
				}
				if full0 != full1 {
					return fmt.Errorf("Databases not equal on prefix: %v, and lastPrefix: %v;" +
						"unequal fulls (db0, db1) : (%v, %v)\n", prefix, lastPrefix, full0, full1)
				}
				//fmt.Println("lastPrefix", lastPrefix, "full", full0, len(*k0))
				totalLen += len(*v0) - 1
				if len(*k0) > 0 {
					lastPrefix, _ = hex.DecodeString((*k0)[len(*k0)-1])
				} else {
					break
				}

				if !full0 {
					break
				}
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