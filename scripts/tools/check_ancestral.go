package main

import (
	"fmt"
	"github.com/deso-protocol/core/lib"
	"github.com/dgraph-io/badger/v3"
)

func main() {
	dirSnap := "/Users/piotr/data_dirs/n1_10/badgerdb/snapshot/"

	opts := badger.DefaultOptions(dirSnap)
	opts.ValueDir = lib.GetBadgerDbPath(dirSnap)
	opts.MemTableSize = 2000 << 20
	db0, err := badger.Open(opts)
	if err != nil {
		fmt.Printf("Error reading db0 err: %v", err)
		return
	}


	//snap, _ := lib.NewSnapshot(100000)
	//fmt.Println(snap.GetMostRecentSnapshot(db0, []byte{5}, []byte{5}))
	//fmt.Println(snap.GetMostRecentSnapshot(db1, []byte{5}, []byte{5}))
	maxBytes := uint32(8<<12)
	//totalLen := 0
	//var timeElapsed float64
	//var currentTime time.Time
	//timeElapsed = 0.0
	//currentTime = time.Now()
	var prefixes [][]byte
	prefixes = append(prefixes, []byte{0})
	//prefixes = append(prefixes, []byte{1})
	prefixes = append(prefixes, []byte{2})
	err = func() error {
		fmt.Printf("Checking prefixes: ")
		for _, prefix := range prefixes {
			fmt.Printf("%v ", prefix)
			lastPrefix := prefix
			k0, v0, _, err := lib.DBIteratePrefixKeys(db0, prefix, lastPrefix, maxBytes)
			if err != nil {
				fmt.Printf("Error reading db0 err: %v", err)
				return nil
			}
			fmt.Println("Number of entries: ", len(*k0))
			for ii, _ := range(*k0) {
				fmt.Printf("Iterating prefix (%v) key (%v) value (%v)\n", prefix, (*k0)[ii], (*v0)[ii])
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