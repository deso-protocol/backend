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
	[]lib.DBEntry, bool) {

	DBEntries := []lib.DBEntry{}
	//for ii := 0; ii < len(StatePrefixes); ii++ {
	//	prefix := StatePrefixes[ii]
	//for {
	fmt.Printf("Prefix (%v)\n", prefix)
	kChunk, vChunk, chunkFull, _ := lib.DBIteratePrefixKeys(handle, prefix, lastKey, chunkSize)
	kAChunk, vAChunk, chunkFullA, _ := lib.DBIteratePrefixKeys(snap.Db, snap.GetSeekPrefix(prefix),
		snap.GetSeekPrefix(lastKey), chunkSize)
	//fmt.Printf("# seek prefix (%v)\n lastKey trimmed (%v)\n last key (%v)\n", snap.GetSeekPrefix(prefix), snap.GetSeekPrefix(lastKey),
	//	lastKey)
	fmt.Println("Number of snap original db keys", len(*kChunk), "full?", chunkFull)
	for _, key := range *kChunk {
		if key == "1703420bfd00431747618ea5231a7637e61c491510b30f5101265d6d5e9d0038b63c" {
			fmt.Println("#It's in the main DB")
		}
	}
	fmt.Println("How many snap keys? ", len(*kAChunk), "full?", chunkFullA)
	numExisted := 0
	numNotExisted := 0
	for ii, key := range *kAChunk {
		valBytesA, _ := hex.DecodeString((*vAChunk)[ii])
		if snap.CheckPrefixExists(valBytesA) {
			numExisted ++
		} else {
			numNotExisted ++
		}
		temp, _ := hex.DecodeString(key)
		tempTrim := snap.SnapPrefixToKey(temp)
		trim := hex.EncodeToString(tempTrim)
		//fmt.Println(key)
		if trim == "1703420bfd00431747618ea5231a7637e61c491510b30f5101265d6d5e9d0038b63c" {
			fmt.Println("#It's in the snap DB")
		}
	}
	fmt.Println("How many snap keys existed:", numExisted, "; and how many did not exist:", numNotExisted)

	indexChunk := 0
	for ii, keyA := range *kAChunk {
		keyBytesA, _ := hex.DecodeString(keyA)
		keyTrimmedBytesA := snap.SnapPrefixToKey(keyBytesA)
		trimmedKey := hex.EncodeToString(keyTrimmedBytesA)
		if trimmedKey == "1703420bfd00431747618ea5231a7637e61c491510b30f5101265d6d5e9d0038b63c" {
			fmt.Println("#FOUND THE MYSTERIOUS KEY")
		}
		valBytesA, _ := hex.DecodeString((*vAChunk)[ii])
		if bytes.HasPrefix(keyTrimmedBytesA, prefix) && snap.CheckPrefixExists(valBytesA) {
			valBytesString := hex.EncodeToString(valBytesA[:len(valBytesA)-1])
			DBEntries = append(DBEntries, lib.DBEntry{
				Key:   trimmedKey,
				Entry: valBytesString,
			})
		}
		for jj := indexChunk; jj < len(*kChunk); {

			keyBytes, _ := hex.DecodeString((*kChunk)[jj])
			if bytes.Compare(keyBytes, keyTrimmedBytesA) == -1 {
					DBEntries = append(DBEntries, lib.DBEntry{
						Key: (*kChunk)[jj],
						Entry: (*vChunk)[jj],
					})
			} else if bytes.Compare(keyBytes, keyTrimmedBytesA) == 1 {
				break
			}
			// if keys are equal we just skip
			jj ++
			indexChunk = jj
		}
		// If we filled the chunk for main db records, we will return so that there is no
		// gap between the most recently added DBEntry and the next ancestral record. Otherwise,
		// we will keep going with the loop and add all the ancestral records.
		if chunkFull && indexChunk == len(*kChunk) {
			break
		}
	}

	// If we got all ancestral records, but there are still some main DB entries that we can add,
	// we will do that now.
	if !chunkFullA {
		for jj := indexChunk; jj < len(*kChunk); jj++ {
			indexChunk = jj
			DBEntries = append(DBEntries, lib.DBEntry{
				Key: (*kChunk)[jj],
				Entry: (*vChunk)[jj],
			})
		}
	}

	if len(DBEntries) == 0 {
		DBEntries = append(DBEntries, lib.EmptyDBEntry())
		return DBEntries, false
	}
	//for i := 0; i < len(*k1); i++ {
	//	fmt.Printf("Keys:%v\n Values:%v\n", (*k1)[i], (*v1)[i])
	//}
	//fmt.Println("iterated", *k1, *v1)
	//for jj, key := range *k1 {
	//	keyBytes, _ := hex.DecodeString(key)
	//	//fmt.Println("comparing", keyBytes, key, prefix, bytes.HasPrefix(keyBytes, prefix))
	//	if bytes.HasPrefix(keyBytes, prefix){
	//		DBEntries = append(DBEntries, DBEntry{
	//			Key:   key,
	//			Entry: (*v1)[jj],
	//		})
	//	}
	//}
	//lastKey, _ = hex.DecodeString((*k1)[len(*k1)-1])
	//fmt.Println("prefixes", full, prefix, lastKey)
	//if !full || !bytes.HasPrefix(lastKey, prefix) {
	//	break
	//}
	//}
	//}

	// If either of the chunks is full, we should return true.
	return DBEntries, chunkFull || chunkFullA
}

func main() {
	//dirSnap := "/Users/piotr/data_dirs/n1_10/badgerdb/snapshot/"
	dirSnap := "/Users/piotr/data_dirs/n1_13/"
	dirDB := "/Users/piotr/data_dirs/n5_13/"

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
	snap.BlockHeight = 4500

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
	//fmt.Println(snap.GetMostRecentSnapshot(db0, []byte{5}, []byte{5}))
	//fmt.Println(snap.GetMostRecentSnapshot(db1, []byte{5}, []byte{5}))
	maxBytes := uint32(8<<20)
	var prefixes [][]byte
	prefixes = append(prefixes, []byte{52})
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
				entries, fullSnap := getMostRecentSnapshot(snap, dbSnap, prefix, lastPrefix, maxBytes)
				fmt.Printf("Found snap (%v) entries and full is (%v)\n", len(entries), fullSnap)
				for _, entry := range entries {
					if entry.Key == "1703420bfd00431747618ea5231a7637e61c491510b30f5101265d6d5e9d0038b63c" {
						fmt.Println("GOT HERE BUT SHOULDN'T")
					}
					existingKeysSnap[entry.Key] = entry.Entry
				}

				k0, v0, fullDb, err := lib.DBIteratePrefixKeys(db, prefix, lastPrefix, maxBytes)
				for ii, _ := range *k0 {
					if (*k0)[ii] == "05000000000000000000000000000000000000000000000000000000000000000000000083" {
						fmt.Println("YES IT EXISTS BUD")
					}
					existingKeysDb[(*k0)[ii]] = (*v0)[ii]
				}
				_ = v0
				if err != nil {
					fmt.Printf("Error reading db0 err: %v", err)
					return
				}
				fmt.Printf("Found db (%v) entries and full is (%v)\n", len((*k0)), fullDb)
				lastKeyStr := (*k0)[len(*k0)-1]
				lastKeyBytes, _ := hex.DecodeString(lastKeyStr)
				lastPrefix = lastKeyBytes
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