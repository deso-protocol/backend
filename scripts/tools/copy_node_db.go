package main

import (
	"fmt"
	"github.com/deso-protocol/backend/scripts/tools/toolslib"
	"github.com/deso-protocol/core/lib"
)

func main() {
	sourceDbDir := "$HOME/data_dirs/hypersync/mini_sentry_nft"
	destinationDbDir := "$HOME/data_dirs/hypersync/mini_sentry_nft_copy"

	sourceDb, err := toolslib.OpenDataDir(sourceDbDir)
	if err != nil {
		fmt.Printf("Error reading sourceDb err: %v", err)
		return
	}
	destinationDb, err := toolslib.OpenDataDir(destinationDbDir)
	if err != nil {
		fmt.Printf("Error reading destinationDb: (%)", err)
		return
	}
	maxBytes := uint32(8 << 22)
	totalLen := 0
	_ = totalLen
	err = func() error {
		for prefixByte := range lib.StatePrefixes.StatePrefixesMap {
			prefix := []byte{prefixByte}
			fmt.Printf("Copying prefix: (%v)\n", prefix)
			lastPrefix := prefix
			for {
				db0Entries, full0, err := lib.DBIteratePrefixKeys(sourceDb, prefix, lastPrefix, maxBytes)
				if err != nil {
					panic(fmt.Errorf("error on DBIteratePrefixKeys! (%v)", err))
				}
				wb := destinationDb.NewWriteBatch()
				for _, dbEntry := range db0Entries {
					err = wb.Set(dbEntry.Key, dbEntry.Value)
					if err != nil {
						panic(fmt.Errorf("error on write batch set! (%v)", err))
					}
				}
				err = wb.Flush()
				if err != nil {
					panic(fmt.Errorf("error on write batch flush! (%v)", err))
				}
				wb.Cancel()

				if len(db0Entries) != 0 {
					lastPrefix = db0Entries[len(db0Entries)-1].Key
				}
				if !full0 {
					break
				}
			}
		}
		return nil
	}()
	fmt.Println("Successfully copied!")

}
