package toolslib

import (
	"github.com/bitclout/core/lib"
	"github.com/dgraph-io/badger/v3"
	"github.com/pkg/errors"
)

// Returns the badgerDB handler associated with a dataDir path.
func OpenDataDir(dataDir string) (*badger.DB, error){
	dir := lib.GetBadgerDbPath(dataDir)
	opts := badger.DefaultOptions(dir)
	opts.ValueDir = lib.GetBadgerDbPath(dataDir)
	db, err := badger.Open(opts)
	if err != nil { return nil, errors.Wrap(err, "OpenBadgerDB() failed to open badger") }
	return db, nil
}

// Returns the best chain associated with a badgerDB handle.
func GetBestChainFromBadger(syncedDBHandle *badger.DB) ([]*lib.BlockNode, error) {
	bestBlockHash := lib.DbGetBestHash(syncedDBHandle, lib.ChainTypeBitCloutBlock)
	if bestBlockHash == nil {
		return nil, errors.Errorf("GetBestChainFromBadger() could not find a blockchain in the provided db")
	}

	// Fetch the block index.
	blockIndex, err := lib.GetBlockIndex(syncedDBHandle, false /*bitcoinNodes*/)
	if err != nil {
		return nil, errors.Errorf("GetBestChainFromBadger() could not get blockIndex")
	}

	// Find the tip node with the best node hash.
	tipNode := blockIndex[*bestBlockHash]
	if tipNode == nil {
		return nil, errors.Errorf("GetBestChainFromBadger() bestBlockHash not found in blockIndex")
	}

	// Walk back from the best node to the genesis block and store them all in bestChain.
	bestChain, err := lib.GetBestChain(tipNode, blockIndex)
	if err != nil {
		return nil, errors.Wrap(err, "GetBestChainFromBadger() failed to GetBestChain")
	}

	return bestChain, nil
}
