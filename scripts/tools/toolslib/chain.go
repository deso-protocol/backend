package toolslib

import (
	"github.com/deso-protocol/core/lib"
	"github.com/dgraph-io/badger/v4"
	"github.com/pkg/errors"
)

// Returns the badgerDB handler associated with a dataDir path.
func OpenDataDir(dataDir string) (*badger.DB, error) {
	dir := lib.GetBadgerDbPath(dataDir)
	opts := lib.PerformanceBadgerOptions(dir)
	opts.ValueDir = lib.GetBadgerDbPath(dataDir)
	db, err := badger.Open(opts)
	if err != nil {
		return nil, errors.Wrap(err, "OpenBadgerDB() failed to open badger")
	}
	return db, nil
}

// Returns the best chain associated with a badgerDB handle.
func GetBestChainFromBadger(syncedDBHandle *badger.DB, params *lib.DeSoParams) ([]*lib.BlockNode, error) {
	bestBlockHash := lib.DbGetBestHash(syncedDBHandle, nil, lib.ChainTypeDeSoBlock)
	if bestBlockHash == nil {
		return nil, errors.Errorf("GetBestChainFromBadger() could not find a blockchain in the provided db")
	}

	// Fetch the block index.
	blockIndex, err := lib.GetBlockIndex(syncedDBHandle, false /*bitcoinNodes*/, params)
	if err != nil {
		return nil, errors.Errorf("GetBestChainFromBadger() could not get blockIndex")
	}

	// Find the tip node with the best node hash.
	tipNode, _ := blockIndex.Get(*bestBlockHash)
	if tipNode == nil {
		return nil, errors.Errorf("GetBestChainFromBadger() bestBlockHash not found in blockIndex")
	}

	// Walk back from the best node to the genesis block and store them all in bestChain.
	bestChain, err := lib.GetBestChain(tipNode)
	if err != nil {
		return nil, errors.Wrap(err, "GetBestChainFromBadger() failed to GetBestChain")
	}

	return bestChain, nil
}
