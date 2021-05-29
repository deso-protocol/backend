package toolslib

import (
	"encoding/hex"
	"github.com/bitclout/core/lib"
	chainlib "github.com/btcsuite/btcd/blockchain"
	"github.com/dgraph-io/badger/v3"
	"github.com/pkg/errors"
	"os"
	"path/filepath"
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

// Returns a fresh UTXO View from a provided dataDir path.
// An example connectPeer is "hubris.media.mit.edu:8333"
func GetNewUTXOView(syncedDBHandle *badger.DB, syncedDataDir string, params *lib.BitCloutParams,
	bitcoinConnectPeer string) (*lib.UtxoView, error) {
	// Generate a fresh (randomly assigned) data directory for storing the UtxoView
	dirName := "/tmp/" + hex.EncodeToString(lib.RandomBytes(32))
	if err := os.MkdirAll(dirName, os.ModePerm); err != nil {
		return nil, errors.Wrap(err, "GetNewUTXOView() failed to make dataDir directory")
	}
	tempDir := lib.GetBadgerDbPath(dirName)
	tempOpts := badger.DefaultOptions(tempDir)
	tempOpts.ValueDir = lib.GetBadgerDbPath(tempDir)
	tempDB, err := badger.Open(tempOpts)
	if err != nil {
		return nil, errors.Wrap(err, "GetNewUTXOView() failed to open badger")
	}

	// Setup the bitcoin manager
	timesource := chainlib.NewMedianTime()
	bitcoinDataDir := filepath.Join(syncedDataDir, "bitcoin_manager") // This doesn't have to be fresh
	if err := os.MkdirAll(bitcoinDataDir, os.ModePerm); err != nil {
		return nil, errors.Wrap(err, "GetNewUTXOView() failed to make bitcoinDataDir directory")
	}
	incomingMessages := make(chan *lib.ServerMessage, 100)
	bitcoinManager, err := lib.NewBitcoinManager(
		syncedDBHandle, params, timesource, bitcoinDataDir, incomingMessages, bitcoinConnectPeer)


	// Initialize the db
	_, err = lib.NewBlockchain([]string{}, 0, params, timesource, tempDB, nil, nil)
	if err != nil {
		return nil, errors.Wrap(err, "GetNewUTXOView() failed to initialize a new blockchain")
	}

	// Create the UTXO View
	utxoView, err := lib.NewUtxoView(tempDB, params, bitcoinManager)
	if err != nil {
		return nil, errors.Wrap(err, "GetNewUTXOView() failed to create a new utxoView")
	}

	return utxoView, nil
}
