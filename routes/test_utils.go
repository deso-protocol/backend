package routes

import (
	"github.com/dgraph-io/badger/v3"
	"log"
	"os"
	"testing"
)

func GetTestBadgerDb(t *testing.T) (_db *badger.DB, _dir string) {
	dir, err := os.MkdirTemp("", "badgerdb")
	if err != nil {
		log.Fatal(err)
	}

	// Open a badgerdb in a temporary directory.
	opts := badger.DefaultOptions(dir)
	opts.Dir = dir
	opts.ValueDir = dir
	// No logger when running tests
	opts.Logger = nil
	db, err := badger.Open(opts)
	if err != nil {
		log.Fatal(err)
	}
	t.Cleanup(func() {
		CleanUpBadger(db)
	})
	return db, dir
}

func CleanUpBadger(db *badger.DB) {
	// Close the database.
	err := db.Close()
	if err != nil {
		log.Fatal(err)
	}
	// Delete the database directory.
	err = os.RemoveAll(db.Opts().Dir)
	if err != nil {
		log.Fatal(err)
	}
}
