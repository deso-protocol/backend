package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/deso-protocol/core/lib"
	"golang.org/x/crypto/sha3"
	"os"
)

func main() {
	flag.Parse()

	pkBytes, _, err := lib.Base58CheckDecode(os.Args[1])
	if err != nil {
		panic(err)
	}

	addressPubKey, err := btcutil.NewAddressPubKey(pkBytes, &chaincfg.MainNetParams)
	if err != nil {
		panic(err)
	}

	hash := sha3.NewLegacyKeccak256()
	hash.Write(addressPubKey.PubKey().SerializeUncompressed()[1:])
	sum := hash.Sum(nil)
	str := hex.EncodeToString(sum[12:])

	fmt.Printf("ETH Address: 0x%s\n", str)

	os.Exit(0)
}
