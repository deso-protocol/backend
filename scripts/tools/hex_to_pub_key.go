package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/deso-protocol/core/lib"
	"os"
)

func main() {
	flag.Parse()

	pkBytes, err := hex.DecodeString(os.Args[1])
	if err != nil {
		panic(err)
	}

	pubKey := lib.PkToStringMainnet(pkBytes)

	fmt.Printf("Public key %s\n", pubKey)

	os.Exit(0)
}
