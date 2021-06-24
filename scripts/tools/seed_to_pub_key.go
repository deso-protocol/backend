package main

import (
	"fmt"
	"github.com/bitclout/core/lib"
	"github.com/tyler-smith/go-bip39"
	"os"
)

func main() {
	seedBytes, err := bip39.NewSeedWithErrorChecking(os.Args[1], "")
	if err != nil {
		panic(err)
	}

	pkBytes, _, _, err := lib.ComputeKeysFromSeedWithNet(seedBytes, 0, false)
	if err != nil {
		panic(err)
	}

	fmt.Println(os.Args[1])
	fmt.Println(lib.PkToStringBoth(pkBytes.SerializeCompressed()))

	os.Exit(0)
}
