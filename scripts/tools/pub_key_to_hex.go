package main

import (
	"encoding/hex"
	"fmt"
	"github.com/bitclout/core/lib"
	"os"
)

func main() {
	pkBytes, _, err := lib.Base58CheckDecode(os.Args[1])
	if err != nil {
		panic(err)
	}

	fmt.Println(hex.EncodeToString(pkBytes))
	os.Exit(0)
}
