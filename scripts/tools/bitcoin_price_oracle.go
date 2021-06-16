package main

import (
	"flag"
	"fmt"
	"github.com/bitclout/backend/routes"
	"github.com/bitclout/backend/scripts/tools/toolslib"
	"github.com/bitclout/core/lib"
	"github.com/tyler-smith/go-bip39"
)

func main() {
	// Establish flags used for passing param updater material
	flagParamUpdaterMnemonic := flag.String("param_updater_mnemonic",
		"", "A mnemonic associated with a param updater public key.")
	flag.Parse()

	finalBitcoinUSDPrice, err := routes.GetUSDToBTCPrice()
	if err != nil {
		panic(err)
	}

	// Network Parameters
	params := &lib.BitCloutMainnetParams
	fmt.Println("Network type set:", params.NetworkType.String())

	// Node Parameters
	node := "http://localhost:17001"
	fmt.Println("Node set:", node)

	// Convert the Bitcoin USD Price to uint64
	newUSDCentsPerBitcoin := uint64(finalBitcoinUSDPrice * 100)
	fmt.Println("Updating BTC/USD exchange rate to", newUSDCentsPerBitcoin, "USD cents per Bitcoin.")

	// Set the param updater mnemonic
	paramUpdaterMnemonic := *flagParamUpdaterMnemonic

	// Generate param updater keys from mnemonic
	seedBytes, err := bip39.NewSeedWithErrorChecking(paramUpdaterMnemonic, "")
	if err != nil { panic(err) }
	updaterPubKey, updaterPrivKey, _, err := lib.ComputeKeysFromSeed(seedBytes, 0, params)
	if err != nil { panic(err) }
	fmt.Println("Public key found:", lib.PkToString(updaterPubKey.SerializeCompressed(), params))

	// Submit the update transaction
	err = toolslib.UpdateBitcoinUSDExchangeRate(updaterPubKey, updaterPrivKey, newUSDCentsPerBitcoin, params, node)
	if err != nil {
		panic(err)
	}
	fmt.Println("BTC/USD exchange rate successfully updated.")
}
