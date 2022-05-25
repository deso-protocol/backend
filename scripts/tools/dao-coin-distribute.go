package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/deso-protocol/backend/routes"
	"github.com/deso-protocol/backend/scripts/tools/toolslib"
	"github.com/deso-protocol/core/lib"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"github.com/tyler-smith/go-bip39"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"sort"
	"time"
)

func _ReadSaveStateJSONFilename(saveStateJSONFilename string) (map[uint64]uint256.Int, error) {
	// If the file doesn't exist, create it and return a new map.
	if _, err := os.Stat(saveStateJSONFilename); errors.Is(err, os.ErrNotExist) {
		newFile, err := os.Create(saveStateJSONFilename)
		if err != nil {
			return nil, errors.Wrap(err, "_ReadSaveStateJSONFilename(): Failed to create new JSON file")
		}
		newFile.Close()

		newMap := make(map[uint64]uint256.Int)
		err = _UpdateSaveState(saveStateJSONFilename, newMap)
		if err != nil {
			return nil, errors.Wrap(err, "_ReadSaveStateJSONFilename(): Could not save new map")
		}
		return newMap, nil
	} else if !errors.Is(err, os.ErrNotExist) && err != nil {
		return nil, errors.Wrap(err, "_ReadSaveStateJSONFilename(): Failed to check if file exists")
	}

	// Read the JSON file's contents.
	jsonFile, err := os.Open(saveStateJSONFilename)
	if err != nil {
		return nil, errors.Wrap(err, "_ReadSaveStateJSONFilename(): Failed to open JSON file")
	}
	defer jsonFile.Close()
	jsonBytes, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return nil, errors.Wrap(err, "_ReadSaveStateJSONFilename(): Failed to read bytes from JSON file")
	}

	// Decode and convert the JSON file.
	var savedUndecodedMap map[uint64]string
	err = json.Unmarshal(jsonBytes, &savedUndecodedMap)
	if err != nil {
		return nil, errors.Wrap(err, "_ReadSaveStateJSONFilename(): Failed to decode JSON file")
	}
	savedMap := make(map[uint64]uint256.Int)
	for kk, vv := range savedUndecodedMap {
		vvBigInt := new(big.Int)
		var successfulSetString bool
		vvBigInt, successfulSetString =
			vvBigInt.SetString(vv, 10)
		if !successfulSetString {
			return nil, errors.Errorf("_ReadSaveStateJSONFilename(): Failed to decode uint256.Int in JSON file")
		}
		vvBaseUnits := uint256.NewInt()
		var overflow bool
		overflow = vvBaseUnits.SetFromBig(vvBigInt)
		if overflow {
			return nil, errors.Errorf("_ReadSaveStateJSONFilename(): Decoding uint256.Int caused overflow")
		}
		savedMap[kk] = *vvBaseUnits
	}
	return savedMap, nil
}

func _UpdateSaveState(saveStateJSONFilename string, newMap map[uint64]uint256.Int) error {
	// Convert the uint256.Ints to decimal output strings.
	outputMap := make(map[uint64]string)
	for kk, vv := range newMap {
		outputMap[kk] = vv.ToBig().String()
	}

	// Convert the state to JSON.
	newMapBytes, err := json.MarshalIndent(outputMap, "", "\t")
	if err != nil {
		return errors.Wrap(err, "_UpdateSaveState(): Failed to JSON marshal save state")
	}

	// Open the JSON file with settings set to overwrite.
	jsonFile, err := os.OpenFile(saveStateJSONFilename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return errors.Wrap(err, "_UpdateSaveState(): Failed to open JSON file")
	}
	defer jsonFile.Close()

	// Write the bytes to the file.
	numBytesWritten, err := jsonFile.Write(newMapBytes)
	if numBytesWritten != len(newMapBytes) {
		return errors.Errorf("_UpdateSaveState(): Expected to write %d bytes, wrote %d bytes\n",
			len(newMapBytes), numBytesWritten)
	}
	if err != nil {
		return errors.Wrap(err, "_UpdateSaveState(): Failed write to JSON file")
	}
	return nil
}

func main() {
	flagParamDeSoNodeURL := flag.String("deso-node",
		"", "A DeSo node to target for sourcing data and submitting transactions.")
	flagParamDAOCoinDistributorMnemonic := flag.String("dao-coin-distributor-mnemonic",
		"", "The mnemonic associated with the burner's public/private key pair.")
	flagParamDAOCoinPublicKey := flag.String("dao-coin-public-key",
		"", "The public key associated with the dao coin to send.")
	flagParamNFTPostHash := flag.String("nft-post-hash",
		"", "A NFT hash to target. This NFT will have all associated unsold copies burnt.\n"+
			"The hash should be passed as a hex string.")
	flagParamDistributionAmountDAOCoinBaseUnits := flag.String("distribution-amount-dao-coin-base-units",
		"0", "The amount of DAO coin (in base units) to distribute to NFT holders.")
	flagParamMaxDistributionAmountDAOCoinBaseUnits := flag.String("max-distribution-amount-dao-coin-base-units",
		"0", "An optional override for the maximum amount of DAO coin to distribute.\n"+
			"If set, the amount sent will will be min(--max-distribution-amount-dao-coin, --distribution-amount-dao-coin).")
	flagParamDisableDAODsitributorPublicKeyCheck := flag.Bool("disable-dao-distributor-public-key-check",
		false, "An optional override on the check to ensure the distributor's public key matches "+
			"the DAO's associated public key.")
	flagDelayMilliseconds := flag.Int("delay_milliseconds", 1000,
		"The delay in milliseconds between each request.")
	flag.Parse()

	// Process flags.
	nftPostHash := *flagParamNFTPostHash
	fmt.Printf("Targeted NFT Post Hash: %s\n", nftPostHash)
	delayMilliseconds := *flagDelayMilliseconds
	saveStateJSONFilename := *flagParamNFTPostHash + "_progress.json"
	fmt.Printf("Save State File: %s\n", saveStateJSONFilename)

	// Process distribution amounts to uint256 DeSo data standard.
	distributionTargetDAOCoinBaseUnitsBigInt := new(big.Int)
	var successfulSetString bool
	distributionTargetDAOCoinBaseUnitsBigInt, successfulSetString =
		distributionTargetDAOCoinBaseUnitsBigInt.SetString(*flagParamDistributionAmountDAOCoinBaseUnits, 10)
	if !successfulSetString {
		panic(errors.Errorf("main(): Could not decode distribution amount from string %s",
			*flagParamDistributionAmountDAOCoinBaseUnits))
	}
	maxDistributionAmountDAOCoinBaseUnitsBigInt := new(big.Int)
	maxDistributionAmountDAOCoinBaseUnitsBigInt, successfulSetString =
		maxDistributionAmountDAOCoinBaseUnitsBigInt.SetString(*flagParamMaxDistributionAmountDAOCoinBaseUnits, 10)
	if !successfulSetString {
		panic(errors.Errorf("main(): Could not decode max distribution amount from string %s",
			*flagParamMaxDistributionAmountDAOCoinBaseUnits))
	}
	distributionTargetDAOCoinBaseUnits := uint256.NewInt()
	var overflow bool
	overflow = distributionTargetDAOCoinBaseUnits.SetFromBig(distributionTargetDAOCoinBaseUnitsBigInt)
	if overflow {
		panic(errors.Errorf("main() failed to convert distribution target from big.Int to uint256"))
	}
	maxDistributionAmountDAOCoinBaseUnits := uint256.NewInt()
	overflow = maxDistributionAmountDAOCoinBaseUnits.SetFromBig(maxDistributionAmountDAOCoinBaseUnitsBigInt)
	if overflow {
		panic(errors.Errorf("main() failed to convert max distribution amount from big.Int to uint256"))
	}

	// Construct necessary endpoints.
	desoNodeURL, err := url.Parse(*flagParamDeSoNodeURL)
	if err != nil {
		panic(errors.Wrap(err, "main(): Invalid DeSo node specified. "+
			"Please specify a valid node using --deso-node flag\n"))
	}
	if len(desoNodeURL.String()) == 0 {
		panic(fmt.Errorf("main(): Please specify a valid node using --deso-node flag\n"))
	}
	fmt.Printf("DeSo Node: %s\n", desoNodeURL.String())
	getNFTEntriesEndpoint := desoNodeURL.String() + routes.RoutePathGetNFTEntriesForPostHash
	getSinglePostEndpoint := desoNodeURL.String() + routes.RoutePathGetSinglePost

	// Setup Network Parameters.
	params := &lib.DeSoMainnetParams
	fmt.Printf("Network type set: %s\n", params.NetworkType.String())

	// Fetch post information on the requested NFT.
	var getSinglePostResponse routes.GetSinglePostResponse
	{
		// Create request payload.
		payload := &routes.GetSinglePostRequest{
			PostHashHex: nftPostHash,
		}
		postBody, err := json.Marshal(payload)
		if err != nil {
			panic(errors.Wrap(err, "main(): Could not complete request"))
		}
		postBuffer := bytes.NewBuffer(postBody)

		// Execute request.
		resp, err := http.Post(getSinglePostEndpoint, "application/json", postBuffer)
		if err != nil {
			panic(errors.Wrap(err, "main(): failed request"))
		}
		if resp.StatusCode != 200 {
			bodyBytes, _ := ioutil.ReadAll(resp.Body)
			panic(errors.Errorf("main(): Received non 200 response code: "+
				"Status Code: %v Body: %v", resp.StatusCode, string(bodyBytes)))
		}

		// Process Response.
		err = json.NewDecoder(resp.Body).Decode(&getSinglePostResponse)
		if err != nil {
			panic(errors.Wrap(err, "main(): Failed to decode response\n"))
		}
		err = resp.Body.Close()
		if err != nil {
			panic(errors.Wrap(err, "main(): Failed to decode body\n"))
		}
	}
	if getSinglePostResponse.PostFound == nil {
		panic(errors.Errorf("main(): Could not find post for the specified NFT post hash."))
	}
	fmt.Printf("main(): Post found contains: \n\tPoster Public Key: %s\n\tPost Body: \"%s\"\n\n",
		getSinglePostResponse.PostFound.PosterPublicKeyBase58Check, getSinglePostResponse.PostFound.Body)
	if !getSinglePostResponse.PostFound.IsNFT {
		panic(errors.Errorf("main(): Post found is not a NFT."))
	}

	// Read save state from file.
	saveStateMap, err := _ReadSaveStateJSONFilename(saveStateJSONFilename)
	if err != nil {
		panic(errors.Wrap(err, "main(): Failed to read saved state"))
	}

	// Generate the sender's keys from provided mnemonic.
	if len(*flagParamDAOCoinDistributorMnemonic) == 0 {
		panic(errors.Errorf("main(): Please specify a valid mnemonic using --dao-coin-distributor-mnemonic flag\n"))
	}
	seedBytes, err := bip39.NewSeedWithErrorChecking(*flagParamDAOCoinDistributorMnemonic, "")
	if err != nil {
		panic(errors.Wrap(err, "main(): Could not generate key pair from mnemonic"))
	}
	distributorPubKey, distributorPrivKey, _, err := lib.ComputeKeysFromSeed(seedBytes, 0, params)
	disablePublicKeyCheck := *flagParamDisableDAODsitributorPublicKeyCheck
	if !disablePublicKeyCheck &&
		lib.PkToString(distributorPubKey.SerializeCompressed(), params) != getSinglePostResponse.PostFound.PosterPublicKeyBase58Check {
		panic(errors.Errorf("main(): Distributor mnemonic generated mismatched key pair. Mnemonic public key: %s\n",
			lib.PkToString(distributorPubKey.SerializeCompressed(), params)))
	}

	// Fetch NFT entry information on the requested NFT.
	fmt.Printf("Requesting entry information on NFT...\n")
	var getNFTEntriesResponse routes.GetNFTEntriesForPostHashResponse
	{
		// Create request payload.
		payload := &routes.GetNFTEntriesForPostHashRequest{
			PostHashHex:                nftPostHash,
			ReaderPublicKeyBase58Check: "",
		}
		postBody, err := json.Marshal(payload)
		if err != nil {
			panic(errors.Wrap(err, "main(): Could not complete request"))
		}
		postBuffer := bytes.NewBuffer(postBody)

		// Execute request.
		resp, err := http.Post(getNFTEntriesEndpoint, "application/json", postBuffer)
		if err != nil {
			panic(errors.Wrap(err, "main(): failed request"))
		}
		if resp.StatusCode != 200 {
			bodyBytes, _ := ioutil.ReadAll(resp.Body)
			panic(errors.Errorf("main(): Received non 200 response code: "+
				"Status Code: %v Body: %v", resp.StatusCode, string(bodyBytes)))
		}

		// Process Response.
		err = json.NewDecoder(resp.Body).Decode(&getNFTEntriesResponse)
		if err != nil {
			panic(errors.Wrap(err, "main(): Failed to decode response\n"))
		}
		err = resp.Body.Close()
		if err != nil {
			panic(errors.Wrap(err, "main(): Failed to decode body\n"))
		}
	}
	sort.Slice(getNFTEntriesResponse.NFTEntryResponses, func(ii, jj int) bool {
		return getNFTEntriesResponse.NFTEntryResponses[ii].SerialNumber <
			getNFTEntriesResponse.NFTEntryResponses[jj].SerialNumber
	})

	// Create data structures needed to track distribution amounts.
	publicKeyToDAODistributionAmountBaseUnits := make(map[string]uint256.Int)
	publicKeyToDAODistributionAmountReadable := make(map[string]string)
	publicKeyToAssociatedSerialNumbers := make(map[string][]uint64)
	serialNumberToDAODistributionAmountBaseUnits := make(map[uint64]uint256.Int)
	serialNumberToDAODistributionAmountReadable := make(map[uint64]string)
	totalDistributionAmountDAOCoinBaseUnits := *uint256.NewInt().SetUint64(0)
	uniqueSerialNumberMap := make(map[uint64]struct{})

	// Process NFT Entries and produce a map from public key to the amount of DAO coin base units needed to be sent.
	for _, nftEntryResponse := range getNFTEntriesResponse.NFTEntryResponses {
		if _, serialNumberSeen := uniqueSerialNumberMap[nftEntryResponse.SerialNumber]; serialNumberSeen {
			panic(errors.Errorf("main(): Found duplicate serial numbers in NFT entries response\n"))
		}
		uniqueSerialNumberMap[nftEntryResponse.SerialNumber] = struct{}{}
		serialNumberToDAODistributionAmountBaseUnits[nftEntryResponse.SerialNumber] = *uint256.NewInt().SetUint64(0)
		if nftEntryResponse.SerialNumber == 2 {
			fmt.Printf("USER FOUND: %s\n", nftEntryResponse.OwnerPublicKeyBase58Check)
		}
		// Check if there is a valid owner.
		if nftEntryResponse.OwnerPublicKeyBase58Check == getSinglePostResponse.PostFound.PosterPublicKeyBase58Check {
			continue
		}

		// Ensure we track that this serial number is associated with the corresponding public key.
		if _, serialNumbersExist := publicKeyToAssociatedSerialNumbers[nftEntryResponse.OwnerPublicKeyBase58Check]; serialNumbersExist {
			publicKeyToAssociatedSerialNumbers[nftEntryResponse.OwnerPublicKeyBase58Check] =
				append(publicKeyToAssociatedSerialNumbers[nftEntryResponse.OwnerPublicKeyBase58Check],
					nftEntryResponse.SerialNumber)
		} else {
			publicKeyToAssociatedSerialNumbers[nftEntryResponse.OwnerPublicKeyBase58Check] =
				[]uint64{nftEntryResponse.SerialNumber}
		}

		// Check if there's previously saved state for this serial number + NFT combo.
		previousDistributionAmountBaseUnits := uint256.NewInt().SetUint64(0)
		if _, saveExists := saveStateMap[nftEntryResponse.SerialNumber]; saveExists {
			*previousDistributionAmountBaseUnits = saveStateMap[nftEntryResponse.SerialNumber]
		}

		// Compute the amount to distribute for this serial number.
		amountToDistributeDAOCoinBaseUnits := *uint256.NewInt().SetUint64(0)
		if distributionTargetDAOCoinBaseUnits.Cmp(previousDistributionAmountBaseUnits) == 0 ||
			distributionTargetDAOCoinBaseUnits.Cmp(previousDistributionAmountBaseUnits) == 1 {
			amountToDistributeDAOCoinBaseUnits = *uint256.NewInt().Sub(distributionTargetDAOCoinBaseUnits, previousDistributionAmountBaseUnits)
		}
		if maxDistributionAmountDAOCoinBaseUnits.Cmp(uint256.NewInt().SetUint64(0)) == 1 &&
			maxDistributionAmountDAOCoinBaseUnits.Cmp(&amountToDistributeDAOCoinBaseUnits) == -1 {
			amountToDistributeDAOCoinBaseUnits = *maxDistributionAmountDAOCoinBaseUnits
		}

		// Update the amount to distribute to the user.
		if _, entryExists := publicKeyToDAODistributionAmountBaseUnits[nftEntryResponse.OwnerPublicKeyBase58Check]; entryExists {
			prevAmount := publicKeyToDAODistributionAmountBaseUnits[nftEntryResponse.OwnerPublicKeyBase58Check]
			publicKeyToDAODistributionAmountBaseUnits[nftEntryResponse.OwnerPublicKeyBase58Check] =
				*uint256.NewInt().SetUint64(0).Add(&prevAmount, &amountToDistributeDAOCoinBaseUnits)
		} else {
			publicKeyToDAODistributionAmountBaseUnits[nftEntryResponse.OwnerPublicKeyBase58Check] = amountToDistributeDAOCoinBaseUnits
		}
		serialNumberToDAODistributionAmountBaseUnits[nftEntryResponse.SerialNumber] = amountToDistributeDAOCoinBaseUnits

		// Prepare human-readable outputs.
		newTotalDistributionAmount := publicKeyToDAODistributionAmountBaseUnits[nftEntryResponse.OwnerPublicKeyBase58Check]
		publicKeyToDAODistributionAmountReadable[nftEntryResponse.OwnerPublicKeyBase58Check] = newTotalDistributionAmount.ToBig().String()
		serialNumberToDAODistributionAmountReadable[nftEntryResponse.SerialNumber] = amountToDistributeDAOCoinBaseUnits.ToBig().String()

		// Keep track of the total distribution amount.
		totalDistributionAmountDAOCoinBaseUnits = *uint256.NewInt().SetUint64(0).Add(
			&totalDistributionAmountDAOCoinBaseUnits, &amountToDistributeDAOCoinBaseUnits)
	}

	// Print the amount to distribute.
	pkDistributionMapBytes, err := json.MarshalIndent(publicKeyToDAODistributionAmountReadable, "", "\t")
	if err != nil {
		panic(errors.Wrap(err, "main(): Could not marshal public key distribution map"))
	}
	serialNumDistributionMapBytes, err := json.MarshalIndent(serialNumberToDAODistributionAmountReadable, "", "\t")
	if err != nil {
		panic(errors.Wrap(err, "main(): Could not marshal serial number distribution map"))
	}
	fmt.Printf("Public Key Distribution Map: \n%s\n", string(pkDistributionMapBytes))
	fmt.Printf("Serial Number Distribution Map: \n%s\n", string(serialNumDistributionMapBytes))
	fmt.Printf("Total Amount DAO Coin Base Units to Distribute: %s\n", totalDistributionAmountDAOCoinBaseUnits.ToBig().String())
	totalDistributionAmountBeforeDecimal := uint256.NewInt().SetUint64(0).Div(&totalDistributionAmountDAOCoinBaseUnits,
		uint256.NewInt().SetUint64(1e18)).ToBig().String()
	totalDistributionAmountAfterDecimal := uint256.NewInt().SetUint64(0).Mod(&totalDistributionAmountDAOCoinBaseUnits,
		uint256.NewInt().SetUint64(1e18)).ToBig().String()
	previousLength := len(totalDistributionAmountAfterDecimal)
	for ii := 0; ii < 18-previousLength; ii++ {
		totalDistributionAmountAfterDecimal = "0" + totalDistributionAmountAfterDecimal
	}
	fmt.Printf("Total Amount DAO Coin to Distribute: %s.%s\n", totalDistributionAmountBeforeDecimal, totalDistributionAmountAfterDecimal)

	// Ask for user confirmation on this amount.
	var userConfirmation string
	fmt.Print("Proceed with distribution (Y/n)? ")
	_, err = fmt.Scan(&userConfirmation)
	if err != nil || userConfirmation != "Y" {
		fmt.Printf("Exiting without distributing.\n")
		return
	}

	// Distribute public key by public key ensuring to update the save state map.
	distributionPublicKeys := make([]string, 0, len(publicKeyToDAODistributionAmountBaseUnits))
	for publicKey := range publicKeyToDAODistributionAmountBaseUnits {
		distributionPublicKeys = append(distributionPublicKeys, publicKey)
	}
	sort.Slice(distributionPublicKeys, func(ii, jj int) bool {
		return distributionPublicKeys[ii] > distributionPublicKeys[jj]
	})
	for ii := 0; ii < len(distributionPublicKeys); ii++ {
		receiverPublicKey := distributionPublicKeys[ii]
		receiverAmountNanosDAOCoinBaseUnits := publicKeyToDAODistributionAmountBaseUnits[receiverPublicKey]
		if receiverAmountNanosDAOCoinBaseUnits.Cmp(uint256.NewInt().SetUint64(0)) == 0 {
			continue
		}

		// Send the amount computed to the public key.
		fmt.Printf("Sending %s Base Units to %s (pk %d of %d)\n", receiverAmountNanosDAOCoinBaseUnits.ToBig().String(),
			receiverPublicKey, ii+1, len(distributionPublicKeys))
		fmt.Printf("Public key has assocaited serial numbers: %v\n", publicKeyToAssociatedSerialNumbers[receiverPublicKey])
		err := toolslib.TransferDAOCoin(distributorPubKey, distributorPrivKey, *flagParamDAOCoinPublicKey,
			receiverPublicKey, receiverAmountNanosDAOCoinBaseUnits, params, desoNodeURL.String())
		if err != nil {
			fmt.Printf("main(): Ran into an error when trying to distribute for pk (%s): %s\n", receiverPublicKey, err.Error())

			var userConfirmation string
			fmt.Print("Cancel distribution (Y/n)? Continuing will retry transaction: ")
			_, err = fmt.Scan(&userConfirmation)
			if err != nil || userConfirmation == "Y" {
				fmt.Printf("Exiting without continuing distribution.\n")
				return
			}
			ii--
			time.Sleep(time.Millisecond * time.Duration(delayMilliseconds))
			continue
		}

		// Update the serial number save state.
		for _, serialNumber := range publicKeyToAssociatedSerialNumbers[receiverPublicKey] {
			if _, saveStateExists := saveStateMap[serialNumber]; saveStateExists {
				prevAmount := saveStateMap[serialNumber]
				distAmount := serialNumberToDAODistributionAmountBaseUnits[serialNumber]
				saveStateMap[serialNumber] = *uint256.NewInt().SetUint64(0).Add(&prevAmount, &distAmount)
			} else {
				saveStateMap[serialNumber] = serialNumberToDAODistributionAmountBaseUnits[serialNumber]
			}
		}
		err = _UpdateSaveState(saveStateJSONFilename, saveStateMap)
		if err != nil {
			fmt.Printf("main(): Ran into an error when trying to update save state: %s\n", err.Error())

			var userConfirmation string
			fmt.Print("Cancel distribution (Y/n)? Continuing will retry this distribution: ")
			_, err = fmt.Scan(&userConfirmation)
			if err != nil || userConfirmation == "Y" {
				fmt.Printf("Exiting without continuing distribution.\n")
				return
			}
			ii--
			time.Sleep(time.Millisecond * time.Duration(delayMilliseconds))
			continue
		}

		// Sleep to prevent rate limiting.
		fmt.Println("Sleeping...")
		time.Sleep(time.Millisecond * time.Duration(delayMilliseconds))
		fmt.Println("Awake!")
	}
	fmt.Printf("Script completed.\n")
}
