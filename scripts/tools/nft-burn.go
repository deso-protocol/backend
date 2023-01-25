package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/deso-protocol/backend/routes"
	"github.com/deso-protocol/backend/scripts/tools/toolslib"
	"github.com/deso-protocol/core/lib"
	"github.com/pkg/errors"
	"github.com/tyler-smith/go-bip39"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"time"
)

// nft-burn.go is a helper script to burn off all remaining NFTs.
// A burnable NFT is defined as one that has never been sold and is still for sale.
func main() {
	flagParamDeSoNodeURL := flag.String("deso-node",
		"", "A DeSo node to target for sourcing data and submitting transactions.")
	flagBurnerMnemonic := flag.String("burner-mnemonic",
		"", "The mnemonic associated with the burner's public/private key pair.")
	flagParamNFTHash := flag.String("nft-post-hash",
		"", "A NFT hash to target. This NFT will have all associated unsold copies burnt.\n"+
			"The hash should be passed as a hex string.")
	flagDelayMilliseconds := flag.Int("delay_milliseconds", 1000,
		"The delay in milliseconds between each burn.")
	flagMaxNFTsBurned := flag.Int("max_nfts_burned", -1,
		"The maximum number of NFTs to be burned.")
	flag.Parse()

	// Process flags.
	nftPostHash := *flagParamNFTHash
	burnDelayMilliseconds := *flagDelayMilliseconds
	maxNFTsBurned := *flagMaxNFTsBurned
	controlledBurn := false
	if maxNFTsBurned > 0 {
		controlledBurn = true
	}
	fmt.Printf("Targeted NFT Post Hash: %s\n", nftPostHash)

	// Construct necessary endpoints.
	desoNodeURL, err := url.Parse(*flagParamDeSoNodeURL)
	if err != nil {
		panic(errors.Wrap(err, "main(): Invalid DeSo node specified. Please specify a valid node using --deso-node flag\n"))
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

	// Generate the burner's keys from provided mnemonic.
	if len(*flagBurnerMnemonic) == 0 {
		panic(errors.Errorf("main(): Please specify a valid mnemonic using --burner-mnemonic flag\n"))
	}
	seedBytes, err := bip39.NewSeedWithErrorChecking(*flagBurnerMnemonic, "")
	if err != nil {
		panic(errors.Wrap(err, "main(): Could not generate key pair from mnemonic"))
	}
	burnerPubKey, burnerPrivKey, _, err := lib.ComputeKeysFromSeed(seedBytes, 0, params)
	if lib.PkToString(burnerPubKey.SerializeCompressed(), params) != getSinglePostResponse.PostFound.PosterPublicKeyBase58Check {
		panic(errors.Errorf("main(): Burner mnemonic generated mismatched key pair. Mnemonic public key: %s\n",
			lib.PkToString(burnerPubKey.SerializeCompressed(), params)))
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

	// Process NFT Entries, collecting burnable NFT copies.
	var burnableNFTEntryResponses []*routes.NFTEntryResponse
	var burnableNFTSerialNumbers []uint64
	uniqueSerialNumberMap := make(map[uint64]struct{})
	for _, nftEntryResponse := range getNFTEntriesResponse.NFTEntryResponses {
		if _, serialNumberSeen := uniqueSerialNumberMap[nftEntryResponse.SerialNumber]; serialNumberSeen {
			panic(errors.Errorf("main(): Found duplicate serial numbers in NFT entries response\n"))
		}
		if nftEntryResponse.OwnerPublicKeyBase58Check == getSinglePostResponse.PostFound.PosterPublicKeyBase58Check {
			burnableNFTEntryResponses = append(burnableNFTEntryResponses, nftEntryResponse)
			burnableNFTSerialNumbers = append(burnableNFTSerialNumbers, nftEntryResponse.SerialNumber)
			uniqueSerialNumberMap[nftEntryResponse.SerialNumber] = struct{}{}
		}
	}
	fmt.Printf("Number of burnable NFTs found: %d\n", len(burnableNFTEntryResponses))
	fmt.Printf("Serial Numbers of Burnable NFTs: %v\n", burnableNFTSerialNumbers)

	// Prompt user to confirm this is the correct NFT to burn.
	var userConfirmation string
	fmt.Print("Proceed with burn (Y/n)? ")
	_, err = fmt.Scan(&userConfirmation)
	if err != nil || userConfirmation != "Y" {
		fmt.Printf("Exiting without burning.\n")
		return
	}

	// Mark all burnable NFTs as not for sale.
	for ii := 0; ii < len(burnableNFTEntryResponses); ii++ {
		// Check if the user specified a controlled burn.
		if controlledBurn && ii >= maxNFTsBurned {
			break
		}

		burnableNFTRespone := burnableNFTEntryResponses[ii]
		if !burnableNFTRespone.IsForSale {
			continue
		}

		// Make sure the NFT is no longer for sale.
		fmt.Printf("Closing Sale For Serial Number #%d (#%d of #%d)\n",
			int(burnableNFTRespone.SerialNumber), ii+1, len(burnableNFTEntryResponses))
		err := toolslib.UpdateNFT(burnerPubKey, burnerPrivKey, nftPostHash, int(burnableNFTRespone.SerialNumber),
			false, int(burnableNFTRespone.MinBidAmountNanos), burnableNFTRespone.IsBuyNow,
			burnableNFTRespone.BuyNowPriceNanos, params, desoNodeURL.String())
		if err != nil {
			fmt.Printf("main(): Ran into an error when trying to close sale for NFT: %s\n", err.Error())

			var userConfirmation string
			fmt.Print("Cancel burn (Y/n)? Continuing will retry transaction: ")
			_, err = fmt.Scan(&userConfirmation)
			if err != nil || userConfirmation == "Y" {
				fmt.Printf("Exiting without burning remaining NFTs.\n")
				return
			}
			ii--
		}

		// Sleep to prevent being blacklisted from the node.
		time.Sleep(time.Duration(burnDelayMilliseconds) * time.Millisecond)
	}

	// Burn all the burnable NFT copies.
	for ii := 0; ii < len(burnableNFTEntryResponses); ii++ {
		// Check if the user specified a controlled burn.
		if controlledBurn && ii >= maxNFTsBurned {
			break
		}

		burnableNFTRespone := burnableNFTEntryResponses[ii]

		// Burn the NFT.
		fmt.Printf("Burning Serial Number #%d (#%d of #%d)\n",
			int(burnableNFTRespone.SerialNumber), ii+1, len(burnableNFTEntryResponses))
		err = toolslib.BurnNFT(burnerPubKey, burnerPrivKey, nftPostHash, int(burnableNFTRespone.SerialNumber),
			params, desoNodeURL.String())
		if err != nil {
			fmt.Printf("main(): Ran into an error when trying to burn NFT: %s\n", err.Error())

			var userConfirmation string
			fmt.Print("Cancel burn (Y/n)? Continuing will retry transaction: ")
			_, err = fmt.Scan(&userConfirmation)
			if err != nil || userConfirmation == "Y" {
				fmt.Printf("Exiting without burning remaining NFTs.\n")
				return
			}
			ii--
		}

		// Sleep to prevent being blacklisted from the node.
		time.Sleep(time.Duration(burnDelayMilliseconds) * time.Millisecond)
	}
}
