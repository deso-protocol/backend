package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/deso-protocol/backend/routes"
	"github.com/deso-protocol/backend/scripts/tools/toolslib"
	"github.com/deso-protocol/core/lib"
	"github.com/pkg/errors"
	"github.com/tyler-smith/go-bip39"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"sort"
	"time"
)

func _ReadMessagedUsersJSONFilename(messagedUsersJSONFilename string) (map[string]string, error) {
	// If the file doesn't exist, create it and return a new map.
	if _, err := os.Stat(messagedUsersJSONFilename); errors.Is(err, os.ErrNotExist) {
		newFile, err := os.Create(messagedUsersJSONFilename)
		if err != nil {
			return nil, errors.Wrap(err, "_ReadMessagedUsersJSONFilename(): Failed to create new JSON file")
		}
		newFile.Close()

		newMap := make(map[string]string)
		err = _UpdateMessagedUsersJSONFilename(messagedUsersJSONFilename, newMap)
		if err != nil {
			return nil, errors.Wrap(err, "_ReadMessagedUsersJSONFilename(): Could not save new map")
		}
		return newMap, nil
	} else if !errors.Is(err, os.ErrNotExist) && err != nil {
		return nil, errors.Wrap(err, "_ReadMessagedUsersJSONFilename(): Failed to check if file exists")
	}

	// Read the JSON file's contents.
	jsonFile, err := os.Open(messagedUsersJSONFilename)
	if err != nil {
		return nil, errors.Wrap(err, "_ReadMessagedUsersJSONFilename(): Failed to open JSON file")
	}
	defer jsonFile.Close()
	jsonBytes, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return nil, errors.Wrap(err, "_ReadMessagedUsersJSONFilename(): Failed to read bytes from JSON file")
	}

	// Decode and convert the JSON file.
	var savedMap map[string]string
	err = json.Unmarshal(jsonBytes, &savedMap)
	if err != nil {
		return nil, errors.Wrap(err, "_ReadMessagedUsersJSONFilename(): Failed to decode JSON file")
	}
	return savedMap, nil
}

func _UpdateMessagedUsersJSONFilename(messagedUsersJSONFilename string, outputMap map[string]string) error {
	// Convert the state to JSON.
	newMapBytes, err := json.MarshalIndent(outputMap, "", "\t")
	if err != nil {
		return errors.Wrap(err, "_UpdateMessagedUsersJSONFilename(): Failed to JSON marshal save state")
	}

	// Open the JSON file with settings set to overwrite.
	jsonFile, err := os.OpenFile(messagedUsersJSONFilename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return errors.Wrap(err, "_UpdateMessagedUsersJSONFilename(): Failed to open JSON file")
	}
	defer jsonFile.Close()

	// Write the bytes to the file.
	numBytesWritten, err := jsonFile.Write(newMapBytes)
	if numBytesWritten != len(newMapBytes) {
		return errors.Errorf("_UpdateMessagedUsersJSONFilename(): Expected to write %d bytes, wrote %d bytes\n",
			len(newMapBytes), numBytesWritten)
	}
	if err != nil {
		return errors.Wrap(err, "_UpdateMessagedUsersJSONFilename(): Failed write to JSON file")
	}
	return nil
}

func main() {
	flagParamDeSoNodeURL := flag.String("deso-node",
		"", "A DeSo node to target for sourcing data and submitting transactions.")
	flagParamKeysFilename := flag.String("keys-filename",
		"", "A file containing new line seperated DAODAO access keys.")
	flagParamMessagedUsersJSONFilename := flag.String("messaged-users-json-filename",
		"", "A JSON map where the keys represent already messaged users.")
	flagParamNFTPostHash := flag.String("nft-post-hash",
		"", "A NFT hash to target. This NFT will have all associated unsold copies burnt.\n"+
			"The hash should be passed as a hex string.")
	flagParamMessengerMnemonic := flag.String("messenger-mnemonic", "",
		"The mnemonic from which to send messages for NFT holders.")
	flagParamDisableMessengerPublicKeyCheck := flag.Bool("disable-messenger-public-key-check",
		false, "An optional override on the public key check.")
	flagParamMessagePretext := flag.String("message-pretext", "",
		"The message to prepend to a password.")
	flagParamTestrun := flag.Bool("testrun", false,
		"An optional override to simulate a message distribution run. Note this does update the "+
			"messaged users JSON save state file.")
	flagDelayMilliseconds := flag.Int("delay-milliseconds", 1000,
		"The delay in milliseconds between each request.")
	flag.Parse()

	// Process flags.
	if _, err := os.Stat(*flagParamKeysFilename); err != nil {
		panic(errors.Wrap(err, "main(): provided keys file specified by --keys-file flag does not exist"))
	}
	desoNodeURL, err := url.Parse(*flagParamDeSoNodeURL)
	if err != nil {
		panic(errors.Wrap(err, "main(): Invalid DeSo node specified. "+
			"Please specify a valid node using --deso-node flag\n"))
	}
	getNFTEntriesEndpoint := desoNodeURL.String() + routes.RoutePathGetNFTEntriesForPostHash
	getSinglePostEndpoint := desoNodeURL.String() + routes.RoutePathGetSinglePost
	nftPostHash := *flagParamNFTPostHash
	fmt.Printf("Targeted NFT Post Hash: %s\n", nftPostHash)

	// Setup Network Parameters.
	params := &lib.DeSoMainnetParams
	fmt.Printf("Network type set: %s\n", params.NetworkType.String())

	// Load the DAODAO passwords into a string array.
	var daodaoPasswords []string
	daodaoPasswordsFile, err := os.Open(*flagParamKeysFilename)
	if err != nil {
		panic(errors.Wrap(err, "main(): Could not open passwords file"))
	}
	daodaoScanner := bufio.NewScanner(daodaoPasswordsFile)
	for daodaoScanner.Scan() {
		daodaoPasswords = append(daodaoPasswords, daodaoScanner.Text())
	}

	// Load the state of public keys already sent a message.
	alreadySentKey, err := _ReadMessagedUsersJSONFilename(*flagParamMessagedUsersJSONFilename)
	if err != nil {
		panic(errors.Wrap(err, "main(): Could not load messaged users file"))
	}
	keyFileOffset := len(alreadySentKey)

	// Fetch post information on the requested NFT.
	var getSinglePostResponse routes.GetSinglePostResponse
	{
		// Create request payload.
		payload := &routes.GetSinglePostRequest{
			PostHashHex: *flagParamNFTPostHash,
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

	// Generate the sender's keys from provided mnemonic.
	if len(*flagParamMessengerMnemonic) == 0 {
		panic(errors.Errorf("main(): Please specify a valid mnemonic using --dao-coin-distributor-mnemonic flag\n"))
	}
	seedBytes, err := bip39.NewSeedWithErrorChecking(*flagParamMessengerMnemonic, "")
	if err != nil {
		panic(errors.Wrap(err, "main(): Could not generate key pair from mnemonic"))
	}
	fromPubKey, fromPrivKey, _, err := lib.ComputeKeysFromSeed(seedBytes, 0, params)
	disablePublicKeyCheck := *flagParamDisableMessengerPublicKeyCheck
	if !disablePublicKeyCheck &&
		lib.PkToString(fromPubKey.SerializeCompressed(), params) != getSinglePostResponse.PostFound.PosterPublicKeyBase58Check {
		panic(errors.Errorf("main(): Distributor mnemonic generated mismatched key pair. Mnemonic public key: %s\n",
			lib.PkToString(fromPubKey.SerializeCompressed(), params)))
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

	// Process and find the unique, not already messaged public keys who own the NFT.
	var uniquePublicKeys []string
	alreadySeenThisNFT := make(map[string]bool)
	for _, nftEntryResponse := range getNFTEntriesResponse.NFTEntryResponses {
		if _, pkSeen := alreadySentKey[nftEntryResponse.OwnerPublicKeyBase58Check]; pkSeen {
			continue
		}

		// Check if there is a valid owner.
		if nftEntryResponse.OwnerPublicKeyBase58Check == getSinglePostResponse.PostFound.PosterPublicKeyBase58Check {
			continue
		}

		// Check if it's already been seen this set.
		if _, pkSeen := alreadySeenThisNFT[nftEntryResponse.OwnerPublicKeyBase58Check]; pkSeen {
			continue
		}
		alreadySeenThisNFT[nftEntryResponse.OwnerPublicKeyBase58Check] = true

		// Append the public key.
		uniquePublicKeys = append(uniquePublicKeys, nftEntryResponse.OwnerPublicKeyBase58Check)
	}
	fmt.Printf("Targetting %d previously unmessaged public keys.\n", len(uniquePublicKeys))

	// Ask for user confirmation on this.
	var userConfirmation string
	fmt.Print("Proceed with messages (Y/n)? ")
	_, err = fmt.Scan(&userConfirmation)
	if err != nil || userConfirmation != "Y" {
		fmt.Printf("Exiting without messaging.\n")
		return
	}

	// Message the accounts.
	for ii := 0; ii < len(uniquePublicKeys); ii++ {
		toPubKey := uniquePublicKeys[ii]

		// Construct the message.
		message := *flagParamMessagePretext + daodaoPasswords[keyFileOffset]
		fmt.Printf("Messaging %s (#%d of %d): %s\n", toPubKey, ii+1, len(uniquePublicKeys), message)

		// Decode the user's public key to btcec data type.
		toKeyBytes, _, err := lib.Base58CheckDecode(toPubKey)
		if err != nil {
			if err != nil {
				fmt.Printf("main(): Ran into an error when trying to decode pk (%s): %s\n", toPubKey, err.Error())

				var userConfirmation string
				fmt.Print("Cancel messages (Y/n)? Continuing will retry transaction: ")
				_, err = fmt.Scan(&userConfirmation)
				if err != nil || userConfirmation == "Y" {
					fmt.Printf("Exiting without continuing.\n")
					return
				}
				ii--
				time.Sleep(time.Millisecond * time.Duration(*flagDelayMilliseconds))
				continue
			}
		}
		toBTCECPubKey, err := btcec.ParsePubKey(toKeyBytes, btcec.S256())
		if err != nil {
			if err != nil {
				fmt.Printf("main(): Ran into an error when trying to btcec parse pk (%s): %s\n", toPubKey, err.Error())

				var userConfirmation string
				fmt.Print("Cancel messages (Y/n)? Continuing will retry transaction: ")
				_, err = fmt.Scan(&userConfirmation)
				if err != nil || userConfirmation == "Y" {
					fmt.Printf("Exiting without continuing.\n")
					return
				}
				ii--
				time.Sleep(time.Millisecond * time.Duration(*flagDelayMilliseconds))
				continue
			}
		}

		// Send the message.
		if !*flagParamTestrun {
			err = toolslib.SendMessage(fromPubKey, fromPrivKey, toBTCECPubKey, message, params, desoNodeURL.String())
			if err != nil {
				fmt.Printf("main(): Ran into an error when trying to message pk (%s): %s\n", toPubKey, err.Error())

				var userConfirmation string
				fmt.Print("Cancel messages (Y/n)? Continuing will retry transaction: ")
				_, err = fmt.Scan(&userConfirmation)
				if err != nil || userConfirmation == "Y" {
					fmt.Printf("Exiting without continuing.\n")
					return
				}
				ii--
				time.Sleep(time.Millisecond * time.Duration(*flagDelayMilliseconds))
				continue
			}
		} else {
			fmt.Printf("THIS IS A TESTRUN.\n")
		}

		alreadySentKey[toPubKey] = daodaoPasswords[keyFileOffset]
		err = _UpdateMessagedUsersJSONFilename(*flagParamMessagedUsersJSONFilename, alreadySentKey)
		if err != nil {
			fmt.Printf("main(): Ran into an error when trying to update save state: %s\n", err.Error())

			var userConfirmation string
			fmt.Print("Cancel messaging (Y/n)? Continuing will retry this distribution: ")
			_, err = fmt.Scan(&userConfirmation)
			if err != nil || userConfirmation == "Y" {
				fmt.Printf("Exiting without continuing.\n")
				return
			}
			ii--
			time.Sleep(time.Millisecond * time.Duration(*flagDelayMilliseconds))
			continue
		}

		// Increment the offset.
		keyFileOffset++

		// Sleep to prevent rate limiting.
		fmt.Println("Sleeping...")
		time.Sleep(time.Millisecond * time.Duration(*flagDelayMilliseconds))
		fmt.Println("Awake!")
	}
	fmt.Printf("Script completed.\n")
}
