package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/deso-protocol/backend/routes"
	"github.com/deso-protocol/core/lib"
	"github.com/pkg/errors"
	"github.com/tyler-smith/go-bip39"
)

var superAdminSeedPhrase = "<SUPER ADMIN SEED PHRASE HERE>"

var nodeURL = "<NODE URL HERE>"
var params = &lib.DeSoTestnetParams

func makePostRequest[TPayload any, TResponse any](url string, payload TPayload) TResponse {
	postBody, err := json.Marshal(payload)
	if err != nil {
		panic(errors.Wrap(err, "main(): Could not complete request"))
	}
	postBuffer := bytes.NewBuffer(postBody)

	// Execute request.
	resp, err := http.Post(url, "application/json", postBuffer)
	if err != nil {
		panic(errors.Wrap(err, "main(): failed request"))
	}
	if resp.StatusCode != 200 {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		panic(errors.Errorf("main(): Received non 200 response code: "+
			"Status Code: %v Body: %v", resp.StatusCode, string(bodyBytes)))
	}

	var decodedResponse TResponse

	// Process Response.
	err = json.NewDecoder(resp.Body).Decode(&decodedResponse)
	if err != nil {
		panic(errors.Wrap(err, "main(): Failed to decode response\n"))
	}
	err = resp.Body.Close()
	if err != nil {
		panic(errors.Wrap(err, "main(): Failed to decode body\n"))
	}

	return decodedResponse
}

func signAndSubmitTxn(txn *lib.MsgDeSoTxn, privKey *btcec.PrivateKey, nodeURL string) {
	signature, err := txn.Sign(privKey)
	if err != nil {
		panic(err)
	}

	txn.Signature.SetSignature(signature)

	txnBytes, err := txn.ToBytes(false)
	if err != nil {
		panic(err)
	}

	txnHex := hex.EncodeToString(txnBytes)

	submitTransactionRequest := routes.SubmitTransactionRequest{
		TransactionHex: txnHex,
	}

	makePostRequest[routes.SubmitTransactionRequest, routes.SubmitTransactionResponse](
		nodeURL+routes.RoutePathSubmitTransaction, submitTransactionRequest,
	)
}

func constructUpdateGlobalParams(adminPublicKey *lib.PublicKey) routes.UpdateGlobalParamsResponse {
	adminPublicKeyString := lib.PkToString(adminPublicKey.ToBytes(), params)

	request := routes.UpdateGlobalParamsRequest{
		UpdaterPublicKeyBase58Check: adminPublicKeyString,
	}

	res := makePostRequest[routes.UpdateGlobalParamsRequest, routes.UpdateGlobalParamsResponse](
		nodeURL+routes.RoutePathUpdateGlobalParams, request,
	)
	return res
}

func generatePubAndPrivKeys(seedPhrase string) (*lib.PublicKey, *btcec.PrivateKey) {
	seedBytes, err := bip39.NewSeedWithErrorChecking(seedPhrase, "")
	if err != nil {
		panic(errors.Wrap(err, "main(): Could not generate key pair from mnemonic"))
	}

	pubKey, privKey, _, err := lib.ComputeKeysFromSeed(seedBytes, 0, &lib.DeSoTestnetParams)
	if err != nil {
		panic(errors.Wrap(err, "main(): Could not generate key pair from mnemonic"))
	}

	publicKey := lib.NewPublicKey(pubKey.SerializeCompressed())
	fmt.Println(lib.PkToString(pubKey.SerializeCompressed(), params))
	return publicKey, privKey
}

func main() {
	adminPublicKey, adminPrivKey := generatePubAndPrivKeys(superAdminSeedPhrase)
	updateGlobalParamsTxn := constructUpdateGlobalParams(adminPublicKey)
	signAndSubmitTxn(updateGlobalParamsTxn.Transaction, adminPrivKey, nodeURL)
}
