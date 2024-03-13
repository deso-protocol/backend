package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/deso-protocol/backend/routes"
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/lib"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"github.com/tyler-smith/go-bip39"
)

var desoSourceSeedPhrase = "<SEED PHRASE HERE>"
var validatorSeedPhrase = "SEED PHRASE HERE"
var nodeApiUrl = "http://localhost:18001"
var validatorDomain string = "localhost:19000"

var params = &lib.DeSoTestnetParams

func getBLSVotingAuthorizationAndPublicKey(blsKeyStore *lib.BLSKeystore, transactorPublicKey *lib.PublicKey) (
	*bls.PublicKey, *bls.Signature,
) {
	votingAuthPayload := lib.CreateValidatorVotingAuthorizationPayload(transactorPublicKey.ToBytes())
	votingAuthorization, err := blsKeyStore.GetSigner().Sign(votingAuthPayload)
	if err != nil {
		panic(err)
	}
	return blsKeyStore.GetSigner().GetPublicKey(), votingAuthorization
}

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

func constructSendDESOTxn(senderPubKey *lib.PublicKey, recipientPubKey *lib.PublicKey) routes.SendDeSoResponse {
	senderPublicKeyString := lib.PkToString(senderPubKey.ToBytes(), params)
	recipientPublicKeyString := lib.PkToString(recipientPubKey.ToBytes(), params)

	sendDESOTxnRequest := routes.SendDeSoRequest{
		SenderPublicKeyBase58Check:   senderPublicKeyString,
		RecipientPublicKeyOrUsername: recipientPublicKeyString,
		AmountNanos:                  11 * 1e9,
		MinFeeRateNanosPerKB:         1000,
	}

	return makePostRequest[routes.SendDeSoRequest, routes.SendDeSoResponse](
		nodeApiUrl+routes.RoutePathSendDeSo, sendDESOTxnRequest,
	)
}

func constructRegisterAsValidatorTxn(keystore *lib.BLSKeystore, pubKey *lib.PublicKey) routes.ValidatorTxnResponse {
	_, votingAuthorization := getBLSVotingAuthorizationAndPublicKey(keystore, pubKey)

	publicKeyString := lib.PkToString(pubKey.ToBytes(), params)

	request := routes.RegisterAsValidatorRequest{
		TransactorPublicKeyBase58Check: publicKeyString,
		Domains:                        []string{validatorDomain},
		DisableDelegatedStake:          false,
		VotingPublicKey:                keystore.GetSigner().GetPublicKey().ToString(),
		VotingAuthorization:            votingAuthorization.ToString(),
		ExtraData:                      map[string]string{},
		MinFeeRateNanosPerKB:           1000,
		TransactionFees:                []routes.TransactionFee{},
	}

	return makePostRequest[routes.RegisterAsValidatorRequest, routes.ValidatorTxnResponse](
		nodeApiUrl+routes.RoutePathValidators+"/register", request,
	)
}

func constructStakeTxn(pubKey *lib.PublicKey) routes.StakeTxnResponse {
	publicKeyString := lib.PkToString(pubKey.ToBytes(), params)

	request := routes.StakeRequest{
		TransactorPublicKeyBase58Check: publicKeyString,
		ValidatorPublicKeyBase58Check:  publicKeyString,
		RewardMethod:                   routes.PayToBalance,
		StakeAmountNanos:               uint256.NewInt().SetUint64(9 * 1e9),
		ExtraData:                      map[string]string{},
		MinFeeRateNanosPerKB:           1000,
		TransactionFees:                []routes.TransactionFee{},
	}

	return makePostRequest[routes.StakeRequest, routes.StakeTxnResponse](nodeApiUrl+routes.RoutePathStake, request)
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
	return publicKey, privKey
}

func generateKeystore(seedPhrase string) *lib.BLSKeystore {
	keystore, err := lib.NewBLSKeystore(seedPhrase)
	if err != nil {
		panic(errors.Wrap(err, "main(): Could not generate keystore"))
	}
	return keystore
}

func main() {
	fmt.Printf("Network Type: %s\n", params.NetworkType.String())

	desoSourcePubKey, desoSourcePrivKey := generatePubAndPrivKeys(desoSourceSeedPhrase)

	validatorKeystore := generateKeystore(validatorSeedPhrase)
	validatorPubKey, validatorPrivKey := generatePubAndPrivKeys(validatorSeedPhrase)

	// First send some DESO to the validator
	sendDESOTxn := constructSendDESOTxn(desoSourcePubKey, validatorPubKey)
	signAndSubmitTxn(sendDESOTxn.Transaction, desoSourcePrivKey, nodeApiUrl)
	fmt.Println("DESO Sent ")

	time.Sleep(5 * time.Second)

	// Register the validator
	validatorRegistrationTxn := constructRegisterAsValidatorTxn(validatorKeystore, validatorPubKey)
	signAndSubmitTxn(validatorRegistrationTxn.Transaction, validatorPrivKey, nodeApiUrl)
	fmt.Println("Validator Registered")

	time.Sleep(5 * time.Second)

	// Have the validator stake to itself
	stakeTxn := constructStakeTxn(validatorPubKey)
	signAndSubmitTxn(stakeTxn.Transaction, validatorPrivKey, nodeApiUrl)
	fmt.Println("Stake Transaction Submitted")
}
