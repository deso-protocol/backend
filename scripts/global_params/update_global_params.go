package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"

	"github.com/golang-jwt/jwt/v4"

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

// Generate a JWT Token for the provided private key.
// This can be added to the payload for requests that require JWT token authentication.
func GenerateJWTToken(privKey *btcec.PrivateKey) (_JWT string, _err error) {
	// Create the ecdsa keys
	ecdsaPrivKey := privKey.ToECDSA()

	// Create a new JWT Token
	token := jwt.New(jwt.SigningMethodES256)

	// Sign using the ECDSA private key
	jwtToken, err := token.SignedString(ecdsaPrivKey)
	if err != nil {
		return "", errors.Wrap(err, "GenerateJWTToken() failed to sign token")
	}
	return jwtToken, nil
}

func constructGlobalParamsRequest(
	privKey *btcec.PrivateKey,
	adminPublicKey *lib.PublicKey,
	globalParamsRequest routes.UpdateGlobalParamsRequest,
) (
	any,
	error,
) {
	interfaceMap := make(map[string]interface{})
	v := reflect.ValueOf(globalParamsRequest)
	for ii := 0; ii < v.NumField(); ii++ {
		if v.Field(ii).IsZero() {
			switch v.Type().Field(ii).Type.Kind() {
			case reflect.String:
				interfaceMap[v.Type().Field(ii).Name] = ""
			case reflect.Bool:
				interfaceMap[v.Type().Field(ii).Name] = false
			case reflect.Uint64:
				interfaceMap[v.Type().Field(ii).Name] = 0
			case reflect.Struct, reflect.Slice:
				interfaceMap[v.Type().Field(ii).Name] = nil
			default:
				interfaceMap[v.Type().Field(ii).Name] = -1
			}
		} else {
			interfaceMap[v.Type().Field(ii).Name] = v.Field(ii).Interface()
		}
	}
	var err error
	interfaceMap["AdminPublicKey"] = lib.PkToString(adminPublicKey.ToBytes(), params)
	interfaceMap["JWT"], err = GenerateJWTToken(privKey)
	if err != nil {
		return nil, errors.Wrap(err, "constructGlobalParamsRequest(): Failed to generate JWT token")
	}
	fmt.Println(interfaceMap)
	return interfaceMap, nil
}

func constructUpdateGlobalParams(
	adminPrivKey *btcec.PrivateKey,
	adminPublicKey *lib.PublicKey,
) (
	*routes.UpdateGlobalParamsResponse,
	error,
) {
	adminPublicKeyString := lib.PkToString(adminPublicKey.ToBytes(), params)

	request := routes.UpdateGlobalParamsRequest{
		UpdaterPublicKeyBase58Check: adminPublicKeyString,
	}

	requestWithJWT, err := constructGlobalParamsRequest(adminPrivKey, adminPublicKey, request)

	if err != nil {
		return nil, errors.Wrap(err, "constructUpdateGlobalParams(): Failed to construct request")
	}

	res := makePostRequest[any, routes.UpdateGlobalParamsResponse](
		nodeURL+routes.RoutePathUpdateGlobalParams, requestWithJWT,
	)
	return &res, nil
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
	updateGlobalParamsTxn, err := constructUpdateGlobalParams(adminPrivKey, adminPublicKey)
	if err != nil {
		panic(err)
	}
	if updateGlobalParamsTxn == nil {
		panic(errors.New("main(): updateGlobalParamsTxn is nil"))
	}
	signAndSubmitTxn(updateGlobalParamsTxn.Transaction, adminPrivKey, nodeURL)
}
