package toolslib

import (
	"bytes"
	"encoding/json"
	"github.com/bitclout/backend/routes"
	"github.com/bitclout/core/lib"
	"github.com/btcsuite/btcd/btcec"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
)

// _generateUnsignedBTCPriceUpdate...
func _generateUnsignedBTCPriceUpdate(updaterPubKey *btcec.PublicKey, newUSDCentsPerBitcoin uint64,
	params *lib.BitCloutParams, node string) (*routes.UpdateGlobalParamsResponse, error) {
	endpoint := node + routes.RoutePathUpdateGlobalParams

	// Setup request
	payload := &routes.UpdateGlobalParamsRequest {
		UpdaterPublicKeyBase58Check: lib.PkToString(updaterPubKey.SerializeCompressed(), params),
		USDCentsPerBitcoin: int64(newUSDCentsPerBitcoin),
		MinFeeRateNanosPerKB: 1000,
	}
	postBody, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedBTCPriceUpdate() failed to marshal json")
	}
	postBuffer := bytes.NewBuffer(postBody)

	// Execute request
	resp, err := http.Post(endpoint, "application/json", postBuffer)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedBTCPriceUpdate() failed to execute request")
	}
	if resp.StatusCode != 200 {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return nil, errors.Errorf("_generateUnsignedBTCPriceUpdate(): Received non 200 response code: " +
			"Status Code: %v Body: %v", resp.StatusCode, string(bodyBytes))
	}

	// Process response
	updateBitcoinUSDExchangeRateResponse := routes.UpdateGlobalParamsResponse{}
	err = json.NewDecoder(resp.Body).Decode(&updateBitcoinUSDExchangeRateResponse)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedBTCPriceUpdate(): failed decoding body")
	}
	err = resp.Body.Close()
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedBTCPriceUpdate(): failed closing body")
	}
	return &updateBitcoinUSDExchangeRateResponse, nil
}

// UpdateBitcoinUSDExchangeRate...
func UpdateBitcoinUSDExchangeRate(updaterPubKey *btcec.PublicKey, updaterPrivKey *btcec.PrivateKey, newUSDCentsPerBitcoin uint64,
	params *lib.BitCloutParams, node string) error {

	// Request an unsigned transaction from the node
	unsignedUpdateBitcoinUSDExchangeRate, err := _generateUnsignedBTCPriceUpdate(updaterPubKey, newUSDCentsPerBitcoin, params, node)
	if err != nil {
		return errors.Wrap(err, "UpdateBitcoinUSDExchangeRate() failed to generate unsigned transaction")
	}
	txn := unsignedUpdateBitcoinUSDExchangeRate.Transaction

	// Sign the transaction
	signature, err := txn.Sign(updaterPrivKey)
	if err != nil {
		return errors.Wrap(err, "UpdateBitcoinUSDExchangeRate() failed to sign the transaction")
	}
	txn.Signature = signature

	// Submit the transaction to the node
	err = SubmitTransactionToNode(txn, node)
	if err != nil {
		return errors.Wrap(err, "UpdateBitcoinUSDExchangeRate() failed to submit transaction")
	}
	return nil
}
