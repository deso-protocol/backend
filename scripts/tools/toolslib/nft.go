package toolslib

import (
	"bytes"
	"encoding/json"
	"github.com/btcsuite/btcd/btcec"
	"github.com/deso-protocol/backend/routes"
	"github.com/deso-protocol/core/lib"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
)

func _generateUnsignedUpdateNFT(updaterPubKey *btcec.PublicKey, nftPostHashHex string, serialNumber int,
	isForSale bool, minBidAmountNanos int, isBuyNow bool, buyNowPriceNanos uint64, params *lib.DeSoParams,
	node string) (*routes.UpdateNFTResponse, error) {
	endpoint := node + routes.RoutePathUpdateNFT

	payload := &routes.UpdateNFTRequest{
		UpdaterPublicKeyBase58Check: lib.PkToString(updaterPubKey.SerializeCompressed(), params),
		NFTPostHashHex:              nftPostHashHex,
		SerialNumber:                serialNumber,
		IsForSale:                   isForSale,
		MinBidAmountNanos:           minBidAmountNanos,
		IsBuyNow:                    isBuyNow,
		BuyNowPriceNanos:            buyNowPriceNanos,
		MinFeeRateNanosPerKB:        1000,
	}
	postBody, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedUpdateNFT() failed to marshal struct")
	}
	postBuffer := bytes.NewBuffer(postBody)

	// Execute request
	resp, err := http.Post(endpoint, "application/json", postBuffer)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedUpdateNFT() failed to execute request")
	}
	if resp.StatusCode != 200 {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return nil, errors.Errorf("_generateUnsignedUpdateNFT(): Received non 200 response code: "+
			"Status Code: %v Body: %v", resp.StatusCode, string(bodyBytes))
	}

	// Process response
	updateNFTResponse := routes.UpdateNFTResponse{}
	err = json.NewDecoder(resp.Body).Decode(&updateNFTResponse)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedUpdateNFT(): failed decoding body")
	}
	err = resp.Body.Close()
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedUpdateNFT(): failed closing body")
	}

	return &updateNFTResponse, nil
}
func _generateUnsignedBurnNFT(burnerPubKey *btcec.PublicKey, nftPostHashHex string, serialNumber int,
	params *lib.DeSoParams, node string) (*routes.BurnNFTResponse, error) {
	endpoint := node + routes.RoutePathBurnNFT

	// Setup request
	payload := &routes.BurnNFTRequest{
		UpdaterPublicKeyBase58Check: lib.PkToString(burnerPubKey.SerializeCompressed(), params),
		NFTPostHashHex:              nftPostHashHex,
		SerialNumber:                serialNumber,
		MinFeeRateNanosPerKB:        1000,
	}
	postBody, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedBurnNFT() failed to marshal struct")
	}
	postBuffer := bytes.NewBuffer(postBody)

	// Execute request
	resp, err := http.Post(endpoint, "application/json", postBuffer)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedBurnNFT() failed to execute request")
	}
	if resp.StatusCode != 200 {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return nil, errors.Errorf("_generateUnsignedBurnNFT(): Received non 200 response code: "+
			"Status Code: %v Body: %v", resp.StatusCode, string(bodyBytes))
	}

	// Process response
	burnNFTResponse := routes.BurnNFTResponse{}
	err = json.NewDecoder(resp.Body).Decode(&burnNFTResponse)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedBurnNFT(): failed decoding body")
	}
	err = resp.Body.Close()
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedBurnNFT(): failed closing body")
	}

	return &burnNFTResponse, nil
}

func UpdateNFT(updaterPubKey *btcec.PublicKey, updaterPrivKey *btcec.PrivateKey, nftPostHashHex string, serialNumber int,
	isForSale bool, minBidAmountNanos int, isBuyNow bool, buyNowPriceNanos uint64, params *lib.DeSoParams,
	node string) error {

	// Request an unsigned transaction from the node
	unsignedMessage, err := _generateUnsignedUpdateNFT(updaterPubKey, nftPostHashHex, serialNumber, isForSale,
		minBidAmountNanos, isBuyNow, buyNowPriceNanos, params, node)
	if err != nil {
		return errors.Wrap(err, "UpdateNFT() failed to call _generateUnsignedBurnNFT()")
	}
	txn := unsignedMessage.Transaction

	// Sign the transaction
	signature, err := txn.Sign(updaterPrivKey)
	if err != nil {
		return errors.Wrap(err, "UpdateNFT() failed to sign transaction")
	}
	txn.Signature = signature

	// Submit the transaction to the node
	err = SubmitTransactionToNode(txn, node)
	if err != nil {
		return errors.Wrap(err, "UpdateNFT() failed to submit transaction")
	}
	return nil
}

func BurnNFT(burnerPubKey *btcec.PublicKey, burnerPrivKey *btcec.PrivateKey,
	nftPostHashHex string, serialNumber int, params *lib.DeSoParams, node string) error {

	// Request an unsigned transaction from the node
	unsignedMessage, err := _generateUnsignedBurnNFT(burnerPubKey, nftPostHashHex, serialNumber, params, node)
	if err != nil {
		return errors.Wrap(err, "BurnNFT() failed to call _generateUnsignedBurnNFT()")
	}
	txn := unsignedMessage.Transaction

	// Sign the transaction
	signature, err := txn.Sign(burnerPrivKey)
	if err != nil {
		return errors.Wrap(err, "BurnNFT() failed to sign transaction")
	}
	txn.Signature = signature

	// Submit the transaction to the node
	err = SubmitTransactionToNode(txn, node)
	if err != nil {
		return errors.Wrap(err, "BurnNFT() failed to submit transaction")
	}
	return nil
}
