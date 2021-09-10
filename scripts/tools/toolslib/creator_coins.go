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

// _generateUnsignedCreatorCoinBuy...
func _generateUnsignedCreatorCoinBuy(buyerPubKey *btcec.PublicKey, creatorPubKey *btcec.PublicKey,
	amountNanos uint64, params *lib.BitCloutParams, node string) (*routes.BuyOrSellCreatorCoinResponse, error){
	endpoint := node + routes.RoutePathBuyOrSellCreatorCoin

	// Setup request
	payload := &routes.BuyOrSellCreatorCoinRequest{
		UpdaterPublicKeyBase58Check: lib.PkToString(buyerPubKey.SerializeCompressed(), params),
		CreatorPublicKeyBase58Check: lib.PkToString(creatorPubKey.SerializeCompressed(), params),
		OperationType: "buy",
		BitCloutToSellNanos: amountNanos,
		CreatorCoinToSellNanos: 0,
		BitCloutToAddNanos: 0,
		MinBitCloutExpectedNanos: 0,
		MinCreatorCoinExpectedNanos: 0,
		MinFeeRateNanosPerKB: 1000,
	}
	postBody, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedCreatorCoinBuy() failed to marshal struct")
	}
	postBuffer := bytes.NewBuffer(postBody)

	// Execute request
	resp, err := http.Post(endpoint, "application/json", postBuffer)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedCreatorCoinBuy() failed to execute request")
	}
	if resp.StatusCode != 200 {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return nil, errors.Errorf("_generateUnsignedCreatorCoinBuy(): Received non 200 response code: " +
			"Status Code: %v Body: %v", resp.StatusCode, string(bodyBytes))
	}

	// Process response
	buyCCResponse := routes.BuyOrSellCreatorCoinResponse{}
	err = json.NewDecoder(resp.Body).Decode(&buyCCResponse)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedCreatorCoinBuy(): failed decoding body")
	}
	err = resp.Body.Close()
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedCreatorCoinBuy(): failed closing body")
	}

	return &buyCCResponse, nil
}

// BuyCreator...
func BuyCreator(buyerPubKey *btcec.PublicKey, buyerPrivKey *btcec.PrivateKey, creatorPubKey *btcec.PublicKey,
	amountNanos uint64, params *lib.BitCloutParams, node string) error {

	// Request an unsigned transaction from the node
	unsignedCCBuy, err := _generateUnsignedCreatorCoinBuy(buyerPubKey, creatorPubKey , amountNanos, params, node)
	if err != nil {
		return errors.Wrap(err, "BuyCreator() failed to call _generateUnsignedCreatorCoinBuy()")
	}
	txn := unsignedCCBuy.Transaction

	// Sign the transaction
	signature, err := txn.Sign(buyerPrivKey)
	if err != nil {
		return errors.Wrap(err, "BuyCreator() failed to sign transaction")
	}
	txn.Signature = signature

	// Submit the transaction to the node
	err = SubmitTransactionToNode(txn, node)
	if err != nil {
		return errors.Wrap(err, "BuyCreator() failed to submit transaction")
	}
	return nil
}
