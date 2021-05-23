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

// _generateUnsignedGiveDiamonds...
func _generateUnsignedSendDiamonds(senderPubKey *btcec.PublicKey, postHashHex string, receiverPublicKeyBase58Check string,
	diamondLevel int64, params *lib.BitCloutParams, node string) (*routes.SendDiamondsResponse, error) {
	endpoint := node + routes.RoutePathSendDiamonds

	// Setup request
	payload := &routes.SendDiamondsRequest{
		SenderPublicKeyBase58Check: lib.PkToString(senderPubKey.SerializeCompressed(), params),
		ReceiverPublicKeyBase58Check: receiverPublicKeyBase58Check,
		DiamondPostHashHex: postHashHex,
		DiamondLevel: diamondLevel,
		MinFeeRateNanosPerKB:  1000,
	}
	postBody, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedSendDiamonds() failed to marshal struct")
	}
	postBuffer := bytes.NewBuffer(postBody)

	// Execute request
	resp, err := http.Post(endpoint, "application/json", postBuffer)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedSendDiamonds() failed to execute request")
	}
	if resp.StatusCode != 200 {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return nil, errors.Errorf("_generateUnsignedSendDiamonds(): Received non 200 response code: " +
			"Status Code: %v Body: %v", resp.StatusCode, string(bodyBytes))
	}

	// Process response
	sendDiamondsResponse := routes.SendDiamondsResponse{}
	err = json.NewDecoder(resp.Body).Decode(&sendDiamondsResponse)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedSendDiamonds(): failed decoding body")
	}
	err = resp.Body.Close()
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedSendDiamonds(): failed closing body")
	}

	return &sendDiamondsResponse, nil
}

// SendDiamonds
func SendDiamonds(senderPubKey *btcec.PublicKey, senderPrivKey *btcec.PrivateKey, postHashHex string,
	receiverPublicKeyBase58Check string, diamondLevel int64, params *lib.BitCloutParams, node string) error {

	// Request an unsigned transaction from the node
	unsignedSendDiamonds, err := _generateUnsignedSendDiamonds(senderPubKey, postHashHex, receiverPublicKeyBase58Check,
		diamondLevel, params, node)
	if err != nil {
		return errors.Wrap(err, "SendDiamonds() failed to call _generateUnsignedSendDiamonds()")
	}
	txn := unsignedSendDiamonds.Transaction

	// Sign the transaction
	signature, err := txn.Sign(senderPrivKey)
	if err != nil {
		return errors.Wrap(err, "SendDiamonds() failed to sign transaction")
	}
	txn.Signature = signature

	// Submit the transaction to the node
	err = SubmitTransactionToNode(txn, node)
	if err != nil {
		return errors.Wrap(err, "SendDiamonds() failed to submit transaction")
	}
	return nil
}
