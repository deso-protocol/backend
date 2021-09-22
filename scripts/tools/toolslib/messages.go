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

func _generateUnsignedMessage(senderPubKey *btcec.PublicKey, recipientPubKey *btcec.PublicKey, message string,
	params *lib.BitCloutParams, node string) (*routes.SendMessageStatelessResponse, error){
	endpoint := node + routes.RoutePathSendMessageStateless

	// Setup request
	payload := &routes.SendMessageStatelessRequest{
		SenderPublicKeyBase58Check: lib.PkToString(senderPubKey.SerializeCompressed(), params),
		RecipientPublicKeyBase58Check: lib.PkToString(recipientPubKey.SerializeCompressed(), params),
		MessageText: message,
		MinFeeRateNanosPerKB: 1000,
	}
	postBody, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedMessage() failed to marshal struct")
	}
	postBuffer := bytes.NewBuffer(postBody)

	// Execute request
	resp, err := http.Post(endpoint, "application/json", postBuffer)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedMessage() failed to execute request")
	}
	if resp.StatusCode != 200 {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return nil, errors.Errorf("_generateUnsignedMessage(): Received non 200 response code: " +
			"Status Code: %v Body: %v", resp.StatusCode, string(bodyBytes))
	}

	// Process response
	sendMessageResponse := routes.SendMessageStatelessResponse{}
	err = json.NewDecoder(resp.Body).Decode(&sendMessageResponse)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedMessage(): failed decoding body")
	}
	err = resp.Body.Close()
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedMessage(): failed closing body")
	}

	return &sendMessageResponse, nil
}

func SendMessage(senderPubKey *btcec.PublicKey, senderPrivKey *btcec.PrivateKey,
	recipientPubKey *btcec.PublicKey, message string, params *lib.BitCloutParams, node string) error {

	// Request an unsigned transaction from the node
	unsignedMessage, err := _generateUnsignedMessage(senderPubKey, recipientPubKey, message, params, node)
	if err != nil {
		return errors.Wrap(err, "SendMessage() failed to call _generateSendBitclout()")
	}
	txn := unsignedMessage.Transaction

	// Sign the transaction
	signature, err := txn.Sign(senderPrivKey)
	if err != nil {
		return errors.Wrap(err, "SendMessage() failed to sign transaction")
	}
	txn.Signature = signature

	// Submit the transaction to the node
	err = SubmitTransactionToNode(txn, node)
	if err != nil {
		return errors.Wrap(err, "SendMessage() failed to submit transaction")
	}
	return nil
}
