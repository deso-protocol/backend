package toolslib

import (
	"bytes"
	"encoding/json"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/deso-protocol/backend/routes"
	"github.com/deso-protocol/core/lib"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
)

// _generateUnsignedSendDeSo...
func _generateUnsignedSendDeSo(senderPubKey *btcec.PublicKey, recipientPubKey *btcec.PublicKey, amountNanos int64,
	params *lib.DeSoParams, node string) (*routes.SendDeSoResponse, error) {
	endpoint := node + routes.RoutePathSendDeSo

	// Setup request
	payload := &routes.SendDeSoRequest{
		SenderPublicKeyBase58Check:   lib.PkToString(senderPubKey.SerializeCompressed(), params),
		RecipientPublicKeyOrUsername: lib.PkToString(recipientPubKey.SerializeCompressed(), params),
		AmountNanos:                  amountNanos,
		MinFeeRateNanosPerKB:         1000,
	}
	postBody, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedSendDeSo() failed to marshal struct")
	}
	postBuffer := bytes.NewBuffer(postBody)

	// Execute request
	resp, err := http.Post(endpoint, "application/json", postBuffer)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedSendDeSo() failed to execute request")
	}
	if resp.StatusCode != 200 {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return nil, errors.Errorf("_generateUnsignedSendDeSo(): Received non 200 response code: "+
			"Status Code: %v Body: %v", resp.StatusCode, string(bodyBytes))
	}

	// Process response
	sendDeSoResponse := routes.SendDeSoResponse{}
	err = json.NewDecoder(resp.Body).Decode(&sendDeSoResponse)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedSendDeSo(): failed decoding body")
	}
	err = resp.Body.Close()
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedSendDeSo(): failed closing body")
	}

	return &sendDeSoResponse, nil
}

// SendDeSo...
func SendDeSo(senderPubKey *btcec.PublicKey,
	senderPrivKey *btcec.PrivateKey,
	recipientPubKey *btcec.PublicKey, amountNanos int64, params *lib.DeSoParams, node string) error {

	// Request an unsigned transaction from the node
	unsignedSendDeSo, err := _generateUnsignedSendDeSo(senderPubKey, recipientPubKey, amountNanos, params, node)
	if err != nil {
		return errors.Wrap(err, "SendDeSo() failed to call _generateSendDeSo()")
	}
	txn := unsignedSendDeSo.Transaction

	// Sign the transaction
	signature, err := txn.Sign(senderPrivKey)
	if err != nil {
		return errors.Wrap(err, "SendDeSo() failed to sign transaction")
	}
	txn.Signature.SetSignature(signature)

	// Submit the transaction to the node
	err = SubmitTransactionToNode(txn, node)
	if err != nil {
		return errors.Wrap(err, "SendDeSo() failed to submit transaction")
	}
	return nil
}
