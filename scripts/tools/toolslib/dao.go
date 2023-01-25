package toolslib

import (
	"bytes"
	"encoding/json"
	"github.com/btcsuite/btcd/btcec"
	"github.com/deso-protocol/backend/routes"
	"github.com/deso-protocol/core/lib"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
)

func _generateUnsignedTransferDAOCoin(senderPubKey *btcec.PublicKey, profilePubKeyBase58Check string,
	receiverPubKeyBase58Check string, daoCoinToTransferNanos uint256.Int, params *lib.DeSoParams,
	node string) (*routes.TransferDAOCoinResponse, error) {
	endpoint := node + routes.RoutePathTransferDAOCoin

	// Setup request
	payload := &routes.TransferDAOCoinRequest{
		SenderPublicKeyBase58Check:             lib.PkToString(senderPubKey.SerializeCompressed(), params),
		ProfilePublicKeyBase58CheckOrUsername:  profilePubKeyBase58Check,
		ReceiverPublicKeyBase58CheckOrUsername: receiverPubKeyBase58Check,
		DAOCoinToTransferNanos:                 daoCoinToTransferNanos,
		MinFeeRateNanosPerKB:                   1000,
	}
	postBody, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedTransferDAOCoin() failed to marshal struct")
	}
	postBuffer := bytes.NewBuffer(postBody)

	// Execute request
	resp, err := http.Post(endpoint, "application/json", postBuffer)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedTransferDAOCoin() failed to execute request")
	}
	if resp.StatusCode != 200 {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return nil, errors.Errorf("_generateUnsignedTransferDAOCoin(): Received non 200 response code: "+
			"Status Code: %v Body: %v", resp.StatusCode, string(bodyBytes))
	}

	// Process response
	transferDAOCoinResponse := routes.TransferDAOCoinResponse{}
	err = json.NewDecoder(resp.Body).Decode(&transferDAOCoinResponse)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedTransferDAOCoin(): failed decoding body")
	}
	err = resp.Body.Close()
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedTransferDAOCoin(): failed closing body")
	}

	return &transferDAOCoinResponse, nil
}

func TransferDAOCoin(senderPubKey *btcec.PublicKey, senderPrivKey *btcec.PrivateKey, profilePubKeyBase58Check string,
	receiverPubKeyBase58Check string, daoCoinToTransferNanos uint256.Int, params *lib.DeSoParams,
	node string) error {

	// Request an unsigned transaction from the node
	unsignedMessage, err := _generateUnsignedTransferDAOCoin(senderPubKey, profilePubKeyBase58Check,
		receiverPubKeyBase58Check, daoCoinToTransferNanos, params, node)
	if err != nil {
		return errors.Wrap(err, "TrasnferDAOCoin() failed to call _generateUnsignedTrasnferDAOCoin()")
	}
	txn := unsignedMessage.Transaction

	// Sign the transaction
	signature, err := txn.Sign(senderPrivKey)
	if err != nil {
		return errors.Wrap(err, "TrasnferDAOCoin() failed to sign transaction")
	}
	txn.Signature.SetSignature(signature)

	// Submit the transaction to the node
	err = SubmitTransactionToNode(txn, node)
	if err != nil {
		return errors.Wrap(err, "TrasnferDAOCoin() failed to submit transaction")
	}
	return nil
}
