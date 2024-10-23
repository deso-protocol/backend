package toolslib

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/deso-protocol/backend/routes"
	"github.com/deso-protocol/core/lib"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
)

// _generateUnsignedGiveDiamonds...
func _generateUnsignedSendDiamonds(senderPubKey *btcec.PublicKey, postHashHex string, receiverPublicKeyBase58Check string,
	diamondLevel int64, params *lib.DeSoParams, node string) (*routes.SendDiamondsResponse, error) {
	endpoint := node + routes.RoutePathSendDiamonds

	// Setup request
	payload := &routes.SendDiamondsRequest{}
	payload.SenderPublicKeyBase58Check = lib.PkToString(senderPubKey.SerializeCompressed(), params)
	payload.ReceiverPublicKeyBase58Check = receiverPublicKeyBase58Check
	payload.DiamondPostHashHex = postHashHex
	payload.DiamondLevel = diamondLevel
	payload.MinFeeRateNanosPerKB = 1000

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
		return nil, errors.Errorf("_generateUnsignedSendDiamonds(): Received non 200 response code: "+
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

	// TODO: Figure out why Decode() loses ExtraData field
	diamondPostHashBytes, err := hex.DecodeString(postHashHex)
	if err != nil {
		return nil, errors.Wrap(err, "_generateUnsignedSendDiamonds(): failed decoding post hash")
	}
	diamondPostHash := &lib.BlockHash{}
	copy(diamondPostHash[:], diamondPostHashBytes[:])

	// Append extra data to the transaction. The fees and everything was already computed correctly server side.
	diamondsExtraData := make(map[string][]byte)
	diamondsExtraData[lib.DiamondLevelKey] = lib.IntToBuf(diamondLevel)
	diamondsExtraData[lib.DiamondPostHashKey] = diamondPostHash[:]
	sendDiamondsResponse.Transaction.ExtraData = diamondsExtraData

	return &sendDiamondsResponse, nil
}

// SendDiamonds
func SendDiamonds(senderPubKey *btcec.PublicKey, senderPrivKey *btcec.PrivateKey, postHashHex string,
	receiverPublicKeyBase58Check string, diamondLevel int64, params *lib.DeSoParams, node string) error {

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
	txn.Signature.SetSignature(signature)

	// Submit the transaction to the node
	err = SubmitTransactionToNode(txn, node)
	if err != nil {
		return errors.Wrap(err, "SendDiamonds() failed to submit transaction")
	}
	return nil
}
