package toolslib

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"github.com/bitclout/backend/routes"
	"github.com/bitclout/core/lib"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
)

// SubmitTransactionToNode...
func SubmitTransactionToNode(txn *lib.MsgBitCloutTxn, node string) error {
	endpoint := node + routes.RoutePathSubmitTransaction

	// Encode the signed transaction to hex
	txnBytes, err := txn.ToBytes(false)
	if err != nil {
		return errors.Wrap(err, "SubmitTransactionToServer() failed to convert txn to bytes")
	}
	txnHex := hex.EncodeToString(txnBytes)


	// Setup request
	payload := &routes.SubmitTransactionRequest{txnHex}
	postBody, err := json.Marshal(payload)
	if err != nil {
		return errors.Wrap(err, "SubmitTransactionToServer() failed to marshal struct")
	}
	postBuffer := bytes.NewBuffer(postBody)

	// Execute request
	resp, err := http.Post(endpoint, "application/json", postBuffer)
	if err != nil {
		return errors.Wrap(err, "SubmitTransactionToServer() failed to execute request")
	}
	if resp.StatusCode != 200 {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return errors.Errorf("_generateUnsignedUpdateProfile(): Received non 200 response code: " +
			"Status Code: %v Body: %v", resp.StatusCode, string(bodyBytes))
	}
	return nil
}
