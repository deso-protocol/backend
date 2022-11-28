package routes

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"github.com/btcsuite/btcd/btcec"
	"github.com/deso-protocol/backend/config"
	coreCmd "github.com/deso-protocol/core/cmd"
	"github.com/deso-protocol/core/lib"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAssociations(t *testing.T) {
	var associationID string
	apiServer := newTestApiServer(t)
	defer apiServer.backendServer.Stop()
	defer apiServer.Stop()

	//
	// UserAssociations
	//
	{
		// Create a UserAssociation.
		// Send POST request.
		body := &CreateUserAssociationRequest{
			TransactorPublicKeyBase58Check: senderPkString,
			TargetUserPublicKeyBase58Check: recipientPkString,
			AssociationType:                "ENDORSEMENT",
			AssociationValue:               "SQL",
			MinFeeRateNanosPerKB:           apiServer.MinFeeRateNanosPerKB,
			TransactionFees:                []TransactionFee{},
		}
		bodyJSON, err := json.Marshal(body)
		require.NoError(t, err)
		request, _ := http.NewRequest("POST", RoutePathUserAssociations+"/create", bytes.NewBuffer(bodyJSON))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		require.NotContains(t, string(response.Body.Bytes()), "error")

		// Decode response.
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		txnResponse := AssociationTxnResponse{}
		err = decoder.Decode(&txnResponse)
		require.NoError(t, err)
		txn := txnResponse.Transaction
		transactorPkBytes, _, err := lib.Base58CheckDecode(senderPkString)
		require.Equal(t, txn.PublicKey, transactorPkBytes)
		txnMeta := txn.TxnMeta.(*lib.CreateUserAssociationMetadata)
		targetUserPkBytes, _, err := lib.Base58CheckDecode(recipientPkString)
		require.Equal(t, txnMeta.TargetUserPublicKey, lib.NewPublicKey(targetUserPkBytes))
		require.Equal(t, txnMeta.AssociationType, "ENDORSEMENT")
		require.Equal(t, txnMeta.AssociationValue, "SQL")

		// Sign txn.
		require.Nil(t, txn.Signature.Sign)
		signTxn(t, txn, senderPrivString)
		require.NotNil(t, txn.Signature.Sign)

		// Submit txn.
		submitTxnResponse := submitTxn(t, apiServer, txn)
		associationID = submitTxnResponse.TxnHashHex
	}
	{
		// Query for UserAssociation by ID.
		// Send GET request.
		request, _ := http.NewRequest("GET", RoutePathUserAssociations+"/"+associationID, nil)
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		require.NotContains(t, string(response.Body.Bytes()), "error")

		// Decode response.
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		associationResponse := UserAssociationResponse{}
		err := decoder.Decode(&associationResponse)
		require.NoError(t, err)
		require.Equal(t, associationResponse.AssociationID, associationID)
		require.Equal(t, associationResponse.AssociationType, "ENDORSEMENT")
		require.Equal(t, associationResponse.AssociationValue, "SQL")
	}
	{
		// Query for UserAssociations by attributes.
		// Send POST request.
		body := &UserAssociationQuery{
			TransactorPublicKeyBase58Check: senderPkString,
			AssociationType:                "ENDORSEMENT",
		}
		bodyJSON, err := json.Marshal(body)
		require.NoError(t, err)
		request, _ := http.NewRequest("POST", RoutePathUserAssociations+"/query", bytes.NewBuffer(bodyJSON))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		require.NotContains(t, string(response.Body.Bytes()), "error")

		// Decode response.
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		queryResponse := UserAssociationsResponse{}
		err = decoder.Decode(&queryResponse)
		require.NoError(t, err)
		require.Len(t, queryResponse.Associations, 1)
		require.Equal(t, queryResponse.Associations[0].TransactorPublicKeyBase58Check, senderPkString)
		require.Equal(t, queryResponse.Associations[0].TargetUserPublicKeyBase58Check, recipientPkString)
		require.Equal(t, queryResponse.Associations[0].AssociationType, "ENDORSEMENT")
		require.Equal(t, queryResponse.Associations[0].AssociationValue, "SQL")
		require.NotNil(t, queryResponse.Associations[0].BlockHeight)

		// Submit invalid query.
		body = &UserAssociationQuery{}
		bodyJSON, err = json.Marshal(body)
		require.NoError(t, err)
		request, _ = http.NewRequest("POST", RoutePathUserAssociations+"/query", bytes.NewBuffer(bodyJSON))
		request.Header.Set("Content-Type", "application/json")
		response = httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		require.Contains(t, string(response.Body.Bytes()), "error")
		require.Contains(t, string(response.Body.Bytes()), "invalid query params")
	}
	{
		// Delete a UserAssociation.
		// Send POST request.
		body := &DeleteAssociationRequest{
			AssociationID:                  associationID,
			TransactorPublicKeyBase58Check: senderPkString,
			MinFeeRateNanosPerKB:           apiServer.MinFeeRateNanosPerKB,
			TransactionFees:                []TransactionFee{},
		}
		bodyJSON, err := json.Marshal(body)
		require.NoError(t, err)
		request, _ := http.NewRequest("POST", RoutePathUserAssociations+"/delete", bytes.NewBuffer(bodyJSON))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		require.NotContains(t, string(response.Body.Bytes()), "error")

		// Decode response.
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		txnResponse := AssociationTxnResponse{}
		err = decoder.Decode(&txnResponse)
		require.NoError(t, err)
		txn := txnResponse.Transaction
		transactorPkBytes, _, err := lib.Base58CheckDecode(senderPkString)
		require.Equal(t, txn.PublicKey, transactorPkBytes)
		txnMeta := txn.TxnMeta.(*lib.DeleteUserAssociationMetadata)
		require.NotNil(t, txnMeta.AssociationID)

		// Sign txn.
		require.Nil(t, txn.Signature.Sign)
		signTxn(t, txn, senderPrivString)
		require.NotNil(t, txn.Signature.Sign)

		// Submit txn.
		submitTxn(t, apiServer, txn)

		// Try to GET deleted association by ID. Errors.
		getRequest, _ := http.NewRequest("GET", RoutePathUserAssociations+"/"+associationID, nil)
		getResponse := httptest.NewRecorder()
		apiServer.router.ServeHTTP(getResponse, getRequest)
		require.Contains(t, string(getResponse.Body.Bytes()), "association not found")
	}

	//
	// PostAssociations
	//
	var postHashHex string
	{
		// Create a Post.
		// Send POST request.
		body := &SubmitPostRequest{
			UpdaterPublicKeyBase58Check: senderPkString,
			BodyObj: &lib.DeSoBodySchema{
				Body: "Hello, world!",
			},
			MinFeeRateNanosPerKB: apiServer.MinFeeRateNanosPerKB,
		}
		bodyJSON, err := json.Marshal(body)
		require.NoError(t, err)
		request, _ := http.NewRequest("POST", RoutePathSubmitPost, bytes.NewBuffer(bodyJSON))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		require.NotContains(t, string(response.Body.Bytes()), "error")

		// Decode response.
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		submitPostResponse := SubmitPostResponse{}
		err = decoder.Decode(&submitPostResponse)
		require.NoError(t, err)
		txn := submitPostResponse.Transaction
		transactorPkBytes, _, err := lib.Base58CheckDecode(senderPkString)
		require.Equal(t, txn.PublicKey, transactorPkBytes)
		txnMeta := txn.TxnMeta.(*lib.SubmitPostMetadata)
		require.NotNil(t, txnMeta.Body)

		// Sign txn.
		require.Nil(t, txn.Signature.Sign)
		signTxn(t, txn, senderPrivString)
		require.NotNil(t, txn.Signature.Sign)

		// Submit txn.
		submitTxnResponse := submitTxn(t, apiServer, txn)
		postHashHex = submitTxnResponse.TxnHashHex
	}
	{
		// Create a PostAssociation.
		// Send POST request.
		body := &CreatePostAssociationRequest{
			TransactorPublicKeyBase58Check: senderPkString,
			PostHashHex:                    postHashHex,
			AssociationType:                "REACTION",
			AssociationValue:               "HEART",
			MinFeeRateNanosPerKB:           apiServer.MinFeeRateNanosPerKB,
			TransactionFees:                []TransactionFee{},
		}
		bodyJSON, err := json.Marshal(body)
		require.NoError(t, err)
		request, _ := http.NewRequest("POST", RoutePathPostAssociations+"/create", bytes.NewBuffer(bodyJSON))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		require.NotContains(t, string(response.Body.Bytes()), "error")

		// Decode response.
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		txnResponse := AssociationTxnResponse{}
		err = decoder.Decode(&txnResponse)
		require.NoError(t, err)
		txn := txnResponse.Transaction
		transactorPkBytes, _, err := lib.Base58CheckDecode(senderPkString)
		require.Equal(t, txn.PublicKey, transactorPkBytes)
		txnMeta := txn.TxnMeta.(*lib.CreatePostAssociationMetadata)
		require.Equal(t, txnMeta.AssociationType, "REACTION")
		require.Equal(t, txnMeta.AssociationValue, "HEART")

		// Sign txn.
		require.Nil(t, txn.Signature.Sign)
		signTxn(t, txn, senderPrivString)
		require.NotNil(t, txn.Signature.Sign)

		// Submit txn.
		submitTxnResponse := submitTxn(t, apiServer, txn)
		associationID = submitTxnResponse.TxnHashHex
	}
	{
		// Query for PostAssociation by ID.
		// Send GET request.
		request, _ := http.NewRequest("GET", RoutePathPostAssociations+"/"+associationID, nil)
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		require.NotContains(t, string(response.Body.Bytes()), "error")

		// Decode response.
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		associationResponse := PostAssociationResponse{}
		err := decoder.Decode(&associationResponse)
		require.NoError(t, err)
		require.Equal(t, associationResponse.AssociationID, associationID)
		require.Equal(t, associationResponse.PostHashHex, postHashHex)
		require.Equal(t, associationResponse.AssociationType, "REACTION")
		require.Equal(t, associationResponse.AssociationValue, "HEART")
	}
	{
		// Query for PostAssociations by attributes.
		// TODO
	}
	{
		// Delete a PostAssociation.
		// Send POST request.
		body := &DeleteAssociationRequest{
			AssociationID:                  associationID,
			TransactorPublicKeyBase58Check: senderPkString,
			MinFeeRateNanosPerKB:           apiServer.MinFeeRateNanosPerKB,
			TransactionFees:                []TransactionFee{},
		}
		bodyJSON, err := json.Marshal(body)
		require.NoError(t, err)
		request, _ := http.NewRequest("POST", RoutePathPostAssociations+"/delete", bytes.NewBuffer(bodyJSON))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		require.NotContains(t, string(response.Body.Bytes()), "error")

		// Decode response.
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		txnResponse := AssociationTxnResponse{}
		err = decoder.Decode(&txnResponse)
		require.NoError(t, err)
		txn := txnResponse.Transaction
		transactorPkBytes, _, err := lib.Base58CheckDecode(senderPkString)
		require.Equal(t, txn.PublicKey, transactorPkBytes)
		txnMeta := txn.TxnMeta.(*lib.DeletePostAssociationMetadata)
		require.NotNil(t, txnMeta.AssociationID)

		// Sign txn.
		require.Nil(t, txn.Signature.Sign)
		signTxn(t, txn, senderPrivString)
		require.NotNil(t, txn.Signature.Sign)

		// Submit txn.
		submitTxn(t, apiServer, txn)

		// Try to GET deleted association by ID. Errors.
		getRequest, _ := http.NewRequest("GET", RoutePathPostAssociations+"/"+associationID, nil)
		getResponse := httptest.NewRecorder()
		apiServer.router.ServeHTTP(getResponse, getRequest)
		require.Contains(t, string(getResponse.Body.Bytes()), "association not found")
	}
}

func newTestApiServer(t *testing.T) *APIServer {
	// Create a badger db instance.
	badgerDB, badgerDir := GetTestBadgerDb()

	// Set core node's config.
	coreConfig := coreCmd.LoadConfig()
	coreConfig.Params = &lib.DeSoTestnetParams
	coreConfig.DataDirectory = badgerDir
	coreConfig.MempoolDumpDirectory = badgerDir
	coreConfig.Regtest = true
	coreConfig.TXIndex = false
	coreConfig.MinerPublicKeys = []string{senderPkString}
	coreConfig.NumMiningThreads = 1
	coreConfig.HyperSync = false
	coreConfig.MinFeerate = 2000
	coreConfig.LogDirectory = badgerDir

	// Create a core node.
	shutdownListener := make(chan struct{})
	node := coreCmd.NewNode(coreConfig)
	node.Start(&shutdownListener)

	// Set api server's config.
	config := config.LoadConfig(coreConfig)
	config.APIPort = testJSONPort
	config.GlobalStateRemoteNode = ""
	config.GlobalStateRemoteSecret = globalStateSharedSecret
	config.RunHotFeedRoutine = false
	config.RunSupplyMonitoringRoutine = false

	// Create an api server.
	apiServer, err := NewAPIServer(
		node.Server,
		node.Server.GetMempool(),
		node.Server.GetBlockchain(),
		node.Server.GetBlockProducer(),
		node.TXIndex,
		node.Params,
		config,
		node.Config.MinFeerate,
		badgerDB,
		nil,
		node.Config.BlockCypherAPIKey,
	)
	require.NoError(t, err)

	// Initialize api server.
	apiServer.MinFeeRateNanosPerKB = node.Config.MinFeerate
	apiServer.initState()
	return apiServer
}

func signTxn(t *testing.T, txn *lib.MsgDeSoTxn, privKeyBase58Check string) {
	privKeyBytes, _, err := lib.Base58CheckDecode(privKeyBase58Check)
	require.NoError(t, err)
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privKeyBytes)
	txnSignature, err := txn.Sign(privKey)
	require.NoError(t, err)
	txn.Signature.SetSignature(txnSignature)
}

func submitTxn(t *testing.T, apiServer *APIServer, txn *lib.MsgDeSoTxn) *SubmitTransactionResponse {
	// Convert txn to txn hex.
	txnBytes, err := txn.ToBytes(false)
	require.NoError(t, err)
	txnHex := hex.EncodeToString(txnBytes)

	// Submit txn.
	body := SubmitTransactionRequest{
		TransactionHex: txnHex,
	}
	bodyJSON, err := json.Marshal(body)
	require.NoError(t, err)
	request, _ := http.NewRequest("POST", RoutePathSubmitTransaction, bytes.NewBuffer(bodyJSON))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	apiServer.router.ServeHTTP(response, request)
	require.NotContains(t, string(response.Body.Bytes()), "error")

	// Decode response.
	decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
	txnResponse := SubmitTransactionResponse{}
	err = decoder.Decode(&txnResponse)
	require.NoError(t, err)
	return &txnResponse
}
