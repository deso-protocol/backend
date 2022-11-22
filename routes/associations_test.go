package routes

import (
	"bytes"
	"encoding/json"
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
	apiServer := newTestApiServer(t)

	//
	// UserAssociations
	//
	{
		// Create a UserAssociation.
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

		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		txnResponse := AssociationTxnResponse{}
		err = decoder.Decode(&txnResponse)
		require.NoError(t, err)
		transactorPkBytes, _, err := lib.Base58CheckDecode(senderPkString)
		require.Equal(t, txnResponse.Transaction.PublicKey, transactorPkBytes)
		txnMeta := txnResponse.Transaction.TxnMeta.(*lib.CreateUserAssociationMetadata)
		targetUserPkBytes, _, err := lib.Base58CheckDecode(recipientPkString)
		require.Equal(t, txnMeta.TargetUserPublicKey, lib.NewPublicKey(targetUserPkBytes))
		require.Equal(t, txnMeta.AssociationType, "ENDORSEMENT")
		require.Equal(t, txnMeta.AssociationValue, "SQL")
	}
	{
		// Query for UserAssociation by ID.
		// TODO
	}
	{
		// Query for UserAssociation by attributes.
		// TODO
	}
	{
		// Delete a UserAssociation.
		// TODO
	}

	//
	// PostAssociations
	//
	{
		// Create a PostAssociation.
		// TODO
	}
	{
		// Query for PostAssociation by ID.
		// TODO
	}
	{
		// Query for PostAssociation by attributes.
		// TODO
	}
	{
		// Delete a PostAssociation.
		// TODO
	}

	apiServer.backendServer.Stop()
}

func newTestApiServer(t *testing.T) *APIServer {
	// Set core node's config.
	coreConfig := coreCmd.LoadConfig()
	coreConfig.Params = &lib.DeSoTestnetParams
	coreConfig.Regtest = true
	coreConfig.TXIndex = false
	coreConfig.MinerPublicKeys = []string{senderPkString}
	coreConfig.NumMiningThreads = 1
	coreConfig.HyperSync = false
	coreConfig.MinFeerate = 2000

	// Create a core node.
	shutdownListener := make(chan struct{})
	node := coreCmd.NewNode(coreConfig)
	node.Start(&shutdownListener)

	// Create a badger db instance.
	badgerDB, _ := GetTestBadgerDb()

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
