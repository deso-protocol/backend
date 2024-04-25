package routes

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/lib"
	"github.com/stretchr/testify/require"
)

func TestValidatorRegistration(t *testing.T) {
	apiServer := newTestApiServer(t)

	// Convert senderPkString to senderPkBytes.
	senderPkBytes, _, err := lib.Base58CheckDecode(senderPkString)
	require.NoError(t, err)

	// sender creates a VotingPublicKey and VotingAuthorization.
	votingPublicKey, votingAuthorization := _generateVotingPublicKeyAndAuthorization(t, senderPkBytes)

	{
		// sender registers as a validator.

		// Send POST request.
		body := &RegisterAsValidatorRequest{
			TransactorPublicKeyBase58Check: senderPkString,
			Domains:                        []string{"sender-001.deso.com:18000", "sender-002.deso.com:18000"},
			DisableDelegatedStake:          false,
			VotingPublicKey:                votingPublicKey.ToString(),
			VotingAuthorization:            votingAuthorization.ToString(),
			ExtraData:                      map[string]string{"Foo": "Bar"},
			MinFeeRateNanosPerKB:           apiServer.MinFeeRateNanosPerKB,
			TransactionFees:                []TransactionFee{},
		}
		bodyJSON, err := json.Marshal(body)
		require.NoError(t, err)
		request, _ := http.NewRequest("POST", RoutePathValidators+"/register", bytes.NewBuffer(bodyJSON))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		require.NotContains(t, string(response.Body.Bytes()), "error")

		// Decode response.
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		txnResponse := ValidatorTxnResponse{}
		err = decoder.Decode(&txnResponse)
		require.NoError(t, err)

		// Verify response fields.
		txn := txnResponse.Transaction
		require.Equal(t, txn.PublicKey, senderPkBytes)
		txnMeta := txn.TxnMeta.(*lib.RegisterAsValidatorMetadata)
		require.Len(t, txnMeta.Domains, 2)
		require.Equal(t, txnMeta.Domains[0], []byte("sender-001.deso.com:18000"))
		require.Equal(t, txnMeta.Domains[1], []byte("sender-002.deso.com:18000"))
		require.False(t, txnMeta.DisableDelegatedStake)
		require.True(t, txnMeta.VotingPublicKey.Eq(votingPublicKey))
		require.True(t, txnMeta.VotingAuthorization.Eq(votingAuthorization))
		require.NotNil(t, txn.ExtraData)
		require.Equal(t, txn.ExtraData["Foo"], []byte("Bar"))

		// Sign txn.
		require.Nil(t, txn.Signature.Sign)
		signTxn(t, txn, senderPrivString)
		require.NotNil(t, txn.Signature.Sign)

		// Submit txn.
		_, err = submitTxn(t, apiServer, txn)
		require.NoError(t, err)
	}
	{
		// get sender validator by PublicKeyBase58Check

		// Send GET request.
		request, _ := http.NewRequest("GET", RoutePathValidators+"/"+senderPkString, nil)
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		require.NotContains(t, string(response.Body.Bytes()), "error")

		// Decode response.
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		validatorResponse := ValidatorResponse{}
		err := decoder.Decode(&validatorResponse)
		require.NoError(t, err)

		// Verify response fields.
		require.Equal(t, validatorResponse.ValidatorPublicKeyBase58Check, senderPkString)
		require.Len(t, validatorResponse.Domains, 2)
		require.Equal(t, validatorResponse.Domains[0], "sender-001.deso.com:18000")
		require.Equal(t, validatorResponse.Domains[1], "sender-002.deso.com:18000")
		require.False(t, validatorResponse.DisableDelegatedStake)
		require.Equal(t, validatorResponse.VotingPublicKey, votingPublicKey.ToString())
		require.Equal(t, validatorResponse.VotingAuthorization, votingAuthorization.ToString())
		require.Equal(t, validatorResponse.TotalStakeAmountNanos.Uint64(), uint64(0))
		require.Equal(t, validatorResponse.Status, "Active")
		require.Equal(t, validatorResponse.JailedAtEpochNumber, uint64(0))
		require.NotNil(t, validatorResponse.ExtraData)
		require.Equal(t, validatorResponse.ExtraData["Foo"], "Bar")
	}
	{
		// sender unregisters as a validator.

		// Send POST request.
		body := &UnregisterAsValidatorRequest{
			TransactorPublicKeyBase58Check: senderPkString,
			ExtraData:                      map[string]string{},
			MinFeeRateNanosPerKB:           apiServer.MinFeeRateNanosPerKB,
			TransactionFees:                []TransactionFee{},
		}
		bodyJSON, err := json.Marshal(body)
		require.NoError(t, err)
		request, _ := http.NewRequest("POST", RoutePathValidators+"/unregister", bytes.NewBuffer(bodyJSON))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		require.NotContains(t, string(response.Body.Bytes()), "error")

		// Decode response.
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		txnResponse := ValidatorTxnResponse{}
		err = decoder.Decode(&txnResponse)
		require.NoError(t, err)

		// Verify response fields.
		txn := txnResponse.Transaction
		require.Equal(t, txn.PublicKey, senderPkBytes)

		// Sign txn.
		require.Nil(t, txn.Signature.Sign)
		signTxn(t, txn, senderPrivString)
		require.NotNil(t, txn.Signature.Sign)

		// Submit txn.
		_, err = submitTxn(t, apiServer, txn)
		require.NoError(t, err)
	}
	{
		// get sender validator by PublicKeyBase58Check

		// Send GET request.
		request, _ := http.NewRequest("GET", RoutePathValidators+"/"+senderPkString, nil)
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		responseBody := string(response.Body.Bytes())

		// errors: doesn't exist
		require.Contains(t, responseBody, "error")
		require.Contains(t, responseBody, "validator not found")
	}
}

func _generateVotingPublicKeyAndAuthorization(t *testing.T, transactorPkBytes []byte) (*bls.PublicKey, *bls.Signature) {
	blsPrivateKey, err := bls.NewPrivateKey()
	require.NoError(t, err)
	votingPublicKey := blsPrivateKey.PublicKey()
	votingAuthorizationPayload := lib.CreateValidatorVotingAuthorizationPayload(transactorPkBytes)
	votingAuthorization, err := blsPrivateKey.Sign(votingAuthorizationPayload)
	require.NoError(t, err)
	return votingPublicKey, votingAuthorization
}
