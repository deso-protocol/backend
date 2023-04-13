package routes

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/btcsuite/btcd/btcec"
	"github.com/deso-protocol/backend/config"
	coreCmd "github.com/deso-protocol/core/cmd"
	"github.com/deso-protocol/core/lib"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
		// Create sender user profile.
		// Send POST request.
		body := &UpdateProfileRequest{
			UpdaterPublicKeyBase58Check: senderPkString,
			NewUsername:                 "sender",
			NewStakeMultipleBasisPoints: 1e5,
			MinFeeRateNanosPerKB:        apiServer.MinFeeRateNanosPerKB,
		}
		bodyJSON, err := json.Marshal(body)
		require.NoError(t, err)
		request, _ := http.NewRequest("POST", RoutePathUpdateProfile, bytes.NewBuffer(bodyJSON))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		require.NotContains(t, string(response.Body.Bytes()), "error")

		// Decode response.
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		updateProfileResponse := UpdateProfileResponse{}
		err = decoder.Decode(&updateProfileResponse)
		require.NoError(t, err)
		txn := updateProfileResponse.Transaction
		require.Equal(
			t, string(txn.TxnMeta.(*lib.UpdateProfileMetadata).NewUsername), "sender",
		)

		// Sign txn.
		require.Nil(t, txn.Signature.Sign)
		signTxn(t, txn, senderPrivString)
		require.NotNil(t, txn.Signature.Sign)

		// Submit txn.
		_, err = submitTxn(t, apiServer, txn)
		require.NoError(t, err)
	}
	{
		// Create a UserAssociation.
		// Send POST request.
		extraData := map[string]string{"PeerID": "A"}
		body := &CreateUserAssociationRequest{
			TransactorPublicKeyBase58Check: senderPkString,
			TargetUserPublicKeyBase58Check: recipientPkString,
			AppPublicKeyBase58Check:        moneyPkString,
			AssociationType:                "ENDORSEMENT",
			AssociationValue:               "SQL",
			ExtraData:                      extraData,
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
		require.Equal(t, txnMeta.AssociationType, []byte("ENDORSEMENT"))
		require.Equal(t, txnMeta.AssociationValue, []byte("SQL"))
		extraDataEncoded, err := EncodeExtraDataMap(extraData)
		require.NoError(t, err)
		require.Equal(t, txn.ExtraData, extraDataEncoded)

		// Sign txn.
		require.Nil(t, txn.Signature.Sign)
		signTxn(t, txn, senderPrivString)
		require.NotNil(t, txn.Signature.Sign)

		// Submit txn.
		submitTxnResponse, err := submitTxn(t, apiServer, txn)
		require.NoError(t, err)
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
		require.Equal(t, associationResponse.ExtraData["PeerID"], "A")
		require.Equal(t, associationResponse.TransactorProfile.Username, "sender")
		require.Nil(t, associationResponse.TargetUserProfile)
		require.Nil(t, associationResponse.AppProfile)
	}
	{
		// Count UserAssociations by attributes.
		// Send POST request.
		body := &UserAssociationQuery{
			TransactorPublicKeyBase58Check: senderPkString,
			AssociationType:                "ENDORSEMENT",
		}
		bodyJSON, err := json.Marshal(body)
		require.NoError(t, err)
		request, _ := http.NewRequest("POST", RoutePathUserAssociations+"/count", bytes.NewBuffer(bodyJSON))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		require.NotContains(t, string(response.Body.Bytes()), "error")

		// Decode response.
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		countResponse := AssociationsCountResponse{}
		err = decoder.Decode(&countResponse)
		require.NoError(t, err)
		require.Equal(t, countResponse.Count, uint64(1))
	}
	{
		// Count UserAssociations for multiple AssociationValues.
		// Send POST request.
		body := &UserAssociationQuery{
			TransactorPublicKeyBase58Check: senderPkString,
			AssociationType:                "ENDORSEMENT",
			AssociationValues:              []string{"JAVASCRIPT", "SQL"},
		}
		bodyJSON, err := json.Marshal(body)
		require.NoError(t, err)
		request, _ := http.NewRequest("POST", RoutePathUserAssociations+"/counts", bytes.NewBuffer(bodyJSON))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		require.NotContains(t, string(response.Body.Bytes()), "error")

		// Decode response.
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		countsResponse := AssociationCountsResponse{}
		err = decoder.Decode(&countsResponse)
		require.NoError(t, err)
		require.Zero(t, countsResponse.Counts["JAVASCRIPT"])
		require.Equal(t, countsResponse.Counts["SQL"], uint64(1))
		require.Equal(t, countsResponse.Total, uint64(1))
	}
	{
		// Query for UserAssociations by attributes.
		// Send POST request.
		body := &UserAssociationQuery{
			TransactorPublicKeyBase58Check: senderPkString,
			AssociationType:                "ENDORSEMENT",
			Limit:                          1,
			SortDescending:                 true,
			IncludeTransactorProfile:       true,
			IncludeAppProfile:              true,
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
		require.Equal(t, queryResponse.Associations[0].ExtraData["PeerID"], "A")
		require.NotNil(t, queryResponse.Associations[0].BlockHeight)
		require.Equal(t, queryResponse.PublicKeyToProfileEntryResponse[senderPkString].Username, "sender")
		require.Nil(t, queryResponse.PublicKeyToProfileEntryResponse[recipientPkString])
		require.Nil(t, queryResponse.PublicKeyToProfileEntryResponse[moneyPkString])

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
		// Query for UserAssociations by multiple AssociationValues.
		// Send POST request.
		body := &UserAssociationQuery{
			TransactorPublicKeyBase58Check: senderPkString,
			AssociationType:                "ENDORSEMENT",
			AssociationValues:              []string{"JAVASCRIPT", "SQL"},
			IncludeTransactorProfile:       true,
			IncludeTargetUserProfile:       true,
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
		require.Equal(t, queryResponse.Associations[0].ExtraData["PeerID"], "A")
		require.NotNil(t, queryResponse.Associations[0].BlockHeight)
		require.Equal(t, queryResponse.PublicKeyToProfileEntryResponse[senderPkString].Username, "sender")
		require.Nil(t, queryResponse.PublicKeyToProfileEntryResponse[recipientPkString])
		require.Nil(t, queryResponse.PublicKeyToProfileEntryResponse[moneyPkString])
	}
	{
		// Delete a UserAssociation.
		// Send POST request.
		body := &DeleteAssociationRequest{
			TransactorPublicKeyBase58Check: senderPkString,
			AssociationID:                  associationID,
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
		_, err = submitTxn(t, apiServer, txn)
		require.NoError(t, err)

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
		submitTxnResponse, err := submitTxn(t, apiServer, txn)
		require.NoError(t, err)
		postHashHex = submitTxnResponse.TxnHashHex
	}
	{
		// Create a PostAssociation.
		// Send POST request.
		extraData := map[string]string{"PeerID": "B"}
		body := &CreatePostAssociationRequest{
			TransactorPublicKeyBase58Check: senderPkString,
			PostHashHex:                    postHashHex,
			AppPublicKeyBase58Check:        moneyPkString,
			AssociationType:                "REACTION",
			AssociationValue:               "HEART",
			ExtraData:                      extraData,
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
		require.Equal(t, txnMeta.AssociationType, []byte("REACTION"))
		require.Equal(t, txnMeta.AssociationValue, []byte("HEART"))
		extraDataEncoded, err := EncodeExtraDataMap(extraData)
		require.NoError(t, err)
		require.Equal(t, txn.ExtraData, extraDataEncoded)

		// Sign txn.
		require.Nil(t, txn.Signature.Sign)
		signTxn(t, txn, senderPrivString)
		require.NotNil(t, txn.Signature.Sign)

		// Submit txn.
		submitTxnResponse, err := submitTxn(t, apiServer, txn)
		require.NoError(t, err)
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
		require.Equal(t, associationResponse.ExtraData["PeerID"], "B")
		require.Equal(t, associationResponse.TransactorProfile.Username, "sender")
		require.Equal(t, associationResponse.PostEntry.Body, "Hello, world!")
		require.Equal(t, associationResponse.PostAuthorProfile.Username, "sender")
		require.Nil(t, associationResponse.AppProfile)
	}
	{
		// Count PostAssociations by attributes.
		// Send POST request.
		body := &PostAssociationQuery{
			PostHashHex:           postHashHex,
			AssociationTypePrefix: "REACT",
		}
		bodyJSON, err := json.Marshal(body)
		require.NoError(t, err)
		request, _ := http.NewRequest("POST", RoutePathPostAssociations+"/count", bytes.NewBuffer(bodyJSON))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		require.NotContains(t, string(response.Body.Bytes()), "error")

		// Decode response.
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		countResponse := AssociationsCountResponse{}
		err = decoder.Decode(&countResponse)
		require.NoError(t, err)
		require.Equal(t, countResponse.Count, uint64(1))
	}
	{
		// Count PostAssociations for multiple AssociationValues.
		// Send POST request.
		body := &PostAssociationQuery{
			PostHashHex:       postHashHex,
			AssociationType:   "REACTION",
			AssociationValues: []string{"HEART", "LAUGH"},
		}
		bodyJSON, err := json.Marshal(body)
		require.NoError(t, err)
		request, _ := http.NewRequest("POST", RoutePathPostAssociations+"/counts", bytes.NewBuffer(bodyJSON))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		require.NotContains(t, string(response.Body.Bytes()), "error")

		// Decode response.
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		countsResponse := AssociationCountsResponse{}
		err = decoder.Decode(&countsResponse)
		require.NoError(t, err)
		require.Equal(t, countsResponse.Counts["HEART"], uint64(1))
		require.Zero(t, countsResponse.Counts["LAUGH"])
		require.Equal(t, countsResponse.Total, uint64(1))
	}
	{
		// Query for PostAssociations by attributes.
		// Send POST request.
		body := &PostAssociationQuery{
			PostHashHex:           postHashHex,
			AssociationTypePrefix: "REACT",
			Limit:                 1,
			SortDescending:        true,
			IncludePostEntry:      true,
		}
		bodyJSON, err := json.Marshal(body)
		require.NoError(t, err)
		request, _ := http.NewRequest("POST", RoutePathPostAssociations+"/query", bytes.NewBuffer(bodyJSON))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		require.NotContains(t, string(response.Body.Bytes()), "error")

		// Decode response.
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		queryResponse := PostAssociationsResponse{}
		err = decoder.Decode(&queryResponse)
		require.NoError(t, err)
		require.Len(t, queryResponse.Associations, 1)
		require.Equal(t, queryResponse.Associations[0].TransactorPublicKeyBase58Check, senderPkString)
		require.Equal(t, queryResponse.Associations[0].PostHashHex, postHashHex)
		require.Equal(t, queryResponse.Associations[0].AssociationType, "REACTION")
		require.Equal(t, queryResponse.Associations[0].AssociationValue, "HEART")
		require.Equal(t, queryResponse.Associations[0].ExtraData["PeerID"], "B")
		require.NotNil(t, queryResponse.Associations[0].BlockHeight)
		require.Nil(t, queryResponse.PublicKeyToProfileEntryResponse[senderPkString])
		require.Equal(t, queryResponse.PostHashHexToPostEntryResponse[postHashHex].Body, "Hello, world!")
		require.Nil(t, queryResponse.PublicKeyToProfileEntryResponse[moneyPkString])

		// Submit invalid query.
		body = &PostAssociationQuery{}
		bodyJSON, err = json.Marshal(body)
		require.NoError(t, err)
		request, _ = http.NewRequest("POST", RoutePathPostAssociations+"/query", bytes.NewBuffer(bodyJSON))
		request.Header.Set("Content-Type", "application/json")
		response = httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		require.Contains(t, string(response.Body.Bytes()), "error")
		require.Contains(t, string(response.Body.Bytes()), "invalid query params")
	}
	{
		// Query for PostAssociations by multiple AssociationValues.
		// Send POST request.
		body := &PostAssociationQuery{
			PostHashHex:              postHashHex,
			AssociationType:          "REACTION",
			AssociationValues:        []string{"HEART", "LAUGH"},
			IncludePostAuthorProfile: true,
			IncludeAppProfile:        true,
		}
		bodyJSON, err := json.Marshal(body)
		require.NoError(t, err)
		request, _ := http.NewRequest("POST", RoutePathPostAssociations+"/query", bytes.NewBuffer(bodyJSON))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		require.NotContains(t, string(response.Body.Bytes()), "error")

		// Decode response.
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		queryResponse := PostAssociationsResponse{}
		err = decoder.Decode(&queryResponse)
		require.NoError(t, err)
		require.Len(t, queryResponse.Associations, 1)
		require.Equal(t, queryResponse.Associations[0].TransactorPublicKeyBase58Check, senderPkString)
		require.Equal(t, queryResponse.Associations[0].PostHashHex, postHashHex)
		require.Equal(t, queryResponse.Associations[0].AssociationType, "REACTION")
		require.Equal(t, queryResponse.Associations[0].AssociationValue, "HEART")
		require.Equal(t, queryResponse.Associations[0].ExtraData["PeerID"], "B")
		require.NotNil(t, queryResponse.Associations[0].BlockHeight)
		require.Nil(t, queryResponse.PostHashHexToPostEntryResponse[postHashHex])
		require.Equal(t, queryResponse.PublicKeyToProfileEntryResponse[senderPkString].Username, "sender")
		require.Nil(t, queryResponse.PublicKeyToProfileEntryResponse[moneyPkString])
	}
	{
		// Delete a PostAssociation.
		// Send POST request.
		body := &DeleteAssociationRequest{
			TransactorPublicKeyBase58Check: senderPkString,
			AssociationID:                  associationID,
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
		_, err = submitTxn(t, apiServer, txn)
		require.NoError(t, err)

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
	apiConfig := config.LoadConfig(coreConfig)
	apiConfig.APIPort = testJSONPort
	apiConfig.GlobalStateRemoteNode = ""
	apiConfig.GlobalStateRemoteSecret = globalStateSharedSecret
	apiConfig.RunHotFeedRoutine = false
	apiConfig.RunSupplyMonitoringRoutine = false

	// Create an api server.
	apiServer, err := NewAPIServer(
		node.Server,
		node.Server.GetMempool(),
		node.Server.GetBlockchain(),
		node.Server.GetBlockProducer(),
		node.TXIndex,
		node.Params,
		apiConfig,
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

func submitTxn(t *testing.T, apiServer *APIServer, txn *lib.MsgDeSoTxn) (*SubmitTransactionResponse, error) {
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
	if strings.Contains(string(response.Body.Bytes()), "{\"error\":") {
		return nil, errors.New(string(response.Body.Bytes()))
	}

	// Decode response.
	decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
	txnResponse := SubmitTransactionResponse{}
	err = decoder.Decode(&txnResponse)
	require.NoError(t, err)
	return &txnResponse, nil
}
