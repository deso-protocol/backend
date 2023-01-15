package routes

import (
	"bytes"
	"encoding/hex"
	"encoding/json"

	"github.com/btcsuite/btcd/btcec"

	"github.com/deso-protocol/core/lib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"net/http"
	"net/http/httptest"
	"testing"
)

func fetchAccessGroupID(t *testing.T, apiServer *APIServer, publicKeyBase58Check string) *GetAccessGroupIDsResponse {
	assert := assert.New(t)
	// form the request for RoutePathGetAllUserAccessGroups
	values := GetAccessGroupIDsRequest{PublicKeyBase58Check: senderPkString}
	requestbody, err := json.Marshal(values)

	require.NoError(t, err)

	// Send the post request to fetch access groups of the user.
	request, err := http.NewRequest("POST", RoutePathGetAllUserAccessGroups, bytes.NewBuffer(requestbody))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	apiServer.router.ServeHTTP(response, request)
	// assert the response status.
	assert.Equal(200, response.Code, "OK response is expected")

	// Deserialize the response.
	unmarshalResponse := &GetAccessGroupIDsResponse{}
	err = json.Unmarshal(response.Body.Bytes(), unmarshalResponse)
	if err != nil {
		t.Fatal("Unable to Base58 Check decode the result")
	}

	return unmarshalResponse
}

// This access group key name is reserved since every user by default belongs to them.
func TestAPIAccessGroupBaseGroupMemberShip(t *testing.T) {
	assert := assert.New(t)

	apiServer, _, _ := newTestAPIServer(t, "" /*globalStateRemoteNode*/)

	// form the request for RoutePathGetAllUserAccessGroups
	values := GetAccessGroupIDsRequest{PublicKeyBase58Check: senderPkString}
	requestbody, err := json.Marshal(values)

	require.NoError(t, err)
	// Expense response for the call to fetch Access group ID.
	expectedResponse := GetAccessGroupIDsResponse{
		AccessGroupIds: &AccessGroupIds{
			AccessGroupIdsOwned: []*AccessGroupIdEncoded{
				// The user should be the owner of the default base group().
				{
					UserPublicKeyBase58Check: senderPkString,
					AccessGroupKeyNameHex:    hex.EncodeToString(lib.BaseGroupKeyName().ToBytes()),
				},
			},
		},
	}

	// Send the post request to fetch access groups of the user.
	request, err := http.NewRequest("POST", RoutePathGetAllUserAccessGroups, bytes.NewBuffer(requestbody))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	apiServer.router.ServeHTTP(response, request)
	// assert the response status.
	assert.Equal(200, response.Code, "OK response is expected")

	// Deserialize the response.
	unmarshalResponse := &GetAccessGroupIDsResponse{}
	err = json.Unmarshal(response.Body.Bytes(), unmarshalResponse)
	if err != nil {
		t.Fatal("Unable to Base58 Check decode the result")
	}
	// Compare the expected
	assert.Equal(&expectedResponse, unmarshalResponse)
}

func signTransaction(t *testing.T, txn *lib.MsgDeSoTxn) {
	privKeyBytes, _, err := lib.Base58CheckDecode(senderPrivString)
	require.NoError(t, err)
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privKeyBytes)
	txnSignature, err := txn.Sign(privKey)
	require.NoError(t, err)
	txn.Signature.SetSignature(txnSignature)
}

func SignAndSubmitTransaction(t *testing.T, privateKeyBase58Check string, txn *lib.MsgDeSoTxn, apiServer *APIServer) *SubmitTransactionResponse {
	t.Helper()
	assert := assert.New(t)
	signTransaction(t, txn)
	txnBytes, err := txn.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	hexTxnBytes := hex.EncodeToString(txnBytes)

	// Compare the expected
	//assert.Equal(&expectedResponse, unmarshalResponse)
	submitReq := &SubmitTransactionRequest{
		TransactionHex: hexTxnBytes,
	}
	requestbody, err := json.Marshal(submitReq)

	if err != nil {
		t.Fatal(err)
	}

	request, _ := http.NewRequest("POST", RoutePathSubmitTransaction, bytes.NewBuffer(requestbody))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	apiServer.router.ServeHTTP(response, request)
	// assert the response status.
	assert.Equal(200, response.Code, "OK response is expected")

	// Deserialize the response.
	unmarshalResponse := &SubmitTransactionResponse{}
	err = json.Unmarshal(response.Body.Bytes(), unmarshalResponse)
	require.NoError(t, err)
	return unmarshalResponse
}

// Tests the creation of new access group.
func TestAPICreateAccessGroup(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	groupPriv1, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(err)
	groupPk1 := groupPriv1.PubKey().SerializeCompressed()

	groupName1 := []byte("group1")
	// form the request for RoutePathGetAllUserAccessGroups
	values := CreateAccessGroupRequest{
		AccessGroupOwnerPublicKeyBase58Check: senderPkString,
		AccessGroupPublicKeyBase58Check:      Base58CheckEncodePublickey(groupPk1),
		AccessGroupKeyNameHexEncoded:         hex.EncodeToString(groupName1),
		MinFeeRateNanosPerKB:                 10,
		TransactionFees:                      nil,
	}

	apiServer, _, _ := newTestAPIServer(t, "" /*globalStateRemoteNode*/)
	requestbody, err := json.Marshal(values)

	if err != nil {
		t.Fatal(err)
	}

	// Send the post request to fetch access groups of the user.
	request, _ := http.NewRequest("POST", RoutePathCreateAccessGroup, bytes.NewBuffer(requestbody))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	apiServer.router.ServeHTTP(response, request)
	// assert the response status.
	assert.Equal(200, response.Code, "OK response is expected")

	// Deserialize the response.
	unmarshalResponse := &CreateAccessGroupResponse{}
	err = json.Unmarshal(response.Body.Bytes(), unmarshalResponse)
	if err != nil {
		t.Fatal("Unable to Base58 Check decode the result")
	}

	txn := unmarshalResponse.Transaction
	signTransaction(t, txn)
	t.Logf("sign: %v\n ", txn.Signature.Sign)
	txnBytes, err := txn.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	hexTxnBytes := hex.EncodeToString(txnBytes)

	// Compare the expected
	//assert.Equal(&expectedResponse, unmarshalResponse)
	submitReq := &SubmitTransactionRequest{
		TransactionHex: hexTxnBytes,
	}
	requestbody, err = json.Marshal(submitReq)

	if err != nil {
		t.Fatal(err)
	}

	request, _ = http.NewRequest("POST", RoutePathSubmitTransaction, bytes.NewBuffer(requestbody))
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	apiServer.router.ServeHTTP(response, request)
	// assert the response status.
	assert.Equal(200, response.Code, "OK response is expected")

	// Deserialize the response.
	unmarshalResponses := &SubmitTransactionResponse{}
	err = json.Unmarshal(response.Body.Bytes(), unmarshalResponses)
	if err != nil {
		t.Fatal("Unable to Base58 Check decode the result")
	}
	t.Logf("%v", unmarshalResponse)

	// If we are here then we've successfully created a new access group
	// for public key senderPkString, and access group key name "groupName1"
	// Fetch all the access groups for sender Pk String
	actualGroupIDsres := fetchAccessGroupID(t, apiServer, senderPkString)
	// Expected response for the call to fetch Access group ID.
	expectedResponse := GetAccessGroupIDsResponse{
		AccessGroupIds: &AccessGroupIds{
			AccessGroupIdsOwned: []*AccessGroupIdEncoded{
				// The user should be the owner of the default base group().
				{
					UserPublicKeyBase58Check: senderPkString,
					AccessGroupKeyNameHex:    hex.EncodeToString(lib.BaseGroupKeyName().ToBytes()),
				},
				{
					UserPublicKeyBase58Check: senderPkString,
					AccessGroupKeyNameHex:    hex.EncodeToString(lib.NewGroupKeyName(groupName1).ToBytes()),
				},
			},
		},
	}
	assert.Equal(&expectedResponse, actualGroupIDsres)
}
