package routes

import (
	"bytes"
	"encoding/hex"
	"encoding/json"

	"github.com/deso-protocol/core/lib"
	"github.com/stretchr/testify/assert"

	"net/http"
	"net/http/httptest"
	"testing"
)

// Test to validate the default access group membership to BaseGroup()
// Every User by default belong to Access group with access group key name lib.BaseGroup().
// This access group key name is reserved since every user by default belongs to them.
func TestAPIAccessGroupBaseGroupMemberShip(t *testing.T) {
	assert := assert.New(t)

	// form the request for RoutePathGetAllUserAccessGroups
	values := GetAccessGroupIDsRequest{PublicKeyBase58Check: senderPkString}
	apiServer, _, _ := newTestAPIServer(t, "" /*globalStateRemoteNode*/)
	requestbody, err := json.Marshal(values)

	if err != nil {
		t.Fatal(err)
	}

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
	request, _ := http.NewRequest("POST", RoutePathGetAllUserAccessGroups, bytes.NewBuffer(requestbody))
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
