package routes

import (
	"bytes"
	"encoding/hex"
	"encoding/json"

	"github.com/deso-protocol/core/lib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBase58Check(t *testing.T) {
	accessGroupOwnedPkBytes, _, err := lib.Base58CheckDecode(senderPkString)
	if err != nil {
		t.Fatal("Unable to Base58 Check decode the result")
	}
	t.Log("----------")
	t.Log(lib.Base58CheckEncodeWithPrefix(accessGroupOwnedPkBytes, [3]byte{0x11, 0xc2, 0x0}))
	t.Log(senderPkString)
}

func TestAPIAccessGroups(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	values := GetAccessGroupIDsRequest{PublicKeyBase58Check: senderPkString}
	apiServer, _, _ := newTestAPIServer(t, "" /*globalStateRemoteNode*/)
	json_data, err := json.Marshal(values)

	if err != nil {
		t.Fatal(err)
	}
	accessGroupOwnedPkBytes, _, err := lib.Base58CheckDecode(senderPkString)
	if err != nil {
		t.Fatal("Unable to Base58 Check decode the result")
	}
	t.Log("In backend----------\n")
	t.Logf("%v", accessGroupOwnedPkBytes)
	t.Logf("%v", Base58EncodePublickey(lib.NewPublicKey(accessGroupOwnedPkBytes).ToBytes()))

	expectedResponse := GetAccessGroupIDsResponse{
		AccessGroupIds: &AccessGroupIds{
			AccessGroupIdsOwned: []*AccessGroupIdEncoded{
				{
					UserPublicKeyBase58Check: senderPkString,
					AccessGroupKeyNameHex:    hex.EncodeToString(lib.BaseGroupKeyName().ToBytes()),
				},
			},
		},
	}

	request, _ := http.NewRequest("POST", RoutePathGetAllUserAccessGroups, bytes.NewBuffer(json_data))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	apiServer.router.ServeHTTP(response, request)
	assert.Equal(200, response.Code, "OK response is expected")

	unmarshalres := &GetAccessGroupIDsResponse{}
	err = json.Unmarshal(response.Body.Bytes(), unmarshalres)
	if err != nil {
		t.Fatal("Unable to Base58 Check decode the result")
	}
	t.Log("response.........")
	t.Logf("%v", unmarshalres.AccessGroupIds.AccessGroupIdsOwned[0].UserPublicKeyBase58Check)
	t.Logf("%v", Base58EncodePublickey(lib.NewPublicKey(accessGroupOwnedPkBytes).ToBytes()))
	assert.Equal(&expectedResponse, unmarshalres)

}
