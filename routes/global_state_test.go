package routes

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGlobalStateServicePutGetDeleteWithDB(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	apiServer, _, _ := newTestAPIServer(
		t, "" /*globalStateRemoteNode*/)

	// Getting when no value is present should return nil without an
	// error.
	val, err := apiServer.GlobalStateGet([]byte("woo"))
	require.NoError(err)
	require.Nil(val)

	// Putting then getting a value should work.
	require.NoError(apiServer.GlobalStatePut([]byte("woo"), []byte("hoo")))
	val, err = apiServer.GlobalStateGet([]byte("woo"))
	require.NoError(err)
	require.Equal(val, []byte("hoo"))

	// Doing a batch get should work.
	require.NoError(apiServer.GlobalStatePut([]byte("fan"), []byte("tastic")))
	valueList, err := apiServer.GlobalStateBatchGet([][]byte{
		[]byte("woo"),
		[]byte("great"),
		[]byte("fan"),
	})
	require.NoError(err)
	expectedValues := [][]byte{
		[]byte("hoo"),
		[]byte{},
		[]byte("tastic"),
	}
	for ii, vv := range valueList {
		require.Equal(vv, expectedValues[ii])
	}

	// Deleting a value should make it no longer gettable.
	require.NoError(apiServer.GlobalStateDelete([]byte("woo")))
	val, err = apiServer.GlobalStateGet([]byte("woo"))
	require.NoError(err)
	require.Nil(val)
}

func TestGlobalStateServicePutGetDeleteWithRemoteNode(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	apiServer, _, _ := newTestAPIServer(
		t, "" /*globalStateRemoteNode*/)

	// Getting when no value is present should return nil without an
	// error.
	{
		url, json_data, err := apiServer.CreateGlobalStateGetRequest([]byte("woo"))
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", url, bytes.NewBuffer(json_data))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		res := GlobalStateGetRemoteResponse{}
		if err := decoder.Decode(&res); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Nil(res.Value)
	}

	// Putting then getting a value should work.
	{
		url, json_data, err := apiServer.CreateGlobalStatePutRequest([]byte("woo"), []byte("hoo"))
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", url, bytes.NewBuffer(json_data))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		res := GlobalStatePutRemoteResponse{}
		if err := decoder.Decode(&res); err != nil {
			require.NoError(err, "Problem decoding response")
		}
	}
	{
		url, json_data, err := apiServer.CreateGlobalStateGetRequest([]byte("woo"))
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", url,
			bytes.NewBuffer(json_data))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		res := GlobalStateGetRemoteResponse{}
		if err := decoder.Decode(&res); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Equal(res.Value, []byte("hoo"))
	}

	// Batch get should work.
	{
		url, json_data, err := apiServer.CreateGlobalStateBatchGetRequest(
			[][]byte{[]byte("woo"), []byte("fantastic"), []byte("great")},
		)
		require.NoError(err)
		request, _ := http.NewRequest("POST", url, bytes.NewBuffer(json_data))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		res := GlobalStateBatchGetRemoteResponse{}
		if err := decoder.Decode(&res); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		expectedValues := [][]byte{
			[]byte("hoo"),
			[]byte{},
			[]byte{},
		}
		for ii, vv := range res.ValueList {
			require.Equal(vv, expectedValues[ii])
		}
	}

	// Deleting a value should make it no longer gettable.
	{
		url, json_data, err := apiServer.CreateGlobalStateDeleteRequest([]byte("woo"))
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", url,
			bytes.NewBuffer(json_data))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		res := GlobalStateDeleteRemoteResponse{}
		if err := decoder.Decode(&res); err != nil {
			require.NoError(err, "Problem decoding response")
		}
	}
	{
		url, json_data, err := apiServer.CreateGlobalStateGetRequest([]byte("woo"))
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", url,
			bytes.NewBuffer(json_data))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		res := GlobalStateGetRemoteResponse{}
		if err := decoder.Decode(&res); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		require.Nil(res.Value)
	}
}

func TestGlobalStateServiceURLCreation(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	apiServer, _, _ := newTestAPIServer(
		t, "https://bitclout.com:17001" /*globalStateRemoteNode*/)

	{
		url, _, err := apiServer.CreateGlobalStateGetRequest([]byte("woo"))
		require.NoError(err)
		assert.Equal("https://bitclout.com:17001/api/v1/global-state/get?shared_secret=abcdef", url)
	}

	{
		url, _, err := apiServer.CreateGlobalStatePutRequest([]byte("woo"), []byte("hoo"))
		require.NoError(err)
		assert.Equal("https://bitclout.com:17001/api/v1/global-state/put?shared_secret=abcdef", url)
	}

	{
		url, _, err := apiServer.CreateGlobalStateBatchGetRequest(
			[][]byte{[]byte("woo"), []byte("fantastic"), []byte("great")},
		)
		require.NoError(err)
		assert.Equal("https://bitclout.com:17001/api/v1/global-state/batch-get?shared_secret=abcdef", url)
	}

	{
		url, _, err := apiServer.CreateGlobalStateDeleteRequest([]byte("woo"))
		require.NoError(err)
		assert.Equal("https://bitclout.com:17001/api/v1/global-state/delete?shared_secret=abcdef", url)
	}
}
