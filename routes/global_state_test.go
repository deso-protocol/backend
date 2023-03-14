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
	val, err := apiServer.GlobalState.Get([]byte("woo"))
	require.NoError(err)
	require.Nil(val)

	// Putting then getting a value should work.
	require.NoError(apiServer.GlobalState.Put([]byte("woo"), []byte("hoo")))
	val, err = apiServer.GlobalState.Get([]byte("woo"))
	require.NoError(err)
	require.Equal(val, []byte("hoo"))

	// Doing a batch get should work.
	require.NoError(apiServer.GlobalState.Put([]byte("fan"), []byte("tastic")))
	valueList, err := apiServer.GlobalState.BatchGet([][]byte{
		[]byte("woo"),
		[]byte("great"),
		[]byte("fan"),
	})
	require.NoError(err)
	expectedValues := [][]byte{
		[]byte("hoo"),
		{},
		[]byte("tastic"),
	}
	for ii, vv := range valueList {
		require.Equal(vv, expectedValues[ii])
	}

	// Deleting a value should make it no longer gettable.
	require.NoError(apiServer.GlobalState.Delete([]byte("woo")))
	val, err = apiServer.GlobalState.Get([]byte("woo"))
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
		url, json_data, err := apiServer.GlobalState.CreateGetRequest([]byte("woo"))
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", url, bytes.NewBuffer(json_data))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		res := GetRemoteResponse{}
		if err := decoder.Decode(&res); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Nil(res.Value)
	}

	// Putting then getting a value should work.
	{
		url, json_data, err := apiServer.GlobalState.CreatePutRequest([]byte("woo"), []byte("hoo"))
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", url, bytes.NewBuffer(json_data))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		res := PutRemoteResponse{}
		if err := decoder.Decode(&res); err != nil {
			require.NoError(err, "Problem decoding response")
		}
	}
	{
		url, json_data, err := apiServer.GlobalState.CreateGetRequest([]byte("woo"))
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", url,
			bytes.NewBuffer(json_data))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		res := GetRemoteResponse{}
		if err := decoder.Decode(&res); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Equal(res.Value, []byte("hoo"))
	}

	// Batch get should work.
	{
		url, json_data, err := apiServer.GlobalState.CreateBatchGetRequest(
			[][]byte{[]byte("woo"), []byte("fantastic"), []byte("great")},
		)
		require.NoError(err)
		request, _ := http.NewRequest("POST", url, bytes.NewBuffer(json_data))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		res := BatchGetRemoteResponse{}
		if err := decoder.Decode(&res); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		expectedValues := [][]byte{
			[]byte("hoo"),
			{},
			{},
		}
		for ii, vv := range res.ValueList {
			require.Equal(vv, expectedValues[ii])
		}
	}

	// Deleting a value should make it no longer gettable.
	{
		url, json_data, err := apiServer.GlobalState.CreateDeleteRequest([]byte("woo"))
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", url,
			bytes.NewBuffer(json_data))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		res := DeleteRemoteResponse{}
		if err := decoder.Decode(&res); err != nil {
			require.NoError(err, "Problem decoding response")
		}
	}
	{
		url, json_data, err := apiServer.GlobalState.CreateGetRequest([]byte("woo"))
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", url,
			bytes.NewBuffer(json_data))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		res := GetRemoteResponse{}
		if err := decoder.Decode(&res); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		require.Nil(res.Value)
	}
}

func TestGlobalStateServiceURLCreation(t *testing.T) {
	t.Skip("FIXME")
	// This test is currently skipped because the backend API Server
	// tries to fetch the transaction fees from global state on
	// boot up
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	apiServer, _, _ := newTestAPIServer(
		t, "https://deso.com:17001" /*globalStateRemoteNode*/)

	{
		url, _, err := apiServer.GlobalState.CreateGetRequest([]byte("woo"))
		require.NoError(err)
		assert.Equal("https://deso.com:17001/api/v1/global-state/get?shared_secret=abcdef", url)
	}

	{
		url, _, err := apiServer.GlobalState.CreatePutRequest([]byte("woo"), []byte("hoo"))
		require.NoError(err)
		assert.Equal("https://deso.com:17001/api/v1/global-state/put?shared_secret=abcdef", url)
	}

	{
		url, _, err := apiServer.GlobalState.CreateBatchGetRequest(
			[][]byte{[]byte("woo"), []byte("fantastic"), []byte("great")},
		)
		require.NoError(err)
		assert.Equal("https://deso.com:17001/api/v1/global-state/batch-get?shared_secret=abcdef", url)
	}

	{
		url, _, err := apiServer.GlobalState.CreateDeleteRequest([]byte("woo"))
		require.NoError(err)
		assert.Equal("https://deso.com:17001/api/v1/global-state/delete?shared_secret=abcdef", url)
	}
}
