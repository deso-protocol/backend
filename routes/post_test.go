package routes

import (
	"bytes"
	"encoding/json"
	"github.com/deso-protocol/core/lib"
	"github.com/stretchr/testify/require"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFreezingPost(t *testing.T) {
	apiServer := newTestApiServer(t)
	defer apiServer.backendServer.Stop()
	defer apiServer.Stop()
	var post *PostEntryResponse

	// Helper utils.
	_submitPost := func(body *SubmitPostRequest) error {
		// Send POST request.
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

		// Sign txn.
		require.Nil(t, txn.Signature.Sign)
		signTxn(t, txn, senderPrivString)
		require.NotNil(t, txn.Signature.Sign)

		// Submit txn.
		_, err = submitTxn(t, apiServer, txn)
		return err
	}

	_getPostsForUsername := func(username string) []*PostEntryResponse {
		body := &GetPostsForPublicKeyRequest{
			Username:   username,
			NumToFetch: math.MaxUint64,
		}
		bodyJSON, err := json.Marshal(body)
		require.NoError(t, err)
		request, _ := http.NewRequest("POST", RoutePathGetPostsForPublicKey, bytes.NewBuffer(bodyJSON))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		require.NotContains(t, string(response.Body.Bytes()), "error")

		// Decode response.
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		postsResponse := GetPostsForPublicKeyResponse{}
		err = decoder.Decode(&postsResponse)
		require.NoError(t, err)
		return postsResponse.Posts
	}

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
		// Create a non-frozen post.
		err := _submitPost(&SubmitPostRequest{
			UpdaterPublicKeyBase58Check: senderPkString,
			BodyObj:                     &lib.DeSoBodySchema{Body: "Hello, world!"},
			MinFeeRateNanosPerKB:        apiServer.MinFeeRateNanosPerKB,
		})
		require.NoError(t, err)

		posts := _getPostsForUsername("sender")
		require.Len(t, posts, 1)
		post = posts[0]
		require.Equal(t, post.Body, "Hello, world!")
		require.False(t, post.IsFrozen)
	}
	{
		// Update the post body.
		err := _submitPost(&SubmitPostRequest{
			UpdaterPublicKeyBase58Check: senderPkString,
			PostHashHexToModify:         post.PostHashHex,
			BodyObj:                     &lib.DeSoBodySchema{Body: "Hello, world... again!"},
			MinFeeRateNanosPerKB:        apiServer.MinFeeRateNanosPerKB,
		})
		require.NoError(t, err)

		posts := _getPostsForUsername("sender")
		require.Len(t, posts, 1)
		post = posts[0]
		require.Equal(t, post.Body, "Hello, world... again!")
		require.False(t, post.IsFrozen)
	}
	{
		// Update the post to frozen.
		err := _submitPost(&SubmitPostRequest{
			UpdaterPublicKeyBase58Check: senderPkString,
			PostHashHexToModify:         post.PostHashHex,
			PostExtraData:               map[string]string{"IsFrozen": "1"},
			MinFeeRateNanosPerKB:        apiServer.MinFeeRateNanosPerKB,
		})
		require.NoError(t, err)

		posts := _getPostsForUsername("sender")
		require.Len(t, posts, 1)
		post = posts[0]
		require.Equal(t, post.Body, "Hello, world... again!")
		require.True(t, post.IsFrozen)
		// The IsFrozen key gets deleted from the ExtraData.
		require.Equal(t, post.PostExtraData["IsFrozen"], "")
	}
	{
		// Try to update the frozen post. Fails.
		err := _submitPost(&SubmitPostRequest{
			UpdaterPublicKeyBase58Check: senderPkString,
			PostHashHexToModify:         post.PostHashHex,
			BodyObj:                     &lib.DeSoBodySchema{Body: "Goodbye, world!"},
			MinFeeRateNanosPerKB:        apiServer.MinFeeRateNanosPerKB,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), lib.RuleErrorSubmitPostModifyingFrozenPost)

		posts := _getPostsForUsername("sender")
		require.Len(t, posts, 1)
		post = posts[0]
		require.Equal(t, post.Body, "Hello, world... again!")
		require.True(t, post.IsFrozen)
	}
}
