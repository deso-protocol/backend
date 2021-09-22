package routes

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/bitclout/core/lib"
	"io"
	"net/http"
)

// AdminPinPostRequest...
type AdminPinPostRequest struct {
	// The post hash of the post to pin or unpin from the global feed
	PostHashHex string `safeForLogging:"true"`
	// If true, remove the given post hash hex from the list of pinned posts
	UnpinPost bool `safeForLogging:"true"`
}

// AdminPinPostResponse ...
type AdminPinPostResponse struct{}

// AdminUpdateGlobalFeed ...
func (fes *APIServer) AdminPinPost(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminPinPostRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateGlobalFeed: Problem parsing request body: %v", err))
		return
	}

	// Decode the postHash.
	postHash := &lib.BlockHash{}
	if requestData.PostHashHex != "" {
		postHashBytes, err := hex.DecodeString(requestData.PostHashHex)
		if err != nil || len(postHashBytes) != lib.HashSizeBytes {
			_AddBadRequestError(ww, fmt.Sprintf("AdminPinPost: Error parsing post hash %v: %v",
				requestData.PostHashHex, err))
			return
		}
		copy(postHash[:], postHashBytes)
	} else {
		_AddBadRequestError(ww, fmt.Sprintf("AdminPinPost: Request missing PostHashHex"))
		return
	}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminPinPost: Problem fetching utxoView: %v", err))
		return
	}

	// Get the post entry.
	postEntry := utxoView.GetPostEntryForPostHash(postHash)
	if postEntry == nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AdminPinPost: Problem getting postEntry for post hash: %v : %s", err, requestData.PostHashHex))
		return
	}

	// Create a key to access the global state object.
	dbKey := GlobalStateKeyForTstampPinnedPostHash(postEntry.TimestampNanos, postHash)
	if requestData.UnpinPost {
		err = fes.GlobalStateDelete(dbKey)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminPinPost: Problem deleting post from global state: %v", err))
			return
		}
	} else {
		// Encode the post entry and stick it in the database.
		err = fes.GlobalStatePut(dbKey, []byte{1})
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminPinPost: Problem putting updated user metadata: %v", err))
			return
		}
	}

	// If we made it this far we were successful, return without error.
	res := AdminPinPostResponse{}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminPinPost: Problem encoding response as JSON: %v", err))
		return
	}
}

// AdminUpdateGlobalFeedRequest...
type AdminUpdateGlobalFeedRequest struct {
	// The post hash of the post to add or remove from the global feed.
	PostHashHex string `safeForLogging:"true"`
	// If true, remove the given post hash hex from the global feed.
	RemoveFromGlobalFeed bool `safeForLogging:"true"`
}

// AdminUpdateGlobalFeedResponse ...
type AdminUpdateGlobalFeedResponse struct{}

// AdminUpdateGlobalFeed ...
func (fes *APIServer) AdminUpdateGlobalFeed(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminUpdateGlobalFeedRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateGlobalFeed: Problem parsing request body: %v", err))
		return
	}

	// Decode the postHash.
	postHash := &lib.BlockHash{}
	if requestData.PostHashHex != "" {
		postHashBytes, err := hex.DecodeString(requestData.PostHashHex)
		if err != nil || len(postHashBytes) != lib.HashSizeBytes {
			_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateGlobalFeed: Error parsing post hash %v: %v",
				requestData.PostHashHex, err))
			return
		}
		copy(postHash[:], postHashBytes)
	} else {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateGlobalFeed: Request missing PostHashHex"))
		return
	}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateGlobalFeed: Problem fetching utxoView: %v", err))
		return
	}

	// Get the post entry.
	postEntry := utxoView.GetPostEntryForPostHash(postHash)
	if postEntry == nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateGlobalFeed: Problem getting postEntry for post hash: %v : %s", err, requestData.PostHashHex))
		return
	}

	// Create a key to access the global state object.
	dbKey := GlobalStateKeyForTstampPostHash(postEntry.TimestampNanos, postHash)
	if requestData.RemoveFromGlobalFeed {
		err = fes.GlobalStateDelete(dbKey)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateGlobalFeed: Problem deleting post from global state: %v", err))
			return
		}
	} else {
		// Encode the post entry and stick it in the database.
		err = fes.GlobalStatePut(dbKey, []byte{1})
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateGlobalFeed: Problem putting updated user metadata: %v", err))
			return
		}
	}

	// If we made it this far we were successful, return without error.
	res := AdminUpdateGlobalFeedResponse{}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateGlobalFeed: Problem encoding response as JSON: %v", err))
		return
	}
}

// AdminRemoveNilPostsRequest...
type AdminRemoveNilPostsRequest struct {
	// Number of posts to try to fetch from global state, starting from the most recent post
	// added to the global feed.
	NumPostsToSearch int `safeForLogging:"true"`
}

// AdminUpdateGlobalFeedResponse ...
type AdminRemoveNilPostsResponse struct{}

func (fes *APIServer) AdminRemoveNilPosts(ww http.ResponseWriter, req *http.Request) {

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminRemoveNilPostsRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateGlobalFeed: Problem parsing request body: %v", err))
		return
	}

	// Get a view with all the mempool transactions (used to get all posts / reader state).
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AdminRemoveNilPosts: Error getting augmented universal view: #{err}"))
		return
	}

	postsToFetchCount := 1000
	if requestData.NumPostsToSearch != 0 {
		postsToFetchCount = requestData.NumPostsToSearch
	}

	maxBigEndianUint64Bytes := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	maxKeyLen := 1 + len(maxBigEndianUint64Bytes) + lib.HashSizeBytes
	// Get postHashes for posts in the globalFeed.
	keys, _, err := fes.GlobalStateSeek(
		_GlobalStatePrefixTstampNanosPostHash, /*startPrefix*/
		_GlobalStatePrefixTstampNanosPostHash, /*validForPrefix*/
		maxKeyLen,                             /*maxKeyLen*/
		postsToFetchCount,                     /*numToFetch*/
		true,                                  /*reverse*/
		false)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AdminRemoveNilPosts: Problem seeking through global state keys: #{err}"))
		return
	}

	for _, dbKeyBytes := range keys {
		// Chop the public key out of the db key.
		// The dbKeyBytes are: [One Prefix Byte][Uint64 Tstamp Bytes][PostHash]
		postHash := &lib.BlockHash{}
		copy(postHash[:], dbKeyBytes[1+len(maxBigEndianUint64Bytes):][:])

		// Get the postEntry from the utxoView.
		postEntry := utxoView.GetPostEntryForPostHash(postHash)

		// If the postEntry doesn't exist, clear the entry for the map of global feed posts
		// from global state
		if postEntry == nil {
			err = fes.GlobalStateDelete(dbKeyBytes)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf(
					"AdminRemoveNilPosts: Problem deleting missing key in GlobalState Key-value store for global feed: #{err}"))
				return
			}
		}
	}

	res := &AdminRemoveNilPostsResponse{}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AdminRemoveNilPosts: Problem encoding response as JSON: #{err}"))
		return
	}
}
