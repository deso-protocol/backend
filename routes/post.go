package routes

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/bitclout/core/lib"
	"github.com/btcsuite/btcd/btcec"
	"github.com/golang/glog"
	"github.com/pkg/errors"
)

// GetPostsStatelessRequest ...
type GetPostsStatelessRequest struct {
	// This is the PostHashHex of the post we want to start our paginated lookup at. We
	// will fetch up to "NumToFetch" posts after it, ordered by time stamp.  If no
	// PostHashHex is provided we will return the most recent posts.
	PostHashHex                string `safeForLogging:"true"`
	ReaderPublicKeyBase58Check string `safeForLogging:"true"`
	OrderBy                    string `safeForLogging:"true"`
	StartTstampSecs            uint64 `safeForLogging:"true"`
	PostContent                string `safeForLogging:"true"`
	NumToFetch                 int    `safeForLogging:"true"`

	// Note: if the GetPostsForFollowFeed option is passed, FetchSubcomments is currently ignored
	// (fetching comments / subcomments for the follow feed is currently unimplemented)
	FetchSubcomments bool `safeForLogging:"true"`

	// This gets posts by people that ReaderPublicKeyBase58Check follows.
	GetPostsForFollowFeed bool `safeForLogging:"true"`

	// This gets posts by people that ReaderPublicKeyBase58Check follows.
	GetPostsForGlobalWhitelist bool `safeForLogging:"true"`

	// This gets posts sorted by clout
	GetPostsByClout bool `safeForLogging:"true"`

	// This only gets posts that include media, like photos and videos
	MediaRequired bool `safeForLogging:"true"`

	PostsByCloutMinutesLookback uint64 `safeForLogging:"true"`

	// If set to true, then the posts in the response will contain a boolean about whether they're in the global feed
	AddGlobalFeedBool bool `safeForLogging:"true"`
}

type PostEntryResponse struct {
	PostHashHex                string
	PosterPublicKeyBase58Check string
	ParentStakeID              string
	Body                       string
	ImageURLs                  []string
	RecloutedPostEntryResponse *PostEntryResponse
	CreatorBasisPoints         uint64
	StakeMultipleBasisPoints   uint64
	TimestampNanos             uint64
	IsHidden                   bool
	ConfirmationBlockHeight    uint32
	InMempool                  bool
	// The profile associated with this post.
	ProfileEntryResponse *ProfileEntryResponse
	// The comments associated with this post.
	Comments     []*PostEntryResponse
	LikeCount    uint64
	DiamondCount uint64
	// Information about the reader's state w/regard to this post (e.g. if they liked it).
	PostEntryReaderState *lib.PostEntryReaderState
	// True if this post hash hex is in the global feed.
	InGlobalFeed *bool `json:",omitempty"`
	// True if this post hash hex is pinned to the global feed.
	IsPinned *bool `json:",omitempty"`
	// PostExtraData stores an arbitrary map of attributes of a PostEntry
	PostExtraData     map[string]string
	CommentCount      uint64
	RecloutCount      uint64
	QuoteRecloutCount uint64
	// A list of parent posts for this post (ordered: root -> closest parent post).
	ParentPosts []*PostEntryResponse

	// NFT info.
	IsNFT                          bool
	NumNFTCopies                   uint64
	NumNFTCopiesForSale            uint64
	HasUnlockable                  bool
	NFTRoyaltyToCreatorBasisPoints uint64
	NFTRoyaltyToCoinBasisPoints    uint64

	// Number of diamonds the sender gave this post. Only set when getting diamond posts.
	DiamondsFromSender uint64
}

// GetPostsStatelessResponse ...
type GetPostsStatelessResponse struct {
	PostsFound []*PostEntryResponse
}

// Given a post entry, check if it is reclouting another post and if so, get that post entry as a response.
func (fes *APIServer) _getRecloutPostEntryResponse(postEntry *lib.PostEntry, addGlobalFeedBool bool, params *lib.BitCloutParams, utxoView *lib.UtxoView, readerPK []byte, maxDepth uint8) (_recloutPostEntry *PostEntryResponse, err error) {
	// if the maxDepth at this point is 0, we stop getting reclouted post entries
	if maxDepth == 0 {
		return nil, nil
	}
	if postEntry == nil {
		return nil, fmt.Errorf("_getRecloutPostEntry: postEntry must be provided ")
	}

	// Only try to get the recloutPostEntryResponse if there is a Reclout PostHashHex
	if postEntry.RecloutedPostHash != nil {
		// Fetch the postEntry requested.
		recloutedPostEntry := utxoView.GetPostEntryForPostHash(postEntry.RecloutedPostHash)
		if recloutedPostEntry == nil {
			return nil, fmt.Errorf("_getRecloutPostEntry: Could not find postEntry for PostHashHex: #{postEntry.RecloutedPostHash}")
		} else {
			var recloutedPostEntryResponse *PostEntryResponse
			recloutedPostEntryResponse, err = fes._postEntryToResponse(recloutedPostEntry, addGlobalFeedBool, params, utxoView, readerPK, maxDepth-1)
			if err != nil {
				return nil, fmt.Errorf("_getRecloutPostEntry: error converting reclout post entry to response")
			}
			profileEntry := utxoView.GetProfileEntryForPublicKey(recloutedPostEntry.PosterPublicKey)
			if profileEntry != nil {
				// Convert it to a response since that sanitizes the inputs.
				verifiedMap, _ := fes.GetVerifiedUsernameToPKIDMap()
				profileEntryResponse := _profileEntryToResponse(profileEntry, fes.Params, verifiedMap, utxoView)
				recloutedPostEntryResponse.ProfileEntryResponse = profileEntryResponse
			}
			recloutedPostEntryResponse.PostEntryReaderState = utxoView.GetPostEntryReaderState(readerPK, recloutedPostEntry)
			return recloutedPostEntryResponse, nil
		}
	} else {
		return nil, nil
	}
}

func (fes *APIServer) _postEntryToResponse(postEntry *lib.PostEntry, addGlobalFeedBool bool, params *lib.BitCloutParams, utxoView *lib.UtxoView, readerPK []byte, maxDepth uint8) (
	*PostEntryResponse, error) {
	// We only want to fetch reclouted posts two levels down.  We only want to display reclout posts that are at most two levels deep.
	// This only happens when someone reclouts a post that is a quoted reclout.  For a quote reclout for which the reclouted
	// post is itself a quote reclout, we only display the new reclout's quote and use quote from the post that was reclouted
	// as the quoted content.
	if maxDepth > 2 {
		maxDepth = 2
	}
	// Get the body
	bodyJSONObj := &lib.BitCloutBodySchema{}
	err := json.Unmarshal(postEntry.Body, bodyJSONObj)
	if err != nil {
		// Just ignore posts whose JSON doesn't parse properly.
		return nil, fmt.Errorf(
			"_postEntryToResponse: Error unmarshling Body: %v", err)
	}

	stakeIDStr := ""
	if len(postEntry.ParentStakeID) == lib.HashSizeBytes {
		stakeIDStr = hex.EncodeToString(postEntry.ParentStakeID)
	} else if len(postEntry.ParentStakeID) == btcec.PubKeyBytesLenCompressed {
		stakeIDStr = lib.PkToString(postEntry.ParentStakeID, params)
	}

	var inMempool bool
	// When a transaction is connected to the view, it is given a block height of
	// "fes.blockchain.BlockTip().Height + 1". Therefore, if a postEntry has a confirmation
	// blockheight greater than the current blockTip height, it hasn't mined yet.
	if postEntry.ConfirmationBlockHeight > fes.blockchain.BlockTip().Height {
		inMempool = true
	}

	var recloutPostEntryResponse *PostEntryResponse
	// Only get recloutPostEntryResponse if this is the origination of the thread.
	if stakeIDStr == "" {
		// We don't care about an error here
		recloutPostEntryResponse, _ = fes._getRecloutPostEntryResponse(postEntry, addGlobalFeedBool, params, utxoView, readerPK, maxDepth)
	}

	postEntryResponseExtraData := make(map[string]string)
	if len(postEntry.PostExtraData) > 0 {
		for k, v := range postEntry.PostExtraData {
			if len(v) > 0 {
				postEntryResponseExtraData[k] = string(v)
			}
		}
	}

	res := &PostEntryResponse{
		PostHashHex:                    hex.EncodeToString(postEntry.PostHash[:]),
		PosterPublicKeyBase58Check:     lib.PkToString(postEntry.PosterPublicKey, params),
		ParentStakeID:                  stakeIDStr,
		Body:                           bodyJSONObj.Body,
		ImageURLs:                      bodyJSONObj.ImageURLs,
		RecloutedPostEntryResponse:     recloutPostEntryResponse,
		CreatorBasisPoints:             postEntry.CreatorBasisPoints,
		StakeMultipleBasisPoints:       postEntry.StakeMultipleBasisPoints,
		TimestampNanos:                 postEntry.TimestampNanos,
		IsHidden:                       postEntry.IsHidden,
		ConfirmationBlockHeight:        postEntry.ConfirmationBlockHeight,
		InMempool:                      inMempool,
		LikeCount:                      postEntry.LikeCount,
		DiamondCount:                   postEntry.DiamondCount,
		CommentCount:                   postEntry.CommentCount,
		RecloutCount:                   postEntry.RecloutCount,
		QuoteRecloutCount:              postEntry.QuoteRecloutCount,
		IsPinned:                       &postEntry.IsPinned,
		IsNFT:                          postEntry.IsNFT,
		NumNFTCopies:                   postEntry.NumNFTCopies,
		NumNFTCopiesForSale:            postEntry.NumNFTCopiesForSale,
		HasUnlockable:                  postEntry.HasUnlockable,
		NFTRoyaltyToCreatorBasisPoints: postEntry.NFTRoyaltyToCreatorBasisPoints,
		NFTRoyaltyToCoinBasisPoints:    postEntry.NFTRoyaltyToCoinBasisPoints,
		PostExtraData:                  postEntryResponseExtraData,
	}

	if addGlobalFeedBool {
		inGlobalFeed := false
		dbKey := GlobalStateKeyForTstampPostHash(postEntry.TimestampNanos, postEntry.PostHash)
		globalStateVal, err := fes.GlobalStateGet(dbKey)
		if err != nil {
			return nil, fmt.Errorf(
				"_postEntryToResponse: Error fetching from global state: %v", err)
		}
		if globalStateVal == nil {
			res.InGlobalFeed = &inGlobalFeed
		} else {
			inGlobalFeed = true
			res.InGlobalFeed = &inGlobalFeed
		}
	}

	return res, nil
}

func (fes *APIServer) GetPostEntriesForFollowFeed(
	startAfterPostHash *lib.BlockHash, readerPK []byte, numToFetch int, utxoView *lib.UtxoView, mediaRequired bool) (
	_postEntries []*lib.PostEntry,
	_profilesByPublicKey map[lib.PkMapKey]*lib.ProfileEntry,
	_postEntryReaderStates map[lib.BlockHash]*lib.PostEntryReaderState, err error) {

	postEntries, err := fes.GetPostsForFollowFeedForPublicKey(utxoView, startAfterPostHash, readerPK, numToFetch, true /* skip hidden */, mediaRequired)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("GetPostEntriesForFollowFeed: Error fetching posts from view: %v", err)
	}

	// Sort the postEntries by time.
	sort.Slice(postEntries, func(ii, jj int) bool {
		return postEntries[ii].TimestampNanos > postEntries[jj].TimestampNanos
	})

	profileEntries := make(map[lib.PkMapKey]*lib.ProfileEntry)
	for _, postEntry := range postEntries {
		{
			profileEntry := utxoView.GetProfileEntryForPublicKey(postEntry.PosterPublicKey)
			if profileEntry != nil {
				profileEntries[lib.MakePkMapKey(profileEntry.PublicKey)] = profileEntry
			}
		}
	}
	postEntryReaderStates := make(map[lib.BlockHash]*lib.PostEntryReaderState)
	// Create reader state map. Ie, whether the reader has liked the post, etc.
	// If nil is passed in as the readerPK, this is skipped.
	if readerPK != nil {
		for _, postEntry := range postEntries {
			postEntryReaderState := utxoView.GetPostEntryReaderState(readerPK, postEntry)
			postEntryReaderStates[*postEntry.PostHash] = postEntryReaderState
		}
	}

	return postEntries, profileEntries, postEntryReaderStates, nil
}

// Get the top numToFetch posts ordered by poster's coin price in the last number of minutes as defined by minutesLookback.
func (fes *APIServer) GetPostEntriesByCloutAfterTimePaginated(readerPK []byte,
	minutesLookback uint64, numToFetch int) (
	_postEntries []*lib.PostEntry,
	_profilesByPublicKey map[lib.PkMapKey]*lib.ProfileEntry, err error) {
	// As a safeguard, we should only be able to look at least one hour in the past -- can be changed later.

	if minutesLookback > 60 {
		return nil, nil, fmt.Errorf("GetPostEntriesByClout: Cannot fetch posts by clout more than an hour back")
	}

	currentTime := time.Now().UnixNano()
	startTstampNanos := uint64(currentTime) - (uint64(time.Minute.Nanoseconds()) * minutesLookback)

	// Get a view with all the mempool transactions (used to get all posts / reader state).
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return nil, nil, fmt.Errorf("GetPostEntriesByClout: Error fetching mempool view: %v", err)
	}
	// Start by fetching the posts we have in the db.
	dbPostHashes, _, _, err := lib.DBGetPaginatedPostsOrderedByTime(
		utxoView.Handle, startTstampNanos, nil, -1, false /*fetchEntries*/, false)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "GetPostEntriesByClout: Problem fetching ProfileEntrys from db: ")
	}

	// Iterate through the entries found in the db and force the view to load them.
	// This fills in any gaps in the view so that, after this, the view should contain
	// the union of what it had before plus what was in the db.
	for _, dbPostHash := range dbPostHashes {
		utxoView.GetPostEntryForPostHash(dbPostHash)
	}
	// Cycle through all the posts and store a map of the PubKeys so we can filter out those
	// that are restricted later.
	postEntryPubKeyMap := make(map[lib.PkMapKey][]byte)
	for _, postEntry := range utxoView.PostHashToPostEntry {
		// Ignore deleted / rolled-back / hidden posts.
		if postEntry.IsDeleted() || postEntry.IsHidden {
			continue
		}

		// We make sure that the post isn't a comment.
		if len(postEntry.ParentStakeID) == 0 {
			postEntryPubKeyMap[lib.MakePkMapKey(postEntry.PosterPublicKey)] = postEntry.PosterPublicKey
		}
	}

	// Filter restricted public keys out of the posts.
	filteredPostEntryPubKeyMap, err := fes.FilterOutRestrictedPubKeysFromMap(postEntryPubKeyMap, readerPK, "leaderboard")
	if err != nil {
		return nil, nil, errors.Wrapf(err, "GetPostsByClout: Problem filtering restricted profiles from map: ")
	}

	// At this point, all the posts should be loaded into the view.
	allCorePosts := []*lib.PostEntry{}
	for _, postEntry := range utxoView.PostHashToPostEntry {

		// Ignore deleted or rolled-back posts.
		if postEntry.IsDeleted() || postEntry.IsHidden {
			continue
		}

		// Make sure this isn't a comment and then make sure the public key isn't restricted.
		if len(postEntry.ParentStakeID) == 0 && postEntry.TimestampNanos > startTstampNanos {
			if filteredPostEntryPubKeyMap[lib.MakePkMapKey(postEntry.PosterPublicKey)] == nil {
				continue
			}
			allCorePosts = append(allCorePosts, postEntry)
		}
	}
	profileEntries := make(map[lib.PkMapKey]*lib.ProfileEntry)
	for _, postEntry := range allCorePosts {
		{
			profileEntry := utxoView.GetProfileEntryForPublicKey(postEntry.PosterPublicKey)
			if profileEntry != nil {
				profileEntries[lib.MakePkMapKey(profileEntry.PublicKey)] = profileEntry
			}
		}
	}

	// Order the posts by the poster's coin price.
	sort.Slice(allCorePosts, func(ii, jj int) bool {
		return profileEntries[lib.MakePkMapKey(allCorePosts[ii].PosterPublicKey)].CoinEntry.BitCloutLockedNanos > profileEntries[lib.MakePkMapKey(allCorePosts[jj].PosterPublicKey)].CoinEntry.BitCloutLockedNanos
	})
	// Select the top numToFetch posts.
	if len(allCorePosts) > numToFetch {
		allCorePosts = allCorePosts[:numToFetch]
	}
	return allCorePosts, profileEntries, nil
}

func (fes *APIServer) GetPostEntriesByTimePaginated(
	startPostHash *lib.BlockHash, readerPK []byte, numToFetch int, utxoView *lib.UtxoView) (
	_postEntries []*lib.PostEntry, _commentsByPostHash map[lib.BlockHash][]*lib.PostEntry,
	_profilesByPublicKey map[lib.PkMapKey]*lib.ProfileEntry,
	_postEntryReaderStates map[lib.BlockHash]*lib.PostEntryReaderState, err error) {

	postEntries,
		commentsByPostHash,
		err := fes.GetPostsByTime(utxoView, startPostHash, readerPK, numToFetch, true /*skipHidden*/, true)

	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("GetAllPostEntries: Error fetching posts from view: %v", err)
	}

	// Sort the postEntries by time.
	sort.Slice(postEntries, func(ii, jj int) bool {
		return postEntries[ii].TimestampNanos > postEntries[jj].TimestampNanos
	})

	// Take up to numToFetch.  If this is a request for a single post, it was selected by the utxo view.
	if len(postEntries) > numToFetch || startPostHash != nil {
		startIndex := 0
		if startPostHash != nil {
			// If we have a startPostHash, find it's index in the postEntries slice as the starting point
			for ii, postEntry := range postEntries {
				if *(postEntry.PostHash) == *(startPostHash) {
					// Start the new slice from the post that comes after the startPostHash
					startIndex = ii + 1
					break
				}
			}
		}
		postEntries = postEntries[startIndex:lib.MinInt(startIndex+numToFetch, len(postEntries))]
	}

	profileEntries := make(map[lib.PkMapKey]*lib.ProfileEntry)
	for _, postEntry := range postEntries {
		{
			profileEntry := utxoView.GetProfileEntryForPublicKey(postEntry.PosterPublicKey)
			if profileEntry != nil {
				profileEntries[lib.MakePkMapKey(profileEntry.PublicKey)] = profileEntry
			}
		}

		// Get the profileEntries for the comments (and subcomments) as well
		commentsFound := commentsByPostHash[*postEntry.PostHash]
		for _, commentEntry := range commentsFound {
			profileEntry := utxoView.GetProfileEntryForPublicKey(commentEntry.PosterPublicKey)
			if profileEntry != nil {
				profileEntries[lib.MakePkMapKey(profileEntry.PublicKey)] = profileEntry
			}

			subCommentsFound := commentsByPostHash[*commentEntry.PostHash]
			for _, subCommentEntry := range subCommentsFound {
				subCommentProfileEntry := utxoView.GetProfileEntryForPublicKey(subCommentEntry.PosterPublicKey)
				if subCommentProfileEntry != nil {
					profileEntries[lib.MakePkMapKey(subCommentProfileEntry.PublicKey)] = subCommentProfileEntry
				}
			}

		}
	}
	postEntryReaderStates := make(map[lib.BlockHash]*lib.PostEntryReaderState)
	// Create reader state map. Ie, whether the reader has liked the post, etc.
	// If nil is passed in as the readerPK, this is skipped.
	if readerPK != nil {
		for _, postEntry := range postEntries {
			postEntryReaderState := utxoView.GetPostEntryReaderState(readerPK, postEntry)
			postEntryReaderStates[*postEntry.PostHash] = postEntryReaderState
		}
	}

	return postEntries, commentsByPostHash, profileEntries, postEntryReaderStates, nil
}

func (fes *APIServer) _getCommentResponse(
	commentEntry *lib.PostEntry, profileEntryMap map[lib.PkMapKey]*lib.ProfileEntry, addGlobalFeedBool bool, verifiedMap map[string]*lib.PKID, utxoView *lib.UtxoView, readerPK []byte) (
	*PostEntryResponse, error) {
	commentResponse, err := fes._postEntryToResponse(commentEntry, addGlobalFeedBool, fes.Params, utxoView, readerPK, 2)
	if err != nil {
		return nil, err
	}

	profileEntryFound := profileEntryMap[lib.MakePkMapKey(commentEntry.PosterPublicKey)]
	commentResponse.ProfileEntryResponse = _profileEntryToResponse(profileEntryFound, fes.Params, verifiedMap, utxoView)

	return commentResponse, nil
}

func (fes *APIServer) _shouldSkipCommentResponse(commentResponse *PostEntryResponse, err error) bool {
	// If there's a problem with this comment then just skip it
	return err != nil ||
		// Don't add hidden comments
		commentResponse.IsHidden
}

func (fes *APIServer) GetPostEntriesForGlobalWhitelist(
	startPostHash *lib.BlockHash, readerPK []byte, numToFetch int, utxoView *lib.UtxoView, mediaRequired bool) (
	_postEntries []*lib.PostEntry,
	_profilesByPublicKey map[lib.PkMapKey]*lib.ProfileEntry,
	_postEntryReaderStates map[lib.BlockHash]*lib.PostEntryReaderState, err error) {

	var startPost *lib.PostEntry
	if startPostHash != nil {
		startPost = utxoView.GetPostEntryForPostHash(startPostHash)
	}

	var seekStartKey []byte
	skipFirstEntry := false
	if startPost != nil {
		seekStartKey = GlobalStateKeyForTstampPostHash(startPost.TimestampNanos, startPost.PostHash)
		skipFirstEntry = true
	} else {
		// If we can't find a valid start post, we just use the prefix. GlobalStateSeek will
		// pad the value as necessary.
		seekStartKey = _GlobalStatePrefixTstampNanosPostHash
	}

	// Seek the global state for a list of [prefix][tstamp][posthash] keys.
	validForPrefix := _GlobalStatePrefixTstampNanosPostHash
	maxBigEndianUint64Bytes := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	maxKeyLen := 1 + len(maxBigEndianUint64Bytes) + lib.HashSizeBytes
	//maxKeyLen := 41
	var postEntries []*lib.PostEntry
	nextStartKey := seekStartKey

	// Iterate over posts in global state until we have at least num to fetch
	for len(postEntries) < numToFetch {
		// Get numToFetch - len(postEntries) postHashes from global state.
		keys, _, err := fes.GlobalStateSeek(nextStartKey /*startPrefix*/, validForPrefix, /*validForPrefix*/
			maxKeyLen /*maxKeyLen -- ignored since reverse is false*/, numToFetch-len(postEntries), true, /*reverse*/
			false /*fetchValues*/)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("GetPostEntriesForGlobalWhitelist: Getting posts for reader: %v", err)
		}
		// If there are no keys left, then there are no more postEntries to get so we exit the loop.
		if len(keys) == 0 || (len(keys) == 1 && skipFirstEntry) {
			break
		}

		for ii, dbKeyBytes := range keys {
			// if we have a postHash at which we are starting, we should skip the first one so we don't have it
			// duplicated in the response.
			if skipFirstEntry && ii == 0 {
				continue
			}
			// Chop the public key out of the db key.
			// The dbKeyBytes are: [One Prefix Byte][Uint64 Tstamp Bytes][PostHash]
			postHash := &lib.BlockHash{}
			copy(postHash[:], dbKeyBytes[1+len(maxBigEndianUint64Bytes):][:])

			// Get the postEntry from the utxoView.
			postEntry := utxoView.GetPostEntryForPostHash(postHash)

			if readerPK != nil && postEntry != nil && reflect.DeepEqual(postEntry.PosterPublicKey, readerPK) {
				// We add the readers posts later so we can skip them here to avoid duplicates.
				continue
			}

			// mediaRequired set to determine if we only want posts that include media and ignore posts without
			if mediaRequired && postEntry != nil && !postEntry.HasMedia() {
				continue
			}

			if postEntry != nil {
				postEntries = append(postEntries, postEntry)
			}
		}
		// Next time through the loop, start at the last key we retrieved
		nextStartKey = keys[len(keys)-1]
		skipFirstEntry = true
	}

	// If we don't have any postEntries at this point, bail.
	profileEntries := make(map[lib.PkMapKey]*lib.ProfileEntry)
	postEntryReaderStates := make(map[lib.BlockHash]*lib.PostEntryReaderState)

	// Now that we have the whitelist posts, we need to insert the user's posts.
	if readerPK != nil {
		maxTimestampNanos := uint64(time.Now().UTC().UnixNano()) // current tstamp
		if startPost != nil {
			maxTimestampNanos = startPost.TimestampNanos
		}
		var minTimestampNanos uint64
		if len(postEntries) == 0 {
			minTimestampNanos = 0
		} else {
			minTimestampNanos = postEntries[len(postEntries)-1].TimestampNanos
		}

		_, dbPostAndCommentHashes, _, err := lib.DBGetAllPostsAndCommentsForPublicKeyOrderedByTimestamp(
			utxoView.Handle, readerPK, false /*fetchEntries*/, minTimestampNanos, maxTimestampNanos,
		)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("GetPostEntriesForGlobalWhitelist: Getting posts for reader: %v", err)
		}

		// Load all the relevant post hashes into the view.
		for _, dbPostOrCommentHash := range dbPostAndCommentHashes {
			utxoView.GetPostEntryForPostHash(dbPostOrCommentHash)
		}

		// Loop through all the posts in the view and add those that are relevant.
		for _, postEntry := range utxoView.PostHashToPostEntry {
			// Skip deleted / hidden posts and any comments.
			if postEntry.IsDeleted() || postEntry.IsHidden || len(postEntry.ParentStakeID) != 0 {
				continue
			}

			// mediaRequired set to determine if we only want posts that include media and ignore posts without
			if mediaRequired && !postEntry.HasMedia() {
				continue
			}

			if postEntry.TimestampNanos <= maxTimestampNanos && postEntry.TimestampNanos > minTimestampNanos {
				if reflect.DeepEqual(postEntry.PosterPublicKey, readerPK) {
					postEntries = append(postEntries, postEntry)
				}
			}
		}
	}
	// Sort the postEntries by time.
	sort.Slice(postEntries, func(ii, jj int) bool {
		return postEntries[ii].TimestampNanos > postEntries[jj].TimestampNanos
	})

	{
		// Only add pinned posts if we are starting from the top of the feed.
		if startPostHash == nil {
			// Get all pinned posts and prepend them to the list of postEntries
			pinnedStartKey := _GlobalStatePrefixTstampNanosPinnedPostHash
			// todo: how many posts can we really pin?
			keys, _, err := fes.GlobalStateSeek(pinnedStartKey, pinnedStartKey, maxKeyLen, 10, true, false)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("GetPostEntriesForWhitelist: Getting pinned posts: %v", err)
			}

			var pinnedPostEntries []*lib.PostEntry
			for _, dbKeyBytes := range keys {
				postHash := &lib.BlockHash{}
				copy(postHash[:], dbKeyBytes[1+len(maxBigEndianUint64Bytes):][:])
				postEntry := utxoView.GetPostEntryForPostHash(postHash)
				if postEntry != nil {
					postEntry.IsPinned = true
					pinnedPostEntries = append(pinnedPostEntries, postEntry)
				}
			}
			postEntries = append(pinnedPostEntries, postEntries...)
		}
	}

	if len(postEntries) == 0 {
		return postEntries, profileEntries, postEntryReaderStates, nil
	}

	for _, postEntry := range postEntries {
		{
			profileEntry := utxoView.GetProfileEntryForPublicKey(postEntry.PosterPublicKey)
			if profileEntry != nil {
				profileEntries[lib.MakePkMapKey(profileEntry.PublicKey)] = profileEntry
			}
		}
	}
	// Create reader state map. Ie, whether the reader has liked the post, etc.
	// If nil is passed in as the readerPK, this is skipped.
	if readerPK != nil {
		for _, postEntry := range postEntries {
			postEntryReaderState := utxoView.GetPostEntryReaderState(readerPK, postEntry)
			postEntryReaderStates[*postEntry.PostHash] = postEntryReaderState
		}
	}

	return postEntries, profileEntries, postEntryReaderStates, nil
}

// GetPostsStateless ...
func (fes *APIServer) GetPostsStateless(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetPostsStatelessRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPostsStateless: Problem parsing request body: %v", err))
		return
	}

	// Decode the reader public key into bytes. Default to nil if no pub key is passed in.
	var readerPublicKeyBytes []byte
	var err error
	if requestData.ReaderPublicKeyBase58Check != "" {

		readerPublicKeyBytes, _, err = lib.Base58CheckDecode(requestData.ReaderPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetPostsStateless: Problem decoding user public key: %v", err))
			return
		}
	}

	var startPostHash *lib.BlockHash
	if requestData.PostHashHex != "" {
		// Decode the postHash.  This will give us the location where we start our paginated search.
		startPostHash, err = GetPostHashFromPostHashHex(requestData.PostHashHex)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetPostsStateless: %v", err))
			return
		}
	}

	// Default to 50 posts fetched.
	numToFetch := 50
	if requestData.NumToFetch != 0 {
		numToFetch = requestData.NumToFetch
	}

	if startPostHash == nil && numToFetch == 1 {
		_AddBadRequestError(ww, fmt.Sprintf("GetPostsStateless: Must provide PostHashHex when NumToFetch is 1"))
		return
	}

	// Get a view with all the mempool transactions (used to get all posts / reader state).
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPostsStateless: Error fetching mempool view"))
		return
	}

	// Get all the PostEntries
	var postEntries []*lib.PostEntry
	var commentsByPostHash map[lib.BlockHash][]*lib.PostEntry
	var profileEntryMap map[lib.PkMapKey]*lib.ProfileEntry
	var readerStateMap map[lib.BlockHash]*lib.PostEntryReaderState
	if requestData.GetPostsForFollowFeed {
		postEntries,
			profileEntryMap,
			readerStateMap,
			err = fes.GetPostEntriesForFollowFeed(startPostHash, readerPublicKeyBytes, numToFetch, utxoView, requestData.MediaRequired)
		// if we're getting posts for follow feed, no comments are returned (they aren't necessary)
		commentsByPostHash = make(map[lib.BlockHash][]*lib.PostEntry)
	} else if requestData.GetPostsForGlobalWhitelist {
		postEntries,
			profileEntryMap,
			readerStateMap,
			err = fes.GetPostEntriesForGlobalWhitelist(startPostHash, readerPublicKeyBytes, numToFetch, utxoView, requestData.MediaRequired)
		// if we're getting posts for the global whitelist, no comments are returned (they aren't necessary)
		commentsByPostHash = make(map[lib.BlockHash][]*lib.PostEntry)
	} else if requestData.GetPostsByClout {
		postEntries,
			profileEntryMap,
			err = fes.GetPostEntriesByCloutAfterTimePaginated(readerPublicKeyBytes, requestData.PostsByCloutMinutesLookback, numToFetch)
	} else {
		postEntries,
			commentsByPostHash,
			profileEntryMap,
			readerStateMap,
			err = fes.GetPostEntriesByTimePaginated(startPostHash, readerPublicKeyBytes, numToFetch, utxoView)
	}

	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPostsStateless: Error fetching posts: %v", err))
		return
	}

	// Grab verified username map pointer
	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetPostsStateless: Error fetching verifiedMap: %v", err))
		return
	}

	// Get a utxoView.
	utxoView, err = fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPostsStateless: Error constucting utxoView: %v", err))
		return
	}

	blockedPubKeys, err := fes.GetBlockedPubKeysForUser(readerPublicKeyBytes)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPostsStateless: Error fetching blocked pub keys for user: %v", err))
		return
	}

	postEntryResponses := []*PostEntryResponse{}
	for _, postEntry := range postEntries {
		// If the creator who posted postEntry is in the map of blocked pub keys, skip this postEntry
		if _, ok := blockedPubKeys[*lib.NewPublicKey(postEntry.PosterPublicKey)]; !ok {
			var postEntryResponse *PostEntryResponse
			postEntryResponse, err = fes._postEntryToResponse(postEntry, requestData.AddGlobalFeedBool, fes.Params, utxoView, readerPublicKeyBytes, 2)
			if err != nil {
				// Just ignore posts that fail to convert for whatever reason.
				continue
			}
			profileEntryFound := profileEntryMap[lib.MakePkMapKey(postEntry.PosterPublicKey)]
			postEntryResponse.ProfileEntryResponse = _profileEntryToResponse(
				profileEntryFound, fes.Params, verifiedMap, utxoView)
			commentsFound := commentsByPostHash[*postEntry.PostHash]
			for _, commentEntry := range commentsFound {
				if _, ok = blockedPubKeys[*lib.NewPublicKey(commentEntry.PosterPublicKey)]; !ok {
					commentResponse, err := fes._getCommentResponse(commentEntry, profileEntryMap, requestData.AddGlobalFeedBool, verifiedMap, utxoView, readerPublicKeyBytes)
					if fes._shouldSkipCommentResponse(commentResponse, err) {
						continue
					}

					// Fetch subcomments if needed
					if requestData.FetchSubcomments {
						subcommentsFound := commentsByPostHash[*commentEntry.PostHash]
						for _, subCommentEntry := range subcommentsFound {
							subcommentResponse, err := fes._getCommentResponse(subCommentEntry, profileEntryMap, requestData.AddGlobalFeedBool, verifiedMap, utxoView, readerPublicKeyBytes)
							if fes._shouldSkipCommentResponse(subcommentResponse, err) {
								continue
							}
							commentResponse.Comments = append(commentResponse.Comments, subcommentResponse)
						}
						postEntryResponse.Comments = append(postEntryResponse.Comments, commentResponse)
					}
				}
			}
			postEntryResponse.PostEntryReaderState = readerStateMap[*postEntry.PostHash]
			postEntryResponses = append(postEntryResponses, postEntryResponse)
		}
	}

	if requestData.PostContent != "" {
		lowercaseFilter := strings.ToLower(requestData.PostContent)
		filteredResponses := []*PostEntryResponse{}
		for _, postRes := range postEntryResponses {
			if strings.Contains(strings.ToLower(postRes.Body), lowercaseFilter) {
				filteredResponses = append(filteredResponses, postRes)
			}
		}
		postEntryResponses = filteredResponses
	}

	if requestData.OrderBy == "newest" {
		// Now sort the post list on the timestamp
		sort.Slice(postEntryResponses, func(ii, jj int) bool {
			return postEntryResponses[ii].TimestampNanos > postEntryResponses[jj].TimestampNanos
		})
	} else if requestData.OrderBy == "oldest" {
		sort.Slice(postEntryResponses, func(ii, jj int) bool {
			return postEntryResponses[ii].TimestampNanos < postEntryResponses[jj].TimestampNanos
		})
	} else if requestData.OrderBy == "last_comment" {
		sort.Slice(postEntryResponses, func(ii, jj int) bool {
			lastCommentTimeii := uint64(0)
			if len(postEntryResponses[ii].Comments) > 0 {
				lastCommentTimeii = postEntryResponses[ii].Comments[len(postEntryResponses[ii].Comments)-1].TimestampNanos
			}
			lastCommentTimejj := uint64(0)
			if len(postEntryResponses[jj].Comments) > 0 {
				lastCommentTimejj = postEntryResponses[jj].Comments[len(postEntryResponses[jj].Comments)-1].TimestampNanos
			}
			return lastCommentTimeii > lastCommentTimejj
		})
	}

	// Return the posts found.
	res := &GetPostsStatelessResponse{
		PostsFound: postEntryResponses,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetPostsStateless: Problem encoding response as JSON: %v", err))
		return
	}
}

type GetSinglePostRequest struct {
	// PostHashHex to fetch.
	PostHashHex                string `safeForLogging:"true"`
	FetchParents               bool   `safeForLogging:"true"`
	CommentOffset              uint32 `safeForLogging:"true"`
	CommentLimit               uint32 `safeForLogging:"true"`
	ReaderPublicKeyBase58Check string `safeForLogging:"true"`

	// If set to true, then the posts in the response will contain a boolean about whether they're in the global feed
	AddGlobalFeedBool bool `safeForLogging:"true"`
}

type GetSinglePostResponse struct {
	PostFound *PostEntryResponse
}

func (fes *APIServer) GetSinglePost(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetSinglePostRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetSinglePost: Problem parsing request body: %v", err))
		return
	}

	// Decode the postHash.
	postHash, err := GetPostHashFromPostHashHex(requestData.PostHashHex)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetSinglePost: %v", err))
		return
	}

	// Decode the reader public key into bytes. Default to nil if no pub key is passed in.
	var readerPublicKeyBytes []byte
	if requestData.ReaderPublicKeyBase58Check != "" {
		var err error
		readerPublicKeyBytes, _, err = lib.Base58CheckDecode(requestData.ReaderPublicKeyBase58Check)
		if requestData.ReaderPublicKeyBase58Check != "" && err != nil {
			_AddBadRequestError(ww,
				fmt.Sprintf("GetSinglePost: Problem decoding user public key: %v : %s", err, requestData.ReaderPublicKeyBase58Check))
			return
		}
	}

	// Get a view with all the mempool transactions.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetSinglePost: Error constucting utxoView: %v", err))
		return
	}

	// Fetch the postEntry requested.
	postEntry := utxoView.GetPostEntryForPostHash(postHash)
	if postEntry == nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetSinglePost: Could not find postEntry for PostHashHex: %s", requestData.PostHashHex))
		return
	}

	// Fetch the commentEntries for the post.
	commentEntries, err := utxoView.GetCommentEntriesForParentStakeID(postHash[:])
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetSinglePost: Error getting commentEntries: %v: %s", err, requestData.PostHashHex))
		return
	}

	// Fetch the parents for the post.
	var parentPostEntries []*lib.PostEntry
	var truncatedTree = false
	if requestData.FetchParents {
		parentPostEntries, truncatedTree = utxoView.GetParentPostEntriesForPostEntry(postEntry, 100 /*maxDepth*/, true /*rootFirst*/)
	}

	// Get profiles blocked by the reader.
	blockedPublicKeys, err := fes.GetBlockedPubKeysForUser(readerPublicKeyBytes)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetSinglePost: Problem getting blocked public keys for user: %v", err))
		return
	}

	// Get users blocked by creator of root post.
	var rootBlockedPublicKeys map[lib.PublicKey]struct{}
	// If we were able to get all parents back to the root post that started this thread, get the public keys blocked
	// by the user who posted the root post. If we did not get the post that started this thread, do not use the blocked
	// public keys of creator of the first post in parentPostEntries to filter out comments. truncatedTree will only be
	// true if the currentPost has more than 100  parent posts or whatever we pass as maxDepth to
	// GetParentPostEntriesForPostEntry.  If we restrict the depth at which users can comment, we can remove the logic
	// around truncatedTree.
	if !truncatedTree && len(parentPostEntries) > 0 {
		rootParent := parentPostEntries[0]
		rootBlockedPublicKeys, err = fes.GetBlockedPubKeysForUser(rootParent.PosterPublicKey)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"GetSinglePost: Problem with GetBlockedPubKeysForUser for root entry: publicKey: %v %v", lib.PkToString(rootParent.PosterPublicKey, fes.Params), err))
			return
		}
	} else if len(parentPostEntries) == 0 {
		// If the current post entry we're at is the root, then use that to determine who is blocked.
		rootBlockedPublicKeys, err = fes.GetBlockedPubKeysForUser(postEntry.PosterPublicKey)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"GetSinglePost: Problem with GetBlockedPubKeysForUser for current post entry: publicKey: %v %v", lib.PkToString(postEntry.PosterPublicKey, fes.Params), err))
			return
		}
	}

	// Merge the blocked public keys from the root entry with the blocked public keys of the reader
	for k, v := range rootBlockedPublicKeys {
		blockedPublicKeys[k] = v
	}

	// Create a map of all the profile pub keys associated with our posts + comments.
	profilePubKeyMap := make(map[lib.PkMapKey][]byte)
	profilePubKeyMap[lib.MakePkMapKey(postEntry.PosterPublicKey)] = postEntry.PosterPublicKey

	// Determine whether or not the posters of the "single post" we are fetching is blocked by the reader.  If the
	// poster of the single post is blocked, we will want to include the single post, but not any of the comments
	// created by the poster that are children of this "single post".
	_, isCurrentPosterBlocked := blockedPublicKeys[*lib.NewPublicKey(postEntry.PosterPublicKey)]
	for _, commentEntry := range commentEntries {
		pkMapKey := lib.MakePkMapKey(commentEntry.PosterPublicKey)
		// Remove comments that are blocked by either the reader or the poster of the root post
		if _, ok := blockedPublicKeys[*lib.NewPublicKey(commentEntry.PosterPublicKey)]; !ok && profilePubKeyMap[pkMapKey] == nil {
			profilePubKeyMap[pkMapKey] = commentEntry.PosterPublicKey
		}
	}
	for _, parentPostEntry := range parentPostEntries {
		pkMapKey := lib.MakePkMapKey(parentPostEntry.PosterPublicKey)
		// Remove parents that are blocked by either the reader or the poster of the root post
		if _, ok := blockedPublicKeys[*lib.NewPublicKey(parentPostEntry.PosterPublicKey)]; !ok && profilePubKeyMap[pkMapKey] == nil {
			profilePubKeyMap[pkMapKey] = parentPostEntry.PosterPublicKey
		}
	}

	// Filter out restricted PosterPublicKeys.
	filteredProfilePubKeyMap, err := fes.FilterOutRestrictedPubKeysFromMap(
		profilePubKeyMap, readerPublicKeyBytes, "leaderboard" /*moderationType*/)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetSinglePost: Error filtering out restricted profiles: %v", err))
		return
	}

	// Figure out if the current poster is greylisted.  If the current poster is greylisted, we will add their
	// public key back to the filteredProfileMap so their profile will appear for the current post
	// and any parents, but we will remove any comments by this greylisted user.
	isCurrentPosterGreylisted := false
	if _, ok := filteredProfilePubKeyMap[lib.MakePkMapKey(postEntry.PosterPublicKey)]; !ok {
		// Get the userMetadata for the currentPosters
		currentPosterUserMetadataKey := append([]byte{}, _GlobalStatePrefixPublicKeyToUserMetadata...)
		currentPosterUserMetadataKey = append(currentPosterUserMetadataKey, postEntry.PosterPublicKey...)
		var currentPosterUserMetadataBytes []byte
		currentPosterUserMetadataBytes, err = fes.GlobalStateGet(currentPosterUserMetadataKey)
		if err != nil {
			_AddBadRequestError(ww,
				fmt.Sprintf("GetSinglePost: Problem getting currentPoster uset metadata from global state: %v", err))
			return
		}
		// If the currentPoster's userMetadata doesn't exist, then they are no greylisted, so we can exit.
		if currentPosterUserMetadataBytes != nil {
			// Decode the currentPoster's userMetadata.
			currentPosterUserMetadata := UserMetadata{}
			err = gob.NewDecoder(bytes.NewReader(currentPosterUserMetadataBytes)).Decode(&currentPosterUserMetadata)
			if err != nil {
				_AddBadRequestError(ww,
					fmt.Sprintf("GetSinglePost: Problem decoding currentPoster user metadata: %v", err))
				return
			}
			// If the currentPoster is not blacklisted (removed everywhere) and is greylisted (removed from leaderboard)
			// add them back to the filteredProfilePubKeyMap and note that the currentPoster is greylisted.
			if currentPosterUserMetadata.RemoveFromLeaderboard && !currentPosterUserMetadata.RemoveEverywhere {
				isCurrentPosterGreylisted = true
				filteredProfilePubKeyMap[lib.MakePkMapKey(postEntry.PosterPublicKey)] = postEntry.PosterPublicKey
			}
		}
	}

	// If the profile that posted this post is not in our filtered list, return with error.
	if filteredProfilePubKeyMap[lib.MakePkMapKey(postEntry.PosterPublicKey)] == nil && !isCurrentPosterGreylisted {
		_AddBadRequestError(ww, fmt.Sprintf("GetSinglePost: The poster public key for this post is restricted."))
		return
	}

	// Grab verified username map pointer
	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetSinglePost: Error fetching verifiedMap: %v", err))
		return
	}

	// Get the profile entry for all PosterPublicKeys that passed our filter.
	pubKeyToProfileEntryResponseMap := make(map[lib.PkMapKey]*ProfileEntryResponse)
	for _, pubKeyBytes := range filteredProfilePubKeyMap {
		profileEntry := utxoView.GetProfileEntryForPublicKey(pubKeyBytes)
		if profileEntry == nil {
			continue
		} else {
			pubKeyToProfileEntryResponseMap[lib.MakePkMapKey(pubKeyBytes)] =
				_profileEntryToResponse(profileEntry, fes.Params, verifiedMap, utxoView)
		}
	}

	// If the profile that posted this post does not have a profile, return with error.
	if pubKeyToProfileEntryResponseMap[lib.MakePkMapKey(postEntry.PosterPublicKey)] == nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetSinglePost: The poster public key for this post is restricted."))
		return
	}

	// Create the postEntryResponse.
	postEntryResponse, err := fes._postEntryToResponse(postEntry, requestData.AddGlobalFeedBool /*AddGlobalFeedBool*/, fes.Params, utxoView, readerPublicKeyBytes, 2)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetSinglePost: Error creating postEntryResponse: %v", err))
		return
	}

	// Add reader state and profile to the postEntryResponse.
	postEntryResponse.PostEntryReaderState = utxoView.GetPostEntryReaderState(readerPublicKeyBytes, postEntry)
	postEntryResponse.ProfileEntryResponse = pubKeyToProfileEntryResponseMap[lib.MakePkMapKey(postEntry.PosterPublicKey)]

	// Process parent posts into something we can return.
	parentPostEntryResponseList := []*PostEntryResponse{}
	for _, parentEntry := range parentPostEntries {
		parentProfileEntryResponse := pubKeyToProfileEntryResponseMap[lib.MakePkMapKey(parentEntry.PosterPublicKey)]

		// If the profile is banned, skip this post.
		if parentProfileEntryResponse == nil {
			continue
		}
		// Build the parent entry response and append.
		parentEntryResponse, err := fes._postEntryToResponse(parentEntry, requestData.AddGlobalFeedBool /*AddGlobalFeed*/, fes.Params, utxoView, readerPublicKeyBytes, 2)

		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetSinglePost: Error creating parentEntryResponse: %v", err))
			return
		}

		parentEntryResponse.ProfileEntryResponse = parentProfileEntryResponse
		parentEntryResponse.PostEntryReaderState = utxoView.GetPostEntryReaderState(readerPublicKeyBytes, parentEntry)
		parentPostEntryResponseList = append(parentPostEntryResponseList, parentEntryResponse)
	}

	// Process the comments into something we can return.
	commentEntryResponseList := []*PostEntryResponse{}
	// Create a map from commentEntryPostHashHex to commentEntry to ease look up of public key bytes when sorting
	commentHashHexToCommentEntry := make(map[string]*lib.PostEntry)
	for _, commentEntry := range commentEntries {
		commentProfileEntryResponse := pubKeyToProfileEntryResponseMap[lib.MakePkMapKey(commentEntry.PosterPublicKey)]
		commentAuthorIsCurrentPoster := reflect.DeepEqual(commentEntry.PosterPublicKey, postEntry.PosterPublicKey)
		// Skip comments that:
		//  - Don't have a profile (it was most likely banned).
		//	- Are hidden *AND* don't have comments. Keep hidden posts with comments.
		//  - isDeleted (this was already filtered in an earlier stage and should never be true)
		//	- Skip comment is it's by the poster of the single post we are fetching and the currentPoster is blocked by
		// 	the reader OR the currentPoster is greylisted
		if commentProfileEntryResponse == nil || commentEntry.IsDeleted() ||
			(commentEntry.IsHidden && commentEntry.CommentCount == 0) ||
			(commentAuthorIsCurrentPoster && (isCurrentPosterBlocked || isCurrentPosterGreylisted)) {
			continue
		}

		// Build the comments entry response and append.
		commentEntryResponse, err := fes._postEntryToResponse(commentEntry, requestData.AddGlobalFeedBool /*AddGlobalFeed*/, fes.Params, utxoView, readerPublicKeyBytes, 2)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetSinglePost: Error creating commentEntryResponse: %v", err))
			return
		}
		commentEntryResponse.ProfileEntryResponse = commentProfileEntryResponse
		commentEntryResponse.PostEntryReaderState = utxoView.GetPostEntryReaderState(readerPublicKeyBytes, commentEntry)
		commentEntryResponseList = append(commentEntryResponseList, commentEntryResponse)
		commentHashHexToCommentEntry[commentEntryResponse.PostHashHex] = commentEntry
	}

	posterPKID := utxoView.GetPKIDForPublicKey(postEntry.PosterPublicKey)
	// Almost done. Just need to sort the comments.
	sort.Slice(commentEntryResponseList, func(ii, jj int) bool {
		iiCommentEntryResponse := commentEntryResponseList[ii]
		jjCommentEntryResponse := commentEntryResponseList[jj]
		// If the poster of ii is the poster of the main post and jj is not, ii should be first.
		iiIsPoster := iiCommentEntryResponse.PosterPublicKeyBase58Check == postEntryResponse.PosterPublicKeyBase58Check
		jjIsPoster := jjCommentEntryResponse.PosterPublicKeyBase58Check == postEntryResponse.PosterPublicKeyBase58Check

		// Sort tweet storms from oldest to newest
		if iiIsPoster && jjIsPoster {
			return iiCommentEntryResponse.TimestampNanos < jjCommentEntryResponse.TimestampNanos
		}

		if iiIsPoster && !jjIsPoster {
			return true
		} else if !iiIsPoster && jjIsPoster {
			return false
		}

		// Next we sort based on diamonds given by the poster.
		iiCommentEntry := commentHashHexToCommentEntry[iiCommentEntryResponse.PostHashHex]
		iiDiamondKey := lib.MakeDiamondKey(
			posterPKID.PKID,
			utxoView.GetPKIDForPublicKey(iiCommentEntry.PosterPublicKey).PKID,
			iiCommentEntry.PostHash)
		iiDiamondLevelByPoster := utxoView.GetDiamondEntryForDiamondKey(&iiDiamondKey)

		jjCommentEntry := commentHashHexToCommentEntry[jjCommentEntryResponse.PostHashHex]
		jjDiamondKey := lib.MakeDiamondKey(
			posterPKID.PKID,
			utxoView.GetPKIDForPublicKey(jjCommentEntry.PosterPublicKey).PKID,
			jjCommentEntry.PostHash)
		jjDiamondLevelByPoster := utxoView.GetDiamondEntryForDiamondKey(&jjDiamondKey)

		if iiDiamondLevelByPoster != nil && jjDiamondLevelByPoster == nil {
			// If ii received any diamonds and jj did not receive any, ii is first.
			return true
		} else if iiDiamondLevelByPoster == nil && jjDiamondLevelByPoster != nil {
			// If jj received any diamonds and ii did not receive any, jj is first.
			return false
		} else if iiDiamondLevelByPoster != nil && jjDiamondLevelByPoster != nil {
			// If both ii and jj received diamonds, whichever received more diamonds is placed first.
			// If they received an equal number of diamonds, continue to the tiebreaker below on coin price.
			if iiDiamondLevelByPoster.DiamondLevel > jjDiamondLevelByPoster.DiamondLevel {
				return true
			} else if iiDiamondLevelByPoster.DiamondLevel < jjDiamondLevelByPoster.DiamondLevel {
				return false
			}
		}

		iiCoinPrice := iiCommentEntryResponse.ProfileEntryResponse.CoinEntry.BitCloutLockedNanos
		jjCoinPrice := jjCommentEntryResponse.ProfileEntryResponse.CoinEntry.BitCloutLockedNanos
		if iiCoinPrice > jjCoinPrice {
			return true
		} else if iiCoinPrice < jjCoinPrice {
			return false
		}

		// Finally, if we can't prioritize based on pub key or clout, we use timestamp.
		return iiCommentEntryResponse.TimestampNanos > jjCommentEntryResponse.TimestampNanos
	})

	commentEntryResponseLength := uint32(len(commentEntryResponseList))
	// Slice the comments from the offset up to either the end of the slice or the offset + limit, whichever is smaller.
	maxIdx := lib.MinUint32(commentEntryResponseLength, requestData.CommentOffset+requestData.CommentLimit)
	var comments []*PostEntryResponse
	if commentEntryResponseLength > requestData.CommentOffset {
		comments = commentEntryResponseList[requestData.CommentOffset:maxIdx]
	}
	postEntryResponse.Comments = comments
	postEntryResponse.ParentPosts = parentPostEntryResponseList

	// Return the posts found.
	res := &GetSinglePostResponse{
		PostFound: postEntryResponse,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetSinglePost: Problem encoding response as JSON: %v", err))
		return
	}
}

// GetPostsForPublicKeyRequest ...
type GetPostsForPublicKeyRequest struct {
	// Either PublicKeyBase58Check or Username can be set by the client to specify
	// which user we're obtaining posts for
	// If both are specified, PublicKeyBase58Check will supercede
	PublicKeyBase58Check string `safeForLogging:"true"`
	Username             string `safeForLogging:"true"`

	ReaderPublicKeyBase58Check string `safeForLogging:"true"`
	// PostHashHex of the last post from the previous page
	LastPostHashHex string `safeForLogging:"true"`
	// Number of records to fetch
	NumToFetch    uint64 `safeForLogging:"true"`
	MediaRequired bool   `safeForLogging:"true"`
}

// GetPostsForPublicKeyResponse ...
type GetPostsForPublicKeyResponse struct {
	Posts           []*PostEntryResponse `safeForLogging:"true"`
	LastPostHashHex string               `safeForLogging:"true"`
}

// GetPostsForPublicKey... Get paginated posts for a public key or username.
func (fes *APIServer) GetPostsForPublicKey(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetPostsForPublicKeyRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPostsForPublicKey: Error parsing request body: %v", err))
		return
	}

	// Get a view
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPostsForPublicKey: Error getting utxoView: %v", err))
		return
	}

	// Decode the public key for which we are fetching posts. If a public key is not provided, use the username
	var publicKeyBytes []byte
	if requestData.PublicKeyBase58Check != "" {
		publicKeyBytes, _, err = lib.Base58CheckDecode(requestData.PublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetPostsForPublicKey: Problem decoding user public key: %v", err))
			return
		}
	} else {
		username := requestData.Username
		profileEntry := utxoView.GetProfileEntryForUsername([]byte(username))

		// Return an error if we failed to find a profile entry
		if profileEntry == nil {
			_AddNotFoundError(ww, fmt.Sprintf("GetPostsForPublicKey: could not find profile for username: %v", username))
			return
		}
		publicKeyBytes = profileEntry.PublicKey
	}
	// Decode the reader's public key so we can fetch each post entry's reader state.
	var readerPk []byte
	if requestData.ReaderPublicKeyBase58Check != "" {
		readerPk, _, err = lib.Base58CheckDecode(requestData.ReaderPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetPostsForPublicKey: Problem decoding reader public key: %v", err))
			return
		}
	}

	var startPostHash *lib.BlockHash
	if requestData.LastPostHashHex != "" {
		// Get the StartPostHash from the LastPostHashHex
		startPostHash, err = GetPostHashFromPostHashHex(requestData.LastPostHashHex)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetPostsForPublicKey: %v", err))
			return
		}
	}

	// Get Posts Ordered by time.
	posts, err := utxoView.GetPostsPaginatedForPublicKeyOrderedByTimestamp(publicKeyBytes, startPostHash, requestData.NumToFetch, requestData.MediaRequired)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPostsForPublicKey: Problem getting paginated posts: %v", err))
		return
	}

	sort.Slice(posts, func(ii, jj int) bool {
		return posts[ii].TimestampNanos > posts[jj].TimestampNanos
	})

	// GetPostsPaginated returns all posts from the db and mempool, so we need to find the correct section of the
	// slice to return.
	if uint64(len(posts)) > requestData.NumToFetch || startPostHash != nil {
		startIndex := 0
		if startPostHash != nil {
			for ii, post := range posts {
				if reflect.DeepEqual(post.PostHash, startPostHash) {
					startIndex = ii + 1
					break
				}
			}
		}
		posts = posts[startIndex:lib.MinInt(len(posts), startIndex+int(requestData.NumToFetch))]
	}

	// Convert postEntries to postEntryResponses and fetch PostEntryReaderState for each post.
	var postEntryResponses []*PostEntryResponse
	for _, post := range posts {
		var postEntryResponse *PostEntryResponse
		postEntryResponse, err = fes._postEntryToResponse(post, true, fes.Params, utxoView, readerPk, 2)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetPostsForPublicKey: Problem converting post entry to response: %v", err))
			return
		}
		if readerPk != nil {
			postEntryReaderState := utxoView.GetPostEntryReaderState(readerPk, post)
			postEntryResponse.PostEntryReaderState = postEntryReaderState
		}
		postEntryResponses = append(postEntryResponses, postEntryResponse)
	}
	// Return the last post hash hex in the slice to simplify pagination.
	var lastPostHashHex string
	if len(postEntryResponses) > 0 {
		lastPostHashHex = postEntryResponses[len(postEntryResponses)-1].PostHashHex
	}
	res := GetPostsForPublicKeyResponse{
		Posts:           postEntryResponses,
		LastPostHashHex: lastPostHashHex,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetPostsForPublicKey: Problem serializing object to JSON: %v", err))
		return
	}
}

type GetPostsDiamondedBySenderForReceiverRequest struct {
	// Public key of the poster who received diamonds from the sender
	ReceiverPublicKeyBase58Check string

	// Username of Receiver
	ReceiverUsername string

	// Public key of the sender who gave diamonds to receiver
	SenderPublicKeyBase58Check string

	// Username of Sender
	SenderUsername string

	// Public key of the reader to get the post entry reader state
	ReaderPublicKeyBase58Check string

	// Start Post Hash Hex
	StartPostHashHex string

	// NumToFetch
	NumToFetch uint64
}

type GetPostsDiamondedBySenderForReceiverResponse struct {
	// Map of diamond level to a list of post entry responses ordered by timestamp
	DiamondedPosts []*PostEntryResponse

	// Sum of all diamonds sender gave to receiver
	TotalDiamondsGiven uint64

	ReceiverProfileEntryResponse *ProfileEntryResponse

	SenderProfileEntryResponse *ProfileEntryResponse
}

func (fes *APIServer) GetDiamondedPosts(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetPostsDiamondedBySenderForReceiverRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetDiamondedPosts: Problem parsing request body: %v", err))
		return
	}

	// Get a view
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDiamondedPosts: Error getting utxoView: %v", err))
		return
	}

	var receiverPublicKeyBytes []byte
	var receiverProfileEntry *lib.ProfileEntry
	if requestData.ReceiverPublicKeyBase58Check != "" {
		// Decode the receiver public key for which we are fetching posts that were diamonded.
		receiverPublicKeyBytes, _, err = lib.Base58CheckDecode(requestData.ReceiverPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetDiamondedPosts: Problem decoding receiver public key: %v", err))
			return
		}
		receiverProfileEntry = utxoView.GetProfileEntryForPublicKey(receiverPublicKeyBytes)
	} else if requestData.ReceiverUsername != "" {
		receiverProfileEntry = utxoView.GetProfileEntryForUsername([]byte(strings.ToLower(requestData.ReceiverUsername)))
		if receiverProfileEntry == nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetDiamondedPosts: No profile entry found for receiver username: %v", requestData.ReceiverUsername))
			return
		}
		receiverPublicKeyBytes = receiverProfileEntry.PublicKey
	} else {
		_AddBadRequestError(ww, fmt.Sprintf("GetDiamondedPosts: Neither ReceiverPublicKeyBase58Check nor ReceiverUsername provided"))
		return
	}

	var senderPublicKeyBytes []byte
	var senderProfileEntry *lib.ProfileEntry
	if requestData.SenderPublicKeyBase58Check != "" {
		// Decode the sender public key for which we are fetching posts that were diamonded.
		senderPublicKeyBytes, _, err = lib.Base58CheckDecode(requestData.SenderPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetDiamondedPosts: Problem decoding sender public key: %v", err))
			return
		}
		senderProfileEntry = utxoView.GetProfileEntryForPublicKey(senderPublicKeyBytes)
	} else if requestData.SenderUsername != "" {
		senderProfileEntry = utxoView.GetProfileEntryForUsername([]byte(strings.ToLower(requestData.SenderUsername)))
		if senderProfileEntry == nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetDiamondedPosts: No profile entry found for sender username: %v", requestData.SenderUsername))
			return
		}
		senderPublicKeyBytes = senderProfileEntry.PublicKey
	} else {
		_AddBadRequestError(ww, fmt.Sprintf("GetDiamondedPosts: Neither SenderPublicKeyBase58Check nor SenderUsername provided"))
		return
	}

	// Decode the reader public key.
	readerPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.ReaderPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDiamondedPosts: Problem decoding reader public key: %v", err))
		return
	}

	// Get the DiamondEntries for this receiver-sender pair of public keys.
	diamondEntries, err := utxoView.GetDiamondEntriesForSenderToReceiver(receiverPublicKeyBytes, senderPublicKeyBytes)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDiamondedPosts: Problem getting diamond entries: %v", err))
		return
	}

	// Grab verified username map pointer so we can verify the profiles.
	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetDiamondedPosts: Error fetching verifiedMap: %v", err))
		return
	}

	totalDiamondsGiven := uint64(0)
	var diamondedPosts []*PostEntryResponse
	for _, diamondEntry := range diamondEntries {
		totalDiamondsGiven += uint64(diamondEntry.DiamondLevel)
		postEntry := utxoView.GetPostEntryForPostHash(diamondEntry.DiamondPostHash)
		if postEntry != nil && !postEntry.IsDeleted() && !postEntry.IsHidden {
			var postEntryResponse *PostEntryResponse
			postEntryResponse, err = fes._postEntryToResponse(postEntry, false, fes.Params, utxoView, readerPublicKeyBytes, 2)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("GetDiamondedPosts: Problem converting post entry to response: %v", err))
				return
			}
			postEntryReaderState := utxoView.GetPostEntryReaderState(readerPublicKeyBytes, postEntry)
			postEntryResponse.PostEntryReaderState = postEntryReaderState
			postEntryResponse.DiamondsFromSender = uint64(diamondEntry.DiamondLevel)
			if postEntry.ParentStakeID != nil && len(postEntry.ParentStakeID) == lib.HashSizeBytes {
				parentPostEntry := utxoView.GetPostEntryForPostHash(lib.NewBlockHash(postEntry.ParentStakeID))
				if parentPostEntry == nil {
					_AddBadRequestError(ww, fmt.Sprintf(
						"GetDiamondedPosts: Problem getting parent post with postHash %v for postEntry with hash %v",
						hex.EncodeToString(postEntry.ParentStakeID), hex.EncodeToString(postEntry.PostHash[:])))
					return
				}
				var parentPostEntryResponse *PostEntryResponse
				parentPostEntryResponse, err = fes._postEntryToResponse(parentPostEntry, false, fes.Params, utxoView, readerPublicKeyBytes, 2)
				if err != nil {
					_AddBadRequestError(ww, fmt.Sprintf("GetDiamondedPosts: Problem converting parent post entry to response: %v", err))
				}
				parentProfileEntry := utxoView.GetProfileEntryForPublicKey(parentPostEntry.PosterPublicKey)
				parentPostEntryResponse.ProfileEntryResponse = _profileEntryToResponse(parentProfileEntry, fes.Params, verifiedMap, utxoView)
				postEntryResponse.ParentPosts = []*PostEntryResponse{parentPostEntryResponse}
			}
			diamondedPosts = append(diamondedPosts, postEntryResponse)
		}
	}

	// Now sort posts by diamond level then timestamp
	sort.Slice(diamondedPosts, func(ii, jj int) bool {
		postii := diamondedPosts[ii]
		postjj := diamondedPosts[jj]

		if postii.DiamondsFromSender > postjj.DiamondsFromSender {
			return true
		}
		if postii.DiamondsFromSender < postjj.DiamondsFromSender {
			return false
		}
		return postii.TimestampNanos > postjj.TimestampNanos
	})

	startPostHashHex := requestData.StartPostHashHex
	numToFetch := int(requestData.NumToFetch)
	if startPostHashHex != "" || len(diamondedPosts) > numToFetch {
		startIndex := 0
		if startPostHashHex != "" {
			for ii, postEntryResponse := range diamondedPosts {
				if postEntryResponse.PostHashHex == startPostHashHex {
					startIndex = ii + 1
					break
				}
			}
		}
		diamondedPosts = diamondedPosts[startIndex:lib.MinInt(startIndex+numToFetch, len(diamondedPosts)-1)]
	}

	res := &GetPostsDiamondedBySenderForReceiverResponse{
		DiamondedPosts:               diamondedPosts,
		TotalDiamondsGiven:           totalDiamondsGiven,
		ReceiverProfileEntryResponse: _profileEntryToResponse(receiverProfileEntry, fes.Params, verifiedMap, utxoView),
		SenderProfileEntryResponse:   _profileEntryToResponse(senderProfileEntry, fes.Params, verifiedMap, utxoView),
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDiamondedPosts: Problem encoding response as JSON: %v", err))
		return
	}
}

type GetLikesForPostRequest struct {
	// PostHashHex to fetch.
	PostHashHex                string `safeForLogging:"true"`
	Offset                     uint32 `safeForLogging:"true"`
	Limit                      uint32 `safeForLogging:"true"`
	ReaderPublicKeyBase58Check string `safeForLogging:"true"`
}

type GetLikesForPostResponse struct {
	Likers []*ProfileEntryResponse
}

func (fes *APIServer) GetLikesForPost(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetLikesForPostRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww,
			fmt.Sprintf("GetLikesForPost: Problem parsing request body: %v", err))
		return
	}

	postHash, err := GetPostHashFromPostHashHex(requestData.PostHashHex)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetLikesForPost: %v", err))
		return
	}

	// Decode the reader public key into bytes. Default to nil if no pub key is passed in.
	var readerPublicKeyBytes []byte
	if requestData.ReaderPublicKeyBase58Check != "" {
		readerPublicKeyBytes, _, err = lib.Base58CheckDecode(requestData.ReaderPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetLikesForPost: Problem decoding user public key: %v : %s", err,
				requestData.ReaderPublicKeyBase58Check))
			return
		}
	}

	// Get a view with all the mempool transactions.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetLikesForPost: Error constucting utxoView: %v", err))
		return
	}

	// Fetch the likers for the post requested.
	likerPubKeys, err := utxoView.GetLikesForPostHash(postHash)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetLikesForPost: Error getting likers %v", err))
		return
	}

	// Filter out any restricted profiles.
	pkMapToFilter := make(map[lib.PkMapKey][]byte)
	for _, pubKey := range likerPubKeys {
		pkMapKey := lib.MakePkMapKey(pubKey)
		pkMapToFilter[pkMapKey] = pubKey
	}

	var filteredPkMap map[lib.PkMapKey][]byte
	if addReaderPublicKey := utxoView.GetLikedByReader(readerPublicKeyBytes, postHash); addReaderPublicKey {
		filteredPkMap, err = fes.FilterOutRestrictedPubKeysFromMap(pkMapToFilter, readerPublicKeyBytes, "leaderboard" /*moderationType*/)
	} else {
		filteredPkMap, err = fes.FilterOutRestrictedPubKeysFromMap(pkMapToFilter, nil, "leaderboard" /*moderationType*/)
	}
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetLikesForPost: Error filtering out restricted profiles: %v", err))
		return
	}

	// Grab verified username map pointer for constructing profile entry responses.
	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetLikesForPost: Error fetching verifiedMap: %v", err))
		return
	}

	// Create a list of the likers that were not restricted.
	likers := []*ProfileEntryResponse{}
	for _, filteredPubKey := range filteredPkMap {
		profileEntry := utxoView.GetProfileEntryForPublicKey(filteredPubKey)
		if profileEntry == nil {
			continue
		}
		profileEntryResponse := _profileEntryToResponse(profileEntry, fes.Params, verifiedMap, utxoView)
		likers = append(likers, profileEntryResponse)
	}

	// Almost done. Just need to sort the likers.
	sort.Slice(likers, func(ii, jj int) bool {

		// Attempt to sort on bitclout locked.
		iiBitCloutLocked := likers[ii].CoinEntry.BitCloutLockedNanos
		jjBitCloutLocked := likers[jj].CoinEntry.BitCloutLockedNanos
		if iiBitCloutLocked > jjBitCloutLocked {
			return true
		} else if iiBitCloutLocked < jjBitCloutLocked {
			return false
		}

		// Sort based on pub key if all else fails.
		return likers[ii].PublicKeyBase58Check > likers[jj].PublicKeyBase58Check
	})

	// Cut out the page of reclouters that we care about.
	likersLength := uint32(len(likers))
	// Slice the comments from the offset up to either the end of the slice or the offset + limit, whichever is smaller.
	maxIdx := lib.MinUint32(likersLength, requestData.Offset+requestData.Limit)
	likersPage := []*ProfileEntryResponse{}
	if likersLength > requestData.Offset {
		likersPage = likers[requestData.Offset:maxIdx]
	}

	// Return the posts found.
	res := &GetLikesForPostResponse{
		Likers: likersPage,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetLikesForPost: Problem encoding response as JSON: %v", err))
		return
	}
}

type GetDiamondsForPostRequest struct {
	// PostHashHex to fetch.
	PostHashHex                string `safeForLogging:"true"`
	Offset                     uint32 `safeForLogging:"true"`
	Limit                      uint32 `safeForLogging:"true"`
	ReaderPublicKeyBase58Check string `safeForLogging:"true"`
}

type GetDiamondsForPostResponse struct {
	DiamondSenders []*DiamondSenderResponse
}

type DiamondSenderResponse struct {
	DiamondSenderProfile *ProfileEntryResponse
	DiamondLevel         int64
}

func (fes *APIServer) GetDiamondsForPost(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetDiamondsForPostRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDiamondsForPost: Problem parsing request body: %v", err))
		return
	}

	postHash, err := GetPostHashFromPostHashHex(requestData.PostHashHex)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDiamondsForPost: %v", err))
		return
	}

	// Decode the reader public key into bytes. Default to nil if no pub key is passed in.
	var readerPublicKeyBytes []byte
	if requestData.ReaderPublicKeyBase58Check != "" {
		readerPublicKeyBytes, _, err = lib.Base58CheckDecode(requestData.ReaderPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww,
				fmt.Sprintf("GetDiamondsForPost: Problem decoding user public key: %v : %s", err, requestData.ReaderPublicKeyBase58Check))
			return
		}
	}

	// Get a view with all the mempool transactions.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDiamondsForPost: Error constucting utxoView: %v", err))
		return
	}

	// Fetch the diamonds for the post requested.
	pkidToDiamondLevel, err := utxoView.GetDiamondSendersForPostHash(postHash)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDiamondsForPost: Error getting pkidToDiamondLevel map %v", err))
		return
	}

	// Filter out any restricted profiles.
	pkMapToFilter := make(map[lib.PkMapKey][]byte)
	for senderPKID := range pkidToDiamondLevel {
		if profileEntry := utxoView.GetProfileEntryForPKID(&senderPKID); profileEntry != nil {
			pkMapKey := lib.MakePkMapKey(profileEntry.PublicKey)
			pkMapToFilter[pkMapKey] = profileEntry.PublicKey
		}
	}
	filteredPkMap, err := fes.FilterOutRestrictedPubKeysFromMap(pkMapToFilter, readerPublicKeyBytes, "leaderboard" /*moderationType*/)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDiamondsForPost: Error filtering out restricted profiles: %v", err))
		return
	}

	// Create a list of unfiltered (aka not blacklisted) diamondSenders.
	diamondSenders := []*lib.ProfileEntry{}
	for senderPKID := range pkidToDiamondLevel {
		profileEntry := utxoView.GetProfileEntryForPKID(&senderPKID)
		if profileEntry == nil {
			continue
		}
		if _, ok := filteredPkMap[lib.MakePkMapKey(profileEntry.PublicKey)]; ok {
			diamondSenders = append(diamondSenders, profileEntry)
		}
	}

	// Almost done. Just need to sort the comments.
	sort.Slice(diamondSenders, func(ii, jj int) bool {

		// Attempt to sort on bitclout locked.
		iiBitCloutLocked := diamondSenders[ii].BitCloutLockedNanos
		jjBitCloutLocked := diamondSenders[jj].BitCloutLockedNanos
		if iiBitCloutLocked > jjBitCloutLocked {
			return true
		} else if iiBitCloutLocked < jjBitCloutLocked {
			return false
		}

		// Attempt to sort on diamond level.
		iiPKID := utxoView.GetPKIDForPublicKey(diamondSenders[ii].PublicKey)
		jjPKID := utxoView.GetPKIDForPublicKey(diamondSenders[jj].PublicKey)
		iiDiamondLevel := pkidToDiamondLevel[*iiPKID.PKID]
		jjDiamondLevel := pkidToDiamondLevel[*jjPKID.PKID]
		if iiDiamondLevel > jjDiamondLevel {
			return true
		} else if iiDiamondLevel < jjDiamondLevel {
			return false
		}

		// Sort based on pub key if all else fails.
		return lib.PkToString(diamondSenders[ii].PublicKey, fes.Params) > lib.PkToString(diamondSenders[jj].PublicKey, fes.Params)
	})

	// Cut out the page of diamondSenders that we care about.
	diamondSendersLength := uint32(len(diamondSenders))
	// Slice the comments from the offset up to either the end of the slice or the offset + limit, whichever is smaller.
	maxIdx := lib.MinUint32(diamondSendersLength, requestData.Offset+requestData.Limit)
	diamondSendersPage := []*lib.ProfileEntry{}
	if diamondSendersLength > requestData.Offset {
		diamondSendersPage = diamondSenders[requestData.Offset:maxIdx]
	}

	// Grab verified username map pointer for constructing profile entry responses.
	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetDiamondsForPost: Error fetching verifiedMap: %v", err))
		return
	}

	// Convert final page of diamondSenders to a list of diamondSender responses.
	diamondSenderResponses := []*DiamondSenderResponse{}
	for _, diamondSender := range diamondSendersPage {
		diamondSenderPKID := utxoView.GetPKIDForPublicKey(diamondSender.PublicKey)
		diamondSenderResponse := &DiamondSenderResponse{
			DiamondSenderProfile: _profileEntryToResponse(diamondSender, fes.Params, verifiedMap, utxoView),
			DiamondLevel:         pkidToDiamondLevel[*diamondSenderPKID.PKID],
		}
		diamondSenderResponses = append(diamondSenderResponses, diamondSenderResponse)
	}

	// Return the posts found.
	res := &GetDiamondsForPostResponse{
		DiamondSenders: diamondSenderResponses,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDiamondsForPost: Problem encoding response as JSON: %v", err))
		return
	}
}

type GetRecloutsForPostRequest struct {
	// PostHashHex to fetch.
	PostHashHex                string `safeForLogging:"true"`
	Offset                     uint32 `safeForLogging:"true"`
	Limit                      uint32 `safeForLogging:"true"`
	ReaderPublicKeyBase58Check string `safeForLogging:"true"`
}

type GetRecloutsForPostResponse struct {
	Reclouters []*ProfileEntryResponse
}

func (fes *APIServer) GetRecloutsForPost(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetRecloutsForPostRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetRecloutsForPost: Problem parsing request body: %v", err))
		return
	}

	postHash, err := GetPostHashFromPostHashHex(requestData.PostHashHex)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetRecloutsForPost: %v", err))
		return
	}

	// Decode the reader public key into bytes. Default to nil if no pub key is passed in.
	var readerPublicKeyBytes []byte
	if requestData.ReaderPublicKeyBase58Check != "" {
		readerPublicKeyBytes, _, err = lib.Base58CheckDecode(requestData.ReaderPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetRecloutsForPost: Problem decoding user public key: %v : %s", err, requestData.ReaderPublicKeyBase58Check))
			return
		}
	}

	// Get a view with all the mempool transactions.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetRecloutsForPost: Error constucting utxoView: %v", err))
		return
	}

	// Fetch the reclouters for the post requested.
	reclouterPubKeys, err := utxoView.GetRecloutsForPostHash(postHash)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetRecloutsForPost: Error getting reclouters %v", err))
		return
	}

	// Filter out any restricted profiles.
	pkMapToFilter := make(map[lib.PkMapKey][]byte)
	for _, pubKey := range reclouterPubKeys {
		pkMapKey := lib.MakePkMapKey(pubKey)
		pkMapToFilter[pkMapKey] = pubKey
	}

	var filteredPkMap map[lib.PkMapKey][]byte
	if _, addReaderPublicKey := utxoView.GetRecloutPostEntryStateForReader(readerPublicKeyBytes, postHash); addReaderPublicKey {
		filteredPkMap, err = fes.FilterOutRestrictedPubKeysFromMap(
			pkMapToFilter, readerPublicKeyBytes, "leaderboard" /*moderationType*/)
	} else {
		filteredPkMap, err = fes.FilterOutRestrictedPubKeysFromMap(pkMapToFilter, nil, "leaderboard" /*moderationType*/)
	}
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetRecloutsForPost: Error filtering out restricted profiles: %v", err))
		return
	}

	// Grab verified username map pointer for constructing profile entry responses.
	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetRecloutsForPost: Error fetching verifiedMap: %v", err))
		return
	}

	// Create a list of the reclouters that were not restricted.
	reclouters := []*ProfileEntryResponse{}
	for _, filteredPubKey := range filteredPkMap {
		profileEntry := utxoView.GetProfileEntryForPublicKey(filteredPubKey)
		if profileEntry == nil {
			continue
		}
		profileEntryResponse := _profileEntryToResponse(profileEntry, fes.Params, verifiedMap, utxoView)
		reclouters = append(reclouters, profileEntryResponse)
	}

	// Almost done. Just need to sort the comments.
	sort.Slice(reclouters, func(ii, jj int) bool {

		// Attempt to sort on bitclout locked.
		iiBitCloutLocked := reclouters[ii].CoinEntry.BitCloutLockedNanos
		jjBitCloutLocked := reclouters[jj].CoinEntry.BitCloutLockedNanos
		if iiBitCloutLocked > jjBitCloutLocked {
			return true
		} else if iiBitCloutLocked < jjBitCloutLocked {
			return false
		}

		// Sort based on pub key if all else fails.
		return reclouters[ii].PublicKeyBase58Check > reclouters[jj].PublicKeyBase58Check
	})

	// Cut out the page of reclouters that we care about.
	recloutersLength := uint32(len(reclouters))
	// Slice the comments from the offset up to either the end of the slice or the offset + limit, whichever is smaller.
	maxIdx := lib.MinUint32(recloutersLength, requestData.Offset+requestData.Limit)
	recloutersPage := []*ProfileEntryResponse{}
	if recloutersLength > requestData.Offset {
		recloutersPage = reclouters[requestData.Offset:maxIdx]
	}

	// Return the posts found.
	res := &GetRecloutsForPostResponse{
		Reclouters: recloutersPage,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetRecloutsForPost: Problem encoding response as JSON: %v", err))
		return
	}
}

type GetQuoteRecloutsForPostRequest struct {
	// PostHashHex to fetch.
	PostHashHex                string `safeForLogging:"true"`
	Offset                     uint32 `safeForLogging:"true"`
	Limit                      uint32 `safeForLogging:"true"`
	ReaderPublicKeyBase58Check string `safeForLogging:"true"`
}

type GetQuoteRecloutsForPostResponse struct {
	QuoteReclouts []*PostEntryResponse
}

func (fes *APIServer) GetQuoteRecloutsForPost(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetQuoteRecloutsForPostRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetQuoteRecloutsForPost: Problem parsing request body: %v", err))
		return
	}

	postHash, err := GetPostHashFromPostHashHex(requestData.PostHashHex)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetQuoteRecloutsForPost: %v", err))
		return
	}

	// Decode the reader public key into bytes. Default to nil if no pub key is passed in.
	var readerPublicKeyBytes []byte
	if requestData.ReaderPublicKeyBase58Check != "" {
		readerPublicKeyBytes, _, err = lib.Base58CheckDecode(requestData.ReaderPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetQuoteRecloutsForPost: Problem decoding user public key: %v : %s",
				err, requestData.ReaderPublicKeyBase58Check))
			return
		}
	}

	// Get a view with all the mempool transactions.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetQuoteRecloutsForPost: Error constucting utxoView: %v", err))
		return
	}

	// Fetch the quote reclouts for the post requested.
	quoteReclouterPubKeys, quoteReclouterPubKeyToPosts, err := utxoView.GetQuoteRecloutsForPostHash(postHash)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetQuoteRecloutsForPost: Error getting reclouters %v", err))
		return
	}

	// Filter out any restricted profiles.
	filteredPubKeys, err := fes.FilterOutRestrictedPubKeysFromList(
		quoteReclouterPubKeys, readerPublicKeyBytes, "leaderboard" /*moderationType*/)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetQuoteRecloutsForPost: Error filtering out restricted profiles: %v", err))
		return
	}

	// Grab verified username map pointer for constructing profile entry responses.
	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetQuoteRecloutsForPost: Error fetching verifiedMap: %v", err))
		return
	}

	// Create a list of all the quote reclouts.
	quoteReclouts := []*PostEntryResponse{}
	for _, filteredPubKey := range filteredPubKeys {
		// We get profile entries first since we do not include pub keys without profiles.
		profileEntry := utxoView.GetProfileEntryForPublicKey(filteredPubKey)
		if profileEntry == nil {
			continue
		}

		// Now that we have a non-nil profile, fetch the post and make the PostEntryResponse.
		recloutPostEntries := quoteReclouterPubKeyToPosts[lib.MakePkMapKey(filteredPubKey)]
		profileEntryResponse := _profileEntryToResponse(profileEntry, fes.Params, verifiedMap, utxoView)
		for _, recloutPostEntry := range recloutPostEntries {
			recloutPostEntryResponse, err := fes._postEntryToResponse(
				recloutPostEntry, false, fes.Params, utxoView, readerPublicKeyBytes, 2)
			if err != nil {
				_AddInternalServerError(ww, fmt.Sprintf("GetQuoteRecloutsForPost: Error creating PostEntryResponse: %v", err))
				return
			}
			recloutPostEntryResponse.ProfileEntryResponse = profileEntryResponse
			recloutPostEntryResponse.PostEntryReaderState = utxoView.GetPostEntryReaderState(readerPublicKeyBytes, recloutPostEntry)
			// Attach the finished recloutPostEntryResponse.
			quoteReclouts = append(quoteReclouts, recloutPostEntryResponse)
		}
	}

	// Almost done. Just need to sort the comments.
	sort.Slice(quoteReclouts, func(ii, jj int) bool {
		iiProfile := quoteReclouts[ii].ProfileEntryResponse
		jjProfile := quoteReclouts[jj].ProfileEntryResponse

		// Attempt to sort on bitclout locked.
		iiBitCloutLocked := iiProfile.CoinEntry.BitCloutLockedNanos
		jjBitCloutLocked := jjProfile.CoinEntry.BitCloutLockedNanos
		if iiBitCloutLocked > jjBitCloutLocked {
			return true
		} else if iiBitCloutLocked < jjBitCloutLocked {
			return false
		}

		// If bitclout locked is the same, sort on timestamp.
		if quoteReclouts[ii].TimestampNanos > quoteReclouts[jj].TimestampNanos {
			return true
		} else if quoteReclouts[ii].TimestampNanos < quoteReclouts[jj].TimestampNanos {
			return false
		}

		// Sort based on pub key if all else fails.
		return iiProfile.PublicKeyBase58Check > jjProfile.PublicKeyBase58Check
	})

	// Cut out the page of reclouters that we care about.
	quoteRecloutsLength := uint32(len(quoteReclouts))
	// Slice the comments from the offset up to either the end of the slice or the offset + limit, whichever is smaller.
	maxIdx := lib.MinUint32(quoteRecloutsLength, requestData.Offset+requestData.Limit)
	quoteRecloutsPage := []*PostEntryResponse{}
	if quoteRecloutsLength > requestData.Offset {
		quoteRecloutsPage = quoteReclouts[requestData.Offset:maxIdx]
	}

	// Return the posts found.
	res := &GetQuoteRecloutsForPostResponse{
		QuoteReclouts: quoteRecloutsPage,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetQuoteRecloutsForPost: Problem encoding response as JSON: %v", err))
		return
	}
}

func GetPostHashFromPostHashHex(postHashHex string) (*lib.BlockHash, error) {
	// Decode the postHash.
	var postHash *lib.BlockHash
	if postHashHex == "" {
		return nil, fmt.Errorf("Must provide a PostHashHex to fetch.")
	}
	postHashBytes, err := hex.DecodeString(postHashHex)
	if err != nil || len(postHashBytes) != lib.HashSizeBytes {
		return nil, fmt.Errorf("Error parsing post hash %v: %v", postHashHex, err)
	}
	postHash = &lib.BlockHash{}
	copy(postHash[:], postHashBytes)
	return postHash, nil
}

func (fes *APIServer) GetPostsForFollowFeedForPublicKey(bav *lib.UtxoView, startAfterPostHash *lib.BlockHash, publicKey []byte, numToFetch int, skipHidden bool, mediaRequired bool) (
	_postEntries []*lib.PostEntry, _err error) {
	// Get the people who follow publicKey
	// Note: GetFollowEntriesForPublicKey also loads them into the view
	followEntries, err := bav.GetFollowEntriesForPublicKey(publicKey, false /* getEntriesFollowingPublicKey */)

	if err != nil {
		return nil, errors.Wrapf(
			err, "GetPostsForFollowFeedForPublicKey: Problem fetching FollowEntries from augmented UtxoView: ")
	}

	// Extract the followed pub keys from the follow entries.
	followedPubKeysMap := make(map[lib.PkMapKey][]byte)
	for _, followEntry := range followEntries {
		// Each follow entry needs to be converted back to a public key to stay consistent with
		// the old logic.
		pubKeyForPKID := bav.GetPublicKeyForPKID(followEntry.FollowedPKID)
		if len(pubKeyForPKID) == 0 {
			glog.Errorf("GetPostsForFollowFeedForPublicKey found PKID %v that "+
				"does not have public key mapping; this should never happen",
				lib.PkToString(followEntry.FollowedPKID[:], bav.Params))
			continue
		}
		followedPubKeysMap[lib.MakePkMapKey(pubKeyForPKID)] = pubKeyForPKID
	}

	// Filter out any restricted pub keys.
	filteredPubKeysMap, err := fes.FilterOutRestrictedPubKeysFromMap(followedPubKeysMap, publicKey, "")
	if err != nil {
		return nil, errors.Wrapf(err, "GetPostsForFollowFeedForPublicKey: Problem filtering out restricted public keys: ")
	}

	minTimestampNanos := uint64(time.Now().UTC().AddDate(0, 0, -2).UnixNano()) // two days ago
	// For each of these pub keys, get their posts, and load them into the view too
	for _, followedPubKey := range filteredPubKeysMap {

		_, dbPostAndCommentHashes, _, err := lib.DBGetAllPostsAndCommentsForPublicKeyOrderedByTimestamp(
			bav.Handle, followedPubKey, false /*fetchEntries*/, minTimestampNanos, 0, /*maxTimestampNanos*/
		)
		if err != nil {
			return nil, errors.Wrapf(err, "GetPostsForFollowFeedForPublicKey: Problem fetching PostEntry's from db: ")
		}

		// Iterate through the entries found in the db and force the view to load them.
		// This fills in any gaps in the view so that, after this, the view should contain
		// the union of what it had before plus what was in the db.
		for _, dbPostOrCommentHash := range dbPostAndCommentHashes {
			bav.GetPostEntryForPostHash(dbPostOrCommentHash)
		}
	}

	// Iterate over the view. Put all posts authored by people you follow into an array
	var postEntriesForFollowFeed []*lib.PostEntry
	for _, postEntry := range bav.PostHashToPostEntry {
		// Ignore deleted or hidden posts and any comments.
		if postEntry.IsDeleted() || (postEntry.IsHidden && skipHidden) || len(postEntry.ParentStakeID) != 0 {
			continue
		}

		// mediaRequired set to determine if we only want posts that include media and ignore posts without
		if mediaRequired && !postEntry.HasMedia() {
			continue
		}

		if _, isFollowedByUser := followedPubKeysMap[lib.MakePkMapKey(postEntry.PosterPublicKey)]; isFollowedByUser {
			postEntriesForFollowFeed = append(postEntriesForFollowFeed, postEntry)
		}
	}

	// Sort the post entries by time (newest to oldest)
	sort.Slice(postEntriesForFollowFeed, func(ii, jj int) bool {
		return postEntriesForFollowFeed[ii].TimestampNanos > postEntriesForFollowFeed[jj].TimestampNanos
	})

	var startIndex = 0
	if startAfterPostHash != nil {
		var indexOfStartAfterPostHash int
		// Find the index of the starting post so that we can paginate the result
		for index, postEntry := range postEntriesForFollowFeed {
			if *postEntry.PostHash == *startAfterPostHash {
				indexOfStartAfterPostHash = index
				break
			}
		}
		// the first element of our new slice should be the element AFTER startAfterPostHash
		startIndex = indexOfStartAfterPostHash + 1
	}

	endIndex := lib.MinInt((startIndex + numToFetch), len(postEntriesForFollowFeed))

	return postEntriesForFollowFeed[startIndex:endIndex], nil
}

// Fetches all the posts from the db starting with a given postHash, up to numToFetch.
// This is then joined with mempool and all posts are returned.  Because the mempool may contain
// post changes, the number of posts returned in the map is not guaranteed to be numToFetch.
func (fes *APIServer) GetPostsByTime(bav *lib.UtxoView, startPostHash *lib.BlockHash, readerPK []byte, numToFetch int, skipHidden bool, skipVanillaReclout bool) (
	_corePosts []*lib.PostEntry, _commentsByPostHash map[lib.BlockHash][]*lib.PostEntry, _err error) {

	var startPost *lib.PostEntry
	if startPostHash != nil {
		startPost = bav.GetPostEntryForPostHash(startPostHash)
	}

	var startTstampNanos uint64
	if startPost != nil {
		startTstampNanos = startPost.TimestampNanos
	}

	allCorePosts := []*lib.PostEntry{}
	addedPostHashes := make(map[lib.BlockHash]struct{})
	skipFirstPost := false
	for len(allCorePosts) < numToFetch {
		// Start by fetching the posts we have in the db.
		dbPostHashes, _, _, err := lib.DBGetPaginatedPostsOrderedByTime(
			bav.Handle, startTstampNanos, startPostHash, numToFetch, false /*fetchEntries*/, true)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "GetAllProfiles: Problem fetching ProfileEntrys from db: ")
		}

		// If we have not found any new post hashes, we exist
		if len(dbPostHashes) == 0 || (len(dbPostHashes) == 1 && skipFirstPost) {
			break
		}
		skipFirstPost = true

		// Iterate through the entries found in the db and force the view to load them.
		// This fills in any gaps in the view so that, after this, the view should contain
		// the union of what it had before plus what was in the db.
		for _, dbPostHash := range dbPostHashes {
			bav.GetPostEntryForPostHash(dbPostHash)
		}
		startPostHash = dbPostHashes[len(dbPostHashes)-1]
		startTstampNanos = bav.GetPostEntryForPostHash(startPostHash).TimestampNanos

		// Cycle through all the posts and store a map of the PubKeys so we can filter out those
		// that are restricted later.
		postEntryPubKeyMap := make(map[lib.PkMapKey][]byte)
		for _, postEntry := range bav.PostHashToPostEntry {
			// Ignore deleted / rolled-back / hidden posts.
			if postEntry.IsDeleted() || (postEntry.IsHidden && skipHidden) {
				continue
			}

			// We make sure that the post isn't a comment.
			if len(postEntry.ParentStakeID) == 0 {
				postEntryPubKeyMap[lib.MakePkMapKey(postEntry.PosterPublicKey)] = postEntry.PosterPublicKey
			}
		}

		// Filter restricted public keys out of the posts.
		filteredPostEntryPubKeyMap, err := fes.FilterOutRestrictedPubKeysFromMap(postEntryPubKeyMap, readerPK, "leaderboard")
		if err != nil {
			return nil, nil, errors.Wrapf(err, "GetAllProfiles: Problem filtering restricted profiles from map: ")
		}

		// At this point, all the posts should be loaded into the view.

		for _, postEntry := range bav.PostHashToPostEntry {

			// Ignore deleted or rolled-back posts. Skip vanilla reclout posts if skipVanillaReclout is true.
			if postEntry.IsDeleted() || (postEntry.IsHidden && skipHidden) || (lib.IsVanillaReclout(postEntry) && skipVanillaReclout) {
				continue
			}

			// If this post has already been added to the list of all core posts, we skip it.
			if _, postAdded := addedPostHashes[*postEntry.PostHash]; postAdded {
				continue
			}

			// Make sure this isn't a comment and then make sure the public key isn't restricted.
			if len(postEntry.ParentStakeID) == 0 {
				if filteredPostEntryPubKeyMap[lib.MakePkMapKey(postEntry.PosterPublicKey)] == nil {
					continue
				}
				allCorePosts = append(allCorePosts, postEntry)
				addedPostHashes[*postEntry.PostHash] = struct{}{}
			}
		}
	}
	// We no longer return comments with the posts.  Too inefficient.
	commentsByPostHash := make(map[lib.BlockHash][]*lib.PostEntry)

	return allCorePosts, commentsByPostHash, nil
}
