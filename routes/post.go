package routes

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/deso-protocol/core/lib"
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

	// This gets posts sorted by deso
	GetPostsByDESO  bool `safeForLogging:"true"`
	GetPostsByClout bool // Deprecated

	// This only gets posts that include media, like photos and videos
	MediaRequired bool `safeForLogging:"true"`

	PostsByDESOMinutesLookback uint64 `safeForLogging:"true"`

	// If set to true, then the posts in the response will contain a boolean about whether they're in the global feed
	AddGlobalFeedBool bool `safeForLogging:"true"`
}

type PostEntryResponse struct {
	PostHashHex                string
	PosterPublicKeyBase58Check string
	ParentStakeID              string
	Body                       string
	ImageURLs                  []string
	VideoURLs                  []string
	RepostedPostEntryResponse  *PostEntryResponse
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
	InGlobalFeed         *bool `json:",omitempty"`
	InHotFeed            *bool `json:",omitempty"`
	// True if this post hash hex is pinned to the global feed.
	IsPinned *bool `json:",omitempty"`
	// PostExtraData stores an arbitrary map of attributes of a PostEntry
	PostExtraData    map[string]string
	CommentCount     uint64
	RepostCount      uint64
	QuoteRepostCount uint64
	// A list of parent posts for this post (ordered: root -> closest parent post).
	ParentPosts []*PostEntryResponse

	// NFT info.
	IsNFT                          bool
	NumNFTCopies                   uint64
	NumNFTCopiesForSale            uint64
	NumNFTCopiesBurned             uint64
	HasUnlockable                  bool
	NFTRoyaltyToCreatorBasisPoints uint64
	NFTRoyaltyToCoinBasisPoints    uint64
	// This map specifies royalties that should go to user's  other than the creator
	AdditionalDESORoyaltiesMap map[string]uint64
	// This map specifies royalties that should be add to creator coins other than the creator's coin.
	AdditionalCoinRoyaltiesMap map[string]uint64

	// Number of diamonds the sender gave this post. Only set when getting diamond posts.
	DiamondsFromSender uint64

	// Score given to this post by the hot feed go routine. Not always populated.
	HotnessScore   uint64
	PostMultiplier float64

	RecloutCount               uint64             // Deprecated
	QuoteRecloutCount          uint64             // Deprecated
	RecloutedPostEntryResponse *PostEntryResponse // Deprecated
}

// GetPostsStatelessResponse ...
type GetPostsStatelessResponse struct {
	PostsFound []*PostEntryResponse
}

// Given a post entry, check if it is reposting another post and if so, get that post entry as a response.
func (fes *APIServer) _getRepostPostEntryResponse(postEntry *lib.PostEntry, addGlobalFeedBool bool, params *lib.DeSoParams, utxoView *lib.UtxoView, readerPK []byte, maxDepth uint8) (_repostPostEntry *PostEntryResponse, err error) {
	// if the maxDepth at this point is 0, we stop getting reposted post entries
	if maxDepth == 0 {
		return nil, nil
	}
	if postEntry == nil {
		return nil, fmt.Errorf("_getRepostPostEntry: postEntry must be provided ")
	}

	// Only try to get the repostPostEntryResponse if there is a Repost PostHashHex
	if postEntry.RepostedPostHash != nil {
		// Fetch the postEntry requested.
		repostedPostEntry := utxoView.GetPostEntryForPostHash(postEntry.RepostedPostHash)
		if repostedPostEntry == nil {
			return nil, fmt.Errorf("_getRepostPostEntry: Could not find postEntry for PostHashHex: #{postEntry.RepostedPostHash}")
		} else {
			var repostedPostEntryResponse *PostEntryResponse
			repostedPostEntryResponse, err = fes._postEntryToResponse(repostedPostEntry, addGlobalFeedBool, params, utxoView, readerPK, maxDepth-1)
			if err != nil {
				return nil, fmt.Errorf("_getRepostPostEntry: error converting repost post entry to response")
			}
			profileEntry := utxoView.GetProfileEntryForPublicKey(repostedPostEntry.PosterPublicKey)
			if profileEntry != nil {
				// Convert it to a response since that sanitizes the inputs.
				profileEntryResponse := fes._profileEntryToResponse(profileEntry, utxoView)
				repostedPostEntryResponse.ProfileEntryResponse = profileEntryResponse
			}
			repostedPostEntryResponse.PostEntryReaderState = utxoView.GetPostEntryReaderState(readerPK, repostedPostEntry)
			return repostedPostEntryResponse, nil
		}
	} else {
		return nil, nil
	}
}

func (fes *APIServer) _postEntryToResponse(postEntry *lib.PostEntry, addGlobalFeedBool bool, params *lib.DeSoParams, utxoView *lib.UtxoView, readerPK []byte, maxDepth uint8) (
	*PostEntryResponse, error) {
	// We only want to fetch reposted posts two levels down.  We only want to display repost posts that are at most two levels deep.
	// This only happens when someone reposts a post that is a quoted repost.  For a quote repost for which the reposted
	// post is itself a quote repost, we only display the new repost's quote and use quote from the post that was reposted
	// as the quoted content.
	if maxDepth > 2 {
		maxDepth = 2
	}
	// Get the body
	bodyJSONObj := &lib.DeSoBodySchema{}
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

	var repostPostEntryResponse *PostEntryResponse
	// Only get repostPostEntryResponse if this is the origination of the thread.
	if stakeIDStr == "" {
		// We don't care about an error here
		repostPostEntryResponse, _ = fes._getRepostPostEntryResponse(postEntry, addGlobalFeedBool, params, utxoView, readerPK, maxDepth)
	}

	postEntryResponseExtraData := make(map[string]string)
	if len(postEntry.PostExtraData) > 0 {
		for k, v := range postEntry.PostExtraData {
			if len(v) > 0 {
				postEntryResponseExtraData[k] = string(v)
			}
		}
	}

	// convert additional DESO royalties map if applicable
	additionalDESORoyaltyMap := make(map[string]uint64)
	for pkidIter, basisPoints := range postEntry.AdditionalNFTRoyaltiesToCreatorsBasisPoints {
		additionalDESORoyaltyPKID := pkidIter

		pkBytes := utxoView.GetPublicKeyForPKID(&additionalDESORoyaltyPKID)
		additionalDESORoyaltyMap[lib.PkToString(pkBytes, fes.Params)] = basisPoints
	}

	// convert additional coin royalties map if applicable
	additionalCoinRoyaltyMap := make(map[string]uint64)
	for pkidIter, basisPoints := range postEntry.AdditionalNFTRoyaltiesToCoinsBasisPoints {
		additionalCoinRoyaltyPKID := pkidIter
		pkBytes := utxoView.GetPublicKeyForPKID(&additionalCoinRoyaltyPKID)
		additionalCoinRoyaltyMap[lib.PkToString(pkBytes, fes.Params)] = basisPoints
	}

	res := &PostEntryResponse{
		PostHashHex:                    hex.EncodeToString(postEntry.PostHash[:]),
		PosterPublicKeyBase58Check:     lib.PkToString(postEntry.PosterPublicKey, params),
		ParentStakeID:                  stakeIDStr,
		Body:                           bodyJSONObj.Body,
		ImageURLs:                      bodyJSONObj.ImageURLs,
		VideoURLs:                      bodyJSONObj.VideoURLs,
		RepostedPostEntryResponse:      repostPostEntryResponse,
		CreatorBasisPoints:             postEntry.CreatorBasisPoints,
		StakeMultipleBasisPoints:       postEntry.StakeMultipleBasisPoints,
		TimestampNanos:                 postEntry.TimestampNanos,
		IsHidden:                       postEntry.IsHidden,
		ConfirmationBlockHeight:        postEntry.ConfirmationBlockHeight,
		InMempool:                      inMempool,
		LikeCount:                      postEntry.LikeCount,
		DiamondCount:                   postEntry.DiamondCount,
		CommentCount:                   postEntry.CommentCount,
		RepostCount:                    postEntry.RepostCount,
		QuoteRepostCount:               postEntry.QuoteRepostCount,
		IsPinned:                       &postEntry.IsPinned,
		IsNFT:                          postEntry.IsNFT,
		NumNFTCopies:                   postEntry.NumNFTCopies,
		NumNFTCopiesForSale:            postEntry.NumNFTCopiesForSale,
		NumNFTCopiesBurned:             postEntry.NumNFTCopiesBurned,
		HasUnlockable:                  postEntry.HasUnlockable,
		NFTRoyaltyToCreatorBasisPoints: postEntry.NFTRoyaltyToCreatorBasisPoints,
		NFTRoyaltyToCoinBasisPoints:    postEntry.NFTRoyaltyToCoinBasisPoints,
		AdditionalDESORoyaltiesMap:     additionalDESORoyaltyMap,
		AdditionalCoinRoyaltiesMap:     additionalCoinRoyaltyMap,
		PostExtraData:                  postEntryResponseExtraData,

		// Deprecated
		RecloutedPostEntryResponse: repostPostEntryResponse,
		RecloutCount:               postEntry.RepostCount,
		QuoteRecloutCount:          postEntry.QuoteRepostCount,
	}

	if addGlobalFeedBool {
		inGlobalFeed := false
		dbKey := GlobalStateKeyForTstampPostHash(postEntry.TimestampNanos, postEntry.PostHash)
		globalStateVal, err := fes.GlobalState.Get(dbKey)
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

		_, inHotFeed := fes.HotFeedApprovedPostsToMultipliers[*postEntry.PostHash]
		res.InHotFeed = &inHotFeed
	}

	return res, nil
}

func (fes *APIServer) GetAllPostEntries(readerPK []byte) (
	_postEntries []*lib.PostEntry, _commentsByPostHash map[lib.BlockHash][]*lib.PostEntry,
	_profilesByPublicKey map[lib.PkMapKey]*lib.ProfileEntry,
	_postEntryReaderStates map[lib.BlockHash]*lib.PostEntryReaderState, err error) {

	// Get a view with all the mempool transactions (used to get all posts / reader state).
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("GetPostsStateless: Error fetching mempool view: %v", err)
	}

	postEntries, commentsByPostHash, err := utxoView.GetAllPosts()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("GetAllPostEntries: Error fetching posts from view: %v", err)
	}
	profileEntries := make(map[lib.PkMapKey]*lib.ProfileEntry)
	for _, postEntry := range postEntries {
		{
			profileEntry := utxoView.GetProfileEntryForPublicKey(postEntry.PosterPublicKey)
			if profileEntry != nil {
				profileEntries[lib.MakePkMapKey(profileEntry.PublicKey)] = profileEntry
			}
		}

		// Get the profileEntries for the comments as well
		commentsFound := commentsByPostHash[*postEntry.PostHash]
		for _, commentEntry := range commentsFound {
			profileEntry := utxoView.GetProfileEntryForPublicKey(commentEntry.PosterPublicKey)
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

	return postEntries, commentsByPostHash, profileEntries, postEntryReaderStates, nil
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
func (fes *APIServer) GetPostEntriesByDESOAfterTimePaginated(readerPK []byte,
	minutesLookback uint64, numToFetch int, mediaRequired bool) (
	_postEntries []*lib.PostEntry,
	_profilesByPublicKey map[lib.PkMapKey]*lib.ProfileEntry, err error) {
	// As a safeguard, we should only be able to look at least one hour in the past -- can be changed later.

	if minutesLookback > 60 {
		return nil, nil, fmt.Errorf("GetPostEntriesByDESO: Cannot fetch posts by deso more than an hour back")
	}

	currentTime := time.Now().UnixNano()
	startTstampNanos := uint64(currentTime) - (uint64(time.Minute.Nanoseconds()) * minutesLookback)

	// Get a view with all the mempool transactions (used to get all posts / reader state).
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return nil, nil, fmt.Errorf("GetPostEntriesByDESO: Error fetching mempool view: %v", err)
	}
	// Start by fetching the posts we have in the db.
	dbPostHashes, _, _, err := lib.DBGetPaginatedPostsOrderedByTime(
		utxoView.Handle, fes.blockchain.Snapshot(), startTstampNanos, nil, -1,
		false /*fetchEntries*/, false)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "GetPostEntriesByDESO: Problem fetching ProfileEntrys from db: ")
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

		// If media is required and this post does not have media, skip it.
		if mediaRequired && !postEntry.HasMedia() {
			continue
		}

		// We make sure that the post isn't a comment.
		if len(postEntry.ParentStakeID) == 0 {
			postEntryPubKeyMap[lib.MakePkMapKey(postEntry.PosterPublicKey)] = postEntry.PosterPublicKey
		}
	}

	// Filter restricted public keys out of the posts.
	filteredPostEntryPubKeyMap, err := fes.FilterOutRestrictedPubKeysFromMap(postEntryPubKeyMap, readerPK, "leaderboard", utxoView)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "GetPostsByDESO: Problem filtering restricted profiles from map: ")
	}

	// At this point, all the posts should be loaded into the view.
	allCorePosts := []*lib.PostEntry{}
	for _, postEntry := range utxoView.PostHashToPostEntry {

		// Ignore deleted or rolled-back posts.
		if postEntry.IsDeleted() || postEntry.IsHidden {
			continue
		}

		if mediaRequired && !postEntry.HasMedia() {
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
		return profileEntries[lib.MakePkMapKey(allCorePosts[ii].PosterPublicKey)].CreatorCoinEntry.DeSoLockedNanos > profileEntries[lib.MakePkMapKey(allCorePosts[jj].PosterPublicKey)].CreatorCoinEntry.DeSoLockedNanos
	})
	// Select the top numToFetch posts.
	if len(allCorePosts) > numToFetch {
		allCorePosts = allCorePosts[:numToFetch]
	}
	return allCorePosts, profileEntries, nil
}

func (fes *APIServer) GetPostEntriesByTimePaginated(
	startPostHash *lib.BlockHash, readerPK []byte, numToFetch int, utxoView *lib.UtxoView, mediaRequired bool) (
	_postEntries []*lib.PostEntry, _commentsByPostHash map[lib.BlockHash][]*lib.PostEntry,
	_profilesByPublicKey map[lib.PkMapKey]*lib.ProfileEntry,
	_postEntryReaderStates map[lib.BlockHash]*lib.PostEntryReaderState, err error) {

	postEntries,
		commentsByPostHash,
		err := fes.GetPostsByTime(utxoView, startPostHash, readerPK, numToFetch,
		true /*skipHidden*/, true, mediaRequired)

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
	commentEntry *lib.PostEntry, profileEntryMap map[lib.PkMapKey]*lib.ProfileEntry, addGlobalFeedBool bool, utxoView *lib.UtxoView, readerPK []byte) (
	*PostEntryResponse, error) {
	commentResponse, err := fes._postEntryToResponse(commentEntry, addGlobalFeedBool, fes.Params, utxoView, readerPK, 2)
	if err != nil {
		return nil, err
	}

	profileEntryFound := profileEntryMap[lib.MakePkMapKey(commentEntry.PosterPublicKey)]
	commentResponse.ProfileEntryResponse = fes._profileEntryToResponse(profileEntryFound, utxoView)

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
	var seekStartPostHash *lib.BlockHash
	skipFirstEntry := false
	if startPost != nil {
		seekStartKey = GlobalStateKeyForTstampPostHash(startPost.TimestampNanos, startPost.PostHash)
		seekStartPostHash = startPost.PostHash
		skipFirstEntry = true
	} else {
		// If we can't find a valid start post, we just use the prefix. Seek will
		// pad the value as necessary.
		seekStartKey = _GlobalStatePrefixTstampNanosPostHash
	}

	// Seek the global state for a list of [prefix][tstamp][posthash] keys.
	validForPrefix := _GlobalStatePrefixTstampNanosPostHash
	maxBigEndianUint64Bytes := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	maxKeyLen := 1 + len(maxBigEndianUint64Bytes) + lib.HashSizeBytes
	var postEntries []*lib.PostEntry
	nextStartKey := seekStartKey
	nextStartPostHash := seekStartPostHash

	index := 0
	// Iterate over posts in global state until we have at least num to fetch
	for len(postEntries) < numToFetch {
		var postHashes []*lib.BlockHash
		// If we're using an external global state, use the cached post hashes.
		if fes.Config.GlobalStateAPIUrl != "" {
			if nextStartPostHash != nil {
				for ii := index; ii < len(fes.GlobalFeedPostHashes); ii++ {
					if reflect.DeepEqual(*fes.GlobalFeedPostHashes[ii], *nextStartPostHash) {
						index = ii
						break
					}
				}
			}
			endIndex := lib.MinInt(index+numToFetch-len(postEntries), len(fes.GlobalFeedPostHashes))
			postHashes = fes.GlobalFeedPostHashes[index:endIndex]
			// At the next iteration, we can start looking endIndex for the post hash we need.
			index = endIndex - 1
		} else {
			// Otherwise, we're using this node's global state.
			var keys [][]byte
			// Get numToFetch - len(postEntries) postHashes from global state.
			keys, _, err = fes.GlobalState.Seek(nextStartKey /*startPrefix*/, validForPrefix, /*validForPrefix*/
				maxKeyLen /*maxKeyLen -- ignored since reverse is false*/, numToFetch-len(postEntries), true, /*reverse*/
				false /*fetchValues*/)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("GetPostEntriesForGlobalWhitelist: Getting posts for reader: %v", err)
			}
			for _, dbKeyBytes := range keys {
				postHash := &lib.BlockHash{}
				copy(postHash[:], dbKeyBytes[1+len(maxBigEndianUint64Bytes):][:])
				postHashes = append(postHashes, postHash)
			}
		}

		// If there are no keys left, then there are no more postEntries to get so we exit the loop.
		if len(postHashes) == 0 || (len(postHashes) == 1 && skipFirstEntry) {
			break
		}

		var lastPost *lib.PostEntry
		for ii, postHash := range postHashes {
			// if we have a postHash at which we are starting, we should skip the first one so we don't have it
			// duplicated in the response.
			if skipFirstEntry && ii == 0 {
				continue
			}

			// Get the postEntry from the utxoView.
			postEntry := utxoView.GetPostEntryForPostHash(postHash)

			if postEntry != nil {
				lastPost = postEntry
			}

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
		// If there are no post entries and no last post, we don't continue to fetch.
		if len(postEntries) == 0 && lastPost == nil {
			break
		}
		// Next time through the loop, start at the last key we retrieved
		nextStartKey = GlobalStateKeyForTstampPostHash(lastPost.TimestampNanos, lastPost.PostHash)
		nextStartPostHash = lastPost.PostHash
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
			utxoView.Handle, fes.blockchain.Snapshot(), readerPK, false /*fetchEntries*/,
			minTimestampNanos, maxTimestampNanos,
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
			keys, _, err := fes.GlobalState.Seek(pinnedStartKey, pinnedStartKey, maxKeyLen, 10, true, false)
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

func (fes *APIServer) GetGlobalFeedPostHashesForLastWeek() (_postHashes []*lib.BlockHash, _err error) {
	minTimestampNanos := uint64(time.Now().UTC().AddDate(0, 0, -7).UnixNano()) // 1 week ago

	seekStartKey := GlobalStateSeekKeyForTstampPostHash(minTimestampNanos)

	validForPrefix := _GlobalStatePrefixTstampNanosPostHash
	maxBigEndianUint64Bytes := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	maxKeyLen := 1 + len(maxBigEndianUint64Bytes) + lib.HashSizeBytes

	var postHashes []*lib.BlockHash

	keys, _, err := fes.GlobalState.Seek(seekStartKey /*startPrefix*/, validForPrefix, /*validForPrefix*/
		maxKeyLen /*maxKeyLen -- ignored since reverse is false*/, 0, false, /*reverse*/
		false /*fetchValues*/)
	if err != nil {
		return nil, err
	}
	// We iterate backwards since we want the Posts to be ordered from most recent to least recent.
	for ii := len(keys) - 1; ii >= 0; ii-- {
		postHash := &lib.BlockHash{}
		copy(postHash[:], keys[ii][1+len(maxBigEndianUint64Bytes):][:])

		postHashes = append(postHashes, postHash)
	}
	return postHashes, nil
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
			err = fes.GetPostEntriesForFollowFeed(startPostHash, readerPublicKeyBytes, numToFetch, utxoView,
			requestData.MediaRequired)
		// if we're getting posts for follow feed, no comments are returned (they aren't necessary)
		commentsByPostHash = make(map[lib.BlockHash][]*lib.PostEntry)
	} else if requestData.GetPostsForGlobalWhitelist {
		postEntries,
			profileEntryMap,
			readerStateMap,
			err = fes.GetPostEntriesForGlobalWhitelist(startPostHash, readerPublicKeyBytes, numToFetch, utxoView,
			requestData.MediaRequired)
		// if we're getting posts for the global whitelist, no comments are returned (they aren't necessary)
		commentsByPostHash = make(map[lib.BlockHash][]*lib.PostEntry)
	} else if requestData.GetPostsByDESO || requestData.GetPostsByClout {
		postEntries,
			profileEntryMap,
			err = fes.GetPostEntriesByDESOAfterTimePaginated(readerPublicKeyBytes,
			requestData.PostsByDESOMinutesLookback, numToFetch, requestData.MediaRequired)
	} else {
		postEntries,
			commentsByPostHash,
			profileEntryMap,
			readerStateMap,
			err = fes.GetPostEntriesByTimePaginated(startPostHash, readerPublicKeyBytes, numToFetch,
			utxoView, requestData.MediaRequired)
	}

	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetPostsStateless: Error fetching posts: %v", err))
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
		if _, ok := blockedPubKeys[lib.PkToString(postEntry.PosterPublicKey, fes.Params)]; !ok {
			var postEntryResponse *PostEntryResponse
			postEntryResponse, err = fes._postEntryToResponse(postEntry, requestData.AddGlobalFeedBool, fes.Params, utxoView, readerPublicKeyBytes, 2)
			if err != nil {
				// Just ignore posts that fail to convert for whatever reason.
				continue
			}
			profileEntryFound := profileEntryMap[lib.MakePkMapKey(postEntry.PosterPublicKey)]
			postEntryResponse.ProfileEntryResponse = fes._profileEntryToResponse(
				profileEntryFound, utxoView)
			commentsFound := commentsByPostHash[*postEntry.PostHash]
			for _, commentEntry := range commentsFound {
				if _, ok = blockedPubKeys[lib.PkToString(commentEntry.PosterPublicKey, fes.Params)]; !ok {
					commentResponse, err := fes._getCommentResponse(commentEntry, profileEntryMap, requestData.AddGlobalFeedBool, utxoView, readerPublicKeyBytes)
					if fes._shouldSkipCommentResponse(commentResponse, err) {
						continue
					}

					// Fetch subcomments if needed
					if requestData.FetchSubcomments {
						subcommentsFound := commentsByPostHash[*commentEntry.PostHash]
						for _, subCommentEntry := range subcommentsFound {
							subcommentResponse, err := fes._getCommentResponse(subCommentEntry, profileEntryMap, requestData.AddGlobalFeedBool, utxoView, readerPublicKeyBytes)
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
	// How many levels of replies will be retrieved. If unset, will only retrieve the top-level replies.
	ThreadLevelLimit uint32 `safeForLogging:"true"`
	// How many child replies of a parent comment will be considered when returning a comment thread. Setting this to -1 will include all child replies. This limit does not affect the top-level replies to a post.
	ThreadLeafLimit int32 `safeForLogging:"true"`
	// If the post contains a comment thread where all comments are created by the author, include that thread in the response.
	LoadAuthorThread bool `safeForLogging:"true"`

	// If set to true, then the posts in the response will contain a boolean about whether they're in the global feed.
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

	if requestData.ThreadLevelLimit > 4 {
		requestData.ThreadLevelLimit = 4
	}

	if requestData.CommentLimit > 30 {
		requestData.CommentLimit = 30
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
	var rootBlockedPublicKeys map[string]struct{}
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

	for _, parentPostEntry := range parentPostEntries {
		pkMapKey := lib.MakePkMapKey(parentPostEntry.PosterPublicKey)
		// Remove parents that are blocked by either the reader or the poster of the root post
		if _, ok := blockedPublicKeys[lib.PkToString(parentPostEntry.PosterPublicKey, fes.Params)]; !ok && profilePubKeyMap[pkMapKey] == nil {
			profilePubKeyMap[pkMapKey] = parentPostEntry.PosterPublicKey
		}
	}

	// Filter out restricted PosterPublicKeys.
	filteredProfilePubKeyMap, err := fes.FilterOutRestrictedPubKeysFromMap(
		profilePubKeyMap, readerPublicKeyBytes, "leaderboard" /*moderationType*/, utxoView)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetSinglePost: Error filtering out restricted profiles: %v", err))
		return
	}

	// Figure out if the current poster is greylisted.  If the current poster is greylisted, we will add their
	// public key back to the filteredProfileMap so their profile will appear for the current post
	// and any parents, but we will remove any comments by this greylisted user.
	isCurrentPosterGreylisted := false
	if _, ok := filteredProfilePubKeyMap[lib.MakePkMapKey(postEntry.PosterPublicKey)]; !ok {
		currentPosterPKID := utxoView.GetPKIDForPublicKey(postEntry.PosterPublicKey)
		// If the currentPoster's userMetadata doesn't exist, then they are no greylisted, so we can exit.
		if fes.IsUserGraylisted(currentPosterPKID.PKID) && !fes.IsUserBlacklisted(currentPosterPKID.PKID) {
			// If the currentPoster is not blacklisted (removed everywhere) and is greylisted (removed from leaderboard)
			// add them back to the filteredProfilePubKeyMap and note that the currentPoster is greylisted.
			isCurrentPosterGreylisted = true
			filteredProfilePubKeyMap[lib.MakePkMapKey(postEntry.PosterPublicKey)] = postEntry.PosterPublicKey
		}
	}

	// If the profile that posted this post is not in our filtered list, return with error.
	if filteredProfilePubKeyMap[lib.MakePkMapKey(postEntry.PosterPublicKey)] == nil && !isCurrentPosterGreylisted {
		_AddBadRequestError(ww, fmt.Sprintf("GetSinglePost: The poster public key for this post is restricted."))
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
				fes._profileEntryToResponse(profileEntry, utxoView)
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

	comments, err := fes.GetSinglePostComments(
		utxoView,
		postEntryResponse,
		requestData,
		postEntry.PosterPublicKey,
		readerPublicKeyBytes,
		blockedPublicKeys,
		0,
		postEntryResponse.PosterPublicKeyBase58Check,
	)

	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetSinglePost: Error Getting Comments: %v", err))
		return
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

// Include poster public key in comments response
type CommentsPostEntryResponse struct {
	PostEntryResponse    *PostEntryResponse
	PosterPublicKeyBytes []byte
}

// Get the comments associated with a single post.
func (fes *APIServer) GetSinglePostComments(
	utxoView *lib.UtxoView,
	postEntryResponse *PostEntryResponse,
	requestData GetSinglePostRequest,
	posterPublicKeyBytes []byte,
	readerPublicKeyBytes []byte,
	blockedPublicKeys map[string]struct{},
	commentLevel uint32,
	topLevelPosterPublicKeyBase58Check string,
) ([]*PostEntryResponse, error) {
	postHash, err := GetPostHashFromPostHashHex(postEntryResponse.PostHashHex)
	if err != nil {
		return nil, err
	}

	// Fetch the commentEntries for the post.
	commentEntries, err := utxoView.GetCommentEntriesForParentStakeID(postHash[:])
	if err != nil {
		return nil, err
	}

	// Process the comments into something we can return.
	commentEntryResponseList := []*CommentsPostEntryResponse{}
	// Create a map from commentEntryPostHashHex to commentEntry to ease look up of public key bytes when sorting
	commentHashHexToCommentEntry := make(map[string]*lib.PostEntry)

	posterPkMapKey := lib.MakePkMapKey(posterPublicKeyBytes)
	// Create a map of all the profile pub keys associated with our posts + comments.
	profilePubKeyMap := make(map[lib.PkMapKey][]byte)
	profilePubKeyMap[posterPkMapKey] = posterPublicKeyBytes

	// Determine whether or not the posters of the "single post" we are fetching is blocked by the reader.  If the
	// poster of the single post is blocked, we will want to include the single post, but not any of the comments
	// created by the poster that are children of this "single post".
	_, isCurrentPosterBlocked := blockedPublicKeys[postEntryResponse.PosterPublicKeyBase58Check]
	for _, commentEntry := range commentEntries {
		pkMapKey := lib.MakePkMapKey(commentEntry.PosterPublicKey)
		// Remove comments that are blocked by either the reader or the poster of the root post
		if _, ok := blockedPublicKeys[lib.PkToString(commentEntry.PosterPublicKey, fes.Params)]; !ok && profilePubKeyMap[pkMapKey] == nil {
			profilePubKeyMap[pkMapKey] = commentEntry.PosterPublicKey
		}
	}

	// Filter out restricted PosterPublicKeys.
	filteredProfilePubKeyMap, err := fes.FilterOutRestrictedPubKeysFromMap(
		profilePubKeyMap, readerPublicKeyBytes, "leaderboard" /*moderationType*/, utxoView)
	if err != nil {
		return nil, err
	}

	// Get the profile entry for all PosterPublicKeys that passed our filter.
	pubKeyToProfileEntryResponseMap := make(map[lib.PkMapKey]*ProfileEntryResponse)
	for _, pubKeyBytes := range filteredProfilePubKeyMap {
		profileEntry := utxoView.GetProfileEntryForPublicKey(pubKeyBytes)
		if profileEntry == nil {
			continue
		}
		pubKeyToProfileEntryResponseMap[lib.MakePkMapKey(pubKeyBytes)] =
			fes._profileEntryToResponse(profileEntry, utxoView)
	}

	// If the profile that posted this post does not have a profile, return with error.
	if pubKeyToProfileEntryResponseMap[posterPkMapKey] == nil {
		return nil, fmt.Errorf("GetSinglePostComments: The profile that posted this post does not have a profile.")
	}

	for _, commentEntry := range commentEntries {
		pkMapKey := lib.MakePkMapKey(commentEntry.PosterPublicKey)
		// Remove comments that are blocked by either the reader or the poster of the root post
		if _, ok := blockedPublicKeys[lib.PkToString(commentEntry.PosterPublicKey, fes.Params)]; !ok && profilePubKeyMap[pkMapKey] == nil {
			profilePubKeyMap[pkMapKey] = commentEntry.PosterPublicKey
		}
		commentProfileEntryResponse := pubKeyToProfileEntryResponseMap[lib.MakePkMapKey(commentEntry.PosterPublicKey)]
		commentAuthorIsCurrentPoster := reflect.DeepEqual(commentEntry.PosterPublicKey, posterPublicKeyBytes)
		// Skip comments that:
		//  - Don't have a profile (it was most likely banned).
		//	- Are hidden *AND* don't have comments. Keep hidden posts with comments.
		//  - isDeleted (this was already filtered in an earlier stage and should never be true)
		//	- Skip comment is it's by the poster of the single post we are fetching and the currentPoster is blocked by
		// 	the reader
		if commentProfileEntryResponse == nil || commentEntry.IsDeleted() ||
			(commentEntry.IsHidden && commentEntry.CommentCount == 0) ||
			(commentAuthorIsCurrentPoster && isCurrentPosterBlocked) {
			continue
		}

		// Build the comments entry response and append.
		commentEntryResponse, err := fes._postEntryToResponse(commentEntry, requestData.AddGlobalFeedBool /*AddGlobalFeed*/, fes.Params, utxoView, readerPublicKeyBytes, 2)
		if err != nil {
			return nil, err
		}
		commentEntryResponse.ProfileEntryResponse = commentProfileEntryResponse
		commentEntryResponse.PostEntryReaderState = utxoView.GetPostEntryReaderState(readerPublicKeyBytes, commentEntry)
		// Include poster public key in comments response
		commentEntryResponseWithPosterBytes := &CommentsPostEntryResponse{}
		commentEntryResponseWithPosterBytes.PostEntryResponse = commentEntryResponse
		commentEntryResponseWithPosterBytes.PosterPublicKeyBytes = commentEntry.PosterPublicKey
		commentEntryResponseList = append(commentEntryResponseList, commentEntryResponseWithPosterBytes)
		commentHashHexToCommentEntry[commentEntryResponse.PostHashHex] = commentEntry
	}

	posterPKID := utxoView.GetPKIDForPublicKey(posterPublicKeyBytes)
	// Almost done. Just need to sort the comments.
	sort.Slice(commentEntryResponseList, func(ii, jj int) bool {
		iiCommentEntryResponse := commentEntryResponseList[ii]
		jjCommentEntryResponse := commentEntryResponseList[jj]
		// If the poster of ii is the poster of the main post and jj is not, ii should be first.
		iiIsPoster := iiCommentEntryResponse.PostEntryResponse.PosterPublicKeyBase58Check == postEntryResponse.PosterPublicKeyBase58Check
		jjIsPoster := jjCommentEntryResponse.PostEntryResponse.PosterPublicKeyBase58Check == postEntryResponse.PosterPublicKeyBase58Check

		// Sort tweet storms from oldest to newest
		if iiIsPoster && jjIsPoster {
			return iiCommentEntryResponse.PostEntryResponse.TimestampNanos < jjCommentEntryResponse.PostEntryResponse.TimestampNanos
		}

		if iiIsPoster && !jjIsPoster {
			return true
		} else if !iiIsPoster && jjIsPoster {
			return false
		}

		// Next we sort based on diamonds given by the poster.
		iiCommentEntry := commentHashHexToCommentEntry[iiCommentEntryResponse.PostEntryResponse.PostHashHex]
		iiDiamondKey := lib.MakeDiamondKey(
			posterPKID.PKID,
			utxoView.GetPKIDForPublicKey(iiCommentEntry.PosterPublicKey).PKID,
			iiCommentEntry.PostHash)
		iiDiamondLevelByPoster := utxoView.GetDiamondEntryForDiamondKey(&iiDiamondKey)

		jjCommentEntry := commentHashHexToCommentEntry[jjCommentEntryResponse.PostEntryResponse.PostHashHex]
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

		iiCoinPrice := iiCommentEntryResponse.PostEntryResponse.ProfileEntryResponse.CoinEntry.DeSoLockedNanos
		jjCoinPrice := jjCommentEntryResponse.PostEntryResponse.ProfileEntryResponse.CoinEntry.DeSoLockedNanos
		if iiCoinPrice > jjCoinPrice {
			return true
		} else if iiCoinPrice < jjCoinPrice {
			return false
		}

		// Finally, if we can't prioritize based on pub key or deso, we use timestamp.
		return iiCommentEntryResponse.PostEntryResponse.TimestampNanos > jjCommentEntryResponse.PostEntryResponse.TimestampNanos
	})

	commentEntryResponseLength := uint32(len(commentEntryResponseList))
	// Slice the comments from the offset up to either the end of the slice or the offset + limit, whichever is smaller.
	maxIdx := lib.MinUint32(commentEntryResponseLength, requestData.CommentOffset+requestData.CommentLimit)
	var comments []*CommentsPostEntryResponse
	// Only apply the offset to top-level comments. CommentOffset & CommentLimit specify how top-level comments are loaded, ThreadLevelLimit & ThreadLeafLevelLimit specify how children comments should be loaded
	// If loading top level comments and the offset is greater than the available # of comments, don't add comments
	if commentEntryResponseLength > requestData.CommentOffset && commentLevel == 0 {
		comments = commentEntryResponseList[requestData.CommentOffset:maxIdx]
	} else if commentLevel > 0 {
		comments = commentEntryResponseList
	}

	for ii, comment := range comments {
		// If the previous stack was loading the comment author thread and the comment in question is from the same author, load it.
		loadCommentAuthorThread := requestData.LoadAuthorThread && comment.PostEntryResponse.PosterPublicKeyBase58Check == topLevelPosterPublicKeyBase58Check
		// Only iterate over comments within the specified leaf-limit. To follow a single reply thread, that limit would be 1. All top-level replies are included. A limit of -1 includes all leafs.
		commentWithinLeafLimit := commentLevel == 0 || int32(ii) < requestData.ThreadLeafLimit || requestData.ThreadLeafLimit == -1
		// Only recurse up to a certain depth. If we're within a thread chain consisting only of posts from the original post author, include all of the comments.
		commentWithinThreadLevelLimit := commentLevel < requestData.ThreadLevelLimit || loadCommentAuthorThread
		// If this comment is within the leaf limit and isn't recursing too deeply, load the comment.
		if commentWithinLeafLimit && commentWithinThreadLevelLimit {
			commentReplies, err := fes.GetSinglePostComments(
				utxoView,
				comment.PostEntryResponse,
				requestData,
				comment.PosterPublicKeyBytes,
				readerPublicKeyBytes,
				blockedPublicKeys,
				commentLevel+1,
				topLevelPosterPublicKeyBase58Check,
			)
			if err != nil {
				return nil, err
			}
			comment.PostEntryResponse.Comments = commentReplies
		}
	}

	// Limit comments to leaf limit, if it's not the first reply level and the leaf limit isn't -1
	// The leaf limit should not apply to the first level of comments (comment lvl === 0) - that limit is defined by the CommentLimit
	var limitedComments []*PostEntryResponse
	var limitedCommentEndIdx int
	if requestData.ThreadLeafLimit == -1 || commentLevel == 0 || int32(len(comments)) <= requestData.ThreadLeafLimit {
		limitedCommentEndIdx = len(comments)
	} else {
		limitedCommentEndIdx = int(requestData.ThreadLeafLimit)
	}

	// Take comments, extract only the PostEntryResponse
	for ii := 0; ii < limitedCommentEndIdx; ii++ {
		limitedComments = append(limitedComments, comments[ii].PostEntryResponse)
	}

	postEntryResponse.Comments = limitedComments
	return limitedComments, nil
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

// GetPostsForPublicKey gets paginated posts for a public key or username.
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
	posts, err := utxoView.GetPostsPaginatedForPublicKeyOrderedByTimestamp(publicKeyBytes, startPostHash, requestData.NumToFetch, requestData.MediaRequired, false)
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

	var readerPublicKeyBytes []byte
	if requestData.ReaderPublicKeyBase58Check != "" {
		// Decode the reader public key.
		readerPublicKeyBytes, _, err = lib.Base58CheckDecode(requestData.ReaderPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetDiamondedPosts: Problem decoding reader public key: %v", err))
			return
		}
	}

	// Get the DiamondEntries for this receiver-sender pair of public keys.
	diamondEntries, err := utxoView.GetDiamondEntriesForSenderToReceiver(receiverPublicKeyBytes, senderPublicKeyBytes)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDiamondedPosts: Problem getting diamond entries: %v", err))
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
				parentPostEntryResponse.ProfileEntryResponse = fes._profileEntryToResponse(parentProfileEntry, utxoView)
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
		ReceiverProfileEntryResponse: fes._profileEntryToResponse(receiverProfileEntry, utxoView),
		SenderProfileEntryResponse:   fes._profileEntryToResponse(senderProfileEntry, utxoView),
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
		filteredPkMap, err = fes.FilterOutRestrictedPubKeysFromMap(pkMapToFilter, readerPublicKeyBytes, "leaderboard" /*moderationType*/, utxoView)
	} else {
		filteredPkMap, err = fes.FilterOutRestrictedPubKeysFromMap(pkMapToFilter, nil, "leaderboard" /*moderationType*/, utxoView)
	}
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetLikesForPost: Error filtering out restricted profiles: %v", err))
		return
	}

	// Create a list of the likers that were not restricted.
	likers := []*ProfileEntryResponse{}
	for _, filteredPubKey := range filteredPkMap {
		profileEntry := utxoView.GetProfileEntryForPublicKey(filteredPubKey)
		if profileEntry == nil {
			continue
		}
		profileEntryResponse := fes._profileEntryToResponse(profileEntry, utxoView)
		likers = append(likers, profileEntryResponse)
	}

	// Almost done. Just need to sort the likers.
	sort.Slice(likers, func(ii, jj int) bool {

		// Attempt to sort on deso locked.
		iiDeSoLocked := likers[ii].CoinEntry.DeSoLockedNanos
		jjDeSoLocked := likers[jj].CoinEntry.DeSoLockedNanos
		if iiDeSoLocked > jjDeSoLocked {
			return true
		} else if iiDeSoLocked < jjDeSoLocked {
			return false
		}

		// Sort based on pub key if all else fails.
		return likers[ii].PublicKeyBase58Check > likers[jj].PublicKeyBase58Check
	})

	// Cut out the page of reposters that we care about.
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
	filteredPkMap, err := fes.FilterOutRestrictedPubKeysFromMap(pkMapToFilter, readerPublicKeyBytes, "leaderboard" /*moderationType*/, utxoView)
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

		// Attempt to sort on deso locked.
		iiDeSoLocked := diamondSenders[ii].CreatorCoinEntry.DeSoLockedNanos
		jjDeSoLocked := diamondSenders[jj].CreatorCoinEntry.DeSoLockedNanos
		if iiDeSoLocked > jjDeSoLocked {
			return true
		} else if iiDeSoLocked < jjDeSoLocked {
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

	// Convert final page of diamondSenders to a list of diamondSender responses.
	diamondSenderResponses := []*DiamondSenderResponse{}
	for _, diamondSender := range diamondSendersPage {
		diamondSenderPKID := utxoView.GetPKIDForPublicKey(diamondSender.PublicKey)
		diamondSenderResponse := &DiamondSenderResponse{
			DiamondSenderProfile: fes._profileEntryToResponse(diamondSender, utxoView),
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

type GetRepostsForPostRequest struct {
	// PostHashHex to fetch.
	PostHashHex                string `safeForLogging:"true"`
	Offset                     uint32 `safeForLogging:"true"`
	Limit                      uint32 `safeForLogging:"true"`
	ReaderPublicKeyBase58Check string `safeForLogging:"true"`
}

type GetRepostsForPostResponse struct {
	Reposters  []*ProfileEntryResponse
	Reclouters []*ProfileEntryResponse // Deprecated
}

func (fes *APIServer) GetRepostsForPost(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetRepostsForPostRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetRepostsForPost: Problem parsing request body: %v", err))
		return
	}

	postHash, err := GetPostHashFromPostHashHex(requestData.PostHashHex)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetRepostsForPost: %v", err))
		return
	}

	// Decode the reader public key into bytes. Default to nil if no pub key is passed in.
	var readerPublicKeyBytes []byte
	if requestData.ReaderPublicKeyBase58Check != "" {
		readerPublicKeyBytes, _, err = lib.Base58CheckDecode(requestData.ReaderPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetRepostsForPost: Problem decoding user public key: %v : %s", err, requestData.ReaderPublicKeyBase58Check))
			return
		}
	}

	// Get a view with all the mempool transactions.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetRepostsForPost: Error constucting utxoView: %v", err))
		return
	}

	// Fetch the reposters for the post requested.
	reposterPubKeys, err := utxoView.GetRepostsForPostHash(postHash)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetRepostsForPost: Error getting reposters %v", err))
		return
	}

	// Filter out any restricted profiles.
	pkMapToFilter := make(map[lib.PkMapKey][]byte)
	for _, pubKey := range reposterPubKeys {
		pkMapKey := lib.MakePkMapKey(pubKey)
		pkMapToFilter[pkMapKey] = pubKey
	}

	var filteredPkMap map[lib.PkMapKey][]byte
	if _, addReaderPublicKey := utxoView.GetRepostPostEntryStateForReader(readerPublicKeyBytes, postHash); addReaderPublicKey {
		filteredPkMap, err = fes.FilterOutRestrictedPubKeysFromMap(
			pkMapToFilter, readerPublicKeyBytes, "leaderboard" /*moderationType*/, utxoView)
	} else {
		filteredPkMap, err = fes.FilterOutRestrictedPubKeysFromMap(pkMapToFilter, nil, "leaderboard" /*moderationType*/, utxoView)
	}
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetRepostsForPost: Error filtering out restricted profiles: %v", err))
		return
	}

	// Create a list of the reposters that were not restricted.
	reposters := []*ProfileEntryResponse{}
	for _, filteredPubKey := range filteredPkMap {
		profileEntry := utxoView.GetProfileEntryForPublicKey(filteredPubKey)
		if profileEntry == nil {
			continue
		}
		profileEntryResponse := fes._profileEntryToResponse(profileEntry, utxoView)
		reposters = append(reposters, profileEntryResponse)
	}

	// Almost done. Just need to sort the comments.
	sort.Slice(reposters, func(ii, jj int) bool {

		// Attempt to sort on deso locked.
		iiDeSoLocked := reposters[ii].CoinEntry.DeSoLockedNanos
		jjDeSoLocked := reposters[jj].CoinEntry.DeSoLockedNanos
		if iiDeSoLocked > jjDeSoLocked {
			return true
		} else if iiDeSoLocked < jjDeSoLocked {
			return false
		}

		// Sort based on pub key if all else fails.
		return reposters[ii].PublicKeyBase58Check > reposters[jj].PublicKeyBase58Check
	})

	// Cut out the page of reposters that we care about.
	repostersLength := uint32(len(reposters))
	// Slice the comments from the offset up to either the end of the slice or the offset + limit, whichever is smaller.
	maxIdx := lib.MinUint32(repostersLength, requestData.Offset+requestData.Limit)
	repostersPage := []*ProfileEntryResponse{}
	if repostersLength > requestData.Offset {
		repostersPage = reposters[requestData.Offset:maxIdx]
	}

	// Return the posts found.
	res := &GetRepostsForPostResponse{
		Reposters:  repostersPage,
		Reclouters: repostersPage,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetRepostsForPost: Problem encoding response as JSON: %v", err))
		return
	}
}

type GetQuoteRepostsForPostRequest struct {
	// PostHashHex to fetch.
	PostHashHex                string `safeForLogging:"true"`
	Offset                     uint32 `safeForLogging:"true"`
	Limit                      uint32 `safeForLogging:"true"`
	ReaderPublicKeyBase58Check string `safeForLogging:"true"`
}

type GetQuoteRepostsForPostResponse struct {
	QuoteReposts  []*PostEntryResponse
	QuoteReclouts []*PostEntryResponse // Deprecated
}

func (fes *APIServer) GetQuoteRepostsForPost(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetQuoteRepostsForPostRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetQuoteRepostsForPost: Problem parsing request body: %v", err))
		return
	}

	postHash, err := GetPostHashFromPostHashHex(requestData.PostHashHex)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetQuoteRepostsForPost: %v", err))
		return
	}

	// Decode the reader public key into bytes. Default to nil if no pub key is passed in.
	var readerPublicKeyBytes []byte
	if requestData.ReaderPublicKeyBase58Check != "" {
		readerPublicKeyBytes, _, err = lib.Base58CheckDecode(requestData.ReaderPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetQuoteRepostsForPost: Problem decoding user public key: %v : %s",
				err, requestData.ReaderPublicKeyBase58Check))
			return
		}
	}

	// Get a view with all the mempool transactions.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetQuoteRepostsForPost: Error constucting utxoView: %v", err))
		return
	}

	// Fetch the quote reposts for the post requested.
	quoteReposterPubKeys, quoteReposterPubKeyToPosts, err := utxoView.GetQuoteRepostsForPostHash(postHash)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetQuoteRepostsForPost: Error getting reposters %v", err))
		return
	}

	// Filter out any restricted profiles.
	filteredPubKeys, err := fes.FilterOutRestrictedPubKeysFromList(
		quoteReposterPubKeys, readerPublicKeyBytes, "leaderboard" /*moderationType*/, utxoView)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetQuoteRepostsForPost: Error filtering out restricted profiles: %v", err))
		return
	}

	// Create a list of all the quote reposts.
	quoteReposts := []*PostEntryResponse{}
	for _, filteredPubKey := range filteredPubKeys {
		// We get profile entries first since we do not include pub keys without profiles.
		profileEntry := utxoView.GetProfileEntryForPublicKey(filteredPubKey)
		if profileEntry == nil {
			continue
		}

		// Now that we have a non-nil profile, fetch the post and make the PostEntryResponse.
		repostPostEntries := quoteReposterPubKeyToPosts[lib.MakePkMapKey(filteredPubKey)]
		profileEntryResponse := fes._profileEntryToResponse(profileEntry, utxoView)
		for _, repostPostEntry := range repostPostEntries {
			repostPostEntryResponse, err := fes._postEntryToResponse(
				repostPostEntry, false, fes.Params, utxoView, readerPublicKeyBytes, 2)
			if err != nil {
				_AddInternalServerError(ww, fmt.Sprintf("GetQuoteRepostsForPost: Error creating PostEntryResponse: %v", err))
				return
			}
			repostPostEntryResponse.ProfileEntryResponse = profileEntryResponse
			repostPostEntryResponse.PostEntryReaderState = utxoView.GetPostEntryReaderState(readerPublicKeyBytes, repostPostEntry)
			// Attach the finished repostPostEntryResponse.
			quoteReposts = append(quoteReposts, repostPostEntryResponse)
		}
	}

	// Almost done. Just need to sort the comments.
	sort.Slice(quoteReposts, func(ii, jj int) bool {
		iiProfile := quoteReposts[ii].ProfileEntryResponse
		jjProfile := quoteReposts[jj].ProfileEntryResponse

		// Attempt to sort on deso locked.
		iiDeSoLocked := iiProfile.CoinEntry.DeSoLockedNanos
		jjDeSoLocked := jjProfile.CoinEntry.DeSoLockedNanos
		if iiDeSoLocked > jjDeSoLocked {
			return true
		} else if iiDeSoLocked < jjDeSoLocked {
			return false
		}

		// If deso locked is the same, sort on timestamp.
		if quoteReposts[ii].TimestampNanos > quoteReposts[jj].TimestampNanos {
			return true
		} else if quoteReposts[ii].TimestampNanos < quoteReposts[jj].TimestampNanos {
			return false
		}

		// Sort based on pub key if all else fails.
		return iiProfile.PublicKeyBase58Check > jjProfile.PublicKeyBase58Check
	})

	// Cut out the page of reposters that we care about.
	quoteRepostsLength := uint32(len(quoteReposts))
	// Slice the comments from the offset up to either the end of the slice or the offset + limit, whichever is smaller.
	maxIdx := lib.MinUint32(quoteRepostsLength, requestData.Offset+requestData.Limit)
	quoteRepostsPage := []*PostEntryResponse{}
	if quoteRepostsLength > requestData.Offset {
		quoteRepostsPage = quoteReposts[requestData.Offset:maxIdx]
	}

	// Return the posts found.
	res := &GetQuoteRepostsForPostResponse{
		QuoteReposts:  quoteRepostsPage,
		QuoteReclouts: quoteRepostsPage,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetQuoteRepostsForPost: Problem encoding response as JSON: %v", err))
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

// Parse post body, extract all tags (e.g. @diamondhands), and return them in a slice.
func ParseTagsFromPost(postEntry *lib.PostEntry) ([]string, error) {
	// Get the body of the post.
	bodyJSONObj := &lib.DeSoBodySchema{}
	err := json.Unmarshal(postEntry.Body, bodyJSONObj)
	if err != nil {
		return nil, fmt.Errorf("Error parsing tags from post: %v", err)
	}
	// Get body text from body and split on whitespace characters.
	bodyString := bodyJSONObj.Body
	bodyWords := strings.Fields(bodyString)

	var tags []string

	// Search each word to see if it's an @ mention, $ mention, or # tag (starts w/ symbol and is at least of length 2).
	for _, word := range bodyWords {
		if len(word) >= 2 && (word[0:1] == "@" || word[0:1] == "#" || word[0:1] == "$") {
			// Remove @ from returned word and normalize to lower-case.
			tags = append(tags, strings.ToLower(word))
		}
	}

	return tags, nil
}
