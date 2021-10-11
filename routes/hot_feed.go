package routes

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"time"

	"github.com/deso-protocol/core/lib"
	"github.com/golang/glog"
)

// This file defines a simple go routine that tracks "hot" posts from the last 24hrs as well
// as API functionality for retrieving scored posts. The algorithm for assessing a post's
// "hotness" is experimental and will likely be iterated upon depending on its results.

// HotnessFeed scoring algorithm knobs.
const (
	// Number of blocks per halving for the scoring time decay.
	DefaultHotFeedTimeDecayBlocks uint64 = 72
	// Maximum score amount that any individual PKID can contribute before time decay.
	DefaultHotFeedInteractionCap uint64 = 4e12
)

// A single element in the server's HotFeedOrderedList.
type HotFeedEntry struct {
	PostHash     *lib.BlockHash
	PostHashHex  string
	HotnessScore uint64
}

// A key to track whether a specific public key has interacted with a post before.
type HotFeedInteractionKey struct {
	InteractionPKID     lib.PKID
	InteractionPostHash lib.BlockHash
}

// A cached "HotFeedOrderedList" is stored on the server object and updated whenever a new
// block is found. In addition, a "HotFeedApprovedPostMap" is maintained using hot feed
// approval/removal operations stored in global state. Once started, the routine runs every
// second in order to make sure hot feed removals are processed quickly.
func (fes *APIServer) StartHotFeedRoutine() {
	glog.Info("Starting hot feed routine.")
	go func() {
	out:
		for {
			select {
			case <-time.After(1 * time.Second):
				fes.UpdateHotFeed()
			case <-fes.quit:
				break out
			}
		}
	}()
}

// The business.
func (fes *APIServer) UpdateHotFeed() {
	// We copy the HotFeedApprovedPosts map so we can access it safely without locking it.
	hotFeedApprovedPosts := fes.CopyHotFeedApprovedPostsMap()

	// Update the approved posts map based on global state.
	fes.UpdateHotFeedApprovedPostsMap(hotFeedApprovedPosts)

	// Update the HotFeedOrderedList based on the last 288 blocks.
	hotFeedPosts := fes.UpdateHotFeedOrderedList()

	// The hotFeedPostsMap will be nil unless we found new blocks in the call above.
	if hotFeedPosts != nil {
		fes.PruneHotFeedApprovedPostsMap(hotFeedPosts, hotFeedApprovedPosts)
	}

	// Replace the HotFeedApprovedPostsMap with the fresh one.
	fes.HotFeedApprovedPosts = hotFeedApprovedPosts
}

func (fes *APIServer) UpdateHotFeedApprovedPostsMap(hotFeedApprovedPosts map[lib.BlockHash][]byte) {
	// Grab all of the relevant operations to update the map with.
	startTimestampNanos := uint64(time.Now().UTC().AddDate(0, 0, -1).UnixNano()) // 1 day ago.
	if fes.LastHotFeedOpProcessedTstampNanos != 0 {
		startTimestampNanos = fes.LastHotFeedOpProcessedTstampNanos
	}
	startPrefix := GlobalStateSeekKeyForHotFeedOps(startTimestampNanos)
	opKeys, _, err := fes.GlobalStateSeek(
		startPrefix,
		_GlobalStatePrefixForHotFeedOps, /*validForPrefix*/
		0,                               /*maxKeyLen -- ignored since reverse is false*/
		0,                               /*numToFetch -- 0 is ignored*/
		false,                           /*reverse*/
		false,                           /*fetchValues*/
	)
	if err != nil {
		glog.Infof("UpdateHotFeedApprovedPostsMap: GlobalStateSeek failed: %v", err)
	}

	// Chop up the keys and process each operation.
	for _, opKey := range opKeys {
		// Each key consists of: prefix, timestamp, posthash, IsRemoval bool.
		timestampStartIdx := 1
		postHashStartIdx := timestampStartIdx + 8
		isRemovalBoolStartIdx := postHashStartIdx + lib.HashSizeBytes

		postHashBytes := opKey[postHashStartIdx:isRemovalBoolStartIdx]
		isRemovalBoolBytes := opKey[isRemovalBoolStartIdx:]

		postHash := &lib.BlockHash{}
		copy(postHash[:], postHashBytes)
		isRemoval := lib.ReadBoolByte(bytes.NewReader(isRemovalBoolBytes))

		if isRemoval {
			delete(hotFeedApprovedPosts, *postHash)
		} else {
			hotFeedApprovedPosts[*postHash] = []byte{}
		}
	}
}

func (fes *APIServer) CopyHotFeedApprovedPostsMap() map[lib.BlockHash][]byte {
	hotFeedApprovedPosts := make(map[lib.BlockHash][]byte, len(fes.HotFeedApprovedPosts))
	for postKey := range fes.HotFeedApprovedPosts {
		hotFeedApprovedPosts[postKey] = []byte{}
	}
	return hotFeedApprovedPosts
}

type HotnessPostInfo struct {
	// How long ago the post was created in number of blocks
	PostBlockAge int
	HotnessScore uint64
}
func (fes *APIServer) UpdateHotFeedOrderedList() (_hotFeedPostsMap map[lib.BlockHash]*HotnessPostInfo) {
	// Check to see if any of the algorithm constants have changed.
	foundNewConstants := false
	globalStateInteractionCap, globalStateTimeDecayBlocks, err := fes.GetHotFeedConstantsFromGlobalState()
	if err != nil {
		glog.Infof("UpdateHotFeedOrderedList: ERROR - Failed to get constants: %v", err)
		return nil
	}
	if globalStateInteractionCap == 0 || globalStateTimeDecayBlocks == 0 {
		// The hot feed go routine has not been run yet since constants have not been set.
		foundNewConstants = true
		// Set the default constants in GlobalState and then on the server object.
		err := fes.GlobalStatePut(
			_GlobalStatePrefixForHotFeedInteractionCap,
			lib.EncodeUint64(DefaultHotFeedInteractionCap),
		)
		if err != nil {
			glog.Infof("UpdateHotFeedOrderedList: ERROR - Failed to put InteractionCap: %v", err)
			return nil
		}
		err = fes.GlobalStatePut(
			_GlobalStatePrefixForHotFeedTimeDecayBlocks,
			lib.EncodeUint64(DefaultHotFeedTimeDecayBlocks),
		)
		if err != nil {
			glog.Infof("UpdateHotFeedOrderedList: ERROR - Failed to put TimeDecayBlocks: %v", err)
			return nil
		}

		// Now that we've successfully updated global state, set them on the server object.
		fes.HotFeedInteractionCap = DefaultHotFeedInteractionCap
		fes.HotFeedTimeDecayBlocks = DefaultHotFeedTimeDecayBlocks
	} else if fes.HotFeedInteractionCap != globalStateInteractionCap ||
		fes.HotFeedTimeDecayBlocks != globalStateTimeDecayBlocks {
		// New constants were found in global state. Set them and proceed.
		fes.HotFeedInteractionCap = globalStateInteractionCap
		fes.HotFeedTimeDecayBlocks = globalStateTimeDecayBlocks
		foundNewConstants = true
	}

	// If the constants for the algorithm haven't changed and we have already seen the latest
	// block or the chain is out of sync, bail.
	blockTip := fes.blockchain.BlockTip()
	chainState := fes.blockchain.ChainState()
	if !foundNewConstants &&
		(blockTip.Height <= fes.HotnessBlockHeight || chainState != lib.SyncStateFullyCurrent) {
		return nil
	}

	// Log how long this routine takes, since it could be heavy.
	glog.Info("UpdateHotFeedOrderedList: Starting new update cycle.")
	start := time.Now()

	// Get a utxoView for lookups.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		glog.Infof("UpdateHotFeedOrderedList: ERROR - Failed to get utxo view: %v", err)
		return nil
	}

	// This offset allows us to see what the hot feed would look like in the past,
	// which is useful for testing purposes.
	blockOffsetForTesting := 0

	// Grab the last 24 hours worth of blocks (288 blocks @ 5min/block).
	blockTipIndex := len(fes.blockchain.BestChain()) - 1 - blockOffsetForTesting
	relevantNodes := fes.blockchain.BestChain()
	if len(fes.blockchain.BestChain()) > (288 + blockOffsetForTesting) {
		relevantNodes = fes.blockchain.BestChain()[blockTipIndex-288-blockOffsetForTesting : blockTipIndex]
	}

	// Iterate over the blocks and track hotness scores.
	hotnessInfoMap := make(map[lib.BlockHash]*HotnessPostInfo)
	postInteractionMap := make(map[HotFeedInteractionKey][]byte)
	for blockIdx, node := range relevantNodes {
		block, _ := lib.GetBlock(node.Hash, utxoView.Handle)
		for _, txn := range block.Txns {
			// For time decay, we care about how many blocks away from the tip this block is.
			blockAgee := len(relevantNodes) - blockIdx

			// We only care about posts created in the last 24hrs. There should always be a
			// transaction that creates a given post before someone interacts with it. By only
			// scoring posts that meet this condition, we can restrict the HotFeedOrderedList
			// to posts from the last 24hours without even looking up the post time stamp.
			isCreatePost, postHashCreated := CheckTxnForCreatePost(txn)
			if isCreatePost {
				hotnessInfoMap[*postHashCreated] = &HotnessPostInfo{
					PostBlockAge: blockAgee,
					HotnessScore: 0,
				}
				continue
			}

			// The age used in determining the score should be that of the post
			// that we are evaluating. The interaction's score will be discounted
			// by this age.
			postHashToScore := GetPostHashToScoreForTxn(txn, utxoView)
			if postHashToScore == nil {
				// If we don't have a post hash to score then this txn is not relevant
				// and we can continue.
				continue
			}
			prevHotnessInfo, inHotnessInfoMap := hotnessInfoMap[*postHashToScore]
			if !inHotnessInfoMap {
				// If the post is not in the hotnessInfoMap yet, it wasn't created
				// in the last 24hrs so we can continue.
				continue
			}
			postBlockAge := prevHotnessInfo.PostBlockAge

			// If we get here, we know we are dealing with a txn that interacts with a
			// post that was created within the last 24 hours.

			// Evaluate the txn and attempt to update the hotnessInfoMap.
			postHashScored, txnHotnessScore := fes.GetHotnessScoreInfoForTxn(
				txn, postBlockAge, postInteractionMap, utxoView)
			if txnHotnessScore != 0 && postHashScored != nil {
				// Check for overflow just in case.
				if prevHotnessInfo.HotnessScore > math.MaxInt64-txnHotnessScore {
					continue
				}
				// Finally, make sure the post scored isn't a comment or repost.
				postEntryScored := utxoView.GetPostEntryForPostHash(postHashScored)
				if len(postEntryScored.ParentStakeID) > 0 || lib.IsVanillaRepost(postEntryScored) {
					continue
				}
				// Update the hotness score.
				prevHotnessInfo.HotnessScore += txnHotnessScore
			}
		}
	}

	// Sort the map into an ordered list and set it as the server's new HotFeedOrderedList.
	hotFeedOrderedList := []*HotFeedEntry{}
	for postHashKey, hotnessInfo := range hotnessInfoMap {
		postHash := postHashKey
		hotFeedEntry := &HotFeedEntry{
			PostHash:     &postHash,
			PostHashHex:  hex.EncodeToString(postHash[:]),
			HotnessScore: hotnessInfo.HotnessScore,
		}
		hotFeedOrderedList = append(hotFeedOrderedList, hotFeedEntry)
	}
	sort.Slice(hotFeedOrderedList, func(ii, jj int) bool {
		return hotFeedOrderedList[ii].HotnessScore > hotFeedOrderedList[jj].HotnessScore
	})
	fes.HotFeedOrderedList = hotFeedOrderedList

	// Update the HotnessBlockHeight so we don't re-evaluate this set of blocks.
	fes.HotnessBlockHeight = blockTip.Height

	elapsed := time.Since(start)
	glog.Infof("Successfully updated HotFeedOrderedList in %s", elapsed)

	return hotnessInfoMap
}

func (fes *APIServer) GetHotFeedConstantsFromGlobalState() (
	_interactionCap uint64, _timeDecayBlocks uint64, _err error,
) {
	interactionCapBytes, err := fes.GlobalStateGet(_GlobalStatePrefixForHotFeedInteractionCap)
	if err != nil {
		return 0, 0, nil
	}
	interactionCap := uint64(0)
	if len(interactionCapBytes) > 0 {
		interactionCap = lib.DecodeUint64(interactionCapBytes)
	}

	timeDecayBlocksBytes, err := fes.GlobalStateGet(_GlobalStatePrefixForHotFeedTimeDecayBlocks)
	if err != nil {
		return 0, 0, nil
	}
	timeDecayBlocks := uint64(0)
	if len(timeDecayBlocksBytes) > 0 {
		timeDecayBlocks = lib.DecodeUint64(timeDecayBlocksBytes)
	}

	return interactionCap, timeDecayBlocks, nil
}

func CheckTxnForCreatePost(txn *lib.MsgDeSoTxn) (
	_isCreatePostTxn bool, _postHashCreated *lib.BlockHash) {
	if txn.TxnMeta.GetTxnType() == lib.TxnTypeSubmitPost {
		txMeta := txn.TxnMeta.(*lib.SubmitPostMetadata)
		// The post hash of a brand new post is the same as its txn hash.
		if len(txMeta.PostHashToModify) == 0 {
			return true, txn.Hash()
		}
	}

	return false, nil
}

func GetPostHashToScoreForTxn(txn *lib.MsgDeSoTxn,
	utxoView *lib.UtxoView) (*lib.BlockHash) {
	// Figure out which post this transaction should affect.
	interactionPostHash := &lib.BlockHash{}
	txnType := txn.TxnMeta.GetTxnType()
	if txnType == lib.TxnTypeLike {
		txMeta := txn.TxnMeta.(*lib.LikeMetadata)
		interactionPostHash = txMeta.LikedPostHash

	} else if txnType == lib.TxnTypeBasicTransfer {
		// Check for a post being diamonded.
		diamondPostHashBytes, hasDiamondPostHash := txn.ExtraData[lib.DiamondPostHashKey]
		if hasDiamondPostHash {
			copy(interactionPostHash[:], diamondPostHashBytes[:])
		} else {
			// If this basic transfer doesn't have a diamond, it is irrelevant.
			return nil
		}

	} else if txnType == lib.TxnTypeSubmitPost {
		txMeta := txn.TxnMeta.(*lib.SubmitPostMetadata)
		// If this is a transaction creating a brand new post, we can ignore it.
		if len(txMeta.PostHashToModify) == 0 {
			return nil
		}
		postHash := &lib.BlockHash{}
		copy(postHash[:], txMeta.PostHashToModify[:])
		postEntry := utxoView.GetPostEntryForPostHash(postHash)

		// For posts we must process three cases: Reposts, Quoted Reposts, and Comments.
		if lib.IsVanillaRepost(postEntry) || lib.IsQuotedRepost(postEntry) {
			repostedPostHashBytes := txn.ExtraData[lib.RepostedPostHash]
			copy(interactionPostHash[:], repostedPostHashBytes)
		} else if len(postEntry.ParentStakeID) > 0 {
			copy(interactionPostHash[:], postEntry.ParentStakeID[:])
		} else {
			return nil
		}

	} else {
		// This transaction is not relevant, bail.
		return nil
	}

	return interactionPostHash
}

// Returns the post hash that a txn is relevant to and the amount that the txn should contribute
// to that post's hotness score. The postInteractionMap is used to ensure that each PKID only
// gets one interaction per post.
func (fes *APIServer) GetHotnessScoreInfoForTxn(
	txn *lib.MsgDeSoTxn,
	blockAge int, // Number of blocks this txn is from the blockTip.  Not block height.
	postInteractionMap map[HotFeedInteractionKey][]byte,
	utxoView *lib.UtxoView,
) (_postHashScored *lib.BlockHash, _hotnessScore uint64) {
	// Figure out who is responsible for the transaction.
	interactionPKIDEntry := utxoView.GetPKIDForPublicKey(txn.PublicKey)

	interactionPostHash := GetPostHashToScoreForTxn(txn, utxoView)

	// Check to see if we've seen this interaction pair before. Log an interaction if not.
	interactionKey := HotFeedInteractionKey{
		InteractionPKID:     *interactionPKIDEntry.PKID,
		InteractionPostHash: *interactionPostHash,
	}
	if _, exists := postInteractionMap[interactionKey]; exists {
		return nil, 0
	} else {
		postInteractionMap[interactionKey] = []byte{}
	}

	// Finally return the post hash and the txn's hotness score.
	interactionProfile := utxoView.GetProfileEntryForPKID(interactionPKIDEntry.PKID)
	// It is possible for the profile to be nil since you don't need a profile for diamonds.
	if interactionProfile == nil || interactionProfile.IsDeleted() {
		return nil, 0
	}
	hotnessScore := interactionProfile.DeSoLockedNanos
	if hotnessScore > fes.HotFeedInteractionCap {
		hotnessScore = fes.HotFeedInteractionCap
	}
	hotnessScoreTimeDecayed := uint64(float64(hotnessScore) *
		math.Pow(0.5, float64(blockAge)/float64(fes.HotFeedTimeDecayBlocks)))
	return interactionPostHash, hotnessScoreTimeDecayed
}

func (fes *APIServer) PruneHotFeedApprovedPostsMap(
	hotFeedPosts map[lib.BlockHash]*HotnessPostInfo, hotFeedApprovedPosts map[lib.BlockHash][]byte,
) {
	for postHash := range fes.HotFeedApprovedPosts {
		if _, inHotFeedMap := hotFeedPosts[postHash]; !inHotFeedMap {
			delete(hotFeedApprovedPosts, postHash)
		}
	}
}

type HotFeedPageRequest struct {
	ReaderPublicKeyBase58Check string
	// Since the hot feed is constantly changing, we pass a list of posts that have already
	// been seen in order to send a more accurate next page.
	SeenPosts []string
	// Number of post entry responses to return.
	ResponseLimit int
}

type HotFeedPageResponse struct {
	HotFeedPage []PostEntryResponse
}

func (fes *APIServer) AdminGetUnfilteredHotFeed(ww http.ResponseWriter, req *http.Request) {
	fes.HandleHotFeedPageRequest(ww, req, false /*approvedPostsOnly*/)
}

func (fes *APIServer) GetHotFeed(ww http.ResponseWriter, req *http.Request) {
	// RPH-FIXME: set approvedPostsOnly to true before launch.
	fes.HandleHotFeedPageRequest(ww, req, false /*approvedPostsOnly*/)
}

func (fes *APIServer) HandleHotFeedPageRequest(
	ww http.ResponseWriter,
	req *http.Request,
	approvedPostsOnly bool,
) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := HotFeedPageRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("HandleHotFeedPageRequest: Problem parsing request body: %v", err))
		return
	}

	var readerPublicKeyBytes []byte
	var err error
	if requestData.ReaderPublicKeyBase58Check != "" {
		readerPublicKeyBytes, _, err = lib.Base58CheckDecode(requestData.ReaderPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("HandleHotFeedPageRequest: Problem decoding reader public key: %v", err))
			return
		}
	}

	// Get a view.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("HandleHotFeedPageRequest: Error getting utxoView: %v", err))
		return
	}
	// Grab verified username map pointer.
	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("HandleHotFeedPageRequest: Problem fetching verifiedMap: %v", err))
		return
	}

	// Make the lists of posts a user has already seen into a map.
	seenPostsMap := make(map[string][]byte)
	for _, postHashHex := range requestData.SeenPosts {
		seenPostsMap[postHashHex] = []byte{}
	}

	hotFeed := []PostEntryResponse{}
	for _, hotFeedEntry := range fes.HotFeedOrderedList {
		if requestData.ResponseLimit != 0 && len(hotFeed) > requestData.ResponseLimit {
			break
		}

		// Skip posts that have already been seen.
		if _, alreadySeen := seenPostsMap[hotFeedEntry.PostHashHex]; alreadySeen {
			continue
		}

		// Skip posts that aren't approved yet, if requested.
		if _, isApproved := fes.HotFeedApprovedPosts[*hotFeedEntry.PostHash]; approvedPostsOnly && !isApproved {
			continue
		}

		postEntry := utxoView.GetPostEntryForPostHash(hotFeedEntry.PostHash)
		postEntryResponse, err := fes._postEntryToResponse(
			postEntry, true, fes.Params, utxoView, readerPublicKeyBytes, 1)
		if err != nil {
			continue
		}
		profileEntry := utxoView.GetProfileEntryForPublicKey(postEntry.PosterPublicKey)
		postEntryResponse.ProfileEntryResponse = _profileEntryToResponse(
			profileEntry, fes.Params, verifiedMap, utxoView)
		postEntryResponse.PostEntryReaderState = utxoView.GetPostEntryReaderState(
			readerPublicKeyBytes, postEntry)
		postEntryResponse.HotnessScore = hotFeedEntry.HotnessScore
		hotFeed = append(hotFeed, *postEntryResponse)
	}

	res := HotFeedPageResponse{HotFeedPage: hotFeed}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("HandleHotFeedPageRequest: Problem encoding response as JSON: %v", err))
		return
	}
}

type AdminUpdateHotFeedAlgorithmRequest struct {
	// Maximum score amount that any individual PKID can contribute to the hot feed score
	// before time decay. Ignored if set to zero.
	InteractionCap int
	// Number of blocks per halving for the hot feed score time decay. Ignored if set to zero.
	TimeDecayBlocks int
}

type AdminUpdateHotFeedAlgorithmResponse struct{}

func (fes *APIServer) AdminUpdateHotFeedAlgorithm(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminUpdateHotFeedAlgorithmRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateHotFeedAlgorithm: Problem parsing request body: %v", err))
		return
	}

	if requestData.InteractionCap < 0 || requestData.TimeDecayBlocks < 0 {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AdminUpdateHotFeedAlgorithm: InteractionCap (%d) and TimeDecayBlocks (%d) can't be negative.",
			requestData.InteractionCap, requestData.TimeDecayBlocks))
		return
	}

	if requestData.InteractionCap > 0 {
		err := fes.GlobalStatePut(
			_GlobalStatePrefixForHotFeedInteractionCap,
			lib.EncodeUint64(uint64(requestData.InteractionCap)),
		)
		if err != nil {
			_AddInternalServerError(ww, fmt.Sprintf("AdminUpdateHotFeedAlgorithm: Error putting InteractionCap: %v", err))
			return
		}
	}

	if requestData.TimeDecayBlocks > 0 {
		err := fes.GlobalStatePut(
			_GlobalStatePrefixForHotFeedTimeDecayBlocks,
			lib.EncodeUint64(uint64(requestData.TimeDecayBlocks)),
		)
		if err != nil {
			_AddInternalServerError(ww, fmt.Sprintf("AdminUpdateHotFeedAlgorithm: Error putting TimeDecayBlocks: %v", err))
			return
		}
	}

	res := AdminUpdateHotFeedAlgorithmResponse{}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateHotFeedAlgorithm: Problem encoding response as JSON: %v", err))
		return
	}
}

type AdminGetHotFeedAlgorithmRequest struct{}

type AdminGetHotFeedAlgorithmResponse struct {
	InteractionCap  uint64
	TimeDecayBlocks uint64
}

func (fes *APIServer) AdminGetHotFeedAlgorithm(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminGetHotFeedAlgorithmRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetHotFeedAlgorithm: Problem parsing request body: %v", err))
		return
	}

	interactionCap, timeDecayBlocks, err := fes.GetHotFeedConstantsFromGlobalState()
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("AdminGetHotFeedAlgorithm: Error getting constants: %v", err))
		return
	}

	res := AdminGetHotFeedAlgorithmResponse{
		InteractionCap:  interactionCap,
		TimeDecayBlocks: timeDecayBlocks,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetHotFeedAlgorithm: Problem encoding response as JSON: %v", err))
		return
	}
}
