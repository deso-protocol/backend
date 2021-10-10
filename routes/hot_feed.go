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
	HotnessScoreTimeDecayBlocks uint64 = 72
	// Maximum score amount that any individual PKID can contribute before time decay.
	HotnessScoreInteractionCap uint64 = 3e12
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
		isRemovalBoolStartIdx := postHashStartIdx + 8

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

func (fes *APIServer) UpdateHotFeedOrderedList() (_hotFeedPostsMap map[lib.BlockHash]uint64) {
	// If we have already seen the latest block or the chain is out of sync, bail.
	blockTip := fes.blockchain.BlockTip()
	chainState := fes.blockchain.ChainState()
	if blockTip.Height <= fes.HotnessBlockHeight || chainState != lib.SyncStateFullyCurrent {
		return nil
	}

	glog.Info("Attempting to update HotFeedOrderedList with new blocks.")
	start := time.Now()

	// Get a utxoView for lookups.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		glog.Infof("UpdateHotFeedOrderedList: Failed to get utxo view: %v", err)
		return nil
	}

	// Grab the last 24 hours worth of blocks (288 blocks @ 5min/block).
	blockTipIndex := len(fes.blockchain.BestChain()) - 1
	relevantNodes := fes.blockchain.BestChain()
	if len(fes.blockchain.BestChain()) > 288 {
		relevantNodes = fes.blockchain.BestChain()[blockTipIndex-288 : blockTipIndex]
	}

	// Iterate over the blocks and track hotness scores.
	hotnessScoreMap := make(map[lib.BlockHash]uint64)
	postInteractionMap := make(map[HotFeedInteractionKey][]byte)
	for blockIdx, node := range relevantNodes {
		block, _ := lib.GetBlock(node.Hash, utxoView.Handle)
		for _, txn := range block.Txns {
			// We only care about posts created in the last 24hrs. There should always be a
			// transaction that creates a given post before someone interacts with it. By only
			// scoring posts that meet this condition, we can restrict the HotFeedOrderedList
			// to posts from the last 24hours without even looking up the post time stamp.
			isCreatePost, postHashCreated := CheckTxnForCreatePost(txn)
			if isCreatePost {
				hotnessScoreMap[*postHashCreated] = 0
				continue
			}

			// Evaluate the txn and attempt to update the hotnessScoreMap.
			postHashScored, txnHotnessScore := GetHotnessScoreInfoForTxn(
				txn, blockIdx, postInteractionMap, utxoView)
			if txnHotnessScore != 0 && postHashScored != nil {
				prevHotnessScore, inHotnessScoreMap := hotnessScoreMap[*postHashScored]
				// Check for overflow just in case.
				if prevHotnessScore > math.MaxInt64-txnHotnessScore {
					continue
				}
				// If it isn't in the hotnessScoreMap yet, it wasn't created in the last 24hrs.
				if !inHotnessScoreMap {
					continue
				}
				hotnessScoreMap[*postHashScored] = prevHotnessScore + txnHotnessScore
			}
		}
	}

	// Sort the map into an ordered list and set it as the server's new HotFeedOrderedList.
	hotFeedOrderedList := []*HotFeedEntry{}
	for postHashKey, hotnessScoreValue := range hotnessScoreMap {
		postHash := postHashKey
		hotFeedEntry := &HotFeedEntry{
			PostHash:     &postHash,
			PostHashHex:  hex.EncodeToString(postHash[:]),
			HotnessScore: hotnessScoreValue,
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

	return hotnessScoreMap
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

// Returns the post hash that a txn is relevant to and the amount that the txn should contribute
// to that post's hotness score. The postInteractionMap is used to ensure that each PKID only
// gets one interaction per post.
func GetHotnessScoreInfoForTxn(
	txn *lib.MsgDeSoTxn,
	blockIndex int, // Position in the last 288 blocks.  Not block height.
	postInteractionMap map[HotFeedInteractionKey][]byte,
	utxoView *lib.UtxoView,
) (_postHashScored *lib.BlockHash, _hotnessScore uint64) {
	// Figure out who is responsible for the transaction.
	interactionPKIDEntry := utxoView.GetPKIDForPublicKey(txn.PublicKey)

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
			return nil, 0
		}

	} else if txnType == lib.TxnTypeSubmitPost {
		txMeta := txn.TxnMeta.(*lib.SubmitPostMetadata)
		// If this is a transaction creating a brand new post, we can ignore it.
		if len(txMeta.PostHashToModify) == 0 {
			return nil, 0
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
			return nil, 0
		}

	} else {
		// This transaction is not relevant, bail.
		return nil, 0
	}

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
	if hotnessScore > HotnessScoreInteractionCap {
		hotnessScore = HotnessScoreInteractionCap
	}
	hotnessScoreTimeDecayed := uint64(float64(hotnessScore) *
		math.Pow(0.5, float64(blockIndex)/float64(HotnessScoreTimeDecayBlocks)))
	return interactionPostHash, hotnessScoreTimeDecayed
}

func (fes *APIServer) PruneHotFeedApprovedPostsMap(
	hotFeedPosts map[lib.BlockHash]uint64, hotFeedApprovedPosts map[lib.BlockHash][]byte,
) {
	for postHash := range fes.HotFeedApprovedPosts {
		if _, inHotFeedMap := hotFeedPosts[postHash]; !inHotFeedMap {
			delete(hotFeedApprovedPosts, postHash)
		}
	}
}

type HotFeedPageRequest struct {
	// Since the hot feed is constantly changing, we pass a map of posts that have already
	// been seen in order to send a more accurate next page. The bool value is unused and
	// only included because golang does not have a native "Set" datastructure.
	SeenPostsMap map[string]bool
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
	fes.HandleHotFeedPageRequest(ww, req, true /*approvedPostsOnly*/)
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

	hotFeed := []PostEntryResponse{}
	for _, hotFeedEntry := range fes.HotFeedOrderedList {
		if requestData.ResponseLimit != 0 && len(hotFeed) > requestData.ResponseLimit {
			break
		}

		// Skip posts that have already been seen.
		if _, alreadySeen := requestData.SeenPostsMap[hotFeedEntry.PostHashHex]; alreadySeen {
			continue
		}

		// Skip posts that aren't approved yet, if requested.
		if _, isApproved := fes.HotFeedApprovedPosts[*hotFeedEntry.PostHash]; approvedPostsOnly && !isApproved {
			continue
		}

		postEntry := utxoView.GetPostEntryForPostHash(hotFeedEntry.PostHash)
		postEntryResponse, err := fes._postEntryToResponse(postEntry, false, fes.Params, utxoView, nil, 1)
		if err != nil {
			continue
		}
		profileEntry := utxoView.GetProfileEntryForPublicKey(postEntry.PosterPublicKey)
		postEntryResponse.ProfileEntryResponse = _profileEntryToResponse(
			profileEntry, fes.Params, verifiedMap, utxoView)
		postEntryResponse.HotnessScore = hotFeedEntry.HotnessScore
		hotFeed = append(hotFeed, *postEntryResponse)
	}

	res := HotFeedPageResponse{HotFeedPage: hotFeed}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("HandleHotFeedPageRequest: Problem encoding response as JSON: %v", err))
		return
	}
}
