package routes

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"reflect"
	"sort"
	"time"

	"github.com/deso-protocol/core/lib"
	"github.com/golang/glog"
)

// This file defines a simple go routine that tracks "hot" posts from the specified look-back period as well
// as API functionality for retrieving scored posts. The algorithm for assessing a post's
// "hotness" is experimental and will likely be iterated upon depending on its results.

// HotnessFeed scoring algorithm knobs.
const (
	// Number of blocks per halving for the scoring time decay for the global hot feed.
	DefaultHotFeedTimeDecayBlocks uint64 = 43200
	// Number of blocks per halving for the scoring time decay for a tag hot feed.
	DefaultHotFeedTagTimeDecayBlocks uint64 = 43200
	// Maximum score amount that any individual PKID can contribute before time decay.
	DefaultHotFeedInteractionCap uint64 = 4e12
	// Maximum score amount that any individual PKID can contribute before time decay for a particular tag grouping.
	DefaultHotFeedTagInteractionCap uint64 = 4e12
	// How many iterations of the hot feed calculation until the built-up caches should be reset. (Once per day)
	ResetCachesIterationLimit int = 288
	// This is how many blocks we consider as part of our ranking. It should be a good deal bigger than
	// the time decay blocks.
	LookbackWindowBlocks = 7 * 24 * 60 * 60
)

// A single element in the server's HotFeedOrderedList.
type HotFeedEntry struct {
	PostHash     *lib.BlockHash
	PostHashHex  string
	HotnessScore uint64
}

// A single element in the server's HotFeedOrderedList, with the age of the post for sorting purposes.
type HotFeedEntryTimeSortable struct {
	PostHash     *lib.BlockHash
	PostHashHex  string
	HotnessScore uint64
	PostBlockAge int
}

// A key to track whether a specific public key has interacted with a post before.
type HotFeedInteractionKey struct {
	InteractionPKID     lib.PKID
	InteractionPostHash lib.BlockHash
}

// Multipliers to help a node operator boost content from PKID's relevant to their node.
// For example, a sports-focused node could boost athlete PKIDs.
type HotFeedPKIDMultiplier struct {
	// A multiplier applied to the score that each user interaction adds to a post.
	InteractionMultiplier float64
	// A multiplier applied to all posts from this specific PKID.
	PostsMultiplier float64
}

// A cached "HotFeedOrderedList" is stored on the server object and updated whenever a new
// block is found. In addition, a "HotFeedApprovedPostMap" is maintained using hot feed
// approval/removal operations stored in global state. Once started, the routine runs every
// second in order to make sure hot feed removals are processed quickly.
func (fes *APIServer) StartHotFeedRoutine() {
	glog.Info("Starting hot feed routine.")
	// Initialize maps used for serving tag-specific hot feeds.
	fes.PostTagToPostHashesMap = make(map[string]map[lib.BlockHash]bool)
	fes.PostTagToOrderedHotFeedEntries = make(map[string][]*HotFeedEntry)
	fes.PostTagToOrderedNewestEntries = make(map[string][]*HotFeedEntry)
	fes.PostHashToPostTagsMap = make(map[lib.BlockHash][]string)
	fes.HotFeedBlockCache = make(map[lib.BlockHash]*lib.MsgDeSoBlock)
	cacheResetCounter := 0
	go func() {
	out:
		for {
			select {
			case <-time.After(30 * time.Second):
				// Use an inner function to unlock the mutex with a defer statement.
				func() {
					// If we're syncing a snapshot, we need to lock the DB mutex before updating the hot feed.
					// This is because at the end of a snapshot sync, we re-start the DB, which will cause
					// the hot feed routine to panic if it's in the middle of updating the hot feed.
					if fes.backendServer.GetBlockchain().ChainState() == lib.SyncStateSyncingSnapshot {
						fes.backendServer.DbMutex.Lock()
						defer fes.backendServer.DbMutex.Unlock()
					}
					resetCache := false
					if cacheResetCounter >= ResetCachesIterationLimit {
						resetCache = true
						cacheResetCounter = 0
					}
					fes.UpdateHotFeed(resetCache)
					cacheResetCounter += 1
				}()
			case <-fes.quit:
				break out
			}
		}
	}()
}

// The business.
func (fes *APIServer) UpdateHotFeed(resetCache bool) {
	glog.V(2).Info("Refreshing hot feed...")
	if resetCache {
		glog.V(2).Info("Resetting hot feed cache.")
		fes.PostTagToPostHashesMap = make(map[string]map[lib.BlockHash]bool)
		fes.PostHashToPostTagsMap = make(map[lib.BlockHash][]string)
		fes.HotFeedBlockCache = make(map[lib.BlockHash]*lib.MsgDeSoBlock)
	}

	// We copy the HotFeedApprovedPosts map and HotFeedPKIDMultiplier maps so we can access
	// them safely without locking them.
	hotFeedApprovedPosts := fes.CopyHotFeedApprovedPostsMap()
	hotFeedPKIDMultipliers := fes.CopyHotFeedPKIDMultipliersMap()

	// Update the approved posts map and pkid multipliers map based on global state.
	fes.UpdateHotFeedApprovedPostsMap(hotFeedApprovedPosts)
	fes.UpdateHotFeedPKIDMultipliersMap(hotFeedPKIDMultipliers)

	// Update the HotFeedOrderedList based on the specified look-back period's blocks.
	hotFeedPosts := fes.UpdateHotFeedOrderedList(hotFeedApprovedPosts, hotFeedPKIDMultipliers)

	// The hotFeedPosts map will be nil unless we found new blocks in the call above.
	if hotFeedPosts != nil {
		fes.PruneHotFeedApprovedPostsMap(hotFeedPosts, hotFeedApprovedPosts)
	}

	// Replace the HotFeedApprovedPostsMap and HotFeedPKIDMultiplier map with the fresh ones.
	fes.HotFeedApprovedPostsToMultipliers = hotFeedApprovedPosts
	fes.HotFeedPKIDMultipliers = hotFeedPKIDMultipliers
	glog.V(2).Infof("Updated hot feed maps")
}

func (fes *APIServer) UpdateHotFeedApprovedPostsMap(hotFeedApprovedPosts map[lib.BlockHash]float64) {
	// Grab all of the relevant operations to update the map with.
	startTimestampNanos := uint64(time.Now().UTC().AddDate(0, 0, -1).UnixNano()) // 1 day ago.
	if fes.LastHotFeedApprovedPostOpProcessedTstampNanos != 0 {
		startTimestampNanos = fes.LastHotFeedApprovedPostOpProcessedTstampNanos
	}
	startPrefix := GlobalStateSeekKeyForHotFeedApprovedPostOps(startTimestampNanos + 1)
	opKeys, opVals, err := fes.GlobalState.Seek(
		startPrefix,
		_GlobalStatePrefixForHotFeedApprovedPostOps, /*validForPrefix*/
		0,     /*maxKeyLen -- ignored since reverse is false*/
		0,     /*numToFetch -- 0 is ignored*/
		false, /*reverse*/
		true,  /*fetchValues*/
	)
	if err != nil {
		glog.Infof("UpdateHotFeedApprovedPostsMap: Seek failed: %v", err)
	}

	// Chop up the keys and process each operation.
	for opIdx, opKey := range opKeys {
		// Each key consists of: prefix, timestamp, posthash.
		timestampStartIdx := 1
		postHashStartIdx := timestampStartIdx + 8

		postHashBytes := opKey[postHashStartIdx:]
		postHash := &lib.BlockHash{}
		copy(postHash[:], postHashBytes)

		// Deserialize the HotFeedApprovedPostOp.
		hotFeedOp := HotFeedApprovedPostOp{}
		hotFeedOpBytes := opVals[opIdx]
		if len(hotFeedOpBytes) > 0 {
			err = gob.NewDecoder(bytes.NewReader(hotFeedOpBytes)).Decode(&hotFeedOp)
			if err != nil {
				glog.Infof("UpdateHotFeedApprovedPostsMap: ERROR decoding HotFeedApprovedPostOp: %v", err)
				continue
			}
		} else {
			// If this row doesn't actually have a HotFeedApprovedPostOp, bail.
			continue
		}

		if hotFeedOp.IsRemoval {
			delete(hotFeedApprovedPosts, *postHash)
		} else if hotFeedOp.Multiplier >= 0 {
			hotFeedApprovedPosts[*postHash] = hotFeedOp.Multiplier

			// Now we need to figure out if this was a multiplier update.
			prevMultiplier, hasPrevMultiplier := fes.HotFeedApprovedPostsToMultipliers[*postHash]
			if hasPrevMultiplier && prevMultiplier != hotFeedOp.Multiplier {
				fes.HotFeedPostMultiplierUpdated = true
			} else if hotFeedOp.Multiplier != 1 {
				fes.HotFeedPostMultiplierUpdated = true
			}
		}

		// If we've made it to the end of the op list, update the last op processed timestamp.
		if opIdx == len(opKeys)-1 {
			opTstampBytes := opKey[timestampStartIdx:postHashStartIdx]
			opTstampNanos := lib.DecodeUint64(opTstampBytes)
			fes.LastHotFeedApprovedPostOpProcessedTstampNanos = opTstampNanos
		}
	}
}

func (fes *APIServer) UpdateHotFeedPKIDMultipliersMap(
	hotFeedPKIDMultipliers map[lib.PKID]*HotFeedPKIDMultiplier,
) {
	// Grab all of the relevant operations to update the map with.
	startTimestampNanos := uint64(time.Now().UTC().AddDate(0, 0, -1).UnixNano()) // 1 day ago.
	if fes.LastHotFeedPKIDMultiplierOpProcessedTstampNanos != 0 {
		startTimestampNanos = fes.LastHotFeedPKIDMultiplierOpProcessedTstampNanos
	}
	startPrefix := GlobalStateSeekKeyForHotFeedPKIDMultiplierOps(startTimestampNanos + 1)
	opKeys, opVals, err := fes.GlobalState.Seek(
		startPrefix,
		_GlobalStatePrefixForHotFeedPKIDMultiplierOps, /*validForPrefix*/
		0,     /*maxKeyLen -- ignored since reverse is false*/
		0,     /*numToFetch -- 0 is ignored*/
		false, /*reverse*/
		true,  /*fetchValues*/
	)
	if err != nil {
		glog.Infof("UpdateHotFeedPKIDMultipliersMap: Seek failed: %v", err)
	}

	// Chop up the keys and process each operation.
	for opIdx, opKey := range opKeys {
		// Each key consists of: prefix, timestamp, PKID.
		timestampStartIdx := 1
		pkidStartIdx := timestampStartIdx + 8

		opPKIDBytes := opKey[pkidStartIdx:]
		opPKID := &lib.PKID{}
		copy(opPKID[:], opPKIDBytes)

		// Deserialize the HotFeedPKIDMultiplierOp.
		hotFeedOp := HotFeedPKIDMultiplierOp{}
		hotFeedOpBytes := opVals[opIdx]
		if len(hotFeedOpBytes) > 0 {
			err = gob.NewDecoder(bytes.NewReader(hotFeedOpBytes)).Decode(&hotFeedOp)
			if err != nil {
				glog.Infof("UpdateHotFeedPKIDMultipliersMap: ERROR decoding HotFeedPKIDMultiplierOp: %v", err)
				continue
			}
		} else {
			// If this row doesn't actually have a HotFeedPKIDMultiplierOp, bail.
			continue
		}

		// Get the current multiplier and update it. Note that negatives are ignored.
		hotFeedPKIDMultiplier := hotFeedPKIDMultipliers[*opPKID]
		if hotFeedPKIDMultiplier == nil {
			hotFeedPKIDMultiplier = &HotFeedPKIDMultiplier{
				InteractionMultiplier: 1,
				PostsMultiplier:       1,
			}
		}
		if hotFeedOp.InteractionMultiplier >= 0 {
			hotFeedPKIDMultiplier.InteractionMultiplier = hotFeedOp.InteractionMultiplier
		} else if hotFeedOp.PostsMultiplier >= 0 {
			hotFeedPKIDMultiplier.PostsMultiplier = hotFeedOp.PostsMultiplier
		}
		hotFeedPKIDMultipliers[*opPKID] = hotFeedPKIDMultiplier

		// If we've made it to the end of the op list, update trackers.
		if opIdx == len(opKeys)-1 {
			// Update the time stamp of the last op processed.
			opTstampBytes := opKey[timestampStartIdx:pkidStartIdx]
			opTstampNanos := lib.DecodeUint64(opTstampBytes)
			fes.LastHotFeedPKIDMultiplierOpProcessedTstampNanos = opTstampNanos

			// Record that the multiplier map has updates.
			fes.HotFeedPKIDMultiplierUpdated = true
		}
	}
}

func (fes *APIServer) CopyHotFeedApprovedPostsMap() map[lib.BlockHash]float64 {
	hotFeedApprovedPosts := make(map[lib.BlockHash]float64, len(fes.HotFeedApprovedPostsToMultipliers))
	for postKey, postVal := range fes.HotFeedApprovedPostsToMultipliers {
		hotFeedApprovedPosts[postKey] = postVal
	}
	return hotFeedApprovedPosts
}

func (fes *APIServer) CopyHotFeedPKIDMultipliersMap() map[lib.PKID]*HotFeedPKIDMultiplier {
	hotFeedPKIDMultipliers := make(map[lib.PKID]*HotFeedPKIDMultiplier, len(fes.HotFeedPKIDMultipliers))
	for pkidKey, multiplierVal := range fes.HotFeedPKIDMultipliers {
		multiplierValCopy := *multiplierVal
		hotFeedPKIDMultipliers[pkidKey] = &multiplierValCopy
	}
	return hotFeedPKIDMultipliers
}

type HotnessPostInfo struct {
	// How long ago the post was created in number of blocks
	PostBlockAge int
	HotnessScore uint64
}

func (fes *APIServer) UpdateHotFeedOrderedList(
	postsToMultipliers map[lib.BlockHash]float64,
	pkidsToMultipliers map[lib.PKID]*HotFeedPKIDMultiplier,
) (_hotFeedPostsMap map[lib.BlockHash]*HotnessPostInfo,
) {
	// Check to see if any of the algorithm constants have changed.
	globalStateInteractionCap, globalStateTagInteractionCap, globalStateTimeDecayBlocks, globalStateTagTimeDecayBlocks, globalStateTxnTypeMultiplierMap, err := fes.GetHotFeedConstantsFromGlobalState()
	if err != nil {
		glog.Infof("UpdateHotFeedOrderedList: ERROR - Failed to get constants: %v", err)
		return nil
	}
	if globalStateInteractionCap == 0 || globalStateTimeDecayBlocks == 0 {
		// The hot feed go routine has not been run yet since constants have not been set.
		// Set the default constants in GlobalState and then on the server object.
		err := fes.GlobalState.Put(
			_GlobalStatePrefixForHotFeedInteractionCap,
			lib.EncodeUint64(DefaultHotFeedInteractionCap),
		)
		if err != nil {
			glog.Infof("UpdateHotFeedOrderedList: ERROR - Failed to put InteractionCap: %v", err)
			return nil
		}
		err = fes.GlobalState.Put(
			_GlobalStatePrefixForHotFeedTagInteractionCap,
			lib.EncodeUint64(DefaultHotFeedTagInteractionCap),
		)
		if err != nil {
			glog.Infof("UpdateHotFeedOrderedList: ERROR - Failed to put InteractionCap for tag feeds: %v", err)
			return nil
		}
		err = fes.GlobalState.Put(
			_GlobalStatePrefixForHotFeedTimeDecayBlocks,
			lib.EncodeUint64(DefaultHotFeedTimeDecayBlocks),
		)
		if err != nil {
			glog.Infof("UpdateHotFeedOrderedList: ERROR - Failed to put TimeDecayBlocks: %v", err)
			return nil
		}
		err = fes.GlobalState.Put(
			_GlobalStatePrefixForHotFeedTagTimeDecayBlocks,
			lib.EncodeUint64(DefaultHotFeedTagTimeDecayBlocks),
		)
		if err != nil {
			glog.Infof("UpdateHotFeedOrderedList: ERROR - Failed to put TimeDecayBlocks for tag feeds: %v", err)
			return nil
		}

		// Now that we've successfully updated global state, set them on the server object.
		fes.HotFeedInteractionCap = DefaultHotFeedInteractionCap
		fes.HotFeedTagInteractionCap = DefaultHotFeedTagInteractionCap
		fes.HotFeedTimeDecayBlocks = DefaultHotFeedTimeDecayBlocks
		fes.HotFeedTagTimeDecayBlocks = DefaultHotFeedTagTimeDecayBlocks
		fes.HotFeedTxnTypeMultiplierMap = make(map[lib.TxnType]uint64)
		// Check to see if only the tag-specific feed configuration variables are unset and set just those.
	} else if globalStateTagInteractionCap == 0 || globalStateTagTimeDecayBlocks == 0 {
		// The hot feed go routine has not been run yet since constants have not been set.
		err = fes.GlobalState.Put(
			_GlobalStatePrefixForHotFeedTagInteractionCap,
			lib.EncodeUint64(DefaultHotFeedTagInteractionCap),
		)
		if err != nil {
			glog.Infof("UpdateHotFeedOrderedList: ERROR - Failed to put InteractionCap: %v", err)
			return nil
		}
		err = fes.GlobalState.Put(
			_GlobalStatePrefixForHotFeedTagTimeDecayBlocks,
			lib.EncodeUint64(DefaultHotFeedTagTimeDecayBlocks),
		)
		if err != nil {
			glog.Infof("UpdateHotFeedOrderedList: ERROR - Failed to put TimeDecayBlocks: %v", err)
			return nil
		}
		// Now that we've successfully updated global state, set them on the server object.
		fes.HotFeedTagInteractionCap = DefaultHotFeedTagInteractionCap
		fes.HotFeedTagTimeDecayBlocks = DefaultHotFeedTagTimeDecayBlocks
		fes.HotFeedTxnTypeMultiplierMap = make(map[lib.TxnType]uint64)
	} else if fes.HotFeedInteractionCap != globalStateInteractionCap ||
		fes.HotFeedTimeDecayBlocks != globalStateTimeDecayBlocks ||
		fes.HotFeedTagInteractionCap != globalStateTagInteractionCap ||
		fes.HotFeedTagTimeDecayBlocks != globalStateTagTimeDecayBlocks ||
		!reflect.DeepEqual(fes.HotFeedTxnTypeMultiplierMap, globalStateTxnTypeMultiplierMap) {
		// New constants were found in global state. Set them and proceed.
		fes.HotFeedInteractionCap = globalStateInteractionCap
		fes.HotFeedTimeDecayBlocks = globalStateTimeDecayBlocks
		fes.HotFeedTagInteractionCap = globalStateTagInteractionCap
		fes.HotFeedTagTimeDecayBlocks = globalStateTagTimeDecayBlocks
		fes.HotFeedTxnTypeMultiplierMap = globalStateTxnTypeMultiplierMap
	} else if fes.HotFeedPostMultiplierUpdated || fes.HotFeedPKIDMultiplierUpdated {
		fes.HotFeedPostMultiplierUpdated = false
		fes.HotFeedPKIDMultiplierUpdated = false
	}

	// If the constants for the algorithm haven't changed and we have already seen the latest
	// block or the chain is out of sync, bail.
	blockTip := fes.blockchain.BlockTip()

	// This offset allows us to see what the hot feed would look like in the past,
	// which is useful for testing purposes.
	blockOffsetForTesting := 0

	lookbackWindowBlocks := LookbackWindowBlocks
	// Check if the most recent blocks that we'll be considering in hot feed computation have been processed.
	for _, blockNode := range fes.blockchain.BestChain() {
		if blockNode.Height < blockTip.Height-uint32(lookbackWindowBlocks+blockOffsetForTesting) {
			continue
		}
	}

	// Log how long this routine takes, since it could be heavy.
	glog.V(2).Info("UpdateHotFeedOrderedList: Starting new update cycle.")
	start := time.Now()

	// Get a utxoView for lookups.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		glog.Infof("UpdateHotFeedOrderedList: ERROR - Failed to get utxo view: %v", err)
		return nil
	}

	// Grab the last 24 hours worth of blocks (288 blocks @ 5min/block).
	blockTipIndex := len(fes.blockchain.BestChain()) - 1 - blockOffsetForTesting
	relevantNodes := fes.blockchain.BestChain()
	if len(fes.blockchain.BestChain()) > (lookbackWindowBlocks + blockOffsetForTesting) {
		relevantNodes = fes.blockchain.BestChain()[blockTipIndex-lookbackWindowBlocks-blockOffsetForTesting : blockTipIndex]
	}

	var hotnessInfoBlocks []*HotnessInfoBlock
	for blockIdx, node := range relevantNodes {
		var block *lib.MsgDeSoBlock
		if cachedBlock, ok := fes.HotFeedBlockCache[*node.Hash]; ok {
			block = cachedBlock
		} else {
			block, _ = lib.GetBlock(node.Hash, utxoView.Handle, fes.blockchain.Snapshot())
			fes.HotFeedBlockCache[*node.Hash] = block
		}
		hotnessInfoBlocks = append(hotnessInfoBlocks, &HotnessInfoBlock{
			Block: block,
			// For time decay, we care about how many blocks away from the tip this block is.
			BlockAge: len(relevantNodes) - blockIdx,
		})
	}

	// Fake block height for mempool transactions that haven't been mined yet
	var mempoolBlockHeight int
	if fes.blockchain.BlockTip() != nil {
		mempoolBlockHeight = int(fes.blockchain.BlockTip().Height + 1)
	} else {
		mempoolBlockHeight = 1
	}

	// Create new "block" for mempool txns, give it a block age of 1 greater than the current tip

	// First get all MempoolTxns from mempool.
	mempoolTxnsOrderedByTime := fes.backendServer.GetMempool().GetOrderedTransactions()
	// Extract MsgDesoTxn from each MempoolTxn
	var txnsFromMempoolOrderedByTime []*lib.MsgDeSoTxn
	for _, mempoolTxn := range mempoolTxnsOrderedByTime {
		txnsFromMempoolOrderedByTime = append(txnsFromMempoolOrderedByTime, mempoolTxn.Tx)
	}

	if err != nil {
		glog.Errorf("Error getting mempool transactions: %v", err)
	} else if len(txnsFromMempoolOrderedByTime) > 0 {
		hotnessInfoBlocks = append(hotnessInfoBlocks, &HotnessInfoBlock{
			Block: &lib.MsgDeSoBlock{
				Txns: txnsFromMempoolOrderedByTime,
			},
			BlockAge: mempoolBlockHeight,
		})
	}

	// Iterate over the blocks and track global feed hotness scores for each post.
	hotnessInfoMapGlobalFeed, err := fes.PopulateHotnessInfoMap(utxoView, postsToMultipliers, pkidsToMultipliers, false, hotnessInfoBlocks)
	if err != nil {
		glog.Infof("UpdateHotFeedOrderedList: ERROR - Failed to put PopulateHotnessInfoMap for global feed: %v", err)
		return nil
	}
	// Iterate over the blocks and track tag feed hotness scores for each post.
	hotnessInfoMapTagFeed, err := fes.PopulateHotnessInfoMap(utxoView, postsToMultipliers, pkidsToMultipliers, true, hotnessInfoBlocks)
	if err != nil {
		glog.Infof("UpdateHotFeedOrderedList: ERROR - Failed to put PopulateHotnessInfoMap for tag feed: %v", err)
		return nil
	}
	// Sort the map into an ordered list and set it as the server's new HotFeedOrderedList.
	hotFeedOrderedList := []*HotFeedEntry{}
	for postHashKey, hotnessInfo := range hotnessInfoMapGlobalFeed {
		postHash := postHashKey
		hotFeedEntry := &HotFeedEntry{
			PostHash:     &postHash,
			PostHashHex:  hex.EncodeToString(postHash[:]),
			HotnessScore: hotnessInfo.HotnessScore,
		}
		hotFeedOrderedList = append(hotFeedOrderedList, hotFeedEntry)
	}
	sort.Slice(hotFeedOrderedList, func(ii, jj int) bool {
		if hotFeedOrderedList[ii].HotnessScore != hotFeedOrderedList[jj].HotnessScore {
			return hotFeedOrderedList[ii].HotnessScore > hotFeedOrderedList[jj].HotnessScore
		} else {
			return hotFeedOrderedList[ii].PostHashHex > hotFeedOrderedList[jj].PostHashHex
		}
	})
	fes.HotFeedOrderedList = hotFeedOrderedList
	fes.HotFeedPostHashToTagScoreMap = hotnessInfoMapTagFeed

	// Set the ordered lists for hot feed based on tags.
	postTagToOrderedHotFeedEntries := make(map[string][]*HotFeedEntry)
	postTagToOrderedHotFeedEntries = fes.SaveOrderedFeedForTags(true, postTagToOrderedHotFeedEntries)
	fes.PostTagToOrderedHotFeedEntries = postTagToOrderedHotFeedEntries

	// Set the ordered lists for newness based on tags.
	postTagToOrderedNewestEntries := map[string][]*HotFeedEntry{}
	postTagToOrderedNewestEntries = fes.SaveOrderedFeedForTags(false, postTagToOrderedNewestEntries)
	fes.PostTagToOrderedNewestEntries = postTagToOrderedNewestEntries

	// Update the HotFeedBlockHeight so we don't re-evaluate this set of blocks.
	fes.HotFeedBlockHeight = blockTip.Height

	elapsed := time.Since(start)
	glog.Infof("Successfully updated HotFeedOrderedList in %s", elapsed)

	return hotnessInfoMapGlobalFeed
}

type HotnessInfoBlock struct {
	Block    *lib.MsgDeSoBlock
	BlockAge int
}

func (fes *APIServer) PopulateHotnessInfoMap(
	utxoView *lib.UtxoView,
	postsToMultipliers map[lib.BlockHash]float64,
	pkidsToMultipliers map[lib.PKID]*HotFeedPKIDMultiplier,
	isTagFeed bool,
	hotnessInfoBlocks []*HotnessInfoBlock,
) (map[lib.BlockHash]*HotnessPostInfo, error) {
	hotnessInfoMap := make(map[lib.BlockHash]*HotnessPostInfo)
	// Map of interaction key to transaction type multiplier applied.
	postInteractionMap := make(map[HotFeedInteractionKey]uint64)

	for _, hotnessInfoBlock := range hotnessInfoBlocks {
		block := hotnessInfoBlock.Block
		blockAgee := hotnessInfoBlock.BlockAge
		if block == nil {
			continue
		}
		for _, txn := range block.Txns {
			// We only care about posts created in the specified look-back period. There should always be a
			// transaction that creates a given post before someone interacts with it. By only
			// scoring posts that meet this condition, we can restrict the HotFeedOrderedList
			// to posts from the specified look-back period without even looking up the post time stamp.
			isCreatePost, postHashCreated := CheckTxnForCreatePost(txn)
			if isCreatePost {
				// We start with the creator's balance in computing the score
				timeDecayBlocks := fes.HotFeedTimeDecayBlocks
				posterPKIDEntry := utxoView.GetPKIDForPublicKey(txn.PublicKey)
				// Finally return the post hash and the txn's hotness score.
				//interactionProfile := utxoView.GetProfileEntryForPKID(posterPKIDEntry.PKID)
				interactionUserBalance, err := utxoView.GetDeSoBalanceNanosForPublicKey(txn.PublicKey)
				if err != nil {
					return nil, err
				}
				// Check for PKID-specifc multipliers for the poster and the interactor.
				posterPKIDMultiplier, hasPosterPKIDMultiplier := pkidsToMultipliers[*posterPKIDEntry.PKID]
				txnHotnessScore := uint64(interactionUserBalance)
				if txnHotnessScore > fes.HotFeedInteractionCap {
					txnHotnessScore = fes.HotFeedInteractionCap
				}
				if hasPosterPKIDMultiplier {
					txnHotnessScore = uint64(
						posterPKIDMultiplier.PostsMultiplier * float64(txnHotnessScore))
				}
				hotnessScoreTimeDecayed := uint64(float64(txnHotnessScore) *
					math.Pow(0.5, float64(blockAgee)/float64(timeDecayBlocks)))
				hotnessInfoMap[*postHashCreated] = &HotnessPostInfo{
					PostBlockAge: blockAgee,
					HotnessScore: hotnessScoreTimeDecayed,
				}
				continue
			}

			// If the post has been edited, remove all tags associated with that post.
			// This ensures that the categorization reflects the most recently edited version.
			isEditPost, postHashEdited := CheckTxnForEditPost(txn)
			if isEditPost {
				tags := fes.PostHashToPostTagsMap[*postHashEdited]
				delete(fes.PostHashToPostTagsMap, *postHashEdited)
				for _, tag := range tags {
					if postHashes, ok := fes.PostTagToPostHashesMap[tag]; ok {
						delete(postHashes, *postHashEdited)
					}
				}
				continue
			}

			// The age used in determining the score should be that of the post
			// that we are evaluating. The interaction's score will be discounted
			// by this age.
			postHashToScore, posterPKID := GetPostHashToScoreForTxn(txn, utxoView)
			if postHashToScore == nil {
				// If we don't have a post hash to score then this txn is not relevant
				// and we can continue.
				continue
			}
			prevHotnessInfo, inHotnessInfoMap := hotnessInfoMap[*postHashToScore]
			if !inHotnessInfoMap {
				// If the post is not in the hotnessInfoMap yet, it wasn't created
				// in the specified look-back period so we can continue.
				continue
			}
			postBlockAge := prevHotnessInfo.PostBlockAge

			// If we get here, we know we are dealing with a txn that interacts with a
			// post that was created within the specified look-back period.

			// Evaluate the txn and attempt to update the hotnessInfoMap.
			postHashScored, interactionPKID, txnHotnessScore :=
				fes.GetHotnessScoreInfoForTxn(txn, postBlockAge, postInteractionMap, utxoView, isTagFeed)
			if postHashScored != nil {
				// Check for a post-specific multiplier.
				multiplier, hasMultiplier := postsToMultipliers[*postHashScored]
				if hasMultiplier && multiplier >= 0 {
					txnHotnessScore = uint64(multiplier * float64(txnHotnessScore))
				}

				// Check for PKID-specifc multipliers for the poster and the interactor.
				posterPKIDMultiplier, hasPosterPKIDMultiplier := pkidsToMultipliers[*posterPKID]
				if hasPosterPKIDMultiplier {
					txnHotnessScore = uint64(
						posterPKIDMultiplier.PostsMultiplier * float64(txnHotnessScore))
				}
				interactionPKIDMultiplier, hasInteractionPKIDMultiplier := pkidsToMultipliers[*interactionPKID]
				if hasInteractionPKIDMultiplier {
					txnHotnessScore = uint64(
						interactionPKIDMultiplier.InteractionMultiplier * float64(txnHotnessScore))
				}
				// Check for overflow just in case.
				if prevHotnessInfo.HotnessScore > math.MaxInt64-txnHotnessScore {
					continue
				}

				// Finally, make sure the post scored isn't a comment or repost.
				postEntryScored := utxoView.GetPostEntryForPostHash(postHashScored)
				if len(postEntryScored.ParentStakeID) > 0 || lib.IsVanillaRepost(postEntryScored) {
					continue
				}
				// If the post has been deleted, then exclude it from the hot feed.
				if postEntryScored.IsHidden {
					continue
				}
				// Exclude posts without media if HotFeedMediaRequired is set
				if fes.Config.HotFeedMediaRequired && !postEntryScored.HasMedia() {
					continue
				}

				var tags []string
				var err error
				// Before parsing the text body, first check to see if this post has been processed and cached prior.
				if postTags, ok := fes.PostHashToPostTagsMap[*postHashScored]; ok {
					tags = postTags
				} else {
					// Parse tags from post entry.
					tags, err = ParseTagsFromPost(postEntryScored)
					if err != nil {
						return nil, err
					}
					// Cache processed post in map.
					fes.PostHashToPostTagsMap[*postHashScored] = tags
					// Add each tagged post to the tag:postEntries map
					for _, tag := range tags {
						// If a post hash set already exists, append to it,
						// otherwise create a new set and add it to the map.
						var postHashSet map[lib.BlockHash]bool
						if postHashSet, ok = fes.PostTagToPostHashesMap[tag]; !ok {
							postHashSet = make(map[lib.BlockHash]bool)
						}
						if _, ok = postHashSet[*postHashScored]; !ok {
							postHashSet[*postHashScored] = true
						}
						fes.PostTagToPostHashesMap[tag] = postHashSet
					}
				}

				// Update the hotness score.
				prevHotnessInfo.HotnessScore += txnHotnessScore
			}
		}
	}
	return hotnessInfoMap, nil
}

// Rank posts on a tag-by-tag basis and save them to their corresponding index in a map.
// If sortByHotness is true, sort by their hotness score, otherwise sort by newness.
func (fes *APIServer) SaveOrderedFeedForTags(sortByHotness bool, PostTagToOrderedEntries map[string][]*HotFeedEntry) map[string][]*HotFeedEntry {
	for tag, tagPostHashes := range fes.PostTagToPostHashesMap {
		tagHotFeedOrderedList := []*HotFeedEntry{}
		tagHotFeedListWithAge := []*HotFeedEntryTimeSortable{}
		// Loop through every tagged post for the tag in question.
		for tagPostHashKey := range tagPostHashes {
			tagPostHash := tagPostHashKey
			if postHotnessInfo, ok := fes.HotFeedPostHashToTagScoreMap[tagPostHash]; ok {
				postHotFeedEntry := &HotFeedEntryTimeSortable{
					PostHash:     &tagPostHash,
					PostHashHex:  hex.EncodeToString(tagPostHash[:]),
					HotnessScore: postHotnessInfo.HotnessScore,
					PostBlockAge: postHotnessInfo.PostBlockAge,
				}
				tagHotFeedListWithAge = append(tagHotFeedListWithAge, postHotFeedEntry)
			}
		}
		// Sort posts based on specified criteria, either age (asc) or hotness (desc).
		sort.Slice(tagHotFeedListWithAge, func(ii, jj int) bool {
			if sortByHotness {
				return tagHotFeedListWithAge[ii].HotnessScore > tagHotFeedListWithAge[jj].HotnessScore
			} else {
				return tagHotFeedListWithAge[ii].PostBlockAge < tagHotFeedListWithAge[jj].PostBlockAge
			}
		})
		// Remove age from entry to save space.
		tagHotFeedOrderedList = removeAgeFromSortedHotFeedEntries(tagHotFeedListWithAge)
		PostTagToOrderedEntries[tag] = tagHotFeedOrderedList
	}
	return PostTagToOrderedEntries
}

// This function removes the age field from a sorted list of hot feed entries. This allows us to reduce the size
// of the entries created.
func removeAgeFromSortedHotFeedEntries(sortedHotFeedEntries []*HotFeedEntryTimeSortable) []*HotFeedEntry {
	hotFeedEntriesWithoutAge := []*HotFeedEntry{}
	for _, hotFeedEntryWithAge := range sortedHotFeedEntries {
		hotFeedEntriesWithoutAge = append(hotFeedEntriesWithoutAge, &HotFeedEntry{
			PostHash:     hotFeedEntryWithAge.PostHash,
			PostHashHex:  hotFeedEntryWithAge.PostHashHex,
			HotnessScore: hotFeedEntryWithAge.HotnessScore,
		})
	}
	return hotFeedEntriesWithoutAge
}

func (fes *APIServer) GetHotFeedParamFromGlobalState(prefix []byte) (uint64, error) {
	valueBytes, err := fes.GlobalState.Get(prefix)
	if err != nil {
		return 0, err
	}
	value := uint64(0)
	if len(valueBytes) > 0 {
		value = lib.DecodeUint64(valueBytes)
	}
	return value, nil
}

func (fes *APIServer) GetHotFeedConstantsFromGlobalState() (
	_interactionCap uint64, _interactionTagCap uint64, _timeDecayBlocks uint64, _timeDecayTagBlocks uint64, _tnxTypeMultiplierMap map[lib.TxnType]uint64, _err error,
) {
	interactionCap, err := fes.GetHotFeedParamFromGlobalState(_GlobalStatePrefixForHotFeedInteractionCap)
	if err != nil {
		return 0, 0, 0, 0, nil, nil
	}

	interactionCapTag, err := fes.GetHotFeedParamFromGlobalState(_GlobalStatePrefixForHotFeedTagInteractionCap)
	if err != nil {
		return 0, 0, 0, 0, nil, nil
	}

	timeDecayBlocks, err := fes.GetHotFeedParamFromGlobalState(_GlobalStatePrefixForHotFeedTimeDecayBlocks)
	if err != nil {
		return 0, 0, 0, 0, nil, nil
	}

	timeDecayBlocksTag, err := fes.GetHotFeedParamFromGlobalState(_GlobalStatePrefixForHotFeedTagTimeDecayBlocks)
	if err != nil {
		return 0, 0, 0, 0, nil, nil
	}

	txnTypeMultiplierMapBytes, err := fes.GlobalState.Get(_GlobalStatePrefixHotFeedTxnTypeMultiplierBasisPoints)
	if err != nil {
		return 0, 0, 0, 0, nil, nil
	}
	txnTypeMultiplierMap := make(map[lib.TxnType]uint64)
	if len(txnTypeMultiplierMapBytes) > 0 {
		if err = gob.NewDecoder(bytes.NewReader(txnTypeMultiplierMapBytes)).Decode(&txnTypeMultiplierMap); err != nil {
			return 0, 0, 0, 0, nil, fmt.Errorf("Error decoding txnTypeMultiplierMapBytes to map: %v", err)
		}
	}

	return interactionCap, interactionCapTag, timeDecayBlocks, timeDecayBlocksTag, txnTypeMultiplierMap, nil
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

func CheckTxnForEditPost(txn *lib.MsgDeSoTxn) (
	_isEditPostTxn bool, _postHashCreated *lib.BlockHash) {
	if txn.TxnMeta.GetTxnType() == lib.TxnTypeSubmitPost {
		txMeta := txn.TxnMeta.(*lib.SubmitPostMetadata)
		// The post hash of a brand new post is the same as its txn hash.
		if len(txMeta.PostHashToModify) != 0 {
			blockHashToModify := lib.NewBlockHash(txMeta.PostHashToModify)
			return true, blockHashToModify
		}
	}

	return false, nil
}

func GetPostHashToScoreForTxn(txn *lib.MsgDeSoTxn,
	utxoView *lib.UtxoView) (_postHashScored *lib.BlockHash, _posterPKID *lib.PKID) {
	// Figure out which post this transaction should affect.
	interactionPostHash := &lib.BlockHash{}
	var interactionPostEntry *lib.PostEntry
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
			return nil, nil
		}

	} else if txnType == lib.TxnTypeSubmitPost {
		txMeta := txn.TxnMeta.(*lib.SubmitPostMetadata)
		// If this is a transaction creating a brand new post, we can ignore it.
		if len(txMeta.PostHashToModify) == 0 {
			return nil, nil
		}
		postHash := &lib.BlockHash{}
		copy(postHash[:], txMeta.PostHashToModify[:])
		interactionPostEntry = utxoView.GetPostEntryForPostHash(postHash)

		// For posts we must process three cases: Reposts, Quoted Reposts, and Comments.
		if lib.IsVanillaRepost(interactionPostEntry) || lib.IsQuotedRepost(interactionPostEntry) {
			repostedPostHashBytes := txn.ExtraData[lib.RepostedPostHash]
			copy(interactionPostHash[:], repostedPostHashBytes)
		} else if len(interactionPostEntry.ParentStakeID) > 0 {
			copy(interactionPostHash[:], interactionPostEntry.ParentStakeID[:])
		} else {
			return nil, nil
		}

	} else {
		// This transaction is not relevant, bail.
		return nil, nil
	}

	// If we haven't gotten the post entry yet, make sure we fetch it.
	if interactionPostEntry == nil {
		interactionPostEntry = utxoView.GetPostEntryForPostHash(interactionPostHash)
	}

	// Double check that we got a valid interaction post entry. If not, bail.
	if interactionPostEntry == nil {
		return nil, nil
	}

	// At this point, we have a post hash to return so look up the posterPKID as well.
	posterPKIDEntry := utxoView.GetPKIDForPublicKey(interactionPostEntry.PosterPublicKey)

	return interactionPostHash, posterPKIDEntry.PKID
}

// Returns the post hash that a txn is relevant to and the amount that the txn should contribute
// to that post's hotness score. The postInteractionMap is used to ensure that each PKID only
// gets one interaction per post.
func (fes *APIServer) GetHotnessScoreInfoForTxn(
	txn *lib.MsgDeSoTxn,
	blockAge int, // Number of blocks this txn is from the blockTip.  Not block height.
	postInteractionMap map[HotFeedInteractionKey]uint64,
	utxoView *lib.UtxoView,
	isTagFeed bool,
) (_postHashScored *lib.BlockHash, _interactionPKID *lib.PKID, _hotnessScore uint64,
) {
	// Figure out who is responsible for the transaction.
	interactionPKIDEntry := utxoView.GetPKIDForPublicKey(txn.PublicKey)

	interactionPostHash, _ := GetPostHashToScoreForTxn(txn, utxoView)

	// Check to see if we've seen this interaction pair before. Log an interaction if not.
	interactionKey := HotFeedInteractionKey{
		InteractionPKID:     *interactionPKIDEntry.PKID,
		InteractionPostHash: *interactionPostHash,
	}

	// Transaction type multiplier for current transaction.
	multiplier := fes.getTxnMultiplier(txn)

	// Get previously applied multiplier for post, if post has been counted already for this user.
	if prevMultiplier, exists := postInteractionMap[interactionKey]; exists {
		// If the previously applied multiplier is greater, skip this transaction.
		if prevMultiplier > multiplier {
			return nil, nil, 0
		}
		postInteractionMap[interactionKey] = multiplier
		// We want to count the difference of the new multiplier and the previously counted multiplier.
		multiplier = multiplier - prevMultiplier
	} else {
		postInteractionMap[interactionKey] = multiplier
	}

	// Finally return the post hash and the txn's hotness score.
	interactionProfile := utxoView.GetProfileEntryForPKID(interactionPKIDEntry.PKID)
	interactionUserBalance, err := utxoView.GetDeSoBalanceNanosForPublicKey(txn.PublicKey)
	if err != nil {
		return nil, nil, 0
	}

	hotnessScore := interactionUserBalance
	// It is possible for the profile to be nil since you don't need a profile for diamonds.
	if interactionProfile != nil && !interactionProfile.IsDeleted() {
		hotnessScore += interactionProfile.CreatorCoinEntry.DeSoLockedNanos
	}

	// Apply transaction type multiplier.
	// Multipliers are defined in basis points, so the resulting product is divided by 10,000.
	hotnessScore = hotnessScore * multiplier / 10000

	if hotnessScore > fes.HotFeedInteractionCap && !isTagFeed {
		hotnessScore = fes.HotFeedInteractionCap
	} else if hotnessScore > fes.HotFeedTagInteractionCap && isTagFeed {
		hotnessScore = fes.HotFeedTagInteractionCap
	}
	var timeDecayBlocks uint64
	if isTagFeed {
		timeDecayBlocks = fes.HotFeedTagTimeDecayBlocks
	} else {
		timeDecayBlocks = fes.HotFeedTimeDecayBlocks
	}
	hotnessScoreTimeDecayed := uint64(float64(hotnessScore) *
		math.Pow(0.5, float64(blockAge)/float64(timeDecayBlocks)))

	return interactionPostHash, interactionPKIDEntry.PKID, hotnessScoreTimeDecayed
}

func (fes *APIServer) PruneHotFeedApprovedPostsMap(
	hotFeedPosts map[lib.BlockHash]*HotnessPostInfo, hotFeedApprovedPosts map[lib.BlockHash]float64,
) {
	for postHash := range fes.HotFeedApprovedPostsToMultipliers {
		if _, inHotFeedMap := hotFeedPosts[postHash]; !inHotFeedMap {
			delete(hotFeedApprovedPosts, postHash)
		}
	}
}

// Get the transaction type multiplier associated with a particular transaction
func (fes *APIServer) getTxnMultiplier(txn *lib.MsgDeSoTxn) uint64 {
	if multiplier, ok := fes.HotFeedTxnTypeMultiplierMap[txn.TxnMeta.GetTxnType()]; ok {
		return multiplier
	} else {
		// If transaction doesn't have a multiplier defined, multiply by 1x (in basis points)
		return 10000
	}

}

type HotFeedPageRequest struct {
	ReaderPublicKeyBase58Check string
	// Since the hot feed is constantly changing, we pass a list of posts that have already
	// been seen in order to send a more accurate next page.
	SeenPosts []string
	// Number of post entry responses to return.
	ResponseLimit int
	// If defined, only get the hot feed for posts tagged with this tag.
	Tag string
	// If true, sort by new instead of by hotness. Only applies to queries where "Tag" is defined.
	SortByNew bool
}

type HotFeedPageResponse struct {
	HotFeedPage []PostEntryResponse
}

func (fes *APIServer) AdminGetUnfilteredHotFeed(ww http.ResponseWriter, req *http.Request) {
	fes.HandleHotFeedPageRequest(ww, req, false /*approvedPostsOnly*/, true /*addMultiplierBool*/)
}

func (fes *APIServer) GetHotFeed(ww http.ResponseWriter, req *http.Request) {
	fes.HandleHotFeedPageRequest(ww, req, false /*approvedPostsOnly*/, false /*addMultiplierBool*/)
}

func (fes *APIServer) HandleHotFeedPageRequest(
	ww http.ResponseWriter,
	req *http.Request,
	approvedPostsOnly bool,
	addMultiplierBool bool,
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

	// Make the lists of posts a user has already seen into a map.
	seenPostsMap := make(map[string][]byte)
	for _, postHashHex := range requestData.SeenPosts {
		seenPostsMap[postHashHex] = []byte{}
	}

	hotFeed := []PostEntryResponse{}

	// The list of posts that will be iterated on
	var hotFeedOrderedList []*HotFeedEntry

	// Only process posts tagged with a particular tag if specified in the request
	if requestData.Tag != "" {
		// Choose the map with the lists sorted in the manner specified by the user (hotness or newness).
		var tagMap map[string][]*HotFeedEntry
		if requestData.SortByNew {
			tagMap = fes.PostTagToOrderedNewestEntries
		} else {
			tagMap = fes.PostTagToOrderedHotFeedEntries
		}
		// Check to make sure key exists in map. If not, return an empty list.
		if orderedEntriesForTag, ok := tagMap[requestData.Tag]; ok {
			hotFeedOrderedList = orderedEntriesForTag
		} else {
			hotFeedOrderedList = []*HotFeedEntry{}
		}
	} else {
		hotFeedOrderedList = fes.HotFeedOrderedList
	}

	for _, hotFeedEntry := range hotFeedOrderedList {
		if requestData.ResponseLimit != 0 && len(hotFeed) > requestData.ResponseLimit {
			break
		}

		// Skip posts that have already been seen.
		if _, alreadySeen := seenPostsMap[hotFeedEntry.PostHashHex]; alreadySeen {
			continue
		}

		// Skip posts that aren't approved yet, if requested.
		if _, isApproved := fes.HotFeedApprovedPostsToMultipliers[*hotFeedEntry.PostHash]; approvedPostsOnly && !isApproved {
			continue
		}

		postEntry := utxoView.GetPostEntryForPostHash(hotFeedEntry.PostHash)
		// Skip posts that are comments.
		if len(postEntry.ParentStakeID) != 0 {
			continue
		}
		postEntryResponse, err := fes._postEntryToResponse(
			postEntry, true, fes.Params, utxoView, readerPublicKeyBytes, 1)
		if err != nil {
			continue
		}

		// Skip posts that are pinned (these will be added to the very top of the feed later)
		if *postEntryResponse.IsPinned {
			continue
		}

		profileEntry := utxoView.GetProfileEntryForPublicKey(postEntry.PosterPublicKey)
		postEntryResponse.ProfileEntryResponse = fes._profileEntryToResponse(
			profileEntry, utxoView)
		postEntryResponse.PostEntryReaderState = utxoView.GetPostEntryReaderState(
			readerPublicKeyBytes, postEntry)
		postEntryResponse.HotnessScore = hotFeedEntry.HotnessScore
		hotFeedMultiplier, inHotFeed := fes.HotFeedApprovedPostsToMultipliers[*postEntry.PostHash]
		if inHotFeed && addMultiplierBool {
			postEntryResponse.PostMultiplier = hotFeedMultiplier
		}
		hotFeed = append(hotFeed, *postEntryResponse)
	}

	{
		// Only add pinned posts if we are starting from the top of the feed.
		if len(requestData.SeenPosts) == 0 {
			maxBigEndianUint64Bytes := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
			maxKeyLen := 1 + len(maxBigEndianUint64Bytes) + lib.HashSizeBytes
			// Get all pinned posts and prepend them to the list of postEntries
			pinnedStartKey := _GlobalStatePrefixTstampNanosPinnedPostHash
			// todo: how many posts can we really pin?
			keys, _, err := fes.GlobalState.Seek(pinnedStartKey, pinnedStartKey, maxKeyLen, 10, true, false)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("HandleHotFeedPageRequest: Getting pinned posts: %v", err))
			}

			var pinnedPostEntryRepsonses []PostEntryResponse
			for _, dbKeyBytes := range keys {
				postHash := &lib.BlockHash{}
				copy(postHash[:], dbKeyBytes[1+len(maxBigEndianUint64Bytes):][:])
				postEntry := utxoView.GetPostEntryForPostHash(postHash)
				if postEntry != nil && !postEntry.IsHidden {
					postEntry.IsPinned = true
					profileEntry := utxoView.GetProfileEntryForPublicKey(postEntry.PosterPublicKey)
					postEntryResponse, err := fes._postEntryToResponse(
						postEntry, true, fes.Params, utxoView, readerPublicKeyBytes, 1)
					postEntryResponse.ProfileEntryResponse = fes._profileEntryToResponse(
						profileEntry, utxoView)
					postEntryResponse.PostEntryReaderState = utxoView.GetPostEntryReaderState(
						readerPublicKeyBytes, postEntry)
					if err != nil {
						continue
					}
					pinnedPostEntryRepsonses = append(pinnedPostEntryRepsonses, *postEntryResponse)
				}
			}
			hotFeed = append(pinnedPostEntryRepsonses, hotFeed...)
		}
	}

	res := HotFeedPageResponse{HotFeedPage: hotFeed}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("HandleHotFeedPageRequest: Problem encoding response as JSON: %v", err))
		return
	}
}

type AdminUpdateHotFeedAlgorithmRequest struct {
	// Maximum score amount that any individual PKID can contribute to the global hot feed score
	// before time decay. Ignored if set to zero.
	InteractionCap int
	// Maximum score amount that any individual PKID can contribute to a particular tag's hot feed score
	// before time decay. Ignored if set to zero.
	InteractionCapTag int
	// Number of blocks per halving for the global hot feed score time decay. Ignored if set to zero.
	TimeDecayBlocks int
	// Number of blocks per halving for a tag's hot feed score time decay. Ignored if set to zero.
	TimeDecayBlocksTag int
	// Multiplier which alters the hotness score for a particular transaction type. Multiplier is stored in basis points.
	TxnTypeMultiplierMap map[lib.TxnType]uint64
}

type AdminUpdateHotFeedAlgorithmResponse struct{}

func (fes *APIServer) AdminUpdateHotFeedAlgorithm(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminUpdateHotFeedAlgorithmRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateHotFeedAlgorithm: Problem parsing request body: %v", err))
		return
	}

	if requestData.InteractionCap < 0 || requestData.TimeDecayBlocks < 0 || requestData.InteractionCapTag < 0 || requestData.TimeDecayBlocksTag < 0 {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AdminUpdateHotFeedAlgorithm: InteractionCap (%d, %d) and TimeDecayBlocks (%d, %d) can't be negative.",
			requestData.InteractionCap, requestData.InteractionCapTag, requestData.TimeDecayBlocks, requestData.TimeDecayBlocksTag))
		return
	}

	err := fes.AddHotFeedParamToGlobalState(_GlobalStatePrefixForHotFeedInteractionCap, requestData.InteractionCap)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("AdminUpdateHotFeedAlgorithm: Error putting InteractionCap: %v", err))
		return
	}

	err = fes.AddHotFeedParamToGlobalState(_GlobalStatePrefixForHotFeedTagInteractionCap, requestData.InteractionCapTag)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("AdminUpdateHotFeedAlgorithm: Error putting InteractionCapTag: %v", err))
		return
	}

	err = fes.AddHotFeedParamToGlobalState(_GlobalStatePrefixForHotFeedTimeDecayBlocks, requestData.TimeDecayBlocks)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("AdminUpdateHotFeedAlgorithm: Error putting TimeDecayBlocks: %v", err))
		return
	}

	err = fes.AddHotFeedParamToGlobalState(_GlobalStatePrefixForHotFeedTagTimeDecayBlocks, requestData.TimeDecayBlocksTag)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("AdminUpdateHotFeedAlgorithm: Error putting TimeDecayBlocksTag: %v", err))
		return
	}

	if len(requestData.TxnTypeMultiplierMap) > 0 {
		txnTypeMultiplierMapBuffer := bytes.NewBuffer([]byte{})
		if err := gob.NewEncoder(txnTypeMultiplierMapBuffer).Encode(requestData.TxnTypeMultiplierMap); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateHotFeedAlgorithm: Problem encoding transaction multiplier map: %v", err))
			return
		}
		if err := fes.GlobalState.Put(_GlobalStatePrefixHotFeedTxnTypeMultiplierBasisPoints, txnTypeMultiplierMapBuffer.Bytes()); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateHotFeedAlgorithm: Problem putting txn type multiplier map in global state: %v", err))
			return
		}
	}

	res := AdminUpdateHotFeedAlgorithmResponse{}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateHotFeedAlgorithm: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) AddHotFeedParamToGlobalState(prefix []byte, value int) error {
	if value > 0 {
		err := fes.GlobalState.Put(
			prefix,
			lib.EncodeUint64(uint64(value)),
		)
		return err
	}
	return nil
}

type AdminGetHotFeedAlgorithmRequest struct{}

type AdminGetHotFeedAlgorithmResponse struct {
	InteractionCap       uint64
	InteractionCapTag    uint64
	TimeDecayBlocks      uint64
	TimeDecayBlocksTag   uint64
	TxnTypeMultiplierMap map[lib.TxnType]uint64
}

func (fes *APIServer) AdminGetHotFeedAlgorithm(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminGetHotFeedAlgorithmRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetHotFeedAlgorithm: Problem parsing request body: %v", err))
		return
	}

	interactionCap, interactionCapTag, timeDecayBlocks, timeDecayBlocksTag, txnTypeMultiplierMap, err := fes.GetHotFeedConstantsFromGlobalState()
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("AdminGetHotFeedAlgorithm: Error getting constants: %v", err))
		return
	}

	res := AdminGetHotFeedAlgorithmResponse{
		InteractionCap:       interactionCap,
		InteractionCapTag:    interactionCapTag,
		TimeDecayBlocks:      timeDecayBlocks,
		TimeDecayBlocksTag:   timeDecayBlocksTag,
		TxnTypeMultiplierMap: txnTypeMultiplierMap,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetHotFeedAlgorithm: Problem encoding response as JSON: %v", err))
		return
	}
}

type AdminUpdateHotFeedPostMultiplierRequest struct {
	PostHashHex string  `safeforlogging:"true"`
	Multiplier  float64 `safeforlogging:"true"`
}

type AdminUpdateHotFeedPostMultiplierResponse struct{}

func (fes *APIServer) AdminUpdateHotFeedPostMultiplier(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminUpdateHotFeedPostMultiplierRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateHotFeedPostMultiplier: Problem parsing request body: %v", err))
		return
	}

	if requestData.Multiplier < 0 {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AdminUpdateHotFeedPostMultiplier: Please provide non-negative multiplier: %f", requestData.Multiplier))
		return
	}

	// Decode the postHash.
	postHash := &lib.BlockHash{}
	if requestData.PostHashHex != "" {
		postHashBytes, err := hex.DecodeString(requestData.PostHashHex)
		if err != nil || len(postHashBytes) != lib.HashSizeBytes {
			_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateHotFeedPostMultiplier: Error parsing post hash %v: %v",
				requestData.PostHashHex, err))
			return
		}
		copy(postHash[:], postHashBytes)
	} else {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateHotFeedPostMultiplier: Request missing PostHashHex"))
		return
	}

	// Add a new hot feed op for this post.
	hotFeedOp := HotFeedApprovedPostOp{
		IsRemoval:  false,
		Multiplier: requestData.Multiplier,
	}
	hotFeedOpDataBuf := bytes.NewBuffer([]byte{})
	gob.NewEncoder(hotFeedOpDataBuf).Encode(hotFeedOp)
	opTimestamp := uint64(time.Now().UnixNano())
	hotFeedOpKey := GlobalStateKeyForHotFeedApprovedPostOp(opTimestamp, postHash)
	err := fes.GlobalState.Put(hotFeedOpKey, hotFeedOpDataBuf.Bytes())
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("AdminUpdateHotFeedPostMultiplier: Problem putting hotFeedOp: %v", err))
		return
	}

	res := AdminUpdateHotFeedPostMultiplierResponse{}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateHotFeedPostMultiplier: Problem encoding response as JSON: %v", err))
		return
	}
}

type AdminUpdateHotFeedUserMultiplierRequest struct {
	Username              string  `safeforlogging:"true"`
	InteractionMultiplier float64 `safeforlogging:"true"`
	PostsMultiplier       float64 `safeforlogging:"true"`
}

type AdminUpdateHotFeedUserMultiplierResponse struct{}

func (fes *APIServer) AdminUpdateHotFeedUserMultiplier(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminUpdateHotFeedUserMultiplierRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateHotFeedUserMultiplier: Problem parsing request body: %v", err))
		return
	}

	// Verify the username adheres to the consensus username criteria.
	if len(requestData.Username) == 0 ||
		len(requestData.Username) > lib.MaxUsernameLengthBytes ||
		!lib.UsernameRegex.Match([]byte(requestData.Username)) {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateHotFeedUserMultiplier: Must provide a valid username"))
		return
	}

	// Verify the username has an underlying profile.
	pubKey, err := fes.getPublicKeyFromUsernameOrPublicKeyString(requestData.Username, nil)
	if err != nil {
		_AddBadRequestError(ww,
			fmt.Sprintf(
				"AdminUpdateHotFeedUserMultiplier: Username %s has no associated underlying publickey.",
				requestData.Username))
		return
	}

	// Use a utxoView to get the pkid for this pub key.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateHotFeedUserMultiplier: Problem getting utxoView: %v", err))
		return
	}
	pkidEntry := utxoView.GetPKIDForPublicKey(pubKey)
	if pkidEntry == nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateHotFeedUserMultiplier: PKID not found for username: %s", requestData.Username))
		return
	}

	// Add a new hot feed op for this post.
	hotFeedOp := HotFeedPKIDMultiplierOp{
		InteractionMultiplier: requestData.InteractionMultiplier,
		PostsMultiplier:       requestData.PostsMultiplier,
	}
	hotFeedOpDataBuf := bytes.NewBuffer([]byte{})
	gob.NewEncoder(hotFeedOpDataBuf).Encode(hotFeedOp)
	opTimestamp := uint64(time.Now().UnixNano())
	hotFeedOpKey := GlobalStateKeyForHotFeedPKIDMultiplierOp(opTimestamp, pkidEntry.PKID)
	err = fes.GlobalState.Put(hotFeedOpKey, hotFeedOpDataBuf.Bytes())
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("AdminUpdateHotFeedUserMultiplier: Problem putting hotFeedOp: %v", err))
		return
	}

	res := AdminUpdateHotFeedUserMultiplierResponse{}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateHotFeedUserMultiplier: Problem encoding response as JSON: %v", err))
		return
	}
}

type AdminGetHotFeedUserMultiplierRequest struct {
	Username string `safeforlogging:"true"`
}

type AdminGetHotFeedUserMultiplierResponse struct {
	InteractionMultiplier float64 `safeforlogging:"true"`
	PostsMultiplier       float64 `safeforlogging:"true"`
}

func (fes *APIServer) AdminGetHotFeedUserMultiplier(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminGetHotFeedUserMultiplierRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetHotFeedUserMultiplier: Problem parsing request body: %v", err))
		return
	}

	// Verify the username adheres to the consensus username criteria.
	if len(requestData.Username) == 0 ||
		len(requestData.Username) > lib.MaxUsernameLengthBytes ||
		!lib.UsernameRegex.Match([]byte(requestData.Username)) {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetHotFeedUserMultiplier: Must provide a valid username"))
		return
	}

	// Verify the username has an underlying profile.
	pubKey, err := fes.getPublicKeyFromUsernameOrPublicKeyString(requestData.Username, nil)
	if err != nil {
		_AddBadRequestError(ww,
			fmt.Sprintf(
				"AdminGetHotFeedUserMultiplier: Username %s has no associated underlying publickey.",
				requestData.Username))
		return
	}

	// Use a utxoView to get the pkid for this pub key.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetHotFeedUserMultiplier: Problem getting utxoView: %v", err))
		return
	}
	pkidEntry := utxoView.GetPKIDForPublicKey(pubKey)
	if pkidEntry == nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetHotFeedUserMultiplier: PKID not found for username: %s", requestData.Username))
		return
	}

	// Grab the current multiplier object for this PKID.
	hotFeedMultiplier := fes.HotFeedPKIDMultipliers[*pkidEntry.PKID]
	if hotFeedMultiplier == nil {
		hotFeedMultiplier = &HotFeedPKIDMultiplier{
			InteractionMultiplier: 1,
			PostsMultiplier:       1,
		}
	}

	res := AdminGetHotFeedUserMultiplierResponse{
		InteractionMultiplier: hotFeedMultiplier.InteractionMultiplier,
		PostsMultiplier:       hotFeedMultiplier.PostsMultiplier,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetHotFeedUserMultiplier: Problem encoding response as JSON: %v", err))
		return
	}
}
