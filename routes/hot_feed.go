package routes

import (
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

// A single element in the server's HotFeedOrderedList.
type HotFeedEntry struct {
	PostHash     *lib.BlockHash
	HotnessScore uint64
}

// A key to track whether a specific public key has interacted with a post before.
type HotFeedInteractionKey struct {
	InteractionPKID     lib.PKID
	InteractionPostHash lib.BlockHash
}

// A cached "HotFeedOrderedList" is stored on the server and updated every 10 seconds.
func (fes *APIServer) StartHotFeedRoutine() {
	glog.Info("Starting hot feed routine.")
	go func() {
	out:
		for {
			select {
			case <-time.After(10 * time.Second):
				fes.UpdateHotFeedOrderedList()
			case <-fes.quit:
				break out
			}
		}
	}()
}

// The business.
func (fes *APIServer) UpdateHotFeedOrderedList() {
	// If we have already seen the latest block or the chain is out of sync, bail.
	blockTip := fes.blockchain.BlockTip()
	chainState := fes.blockchain.ChainState()
	if blockTip.Height <= fes.HotnessBlockHeight || chainState != lib.SyncStateFullyCurrent {
		return
	}

	glog.Info("Attempting to update hot feed with new blocks.")
	start := time.Now()

	// Get a utxoView for lookups.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		glog.Infof("UpdateHotFeedOrderedList: Failed to get ordered list: %v", err)
		return
	}

	// Grab the last 24 hours worth of blocks (288 blocks @ 5min/block).
	blockTipIndex := len(fes.blockchain.BestChain()) - 1
	relevantNodes := fes.blockchain.BestChain()[blockTipIndex-288 : blockTipIndex]

	// Iterate over the blocks and track hotness scores.
	hotnessScoreMap := make(map[lib.BlockHash]uint64)
	postInteractionMap := make(map[HotFeedInteractionKey][]byte)
	for _, node := range relevantNodes {
		block, _ := lib.GetBlock(node.Hash, utxoView.Handle)
		for _, txn := range block.Txns {
			// Evaluate the txn and attempt to update the hotnessScoreMap.
			postHashScored, txnHotnessScore := GetHotnessScoreInfoForTxn(txn, postInteractionMap, utxoView)
			if txnHotnessScore != 0 && postHashScored != nil {
				prevHotnessScore := hotnessScoreMap[*postHashScored]
				// Check for overflow just in case.
				if prevHotnessScore > math.MaxInt64-txnHotnessScore {
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
	glog.Infof("Successfully updated DIAMOND hot feed in %s", elapsed)
}

// Returns the post hash that a txn is relevant to and the amount that the txn should contribute
// to that post's hotness score. The postInteractionMap is used to ensure that each PKID only
// gets one interaction per post.
func GetHotnessScoreInfoForTxn2(
	txn *lib.MsgDeSoTxn, postInteractionMap map[HotFeedInteractionKey][]byte, utxoView *lib.UtxoView,
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

	// Now that we have the post hash for the interaction, we must decide if it is relevant.
	interactionPostEntry := utxoView.GetPostEntryForPostHash(interactionPostHash)
	// If the post is >24hrs old, it's not relevant.
	oneDayAgoTimestampNanos := uint64(time.Now().Add(-time.Hour * 24).UTC().UnixNano())
	if interactionPostEntry.TimestampNanos < oneDayAgoTimestampNanos {
		return nil, 0
	}
	if len(interactionPostEntry.ParentStakeID) > 0 {
		return nil, 0
	}

	// Check to see if we've seen this interaction pair before.
	interactionKey := HotFeedInteractionKey{
		InteractionPKID:     *interactionPKIDEntry.PKID,
		InteractionPostHash: *interactionPostHash,
	}
	if _, exists := postInteractionMap[interactionKey]; exists {
		return nil, 0
	}

	// Finally return the post hash and the txn's hotness score.
	interactionProfile := utxoView.GetProfileEntryForPKID(interactionPKIDEntry.PKID)
	// It is possible for the profile to be nil since you don't need a profile for diamonds.
	if interactionProfile == nil || interactionProfile.IsDeleted() {
		return nil, 0
	}
	hotnessScore := interactionProfile.DeSoLockedNanos
	if hotnessScore > 3e12 {
		hotnessScore = 3e12
	}
	return interactionPostHash, hotnessScore
}

// Returns the post hash that a txn is relevant to and the amount that the txn should contribute
// to that post's hotness score. The postInteractionMap is used to ensure that each PKID only
// gets one interaction per post.
func GetHotnessScoreInfoForTxn(
	txn *lib.MsgDeSoTxn, postInteractionMap map[HotFeedInteractionKey][]byte, utxoView *lib.UtxoView,
) (_postHashScored *lib.BlockHash, _hotnessScore uint64) {

	// Figure out which post this transaction should affect.
	interactionPostHash := &lib.BlockHash{}
	txnType := txn.TxnMeta.GetTxnType()
	if txnType == lib.TxnTypeBasicTransfer {
		// Check for a post being diamonded.
		diamondPostHashBytes, hasDiamondPostHash := txn.ExtraData[lib.DiamondPostHashKey]
		if hasDiamondPostHash {
			copy(interactionPostHash[:], diamondPostHashBytes[:])
			postEntry := utxoView.GetPostEntryForPostHash(interactionPostHash)
			// If the post is >24hrs old, it's not relevant.
			oneDayAgoTimestampNanos := uint64(time.Now().Add(-time.Hour * 24).UTC().UnixNano())
			if postEntry.TimestampNanos < oneDayAgoTimestampNanos {
				return nil, 0
			}
			if len(postEntry.ParentStakeID) > 0 {
				return nil, 0
			}
			amountsByPublicKey := make(map[lib.PkMapKey]uint64)
			for _, desoOutput := range txn.TxOutputs {
				// Create a map of total output by public key. This is used to check diamond
				// amounts below.
				//
				// Note that we don't need to check overflow here because overflow is checked
				// directly above when adding to totalOutput.
				currentAmount, _ := amountsByPublicKey[lib.MakePkMapKey(desoOutput.PublicKey)]
				amountsByPublicKey[lib.MakePkMapKey(desoOutput.PublicKey)] = currentAmount + desoOutput.AmountNanos
			}
			return interactionPostHash, amountsByPublicKey[lib.MakePkMapKey(postEntry.PosterPublicKey)]
		} else {
			// If this basic transfer doesn't have a diamond, it is irrelevant.
			return nil, 0
		}

	} else {
		// This transaction is not relevant, bail.
		return nil, 0
	}
}

type AdminGetUnfilteredHotFeedRequest struct {
	ResponseLimit int
}

type GetUnfilteredHotFeedResponse struct {
	HotFeed []PostEntryResponse
}

func (fes *APIServer) AdminGetUnfilteredHotFeed(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminGetUnfilteredHotFeedRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetUnfilteredHotFeed: Problem parsing request body: %v", err))
		return
	}

	// Get a view.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetUnfilteredHotFeed: Error getting utxoView: %v", err))
		return
	}
	// Grab verified username map pointer.
	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetUnfilteredHotFeed: Problem fetching verifiedMap: %v", err))
		return
	}

	hotFeed := []PostEntryResponse{}
	for hotFeedIdx, hotFeedEntry := range fes.HotFeedOrderedList {
		if requestData.ResponseLimit != 0 && hotFeedIdx > requestData.ResponseLimit {
			break
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

	_, _ = utxoView, verifiedMap

	res := GetUnfilteredHotFeedResponse{HotFeed: hotFeed}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetUnfilteredHotFeed: Problem encoding response as JSON: %v", err))
		return
	}
}
