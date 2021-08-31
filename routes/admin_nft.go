package routes

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"time"

	"github.com/bitclout/core/lib"
)

type AdminGetNFTDropRequest struct {
	// "-1" is used to request the next planned drop.
	DropNumber int `safeForLogging:"true"`
}

type AdminGetNFTDropResponse struct {
	DropEntry *NFTDropEntry
	Posts     []*PostEntryResponse
}

// Check global state and get the latest drop entry if available.
// If no drop entry is found in global state, returns a default-initialized NFTDropEntry.
func (fes *APIServer) GetLatestNFTDropEntry() (_dropEntry *NFTDropEntry, _err error) {
	seekKey := _GlobalStatePrefixNFTDropNumberToNFTDropEntry
	maxKeyLen := 9 // These keys are 1 prefix byte + 8 bytes for the uint64 drop number.
	_, vals, err := fes.GlobalStateSeek(seekKey, seekKey, maxKeyLen, 1, true, true)
	if err != nil {
		return nil, fmt.Errorf("AdminGetNFTDrop: Error getting latest drop: %v", err)
	}

	if len(vals) > 1 {
		return nil, fmt.Errorf(
			"AdminGetNFTDrop: Unexpected number of drop entries (%d) returned.", len(vals))
	}

	dropEntry := &NFTDropEntry{}
	if len(vals) != 0 {
		// If we got here, we found a drop entry. Save the bytes to decode later.
		dropEntryBytes := vals[0]
		err = gob.NewDecoder(bytes.NewReader(dropEntryBytes)).Decode(&dropEntry)
		if err != nil {
			return nil, fmt.Errorf("AdminGetNFTDrop: Problem decoding bytes for latest drop entry: %v", err)
		}
	}

	return dropEntry, nil
}

func (fes *APIServer) GetNFTDropEntry(nftDropNumber uint64) (_dropEntry *NFTDropEntry, _err error) {
	keyBytes := GlobalStateKeyForNFTDropEntry(uint64(nftDropNumber))
	dropEntryBytes, err := fes.GlobalStateGet(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("GetNFTDropEntry: %v", err)
	}

	dropEntry := &NFTDropEntry{}
	err = gob.NewDecoder(bytes.NewReader(dropEntryBytes)).Decode(&dropEntry)
	if err != nil {
		return nil, fmt.Errorf("GetNFTDropEntry: %v", err)
	}

	return dropEntry, nil
}

func (fes *APIServer) GetPostsForNFTDropEntry(dropEntryToReturn *NFTDropEntry,
) (_posts []*PostEntryResponse, _err error) {
	profileEntryResponseMap := make(map[lib.PkMapKey]*ProfileEntryResponse)
	var postEntryResponses []*PostEntryResponse

	// Grab a view (needed for getting global params, etc).
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return nil, fmt.Errorf("AdminGetPostsForNFTDropEntry: Error getting utxoView: %v", err)
	}

	// Grab verified username map pointer
	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
	if err != nil {
		return nil, fmt.Errorf("GetTutorialCreators: Problem fetching verifiedMap: %v", err)
	}
	for _, postHash := range dropEntryToReturn.NFTHashes {
		postEntry := utxoView.GetPostEntryForPostHash(postHash)
		postEntryResponse, err := fes._postEntryToResponse(postEntry, false, fes.Params, utxoView, nil, verifiedMap, 2)
		if err != nil {
			return nil, fmt.Errorf(
				"AdminGetPostsForNFTDropEntry: Error building postEntryResponse: %v, %s", err, postHash.String())
		}

		// Add the profile entry to the post entry.
		profileEntryResponse, entryFound := profileEntryResponseMap[lib.MakePkMapKey(postEntry.PosterPublicKey)]
		if !entryFound {
			// If we didn't find the entry in our map, we need to make it...
			profileEntry := utxoView.GetProfileEntryForPublicKey(postEntry.PosterPublicKey)
			if profileEntry == nil {
				// If we didn't find a profile entry, skip this post.
				continue
			} else {
				profileEntryResponse = _profileEntryToResponse(profileEntry, fes.Params, nil, utxoView)
				profileEntryResponseMap[lib.MakePkMapKey(postEntry.PosterPublicKey)] = profileEntryResponse
			}
		}
		postEntryResponse.ProfileEntryResponse = profileEntryResponse

		postEntryResponses = append(postEntryResponses, postEntryResponse)
	}

	return postEntryResponses, nil
}

func (fes *APIServer) AdminGetNFTDrop(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminGetNFTDropRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetNFTDrop: Error parsing request body: %v", err))
		return
	}

	var err error
	var dropEntryToReturn *NFTDropEntry
	if requestData.DropNumber < 0 {
		dropEntryToReturn, err = fes.GetLatestNFTDropEntry()
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminGetNFTDrop: Error getting latest drop: %v", err))
			return
		}
	} else {
		// Look up the drop entry for the drop number given.
		dropEntryToReturn, err = fes.GetNFTDropEntry(uint64(requestData.DropNumber))
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"AdminGetNFTDrop: Error getting NFT drop #%d: %v", requestData.DropNumber, err))
			return
		}
	}

	// Note that "dropEntryToReturn" can be nil if there are no entries in global state.
	var postEntryResponses []*PostEntryResponse
	if dropEntryToReturn != nil {
		postEntryResponses, err = fes.GetPostsForNFTDropEntry(dropEntryToReturn)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminGetNFTDrop: : %v", err))
			return
		}
	}

	// Return all the data associated with the transaction in the response
	res := AdminGetNFTDropResponse{
		DropEntry: dropEntryToReturn,
		Posts:     postEntryResponses,
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("AdminGetNFTDrop: Problem serializing object to JSON: %v", err))
		return
	}
}

type AdminUpdateNFTDropRequest struct {
	DropNumber         int    `safeForLogging:"true"`
	DropTstampNanos    int    `safeForLogging:"true"`
	IsActive           bool   `safeForLogging:"true"`
	NFTHashHexToAdd    string `safeForLogging:"true"`
	NFTHashHexToRemove string `safeForLogging:"true"`
}

type AdminUpdateNFTDropResponse struct {
	DropEntry *NFTDropEntry
	Posts     []*PostEntryResponse
}

func (fes *APIServer) AdminUpdateNFTDrop(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminUpdateNFTDropRequest{}
	err := decoder.Decode(&requestData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateNFTDrop: Error parsing request body: %v", err))
		return
	}

	if requestData.DropNumber < 1 {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AdminUpdateNFTDrop: Drop number must be greater than zero, received: %d", requestData.DropNumber))
		return
	}

	if requestData.DropTstampNanos < 0 {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AdminUpdateNFTDrop: Drop timestamp cannot be negative, received: %d", requestData.DropTstampNanos))
		return
	}

	if requestData.NFTHashHexToAdd != "" && requestData.NFTHashHexToRemove != "" {
		_AddBadRequestError(ww, fmt.Sprint(
			"AdminUpdateNFTDrop: Cannot add and remove an NFT in the same operation."))
		return
	}

	var latestDropEntry *NFTDropEntry
	latestDropEntry, err = fes.GetLatestNFTDropEntry()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateNFTDrop: Error getting latest drop: %v", err))
		return
	}

	// Now for the business.
	var updatedDropEntry *NFTDropEntry
	currentTime := uint64(time.Now().UnixNano())
	if uint64(requestData.DropNumber) > latestDropEntry.DropNumber {
		// If we make it here, we are making a new drop. Run some checks to make sure that the
		// timestamp provided make sense.
		if latestDropEntry.DropTstampNanos > currentTime {
			_AddBadRequestError(ww, fmt.Sprint(
				"AdminUpdateNFTDrop: Cannot create a new drop when one is already pending."))
			return
		}
		if uint64(requestData.DropTstampNanos) < currentTime {
			_AddBadRequestError(ww, fmt.Sprint(
				"AdminUpdateNFTDrop: Cannot create a new drop with a tstamp in the past."))
			return
		}
		if uint64(requestData.DropTstampNanos) < latestDropEntry.DropTstampNanos {
			_AddBadRequestError(ww, fmt.Sprint(
				"AdminUpdateNFTDrop: Cannot create a new drop with a tstamp before the previous drop."))
			return
		}

		// Regardless of the drop number provided, we force the new drop to be the previous number + 1.
		updatedDropEntry = &NFTDropEntry{
			DropNumber:      uint64(latestDropEntry.DropNumber + 1),
			DropTstampNanos: uint64(requestData.DropTstampNanos),
		}

	} else {
		// In this case, we are updating an existing drop.
		updatedDropEntry = latestDropEntry
		if uint64(requestData.DropNumber) != latestDropEntry.DropNumber {
			updatedDropEntry, err = fes.GetNFTDropEntry(uint64(requestData.DropNumber))
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf(
					"AdminUpdateNFTDrop: Error getting drop #%d: %v", requestData.DropNumber, err))
				return
			}
		}

		// There are only two possible drops that can be updated (you can't update past drops):
		//   - The current "active" drop.
		//   - The next "pending" drop.
		canUpdateDrop := false
		latestDropIsPending := latestDropEntry.DropTstampNanos > currentTime
		if latestDropIsPending && uint64(requestData.DropNumber) >= latestDropEntry.DropNumber-1 {
			// In this case their is a pending drop so the latest drop and the previous drop are editable.
			canUpdateDrop = true
		} else if !latestDropIsPending && uint64(requestData.DropNumber) == latestDropEntry.DropNumber {
			// In this case there is no pending drop so you can only update the latest drop.
			canUpdateDrop = true
		}

		if !canUpdateDrop {
			_AddBadRequestError(ww, fmt.Sprintf(
				"AdminUpdateNFTDrop: Cannot edit past drop #%d.", requestData.DropNumber))
			return
		}

		// Update IsActive.
		updatedDropEntry.IsActive = requestData.IsActive

		// Consider updating DropTstampNanos.
		if uint64(requestData.DropTstampNanos) > currentTime &&
			uint64(requestData.DropNumber) == latestDropEntry.DropNumber {
			updatedDropEntry.DropTstampNanos = uint64(requestData.DropTstampNanos)

		} else if uint64(requestData.DropTstampNanos) != updatedDropEntry.DropTstampNanos {
			_AddBadRequestError(ww, fmt.Sprintf(
				"AdminUpdateNFTDrop: Can only update latest drop with tstamp in the future."))
			return
		}

		utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateNFTDrop: Error getting utxoView: %v", err))
			return
		}

		// Add new NFT hashes.
		if requestData.NFTHashHexToAdd != "" {
			// Decode the hash and make sure it is a valid NFT so that we can add it to the entry.
			postHash, err := GetPostHashFromPostHashHex(requestData.NFTHashHexToAdd)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateNFTDrop: Error getting post hash: %v", err))
				return
			}
			postEntry := utxoView.GetPostEntryForPostHash(postHash)
			if !postEntry.IsNFT {
				_AddBadRequestError(ww, fmt.Sprintf(
					"AdminUpdateNFTDrop: Cannot add non-NFT to drop: %v", postHash.String()))
				return
			}

			updatedDropEntry.NFTHashes = append(updatedDropEntry.NFTHashes, postHash)
		}

		// Remove unwanted NFT hashes.
		if requestData.NFTHashHexToRemove != "" {
			// Decode the hash and make sure it is a valid NFT.
			nftHashToRemove, err := GetPostHashFromPostHashHex(requestData.NFTHashHexToRemove)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf(
					"AdminUpdateNFTDrop: Error getting post hash to remove: %v", err))
				return
			}

			for nftHashIdx, nftHash := range updatedDropEntry.NFTHashes {
				if reflect.DeepEqual(nftHash, nftHashToRemove) {
					updatedDropEntry.NFTHashes = append(
						updatedDropEntry.NFTHashes[:nftHashIdx], updatedDropEntry.NFTHashes[nftHashIdx+1:]...)
					break
				}
			}
		}
	}

	// Set the updated drop entry.
	globalStateKey := GlobalStateKeyForNFTDropEntry(uint64(requestData.DropNumber))
	updatedDropEntryBuf := bytes.NewBuffer([]byte{})
	gob.NewEncoder(updatedDropEntryBuf).Encode(updatedDropEntry)
	err = fes.GlobalStatePut(globalStateKey, updatedDropEntryBuf.Bytes())
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateNFTDrop: Error encoding updated drop: %v", err))
		return
	}

	// Note that "dropEntryToReturn" can be nil if there are no entries in global state.
	postEntryResponses, err := fes.GetPostsForNFTDropEntry(updatedDropEntry)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetNFTDrop: : %v", err))
		return
	}

	// Return all the data associated with the transaction in the response
	res := AdminUpdateNFTDropResponse{
		DropEntry: updatedDropEntry,
		Posts:     postEntryResponses,
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("AdminUpdateNFTDrop: Problem serializing object to JSON: %v", err))
		return
	}
}
