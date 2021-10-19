package routes

import (
	"encoding/json"
	"fmt"
	"github.com/deso-protocol/core/lib"
	"io"
	"net/http"
)

func (fes *APIServer) GetVerifiedUsernameMap(ww http.ResponseWriter, req *http.Request) {
	if !fes.Config.ExposeGlobalState {
		_AddNotFoundError(ww, fmt.Sprintf("Global state not exposed"))
		return
	}
	WriteGlobalStateDataToResponse(fes.VerifiedUsernameToPKIDMap, "GetVerifiedUsernameMap", ww)
}

func (fes *APIServer) makeMapJSONEncodable(restrictedKeysMap map[lib.PKID][]byte) map[string][]byte {
	outputMap := make(map[string][]byte)
	for k, v := range restrictedKeysMap {
		outputMap[lib.PkToString(k.ToBytes(), fes.Params)] = v
	}
	return outputMap
}

func (fes *APIServer) GetBlacklistedPublicKeys(ww http.ResponseWriter, req *http.Request) {
	if !fes.Config.ExposeGlobalState {
		_AddNotFoundError(ww, fmt.Sprintf("Global state not exposed"))
		return
	}
	WriteGlobalStateDataToResponse(fes.makeMapJSONEncodable(fes.BlacklistedPKIDMap), "GetBlacklistedPublicKeys", ww)
}

func (fes *APIServer) GetGraylistedPublicKeys(ww http.ResponseWriter, req *http.Request) {
	if !fes.Config.ExposeGlobalState {
		_AddNotFoundError(ww, fmt.Sprintf("Global state not exposed"))
		return
	}
	WriteGlobalStateDataToResponse(fes.makeMapJSONEncodable(fes.GraylistedPKIDMap), "GetGraylistedPublicKeys", ww)
}

func WriteGlobalStateDataToResponse(data interface{}, functionName string, ww http.ResponseWriter) {
	if err := json.NewEncoder(ww).Encode(data); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("%v: Problem encoding response as JSON: %v", functionName, err))
		return
	}
}

type GetGlobalFeedRquest struct {
	PostHashHex   string
	NumToFetch    int
	MediaRequired bool
}

func (fes *APIServer) GetGlobalFeed(ww http.ResponseWriter, req *http.Request) {
	if !fes.Config.ExposeGlobalState {
		_AddNotFoundError(ww, fmt.Sprintf("Global state not exposed"))
		return
	}
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetGlobalFeedRquest{}
	var err error
	if err = decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetGlobalFeed: Problem parsing request body: %v", err))
		return
	}

	var startPostHash *lib.BlockHash
	if requestData.PostHashHex != "" {
		// Decode the postHash.  This will give us the location where we start our paginated search.
		startPostHash, err = GetPostHashFromPostHashHex(requestData.PostHashHex)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetGlobalFeed: %v", err))
			return
		}
	}

	// Default to 50 posts fetched.
	numToFetch := 50
	if requestData.NumToFetch != 0 {
		numToFetch = requestData.NumToFetch
	}

	// Get a view with all the mempool transactions (used to get all posts / reader state).
	var utxoView *lib.UtxoView
	utxoView, err = fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetGlobalFeed: Error fetching mempool view"))
		return
	}

	// TODO: GetPostEntriesForGlobalWhitelist is a bit overkill for what we need here. Write a simpler and more efficient version.
	var postEntries []*lib.PostEntry
	postEntries, _, _, err = fes.GetPostEntriesForGlobalWhitelist(startPostHash, nil, numToFetch, utxoView, requestData.MediaRequired)

	var postEntryResponses []*PostEntryResponse
	for _, postEntry := range postEntries {
		var postEntryResponse *PostEntryResponse
		postEntryResponse, err = fes._postEntryToResponse(postEntry, false, fes.Params, utxoView, nil, 2)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetGlobalFeed: Error converting post entry to respones: %v"))
			return
		}
		postEntryResponses = append(postEntryResponses, postEntryResponse)
	}

	WriteGlobalStateDataToResponse(postEntryResponses, "GetGlobalFeed", ww)
}
