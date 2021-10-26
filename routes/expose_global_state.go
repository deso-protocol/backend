package routes

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/deso-protocol/core/lib"
	"io"
	"io/ioutil"
	"net/http"
)

// GetVerifiedUsernameMap returns the VerifiedUsernameToPKID map if global state is exposed.
func (fes *APIServer) GetVerifiedUsernameMap(ww http.ResponseWriter, req *http.Request) {
	if !fes.Config.ExposeGlobalState {
		_AddNotFoundError(ww, fmt.Sprintf("Global state not exposed"))
		return
	}
	WriteGlobalStateDataToResponse(fes.VerifiedUsernameToPKIDMap, "GetVerifiedUsernameMap", ww)
}

// makeMapJSONEncodable converts a map that has PKID keys into Base58-encoded strings.
func (fes *APIServer) makeMapJSONEncodable(restrictedKeysMap map[lib.PKID][]byte) map[string][]byte {
	outputMap := make(map[string][]byte)
	for k, v := range restrictedKeysMap {
		outputMap[lib.PkToString(k.ToBytes(), fes.Params)] = v
	}
	return outputMap
}

// GetBlacklistedPublicKeys returns a map of PKID (as Base58 encoded string) to Blacklist state bytes if global state
// is exposed.
func (fes *APIServer) GetBlacklistedPublicKeys(ww http.ResponseWriter, req *http.Request) {
	if !fes.Config.ExposeGlobalState {
		_AddNotFoundError(ww, fmt.Sprintf("Global state not exposed"))
		return
	}
	WriteGlobalStateDataToResponse(fes.makeMapJSONEncodable(fes.BlacklistedPKIDMap), "GetBlacklistedPublicKeys", ww)
}

// GetGraylistedPublicKeys returns a map of PKID (as Base58 encoded string) to Graylist state bytes if global state
// is exposed.
func (fes *APIServer) GetGraylistedPublicKeys(ww http.ResponseWriter, req *http.Request) {
	if !fes.Config.ExposeGlobalState {
		_AddNotFoundError(ww, fmt.Sprintf("Global state not exposed"))
		return
	}
	WriteGlobalStateDataToResponse(fes.makeMapJSONEncodable(fes.GraylistedPKIDMap), "GetGraylistedPublicKeys", ww)
}

// WriteGlobalStateDataToResponse is a helper to encode the response.
func WriteGlobalStateDataToResponse(data interface{}, functionName string, ww http.ResponseWriter) {
	if err := json.NewEncoder(ww).Encode(data); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("%v: Problem encoding response as JSON: %v", functionName, err))
		return
	}
}

type GetGlobalFeedRequest struct {
	PostHashHex   string
	NumToFetch    int
	MediaRequired bool
}

// GetGlobalFeed returns the global feed (without context of the reader). It functions almost exactly the same as
// GetPostsStateless when fetching the global feed.
func (fes *APIServer) GetGlobalFeed(ww http.ResponseWriter, req *http.Request) {
	if !fes.Config.ExposeGlobalState {
		_AddNotFoundError(ww, fmt.Sprintf("Global state not exposed"))
		return
	}
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetGlobalFeedRequest{}
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

// GetVerifiedUsernameMapResponse gets the verified username map (both map[string]string and map[string]*lib.PKID) from
// the configured GlobalStateAPIUrl and merges it with this node's global state.
// Note that it is not possible to remove a verification from a user who has been granted verification on the node
// configured at the GlobalStateAPIUrl.
func (fes *APIServer) GetVerifiedUsernameMapResponse() (
	_verifiedUsernameToPKID map[string]*lib.PKID, _err error,
){
	verifiedUsernameMap := make(map[string]*lib.PKID)
	var err error
	// If there is an external global state specified, fetch the verified username map from there.
	if fes.Config.GlobalStateAPIUrl != "" {
		// Get the bytes.
		var mapBytes []byte
		mapBytes, err = fes.FetchFromExternalGlobalState(RoutePathGetVerifiedUsernameMap)
		if err != nil {
			return  nil, fmt.Errorf("GetVerifiedUsernameMapResponse: Error fetching map from external global state: %v", err)
		}
		// Decode the response into the appropriate struct.
		decoder := json.NewDecoder(bytes.NewReader(mapBytes))
		if err = decoder.Decode(&verifiedUsernameMap); err != nil {
			return  nil, fmt.Errorf("GetVerifiedUsernameMapResponse: Error decoding bytes: %v", err)
		}
	}
	verifiedUsernameMapLocal := make(map[string]*lib.PKID)
	// Now we merge this node's global state in with the verifications fetch from the remote node
	// If we're getting from this node's global state, fetch the bytes from the global state instead of using the
	// cache.
	verifiedUsernameMapLocal, err = fes.GetVerifiedUsernameToPKIDMapFromGlobalState()
	if err != nil {
		return  nil, fmt.Errorf("GetVerifiedUsernameMapResponse: Error getting verified username map %v", err)
	}

	for username, pkid := range verifiedUsernameMapLocal {
		verifiedUsernameMap[username] = pkid
	}

	return verifiedUsernameMap, nil
}

// GetBlacklist returns both a slice of strings and a map of PKID to []byte representing the current state of
// blacklisted users.
func (fes *APIServer) GetBlacklist(utxoView *lib.UtxoView) (
	_blacklistedPKIDMap map[lib.PKID][]byte, _err error,
) {
	return fes.GetRestrictedPublicKeys(_GlobalStatePrefixPublicKeyToBlacklistState, utxoView, RoutePathGetBlacklistedPublicKeys)
}

// GetGraylist returns both a slice of strings and a map of PKID to []byte representing the current state of graylisted
// users.
func (fes *APIServer) GetGraylist(utxoView *lib.UtxoView) (
	_graylistedPKIDMap map[lib.PKID][]byte, _err error,
) {
	return fes.GetRestrictedPublicKeys(_GlobalStatePrefixPublicKeyToGraylistState, utxoView, RoutePathGetGraylistedPublicKeys)
}

// GetRestrictedPublicKeys fetches the blacklisted or graylisted public keys from the configured external global state
// (if available) and merges it with this node's global state. This returns a map of PKID to restricted bytes.
func (fes *APIServer) GetRestrictedPublicKeys(prefix []byte, utxoView *lib.UtxoView, routePath string) (
	_pkidMap map[lib.PKID][]byte, _err error,
) {
	pkidMap := make(map[lib.PKID][]byte)
	// Hit GlobalStateAPIUrl for restricted public keys.
	if fes.Config.GlobalStateAPIUrl != "" {
		// Fetch the bytes from the external global state.
		restrictedPublicKeyMapBytes, err := fes.FetchFromExternalGlobalState(routePath)
		if err != nil {
			return nil, err
		}
		// Decode the response into the appropriate struct. To use json encoding, we had to convert PKID to a string
		// so we'll need to convert back from string to PKID here.
		stringifiedPKIDsMap := make(map[string][]byte)
		decoder := json.NewDecoder(bytes.NewReader(restrictedPublicKeyMapBytes))
		if err = decoder.Decode(&stringifiedPKIDsMap); err != nil {
			return nil, fmt.Errorf("GetRestrictedPublicKeys: Error decoding bytes: %v", err)
		}
		// Iterate over the restricted public key map to convert string to PKIDs and create a filteredPublicKeys slice.
		for k, v := range stringifiedPKIDsMap {
			var publicKeyBytes []byte
			publicKeyBytes, _, err = lib.Base58CheckDecode(k)
			if err != nil {
				return nil, err
			}
			pkid := lib.PublicKeyToPKID(publicKeyBytes)
			pkidMap[*pkid] = v
		}
	}
	// Now, get  we're using our own global state. Seek global state for all restricted public keys of this type.
	publicKeys, states, err := fes.GlobalStateSeek(
		prefix,
		prefix, /*validForPrefix*/
		0,     /*maxKeyLen -- ignored since reverse is false*/
		0,     /*numToFetch -- 0 is ignored*/
		false, /*reverse*/
		true,  /*fetchValues*/
	)
	if err != nil {
		return nil, err
	}
	// Iterate over all restricted public keys from the local global state and merge into the map.
	for ii, publicKeyWithPrefix := range publicKeys {
		// Remove the prefix byte
		publicKey := publicKeyWithPrefix[1:]
		pkid := utxoView.GetPKIDForPublicKey(publicKey)
		pkidMap[*pkid.PKID] = states[ii]
	}
	return pkidMap, nil
}

// FetchFromExternalGlobalState hits an endpoint at the configured GlobalStateAPIUrl and returns the bytes read from
// the response body.
func (fes *APIServer) FetchFromExternalGlobalState(routePath string) (_body []byte, _err error){
	URL := fmt.Sprintf("%v%v", fes.Config.GlobalStateAPIUrl, routePath)
	req, _ := http.NewRequest("GET", URL, nil)

	client := &http.Client{}
	resp, err := client.Do(req)

	defer resp.Body.Close()

	if resp.StatusCode != 200 {

		var body []byte
		// Decode the response into the appropriate struct.
		body, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("FetchFromExternalGlobalState: error reading body in from non-200 response for route %v. Status code: %v. Error: %v", routePath, resp.StatusCode, err)
		}
		return nil, fmt.Errorf("FetchFromExternalGlobalState: error fetching %v: %v", routePath, string(body))
	}

	return ioutil.ReadAll(resp.Body)
}
