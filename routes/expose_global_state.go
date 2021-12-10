package routes

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/deso-protocol/core/lib"
	"io/ioutil"
	"net/http"
	"reflect"
)

// GetVerifiedUsernames returns the VerifiedUsernameToPKID map if global state is exposed.
func (fes *APIServer) GetVerifiedUsernames(ww http.ResponseWriter, req *http.Request) {
	fes.WriteGlobalStateDataToResponse(fes.VerifiedUsernameToPKIDMap, "GetVerifiedUsernames", ww)
}

// GetBlacklistedPublicKeys returns a map of PKID (as Base58 encoded string) to Blacklist state bytes if global state
// is exposed.
func (fes *APIServer) GetBlacklistedPublicKeys(ww http.ResponseWriter, req *http.Request) {
	fes.WriteGlobalStateDataToResponse(fes.BlacklistedResponseMap, "GetBlacklistedPublicKeys", ww)
}

// GetGraylistedPublicKeys returns a map of PKID (as Base58 encoded string) to Graylist state bytes if global state
// is exposed.
func (fes *APIServer) GetGraylistedPublicKeys(ww http.ResponseWriter, req *http.Request) {
	fes.WriteGlobalStateDataToResponse(fes.GraylistedResponseMap, "GetGraylistedPublicKeys", ww)
}

// GetGlobalFeed returns the post hashes in the global feed for the last 7 days
func (fes *APIServer) GetGlobalFeed(ww http.ResponseWriter, req *http.Request) {
	fes.WriteGlobalStateDataToResponse(fes.GlobalFeedPostHashes, "GetGlobalFeed", ww)
}

// WriteGlobalStateDataToResponse is a helper to encode the response.
func (fes *APIServer) WriteGlobalStateDataToResponse(data interface{}, functionName string, ww http.ResponseWriter) {
	if !fes.Config.ExposeGlobalState {
		_AddNotFoundError(ww, fmt.Sprintf("Global state not exposed"))
		return
	}
	if err := json.NewEncoder(ww).Encode(data); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("%v: Problem encoding response as JSON: %v", functionName, err))
		return
	}
}

// GetVerifiedUsernameMapResponse gets the verified username map (both map[string]string and map[string]*lib.PKID) from
// the configured GlobalStateAPIUrl or this node's global state.
func (fes *APIServer) GetVerifiedUsernameMap() (
	_verifiedUsernameToPKID map[string]*lib.PKID, _err error,
) {
	verifiedUsernameMap := make(map[string]*lib.PKID)
	var err error
	// If there is an external global state specified, fetch the verified username map from there.
	if fes.Config.GlobalStateAPIUrl != "" {
		// Get the bytes.
		var mapBytes []byte
		mapBytes, err = fes.FetchFromExternalGlobalState(RoutePathGetVerifiedUsernames)
		if err != nil {
			return nil, fmt.Errorf("GetVerifiedUsernameMap: Error fetching map from external global state: %v", err)
		}
		// Decode the response into the appropriate struct.
		decoder := json.NewDecoder(bytes.NewReader(mapBytes))
		if err = decoder.Decode(&verifiedUsernameMap); err != nil {
			return nil, fmt.Errorf("GetVerifiedUsernameMap: Error decoding bytes: %v", err)
		}
	} else {
		// If we're getting from this node's global state, fetch the bytes from the global state instead of using the
		// cache.
		verifiedUsernameMap, err = fes.GetVerifiedUsernameToPKIDMapFromGlobalState()
		if err != nil {
			return nil, fmt.Errorf("GetVerifiedUsernameMap: Error getting verified username map %v", err)
		}
	}

	return verifiedUsernameMap, nil
}

// GetBlacklist returns both a slice of strings and a map of PKID to []byte representing the current state of
// blacklisted users.
func (fes *APIServer) GetBlacklist(utxoView *lib.UtxoView) (
	_blacklistedPKIDMap map[lib.PKID][]byte, _err error,
) {
	return fes.GetRestrictedPublicKeys(_GlobalStatePrefixPublicKeyToBlacklistState, lib.IsBlacklisted, utxoView, RoutePathGetBlacklistedPublicKeys)
}

// GetGraylist returns both a slice of strings and a map of PKID to []byte representing the current state of graylisted
// users.
func (fes *APIServer) GetGraylist(utxoView *lib.UtxoView) (
	_graylistedPKIDMap map[lib.PKID][]byte, _err error,
) {
	return fes.GetRestrictedPublicKeys(_GlobalStatePrefixPublicKeyToGraylistState, lib.IsGraylisted, utxoView, RoutePathGetGraylistedPublicKeys)
}

// GetRestrictedPublicKeys fetches the blacklisted or graylisted public keys from this node's global state or the configured
// external global state. This returns both a slice of public keys (strings) and a map of PKID to restricted bytes.
func (fes *APIServer) GetRestrictedPublicKeys(prefix []byte, filterValue []byte, utxoView *lib.UtxoView, routePath string) (
	_pkidMap map[lib.PKID][]byte, _err error,
) {
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
		pkidMap := make(map[lib.PKID][]byte)
		for k, v := range stringifiedPKIDsMap {
			var publicKeyBytes []byte
			publicKeyBytes, _, err = lib.Base58CheckDecode(k)
			if err != nil {
				return nil, err
			}
			pkid := lib.PublicKeyToPKID(publicKeyBytes)
			pkidMap[*pkid] = v
		}
		return pkidMap, nil
	}
	// Otherwise, we're using our own global state. Seek global state for all restricted public keys of this type.
	publicKeys, states, err := fes.GlobalState.Seek(
		prefix,
		prefix, /*validForPrefix*/
		0,      /*maxKeyLen -- ignored since reverse is false*/
		0,      /*numToFetch -- 0 is ignored*/
		false,  /*reverse*/
		true,   /*fetchValues*/
	)
	if err != nil {
		return nil, err
	}
	filteredPKIDMap := make(map[lib.PKID][]byte)
	// Iterate over all restricted public keys
	for ii, publicKeyWithPrefix := range publicKeys {
		// Sanity check that the byte found in global state indicates this is a restricted key.
		if reflect.DeepEqual(states[ii], filterValue) {
			// Remove the prefix byte
			publicKey := publicKeyWithPrefix[1:]
			pkid := utxoView.GetPKIDForPublicKey(publicKey)
			filteredPKIDMap[*pkid.PKID] = filterValue
		}
	}
	return filteredPKIDMap, nil
}

func (fes *APIServer) GetGlobalFeedCache() (_postHashes []*lib.BlockHash, _err error) {
	if fes.Config.GlobalStateAPIUrl != "" {
		body, err := fes.FetchFromExternalGlobalState(RoutePathGetGlobalFeed)
		if err != nil {
			return nil, err
		}

		// Decode the body into a slice of BlockHashes
		var blockHashes []*lib.BlockHash
		decoder := json.NewDecoder(bytes.NewReader(body))
		if err = decoder.Decode(&blockHashes); err != nil {
			return nil, fmt.Errorf("GetGlobalFeed: Error decoding bytes: %v", err)
		}
		return blockHashes, nil
	}
	postHashes, err := fes.GetGlobalFeedPostHashesForLastWeek()
	if err != nil {
		return nil, err
	}
	return postHashes, nil
}

// FetchFromExternalGlobalState hits an endpoint at the configured GlobalStateAPIUrl and returns the bytes read from
// the response body.
func (fes *APIServer) FetchFromExternalGlobalState(routePath string) (_body []byte, _err error) {
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
