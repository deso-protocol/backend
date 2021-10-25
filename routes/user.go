package routes

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/dgraph-io/badger/v3"
	"github.com/gorilla/mux"

	"github.com/deso-protocol/core/lib"
	"github.com/golang/glog"
	"github.com/pkg/errors"
)

// GetUsersRequest ...
type GetUsersStatelessRequest struct {
	PublicKeysBase58Check []string `safeForLogging:"true"`
	SkipForLeaderboard    bool     `safeForLogging:"true"`
}

// GetUsersResponse ...
type GetUsersResponse struct {
	UserList                 []*User
	DefaultFeeRateNanosPerKB uint64
	ParamUpdaters            map[string]bool
}

// GetUsersStateless ...
func (fes *APIServer) GetUsersStateless(ww http.ResponseWriter, rr *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(rr.Body, MaxRequestBodySizeBytes))
	getUsersRequest := GetUsersStatelessRequest{}
	if err := decoder.Decode(&getUsersRequest); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetUsersStateless: Error parsing request body: %v", err))
		return
	}

	userList := []*User{}
	for ii := range getUsersRequest.PublicKeysBase58Check {
		currentUser := &User{
			PublicKeyBase58Check: getUsersRequest.PublicKeysBase58Check[ii],
			// All the other fields will be set in the call to UpdateUsers below.
		}
		userList = append(userList, currentUser)
	}

	globalParams, err := fes.updateUsersStateless(userList, getUsersRequest.SkipForLeaderboard)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetUsersStateless: Error fetching data for user: %v", err))
		return
	}

	// Compute a default fee rate.
	defaultFeeRateNanosPerKB := fes.MinFeeRateNanosPerKB
	if globalParams != nil && globalParams.MinimumNetworkFeeNanosPerKB > 0 {
		defaultFeeRateNanosPerKB = globalParams.MinimumNetworkFeeNanosPerKB
	}

	paramUpdaters := make(map[string]bool)
	for kk := range fes.Params.ParamUpdaterPublicKeys {
		paramUpdaters[lib.PkToString(kk[:], fes.Params)] = true
	}

	// Update all user information before returning.
	res := GetUsersResponse{
		UserList:                 userList,
		DefaultFeeRateNanosPerKB: defaultFeeRateNanosPerKB,
		ParamUpdaters:            paramUpdaters,
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetUsers: Problem serializing object to Error: %v", err))
		return
	}
}

func (fes *APIServer) updateUsersStateless(userList []*User, skipForLeaderboard bool) (*lib.GlobalParamsEntry, error) {
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return nil, fmt.Errorf("updateUserFields: Error calling GetAugmentedUtxoViewForPublicKey: %v", err)
	}
	globalParams := utxoView.GlobalParamsEntry
	// Grab verified username map pointer
	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
	if err != nil {
		glog.Errorf(fmt.Sprintf("updateUserFields: Problem fetching verifiedMap: %v", err))
	}
	for _, user := range userList {
		// If we get an error updating the user, log it but don't stop the show.
		if err = fes.updateUserFieldsStateless(user, utxoView, skipForLeaderboard, verifiedMap); err != nil {
			glog.Errorf(fmt.Sprintf("updateUsers: Problem updating user with pk %s: %v", user.PublicKeyBase58Check, err))
		}
	}

	return globalParams, nil
}

func (fes *APIServer) updateUserFieldsStateless(user *User, utxoView *lib.UtxoView, skipForLeaderboard bool, verifiedMap map[string]*lib.PKID) error {
	// If there's no public key, then return an error. We need a public key on
	// the user object in order to be able to update the fields.
	if user.PublicKeyBase58Check == "" {
		return fmt.Errorf("updateUserFields: Missing PublicKeyBase58Check")
	}

	// Decode the public key into bytes.
	publicKeyBytes, _, err := lib.Base58CheckDecode(user.PublicKeyBase58Check)
	if err != nil {
		return errors.Wrapf(err, "updateUserFields: Problem decoding user public key: ")
	}

	// Get the ProfileEntry corresponding to this user's public key from the view.
	profileEntryy := utxoView.GetProfileEntryForPublicKey(publicKeyBytes)
	var profileEntryResponse *ProfileEntryResponse
	if profileEntryy != nil {
		// Convert it to a response since that sanitizes the inputs.
		profileEntryResponse = _profileEntryToResponse(profileEntryy, fes.Params, verifiedMap, utxoView)
		user.ProfileEntryResponse = profileEntryResponse
	}

	// We do not need a user's balance for the leaderboard
	if !skipForLeaderboard {
		// Get the UtxoEntries from the augmented view
		utxoEntries, err := fes.blockchain.GetSpendableUtxosForPublicKey(
			publicKeyBytes, fes.backendServer.GetMempool(), utxoView)
		if err != nil {
			return errors.Wrapf(err, "updateUserFields: Problem getting utxos from view: ")
		}
		totalBalanceNanos := uint64(0)
		unminedBalanceNanos := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalanceNanos += utxoEntry.AmountNanos
			if utxoEntry.BlockHeight > fes.blockchain.BlockTip().Height {
				unminedBalanceNanos += utxoEntry.AmountNanos
			}
		}
		// Set the user's balance.
		user.BalanceNanos = totalBalanceNanos
		user.UnminedBalanceNanos = unminedBalanceNanos
	}

	// We do not need follows for the leaderboard
	if !skipForLeaderboard {
		// Get the people who the user is following
		// Note: we may want to revisit this in the future. This might be inefficient if we're obtaining
		// a lot of users and all their followers.
		// Set NumToFetch to 0 and fetchAll to true to retrieve all followed public keys.
		publicKeyToProfileEntry, _, err := fes.getPublicKeyToProfileEntryMapForFollows(
			publicKeyBytes, false, utxoView, nil, 0, false, true)
		if err != nil {
			return errors.Wrapf(err, "GetFollowsStateless: Problem fetching and decrypting follows:")
		}
		publicKeysBase58CheckFollowedByUser := make([]string, 0, len(publicKeyToProfileEntry))
		for k := range publicKeyToProfileEntry {
			publicKeysBase58CheckFollowedByUser = append(publicKeysBase58CheckFollowedByUser, k)
		}
		// Ensure that these show up in the frontend in a consistent order
		// The frontend needs consistent ordering since app.component.ts does the following
		// to determine whether any user fields are changed:
		//   (JSON.stringify(this.appData.loggedInUser) !== JSON.stringify(loggedInUserFound))
		sort.Strings(publicKeysBase58CheckFollowedByUser)
		user.PublicKeysBase58CheckFollowedByUser = publicKeysBase58CheckFollowedByUser
	}

	pkid := utxoView.GetPKIDForPublicKey(publicKeyBytes)
	// We don't need hodlings for the leaderboard
	if !skipForLeaderboard {
		var youHodlMap map[string]*BalanceEntryResponse
		// Get the users that the user hodls
		youHodlMap, err = fes.GetYouHodlMap(pkid, true, utxoView)
		if err != nil {
			return errors.Errorf("updateUserFieldsStateless: Problem with canUserCreateProfile: %v", err)
		}

		youHodlList := []*BalanceEntryResponse{}
		for _, entryRes := range youHodlMap {
			youHodlList = append(youHodlList, entryRes)
		}
		// Note we sort the youHodl list by the creator pk
		sort.Slice(youHodlList, func(ii, jj int) bool {
			return youHodlList[ii].CreatorPublicKeyBase58Check > youHodlList[jj].CreatorPublicKeyBase58Check
		})

		var hodlYouMap map[string]*BalanceEntryResponse
		hodlYouMap, err = fes.GetHodlYouMap(utxoView.GetPKIDForPublicKey(publicKeyBytes), false, utxoView)
		// Assign the new hodl lists to the user object
		user.UsersYouHODL = youHodlList
		user.UsersWhoHODLYouCount = len(hodlYouMap)
	}

	// We don't need user metadata from global state for the leaderboard.
	if !skipForLeaderboard {
		// Populate fields from userMetadata global state
		var userMetadata *UserMetadata
		userMetadata, err = fes.getUserMetadataFromGlobalState(user.PublicKeyBase58Check)
		if err != nil {
			return errors.Wrap(fmt.Errorf(
				"updateUserFieldsStateless: Problem with getUserMetadataFromGlobalState: %v", err), "")
		}

		// HasPhoneNumber is a computed boolean so we can avoid returning the phone number in the
		// API response, since phone numbers are sensitive PII. Same for emails.
		user.HasPhoneNumber = userMetadata.PhoneNumber != ""
		user.HasEmail = userMetadata.Email != ""
		user.EmailVerified = userMetadata.EmailVerified
		user.JumioVerified = userMetadata.JumioVerified
		user.JumioReturned = userMetadata.JumioReturned
		user.JumioFinishedTime = userMetadata.JumioFinishedTime
		user.TutorialStatus = userMetadata.TutorialStatus
		user.MustCompleteTutorial = userMetadata.MustCompleteTutorial
		// We only need to fetch the creator purchased in the tutorial if the user is still in the tutorial
		if user.TutorialStatus != COMPLETE && user.TutorialStatus != SKIPPED && userMetadata.CreatorPurchasedInTutorialPKID != nil {
			tutorialCreatorProfileEntry := utxoView.GetProfileEntryForPKID(userMetadata.CreatorPurchasedInTutorialPKID)
			if tutorialCreatorProfileEntry == nil {
				return fmt.Errorf("updateUserFieldsStateless: Did not find profile entry for PKID for creator purchased in tutorial")
			}
			username := string(tutorialCreatorProfileEntry.Username)
			user.CreatorPurchasedInTutorialUsername = &username
			user.CreatorCoinsPurchasedInTutorial = userMetadata.CreatorCoinsPurchasedInTutorial
		}
		if profileEntryy != nil {
			user.ProfileEntryResponse.IsFeaturedTutorialUpAndComingCreator = userMetadata.IsFeaturedTutorialUpAndComingCreator
			user.ProfileEntryResponse.IsFeaturedTutorialWellKnownCreator = userMetadata.IsFeaturedTutorialWellKnownCreator
		}
		if user.CanCreateProfile, err = fes.canUserCreateProfile(userMetadata, utxoView); err != nil {
			return errors.Wrap(fmt.Errorf("updateUserFieldsStateless: Problem with canUserCreateProfile: %v", err), "")
		}
		// Get map of public keys user has blocked
		if user.BlockedPubKeys, err = fes.GetBlockedPubKeysForUser(publicKeyBytes); err != nil {
			return errors.Wrap(fmt.Errorf("updateUserFieldsStateless: Problem with GetBlockedPubKeysForUser: %v", err), "")
		}
	}

	// Check if the user is blacklisted/graylisted
	blacklistKey := GlobalStateKeyForBlacklistedProfile(publicKeyBytes[:])
	userBlacklistState, err := fes.GlobalStateGet(blacklistKey)
	if err != nil {
		return errors.Wrap(fmt.Errorf("updateUserFieldsStateless: Problem getting blacklist: %v", err), "")
	}
	if reflect.DeepEqual(userBlacklistState, lib.IsBlacklisted) {
		user.IsBlacklisted = true
	}
	graylistKey := GlobalStateKeyForGraylistedProfile(publicKeyBytes[:])
	userGraylistState, err := fes.GlobalStateGet(graylistKey)
	if err != nil {
		return errors.Wrap(fmt.Errorf("updateUserFieldsStateless: Problem getting graylist: %v", err), "")
	}
	if reflect.DeepEqual(userGraylistState, lib.IsGraylisted) {
		user.IsGraylisted = true
	}

	// Only set User.IsAdmin in GetUsersStateless
	// We don't want or need to set this on every endpoint that generates a ProfileEntryResponse
	isAdmin, isSuperAdmin := fes.UserAdminStatus(user.PublicKeyBase58Check)
	user.IsAdmin = isAdmin
	user.IsSuperAdmin = isSuperAdmin

	return nil
}

func (fes *APIServer) UserAdminStatus(publicKeyBase58Check string) (_isAdmin bool, _isSuperAdmin bool) {
	for _, k := range fes.Config.SuperAdminPublicKeys {
		if k == publicKeyBase58Check || k == "*" {
			return true, true
		}
	}
	for _, k := range fes.Config.AdminPublicKeys {
		if k == publicKeyBase58Check || k == "*" {
			return true, false
		}
	}
	return false, false
}

// Get map of creators you hodl.
func (fes *APIServer) GetYouHodlMap(pkid *lib.PKIDEntry, fetchProfiles bool, utxoView *lib.UtxoView) (
	_youHodlMap map[string]*BalanceEntryResponse, _err error) {
	// Grab verified username map pointer
	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
	if err != nil {
		return nil, fmt.Errorf(
			"GetYouHodlMap: Error fetching verifiedMap: %v", err)
	}

	// Get all the hodlings for this user from the db
	entriesYouHodl, profilesYouHodl, err := utxoView.GetHoldings(pkid.PKID, fetchProfiles)
	if err != nil {
		return nil, fmt.Errorf(
			"GetHodlingsForPublicKey: Error looking up balance entries in db: %v", err)
	}

	// Map hodler pk -> their entry
	youHodlMap := fes.getMapFromEntries(entriesYouHodl, profilesYouHodl, true, utxoView, verifiedMap)

	// Iterate over the view and use the entries to update our maps.
	//
	// TODO: We need to screen out zero balances in the view. Right now we only screen them
	// out from the DB query.
	for _, balanceEntry := range utxoView.HODLerPKIDCreatorPKIDToBalanceEntry {
		dbBalanceEntryResponse := &BalanceEntryResponse{}
		if reflect.DeepEqual(balanceEntry.HODLerPKID, pkid.PKID) {
			// In this case the user is the HODLer.

			// Optionally look up the profile of the creator.
			var profileEntry *lib.ProfileEntry
			if fetchProfiles {
				profileEntry = utxoView.GetProfileEntryForPKID(balanceEntry.CreatorPKID)
			}

			if _, ok := youHodlMap[lib.PkToString(balanceEntry.CreatorPKID[:], fes.Params)]; ok {
				// If we made it here, we found both a mempool and a db balanceEntry.
				// We update the dbBalanceEntry so it can be used in order to get net mempool data.
				dbBalanceEntryResponse = youHodlMap[lib.PkToString(balanceEntry.CreatorPKID[:], fes.Params)]
			}
			youHodlMap[lib.PkToString(balanceEntry.CreatorPKID[:], fes.Params)] = _balanceEntryToResponse(
				balanceEntry, dbBalanceEntryResponse.BalanceNanos, profileEntry, fes.Params, utxoView, verifiedMap)
		}
	}
	return youHodlMap, nil
}

// Convert list of BalanceEntries to a map of hodler / creator PKID to balance entry response.
func (fes *APIServer) getMapFromEntries(entries []*lib.BalanceEntry, profiles []*lib.ProfileEntry, useCreatorPKIDAsKey bool, utxoView *lib.UtxoView, verifiedMap map[string]*lib.PKID) map[string]*BalanceEntryResponse {
	mapYouHodl := map[string]*BalanceEntryResponse{}
	for ii, entry := range entries {
		var currentProfile *lib.ProfileEntry
		if len(profiles) != 0 {
			currentProfile = profiles[ii]
		}
		if useCreatorPKIDAsKey {
			mapYouHodl[lib.PkToString(entry.CreatorPKID[:], fes.Params)] =
				_balanceEntryToResponse(entry, entry.BalanceNanos /*dbBalanceNanos*/, currentProfile, fes.Params, utxoView, verifiedMap)
		} else {
			mapYouHodl[lib.PkToString(entry.HODLerPKID[:], fes.Params)] =
				_balanceEntryToResponse(entry, entry.BalanceNanos /*dbBalanceNanos*/, currentProfile, fes.Params, utxoView, verifiedMap)
		}
	}
	return mapYouHodl
}

func _balanceEntryToResponse(
	balanceEntry *lib.BalanceEntry, dbBalanceNanos uint64, profileEntry *lib.ProfileEntry,
	params *lib.DeSoParams, utxoView *lib.UtxoView, verifiedMap map[string]*lib.PKID) *BalanceEntryResponse {

	if balanceEntry == nil {
		return nil
	}

	// Convert the PKIDs to public keys.
	hodlerPk := utxoView.GetPublicKeyForPKID(balanceEntry.HODLerPKID)
	creatorPk := utxoView.GetPublicKeyForPKID(balanceEntry.CreatorPKID)

	return &BalanceEntryResponse{
		HODLerPublicKeyBase58Check:  lib.PkToString(hodlerPk, params),
		CreatorPublicKeyBase58Check: lib.PkToString(creatorPk, params),
		HasPurchased:                balanceEntry.HasPurchased,
		BalanceNanos:                balanceEntry.BalanceNanos,
		NetBalanceInMempool:         int64(balanceEntry.BalanceNanos) - int64(dbBalanceNanos),

		// If the profile is nil, this will be nil
		ProfileEntryResponse: _profileEntryToResponse(profileEntry, params, verifiedMap, utxoView),
	}
}

// GetHodlingsForPublicKey ...
func (fes *APIServer) GetHodlingsForPublicKey(pkid *lib.PKIDEntry, fetchProfiles bool, referenceUtxoView *lib.UtxoView) (
	_youHodlMap map[string]*BalanceEntryResponse,
	_hodlYouMap map[string]*BalanceEntryResponse, _err error) {
	// Get a view that considers all of this user's transactions.
	var utxoView *lib.UtxoView
	if referenceUtxoView != nil {
		utxoView = referenceUtxoView
	} else {
		var err error
		utxoView, err = fes.backendServer.GetMempool().GetAugmentedUniversalView()
		if err != nil {
			return nil, nil, fmt.Errorf(
				"GetHodlingsForPublicKey: Error calling GetAugmentedUtxoViewForPublicKey: %v", err)
		}
	}
	// Get the map of entries this PKID hodls.
	youHodlMap, err := fes.GetYouHodlMap(pkid, fetchProfiles, utxoView)
	if err != nil {
		return nil, nil, err
	}
	// Get the map of the entries hodlings this PKID
	hodlYouMap, err := fes.GetHodlYouMap(pkid, fetchProfiles, utxoView)
	if err != nil {
		return nil, nil, err
	}

	// At this point, the maps should reflect all the creators the user HODLs
	// and all the people who HODL the user.
	return youHodlMap, hodlYouMap, nil
}

// Get map of public keys hodling your coin.
func (fes *APIServer) GetHodlYouMap(pkid *lib.PKIDEntry, fetchProfiles bool, utxoView *lib.UtxoView) (
	_youHodlMap map[string]*BalanceEntryResponse, _err error) {
	// Grab verified username map pointer
	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
	if err != nil {
		return nil, fmt.Errorf(
			"GetYouHodlMap: Error fetching verifiedMap: %v", err)
	}

	// Get all the hodlings for this user from the db
	entriesHodlingYou, profileHodlingYou, err := utxoView.GetHolders(pkid.PKID, fetchProfiles)
	if err != nil {
		return nil, fmt.Errorf(
			"GetHodlingsForPublicKey: Error looking up balance entries in db: %v", err)
	}
	// Map hodler pk -> their entry
	hodlYouMap := fes.getMapFromEntries(entriesHodlingYou, profileHodlingYou, false, utxoView, verifiedMap)

	// Iterate over the view and use the entries to update our maps.
	//
	// TODO: We need to screen out zero balances in the view. Right now we only screen them
	// out from the DB query.
	for _, balanceEntry := range utxoView.HODLerPKIDCreatorPKIDToBalanceEntry {
		dbBalanceEntryResponse := &BalanceEntryResponse{}
		if reflect.DeepEqual(balanceEntry.CreatorPKID, pkid.PKID) {
			// In this case the user is the one *being* HODL'ed.

			// Optionally ook up the profile of the person who is HODL'ing the user.
			var profileEntry *lib.ProfileEntry
			if fetchProfiles {
				profileEntry = utxoView.GetProfileEntryForPKID(balanceEntry.HODLerPKID)
			}

			if _, ok := hodlYouMap[lib.PkToString(balanceEntry.HODLerPKID[:], fes.Params)]; ok {
				// If we made it here, we found both a mempool and a db balanceEntry.
				// We update the dbBalanceEntry so it can be used in order to get net mempool data.
				dbBalanceEntryResponse = hodlYouMap[lib.PkToString(balanceEntry.HODLerPKID[:], fes.Params)]
			}
			hodlYouMap[lib.PkToString(balanceEntry.HODLerPKID[:], fes.Params)] = _balanceEntryToResponse(
				balanceEntry, dbBalanceEntryResponse.BalanceNanos, profileEntry, fes.Params, utxoView, verifiedMap)
		}
	}
	return hodlYouMap, nil
}

type DeleteIdentityRequest struct{}

type DeleteIdentityResponse struct{}

func (fes *APIServer) DeleteIdentities(ww http.ResponseWriter, req *http.Request) {
	// Decode the request data.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := DeleteIdentityRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("DeleteIdentities: Problem parsing request body: %v", err))
		return
	}

	for _, cookie := range req.Cookies() {
		if strings.HasPrefix(cookie.Name, SeedInfoCookieKey) {
			cookie := &http.Cookie{
				Name:     cookie.Name,
				Value:    "",
				MaxAge:   1, // expire immediately
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			}
			http.SetCookie(ww, cookie)
		}
	}

	res := DeleteIdentityResponse{}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("DeleteIdentities: Problem encoding response as JSON: %v", err))
		return
	}
}

// GetProfilesStatelessRequest ...
type GetProfilesRequest struct {
	// When set, we return profiles starting at the given pubkey up to numEntriesToReturn.
	PublicKeyBase58Check string `safeForLogging:"true"`
	// When set, we return profiles starting at the given username up to numEntriesToReturn.
	Username string `safeForLogging:"true"`
	// When specified, we filter out all profiles that don't have this
	// string as a prefix on their username.
	UsernamePrefix string `safeForLogging:"true"`
	// When set, we filter out profiles that don't contain this string
	// in their Description field.
	Description string `safeForLogging:"true"`
	OrderBy     string `safeForLogging:"true"`
	NumToFetch  uint32 `safeForLogging:"true"`
	// Public key of the user viewing the profile (affects post entry reader state).
	ReaderPublicKeyBase58Check string `safeForLogging:"true"`
	// Moderation type (currently empty string or 'leaderboard'). Empty string is for default
	// moderation.  'Leaderboard' is a special subset of profiles only removed from the leaderboards.
	ModerationType string `safeForLogging:"true"`
	// If a single profile is requested, return a list of HODLers and amount they HODL.
	FetchUsersThatHODL bool `safeForLogging:"true"`

	// If set to true, then the posts in the response will contain a boolean about whether they're in the global feed
	AddGlobalFeedBool bool `safeForLogging:"true"`
}

// GetProfilesResponse ...
type GetProfilesResponse struct {
	ProfilesFound []*ProfileEntryResponse
	NextPublicKey *string
}

type ProfileEntryResponse struct {
	// PublicKey is the key used by the user to sign for things and generally
	// verify her identity.
	PublicKeyBase58Check string
	Username             string
	Description          string
	IsHidden             bool
	IsReserved           bool
	IsVerified           bool
	Comments             []*PostEntryResponse
	Posts                []*PostEntryResponse
	// Creator coin fields
	CoinEntry *CoinEntryResponse
	// Include current price for the frontend to display.
	CoinPriceDeSoNanos     uint64
	CoinPriceBitCloutNanos uint64 // Deprecated

	// Profiles of users that hold the coin + their balances.
	UsersThatHODL []*BalanceEntryResponse

	// If user is featured as a well known creator in the tutorial.
	IsFeaturedTutorialWellKnownCreator bool
	// If user is featured as an up and coming creator in the tutorial.
	// Note: a user should not be both featured as well known and up and coming
	IsFeaturedTutorialUpAndComingCreator bool
}

// Deprecated: Temporary to add support for BitCloutLockedNanos
type CoinEntryResponse struct {
	CreatorBasisPoints      uint64
	DeSoLockedNanos         uint64
	NumberOfHolders         uint64
	CoinsInCirculationNanos uint64
	CoinWatermarkNanos      uint64

	BitCloutLockedNanos uint64 // Deprecated
}

// GetProfiles ...
func (fes *APIServer) GetProfiles(ww http.ResponseWriter, req *http.Request) {
	profileEntryResponses := []*ProfileEntryResponse{}

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetProfilesRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetProfiles: Problem parsing request body: %v", err))
		return
	}

	// The default number of profiles returned is 20.
	numToFetch := 20
	if requestData.NumToFetch != 0 {
		numToFetch = int(requestData.NumToFetch)
	}

	// Cap numToFetch at 100
	if requestData.NumToFetch > 100 {
		_AddBadRequestError(ww, fmt.Sprintf("GetProfiles: Max value for NumToFetch exceeded"))
		return
	}

	// Decode the reader public key into bytes. Default to nil if no pub key is passed in.
	var readerPubKey []byte
	if requestData.ReaderPublicKeyBase58Check != "" {
		var err error
		readerPubKey, _, err = lib.Base58CheckDecode(requestData.ReaderPublicKeyBase58Check)
		if requestData.ReaderPublicKeyBase58Check != "" && err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"GetProfiles: Problem decoding user public key: %v : %s", err, requestData.ReaderPublicKeyBase58Check))
			return
		}
	}

	// Get a utxo view for lookups.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetProfiles: Error fetching profiles from mempool: %v", err))
		return
	}

	// If this is a usernamePrefix request, we hit the DB.
	if requestData.UsernamePrefix != "" {
		// TODO(performance): This currently fetches all usernames that match this prefix, which
		// could get slow. Bandaid fix would be to not search until we have a few characters.

		// Read in verified users map from DB
		verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
		if err != nil {
			_AddInternalServerError(ww, fmt.Sprintf("GetProfiles: Error fetching verifiedMap: %v", err))
			return
		}

		profileEntries, err := fes.GetProfilesByUsernamePrefixAndDeSoLocked(
			fes.blockchain.DB(), requestData.UsernamePrefix, readerPubKey, utxoView)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"GetProfiles: Error fetching profiles from view: %v", err))
			return
		}

		for _, profileEntry := range profileEntries {
			profileEntryResponses = append(
				profileEntryResponses, _profileEntryToResponse(profileEntry, fes.Params, verifiedMap, utxoView))
			if len(profileEntryResponses) == numToFetch {
				break
			}
		}

		usernameSearchRes := &GetProfilesResponse{ProfilesFound: profileEntryResponses}

		// If we get here, we already handled a username prefix search request and can bail.
		if err = json.NewEncoder(ww).Encode(usernameSearchRes); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"GetProfiles: Problem encoding response as JSON: %v", err))
			return
		}
		return
	}

	// Decode the start public key into bytes. Default to nil if no pub key is passed in.
	var startPubKey []byte
	if requestData.PublicKeyBase58Check != "" {
		var err error
		startPubKey, _, err = lib.Base58CheckDecode(requestData.PublicKeyBase58Check)
		if requestData.PublicKeyBase58Check != "" && err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"GetProfiles: Problem decoding user public key: %v : %s", err, requestData.PublicKeyBase58Check))
			return
		}
	}

	// If we don't have a public key, check for a username and get the public key if it exists.
	if startPubKey == nil && requestData.Username != "" {
		profile := utxoView.GetProfileEntryForUsername([]byte(requestData.Username))
		if profile == nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"GetProfiles: Problem getting profile for username: %v : %s", err, requestData.Username))
			return
		}
		startPubKey = profile.PublicKey
	}

	getPosts := false
	if numToFetch == 1 {
		// The only time we need comments and posts attached to profile entries right now
		// is on the profile detail page where we are fetching a single profile.
		getPosts = true
	}

	// Fetch the profiles.
	// TODO: extraNumToFetchMultiplier is a dirty hack. We fetch more than numToFetch profiles
	// to adjust for the fact that some profiles will be filtered out from the fetch due to their
	// being blacklisted. The real fix would be to have GetProfilesByCoinValue to keep fetching
	// until it has numToFetch profiles, while not considering blacklisted profiles.  When numToFetch is 1, only fetch that
	// single profile.
	extraNumToFetchMultiplier := 5
	totalToFetch := extraNumToFetchMultiplier * numToFetch
	if numToFetch == 1 {
		totalToFetch = 1
	}
	profileEntriesByPublicKey,
		postsByProfilePublicKey,
		postEntryReaderStates,
		err := fes.GetProfilesByCoinValue(
		utxoView, readerPubKey, startPubKey, totalToFetch,
		getPosts, requestData.ModerationType)

	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetProfiles: Error fetching profiles from view: %v", err))
		return
	}

	// Get the map of verified usernames.
	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetProfiles: Error fetching verifiedMap: %v", err))
		return
	}

	if numToFetch == 1 {
		// If only one entry was requested, find that one.
		profileEntry := profileEntriesByPublicKey[lib.MakePkMapKey(startPubKey)]
		if profileEntry == nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetProfiles: Could not find profile for pub key: %v", startPubKey))
			return
		}
		profileEntryResponse := fes.augmentProfileEntry(
			profileEntry,
			profileEntriesByPublicKey,
			postsByProfilePublicKey,
			postEntryReaderStates,
			requestData.AddGlobalFeedBool,
			verifiedMap,
			utxoView,
			readerPubKey,
		)

		// Get the users that HODL this profile, if requested.
		hodlYouList := []*BalanceEntryResponse{}
		if requestData.FetchUsersThatHODL {
			// Get the users that the user hodls and vice versa
			pkid := utxoView.GetPKIDForPublicKey(startPubKey)
			_, hodlYouMap, err := fes.GetHodlingsForPublicKey(
				pkid, true /*fetchProfiles*/, utxoView)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf(
					"GetProfiles: Could not find HODLers for pub key: %v", startPubKey))
				return
			}
			for _, entryRes := range hodlYouMap {
				hodlYouList = append(hodlYouList, entryRes)
			}
			// Note we sort the hodlYou list by amount held, descending. If creator is hodler, creator should be first
			sort.Slice(hodlYouList, func(ii, jj int) bool {
				if hodlYouList[ii].CreatorPublicKeyBase58Check == hodlYouList[ii].HODLerPublicKeyBase58Check {
					return true
				}
				if hodlYouList[jj].CreatorPublicKeyBase58Check == hodlYouList[jj].HODLerPublicKeyBase58Check {
					return false
				}
				return hodlYouList[ii].BalanceNanos > hodlYouList[jj].BalanceNanos
			})
		}
		profileEntryResponse.UsersThatHODL = hodlYouList

		// Add the completed profileEntryResponse to the list we return.
		profileEntryResponses = append(profileEntryResponses, profileEntryResponse)
	} else {
		for _, profileEntry := range profileEntriesByPublicKey {
			// Append the profile to the list
			profileEntryResponses = append(profileEntryResponses, fes.augmentProfileEntry(
				profileEntry,
				profileEntriesByPublicKey,
				postsByProfilePublicKey,
				postEntryReaderStates,
				requestData.AddGlobalFeedBool,
				verifiedMap,
				utxoView,
				readerPubKey,
			))
		}
	}

	if requestData.OrderBy == "newest_last_post" {
		// Sort each profile's posts so that the newest post is first.
		for _, profileRes := range profileEntryResponses {
			if len(profileRes.Posts) == 0 {
				continue
			}
			sort.Slice(profileRes.Posts, func(ii, jj int) bool {
				return profileRes.Posts[ii].TimestampNanos > profileRes.Posts[jj].TimestampNanos
			})
		}
		// The posts should be sorted so that the latest post is first.

		sort.Slice(profileEntryResponses, func(ii, jj int) bool {
			lastPostTimeii := uint64(0)
			if len(profileEntryResponses[ii].Posts) > 0 {
				lastPostTimeii = profileEntryResponses[ii].Posts[0].TimestampNanos
			}
			lastPostTimejj := uint64(0)
			if len(profileEntryResponses[jj].Posts) > 0 {
				lastPostTimejj = profileEntryResponses[jj].Posts[0].TimestampNanos
			}
			return lastPostTimeii > lastPostTimejj
		})
	} else if requestData.OrderBy == "newest_last_comment" {
		sort.Slice(profileEntryResponses, func(ii, jj int) bool {
			lastCommentTimeii := uint64(0)
			if len(profileEntryResponses[ii].Comments) > 0 {
				lastCommentTimeii = profileEntryResponses[ii].Comments[len(profileEntryResponses[ii].Comments)-1].TimestampNanos
			}
			lastCommentTimejj := uint64(0)
			if len(profileEntryResponses[jj].Comments) > 0 {
				lastCommentTimejj = profileEntryResponses[jj].Comments[len(profileEntryResponses[jj].Comments)-1].TimestampNanos
			}
			return lastCommentTimeii > lastCommentTimejj
		})
	} else if requestData.OrderBy == "influencer_coin_price" {
		sort.Slice(profileEntryResponses, func(ii, jj int) bool {
			return profileEntryResponses[ii].CoinEntry.DeSoLockedNanos > profileEntryResponses[jj].CoinEntry.DeSoLockedNanos
		})
	}

	// Sliced returned profiles found down to the number of entries specified, if necessary.
	var res *GetProfilesResponse
	if len(profileEntryResponses) > numToFetch || startPubKey != nil {
		// Find the startPubKey and start response from that index
		startIdx := 0
		if startPubKey != nil {
			for ii, profileEntryResponse := range profileEntryResponses {
				if profileEntryResponse.PublicKeyBase58Check == requestData.PublicKeyBase58Check {
					startIdx = ii
					break
				}
			}
		}
		var maxIdx int
		var nextPubKey *string
		if len(profileEntryResponses) > startIdx+numToFetch {
			maxIdx = startIdx + numToFetch
			nextPubKey = &profileEntryResponses[maxIdx].PublicKeyBase58Check
		} else {
			maxIdx = len(profileEntryResponses)
			nextPubKey = nil
		}
		res = &GetProfilesResponse{
			ProfilesFound: profileEntryResponses[startIdx:maxIdx],
			NextPublicKey: nextPubKey,
		}
	} else {
		res = &GetProfilesResponse{ProfilesFound: profileEntryResponses}
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetProfiles: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) GetProfilesByUsernamePrefixAndDeSoLocked(
	db *badger.DB, usernamePrefix string, readerPK []byte, utxoView *lib.UtxoView) (
	_profileEntries []*lib.ProfileEntry, _err error) {

	profileEntries, err := lib.DBGetProfilesByUsernamePrefixAndDeSoLocked(db, usernamePrefix, utxoView)

	pubKeyMap := make(map[lib.PkMapKey][]byte)
	for _, profileEntry := range profileEntries {
		pubKeyMap[lib.MakePkMapKey(profileEntry.PublicKey)] = profileEntry.PublicKey
	}

	filteredPubKeyMap, err := fes.FilterOutRestrictedPubKeysFromMap(pubKeyMap, readerPK, "leaderboard")
	if err != nil {
		return nil, fmt.Errorf("DBGetProfilesByUsernamePrefixAndDeSoLocked: %v", err)
	}

	var filteredProfileEntries []*lib.ProfileEntry
	for _, profileEntry := range profileEntries {
		_, found := filteredPubKeyMap[lib.MakePkMapKey(profileEntry.PublicKey)]
		if found {
			filteredProfileEntries = append(filteredProfileEntries, profileEntry)
		}
	}

	return filteredProfileEntries, nil
}

func _profileEntryToResponse(profileEntry *lib.ProfileEntry, params *lib.DeSoParams, verifiedUsernameMap map[string]*lib.PKID, utxoView *lib.UtxoView) *ProfileEntryResponse {
	if profileEntry == nil {
		return nil
	}

	coinPriceDeSoNanos := uint64(0)
	if profileEntry.CoinsInCirculationNanos != 0 {
		// The price formula is:
		// coinPriceDeSoNanos = DeSoLockedNanos / (CoinsInCirculationNanos * ReserveRatio) * NanosPerUnit
		bigNanosPerUnit := lib.NewFloat().SetUint64(lib.NanosPerUnit)
		coinPriceDeSoNanos, _ = lib.Mul(lib.Div(
			lib.Div(lib.NewFloat().SetUint64(profileEntry.DeSoLockedNanos), bigNanosPerUnit),
			lib.Mul(lib.Div(lib.NewFloat().SetUint64(profileEntry.CoinsInCirculationNanos), bigNanosPerUnit),
				params.CreatorCoinReserveRatio)), lib.NewFloat().SetUint64(lib.NanosPerUnit)).Uint64()
	}

	// TODO: Delete this and use global state for verifications once we move all usernames
	// out of reserved_usernames.go.
	isReserved := false
	isVerified := false
	lowercaseUsernameString := strings.ToLower(string(profileEntry.Username))
	if val, ok := lib.IsReserved[lowercaseUsernameString]; ok {
		isReserved = val
		// As a quick hack, we set the value in our IsReserved map to false when a profile is claimed.
		isVerified = !val
	}

	// Check global state for isVerified bool.
	if verifiedUsernameMap != nil && utxoView != nil {
		pkidEntry := utxoView.GetPKIDForPublicKey(profileEntry.PublicKey)
		verifiedUsernamePKID := verifiedUsernameMap[strings.ToLower(string(profileEntry.Username))]
		if verifiedUsernamePKID != nil {
			// TODO: Delete the "isVerified" or statement once we kell reserved_usernames.go.
			isVerified = (*verifiedUsernamePKID == *pkidEntry.PKID) || isVerified
		}
	}

	// Generate profile entry response
	profResponse := &ProfileEntryResponse{
		PublicKeyBase58Check: lib.PkToString(profileEntry.PublicKey, params),
		Username:             string(profileEntry.Username),
		Description:          string(profileEntry.Description),
		CoinEntry: &CoinEntryResponse{
			CreatorBasisPoints:      profileEntry.CoinEntry.CreatorBasisPoints,
			DeSoLockedNanos:         profileEntry.CoinEntry.DeSoLockedNanos,
			NumberOfHolders:         profileEntry.CoinEntry.NumberOfHolders,
			CoinsInCirculationNanos: profileEntry.CoinEntry.CoinsInCirculationNanos,
			CoinWatermarkNanos:      profileEntry.CoinEntry.CoinWatermarkNanos,
			BitCloutLockedNanos:     profileEntry.CoinEntry.DeSoLockedNanos,
		},
		CoinPriceDeSoNanos:     coinPriceDeSoNanos,
		CoinPriceBitCloutNanos: coinPriceDeSoNanos,
		IsHidden:               profileEntry.IsHidden,
		IsReserved:             isReserved,
		IsVerified:             isVerified,
	}

	return profResponse
}

func (fes *APIServer) augmentProfileEntry(
	profileEntry *lib.ProfileEntry,
	profileEntriesByPublicKey map[lib.PkMapKey]*lib.ProfileEntry,
	postsByProfilePublicKey map[lib.PkMapKey][]*lib.PostEntry,
	postEntryReaderStates map[lib.BlockHash]*lib.PostEntryReaderState,
	addGlobalFeedBool bool,
	verifiedMap map[string]*lib.PKID,
	utxoView *lib.UtxoView,
	readerPK []byte) *ProfileEntryResponse {

	profileEntryResponse := _profileEntryToResponse(profileEntry, fes.Params, verifiedMap, utxoView)

	// Attach the posts to the profile
	profilePostsFound := postsByProfilePublicKey[lib.MakePkMapKey(profileEntry.PublicKey)]
	for _, profilePostEntry := range profilePostsFound {
		profilePostRes, err := fes._postEntryToResponse(profilePostEntry, addGlobalFeedBool, fes.Params, utxoView, readerPK, 2)

		if err != nil {
			glog.Error(err)
			continue
		}

		// Attach reader state to each post.
		profilePostRes.PostEntryReaderState = postEntryReaderStates[*profilePostEntry.PostHash]

		profileEntryFound := profileEntriesByPublicKey[lib.MakePkMapKey(profilePostEntry.PosterPublicKey)]
		profilePostRes.ProfileEntryResponse = _profileEntryToResponse(
			profileEntryFound, fes.Params, verifiedMap, utxoView)
		if profilePostRes.IsHidden {
			// Don't show posts that this user has chosen to hide.
			continue
		}
		profileEntryResponse.Posts = append(profileEntryResponse.Posts, profilePostRes)
	}

	return profileEntryResponse
}

func (fes *APIServer) _getProfilePictureForPublicKey(publicKey []byte) ([]byte, string, error) {
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return []byte{}, "", fmt.Errorf("_getProfilePictureforPublicKey: Error getting utxoView: %v", err)
	}

	profileEntry := utxoView.GetProfileEntryForPublicKey(publicKey)
	if profileEntry == nil {
		return []byte{}, "", fmt.Errorf("_getProfilePictureForPublicKey: Profile not found")
	}
	profilePic := string(profileEntry.ProfilePic)
	if !strings.HasPrefix(profilePic, "data:image/") && !lib.ProfilePicRegex.Match([]byte(profilePic)) {
		return []byte{}, "", fmt.Errorf("_getProfilePictureForPublicKey: profile picture is not base64 encoded image")
	}
	contentTypeEnd := strings.Index(profilePic, ";base64")
	if contentTypeEnd < 6 {
		return []byte{}, "", fmt.Errorf("_getProfilePictureForPublicKey: cannot extract content type")
	}
	contentType := profilePic[5:contentTypeEnd]
	return profileEntry.ProfilePic, contentType, nil
}

func (fes *APIServer) GetSingleProfilePicture(ww http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	publicKeyBase58Check, publicKeyBase58CheckExists := vars["publicKeyBase58Check"]
	if !publicKeyBase58CheckExists {
		_AddBadRequestError(ww, fmt.Sprintf("GetSingleProfilePicture: Missing public key base 58 check"))
		return
	}
	publicKeyBytes, _, err := lib.Base58CheckDecode(publicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetSingleProfilePicture: Problem decoding user public key: %v", err))
		return
	}
	// Get the profile picture.
	profilePicture, contentType, err := fes._getProfilePictureForPublicKey(publicKeyBytes)
	if err != nil {
		// If we can't get the profile picture, we redirect to the fallback.
		fallbackRoute := req.URL.Query().Get("fallback")
		if fallbackRoute == "" {
			_AddNotFoundError(ww, fmt.Sprintf("GetSingleProfilePicture: Profile Picture not found: %v", err))
			return
		}
		http.Redirect(ww, req, fallbackRoute, http.StatusFound)
		return
	}

	profilePictureStr := string(profilePicture)
	decodedBytes, err := base64.StdEncoding.DecodeString(profilePictureStr[strings.Index(profilePictureStr, ";base64,")+8:])
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetSingleProfilePicture: Error decoding images bytes: %v", err))
		return
	}
	ww.Header().Set("Content-Type", contentType)
	ww.Header().Set("Content-Length", strconv.Itoa(len(decodedBytes)))
	if _, err = ww.Write(decodedBytes); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetSingleProfilePicture: Problem writing profile picture bytes: %v", err))
		return
	}
}

type GetSingleProfileRequest struct {
	// When set, we return profiles starting at the given pubkey up to numEntriesToReturn.
	PublicKeyBase58Check string `safeForLogging:"true"`
	// When set, we return profiles starting at the given username up to numEntriesToReturn.
	Username string `safeForLogging:"true"`
	// When true, we don't log a 404 for missing profiles
	NoErrorOnMissing bool `safeForLogging:"true"`
}

type GetSingleProfileResponse struct {
	Profile       *ProfileEntryResponse
	IsBlacklisted bool
	IsGraylisted  bool
}

// GetSingleProfile...
func (fes *APIServer) GetSingleProfile(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetSingleProfileRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetSingleProfile: Error parsing request body: %v", err))
		return
	}
	// Get a view
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetSingleProfile: Error getting utxoView: %v", err))
		return
	}

	// Get profile entry by public key.  If public key not provided, get profileEntry by username.
	var profileEntry *lib.ProfileEntry
	var publicKeyBytes []byte
	var publicKeyBase58Check string
	if requestData.PublicKeyBase58Check != "" {
		publicKeyBase58Check = requestData.PublicKeyBase58Check
		publicKeyBytes, _, err = lib.Base58CheckDecode(requestData.PublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetSingleProfile: Problem decoding user public key: %v", err))
			return
		}
		profileEntry = utxoView.GetProfileEntryForPublicKey(publicKeyBytes)
	} else {
		profileEntry = utxoView.GetProfileEntryForUsername([]byte(requestData.Username))
		if profileEntry != nil {
			publicKeyBytes = profileEntry.PublicKey
			publicKeyBase58Check = lib.Base58CheckEncode(publicKeyBytes, false, fes.Params)
		}
	}

	// Return an error if we failed to find a profile entry
	if profileEntry == nil {
		if (!requestData.NoErrorOnMissing) {
			_AddNotFoundError(ww, fmt.Sprintf("GetSingleProfile: could not find profile for username or public key: %v, %v", requestData.Username, requestData.PublicKeyBase58Check))
		}
		return
	}

	// Grab verified username map pointer
	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetSingleProfile: could not get verified map: %v", err))
		return
	}

	profileEntryResponse := _profileEntryToResponse(profileEntry, fes.Params, verifiedMap, utxoView)
	res := GetSingleProfileResponse{
		Profile: profileEntryResponse,
	}

	// Check if the user is blacklisted/graylisted
	blacklistKey := GlobalStateKeyForBlacklistedProfile(publicKeyBytes[:])
	userBlacklistState, err := fes.GlobalStateGet(blacklistKey)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetSingleProfile: Problem getting blacklist: %v", err))
		return
	}

	if reflect.DeepEqual(userBlacklistState, lib.IsBlacklisted) {
		res.IsBlacklisted = true
	}

	graylistKey := GlobalStateKeyForGraylistedProfile(publicKeyBytes[:])
	userGraylistState, err := fes.GlobalStateGet(graylistKey)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetSingleProfile: Problem getting graylist: %v", err))
		return
	}

	if reflect.DeepEqual(userGraylistState, lib.IsGraylisted) {
		res.IsGraylisted = true
	}

	var userMetadata *UserMetadata
	userMetadata, err = fes.getUserMetadataFromGlobalState(publicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetSingleProfile: error getting usermetadata for public key: %v", err))
		return
	}

	res.Profile.IsFeaturedTutorialUpAndComingCreator = userMetadata.IsFeaturedTutorialUpAndComingCreator
	res.Profile.IsFeaturedTutorialWellKnownCreator = userMetadata.IsFeaturedTutorialWellKnownCreator

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetSingleProfile: Problem serializing object to JSON: %v", err))
		return
	}
}

type GetHodlersForPublicKeyRequest struct {
	// Either PublicKeyBase58Check or Username can be set by the client to specify
	// which user we're obtaining posts for
	// If both are specified, PublicKeyBase58Check will supercede
	PublicKeyBase58Check string `safeForLogging:"true"`
	Username             string `safeForLogging:"true"`

	// Public Key of the last post from the previous page
	LastPublicKeyBase58Check string `safeForLogging:"true"`
	// Number of records to fetch
	NumToFetch uint64 `safeForLogging:"true"`

	// If true, fetch balance entries for your hodlings instead of balance entries for hodler's of your coin
	FetchHodlings bool

	// If true, fetch all hodlers/hodlings -- supercedes NumToFetch
	FetchAll bool
}

type GetHodlersForPublicKeyResponse struct {
	Hodlers                  []*BalanceEntryResponse
	LastPublicKeyBase58Check string
}

// Helper function to get the creator public key or the hodler public key depending upon fetchHodlings.
func getHodlerOrHodlingPublicKey(balanceEntryResponse *BalanceEntryResponse, fetchHodlings bool) (_publicKeyBase58Check string) {
	if fetchHodlings {
		return balanceEntryResponse.CreatorPublicKeyBase58Check
	} else {
		return balanceEntryResponse.HODLerPublicKeyBase58Check
	}
}

// GetHodlersForPublicKey... Get BalanceEntryResponses for hodlings.
func (fes *APIServer) GetHodlersForPublicKey(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetHodlersForPublicKeyRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetHodlersForPublicKey: Problem parsing request body: %v", err))
		return
	}

	// Get a view
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetHodlersForPublicKey: Error getting utxoView: %v", err))
		return
	}

	// Decode the public key for which we are fetching hodlers / hodlings.  If public key is not provided, use username
	var publicKeyBytes []byte
	if requestData.PublicKeyBase58Check != "" {
		publicKeyBytes, _, err = lib.Base58CheckDecode(requestData.PublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetHodlersForPublicKey: Problem decoding user public key: %v", err))
			return
		}
	} else {
		username := requestData.Username
		profileEntry := utxoView.GetProfileEntryForUsername([]byte(username))

		// Return an error if we failed to find a profile entry
		if profileEntry == nil {
			_AddNotFoundError(ww, fmt.Sprintf("GetHodlersForPublicKey: could not find profile for username: %v", username))
			return
		}
		publicKeyBytes = profileEntry.PublicKey
	}

	// Get the appropriate hodl map, convert to a slice, and order by balance.
	var hodlMap map[string]*BalanceEntryResponse
	hodlList := []*BalanceEntryResponse{}
	if requestData.FetchHodlings {
		hodlMap, err = fes.GetYouHodlMap(utxoView.GetPKIDForPublicKey(publicKeyBytes), false, utxoView)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetHodlersForPublicKey: error getting youHodlMap: %v", err))
			return
		}

	} else {
		hodlMap, err = fes.GetHodlYouMap(utxoView.GetPKIDForPublicKey(publicKeyBytes), false, utxoView)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetHodlersForPublicKey: error getting youHodlMap: %v", err))
			return
		}
	}
	for _, balanceEntryResponse := range hodlMap {
		hodlList = append(hodlList, balanceEntryResponse)
	}
	sort.Slice(hodlList, func(ii, jj int) bool {
		if hodlList[ii].CreatorPublicKeyBase58Check == hodlList[ii].HODLerPublicKeyBase58Check {
			return true
		}
		if hodlList[jj].CreatorPublicKeyBase58Check == hodlList[jj].HODLerPublicKeyBase58Check {
			return false
		}
		return hodlList[ii].BalanceNanos > hodlList[jj].BalanceNanos
	})
	if !requestData.FetchAll {
		numToFetch := int(requestData.NumToFetch)
		lastPublicKey := requestData.LastPublicKeyBase58Check
		// Take up to numToFetch.  If this is a request for a single post, it was selected by the utxo view.
		if len(hodlList) > numToFetch || lastPublicKey != "" {
			startIndex := 0
			if lastPublicKey != "" {
				// If we have a startPostHash, find it's index in the postEntries slice as the starting point
				for ii, balanceEntryResponse := range hodlList {
					if getHodlerOrHodlingPublicKey(balanceEntryResponse, requestData.FetchHodlings) == lastPublicKey {
						// Start the new slice from the post that comes after the startPostHash
						startIndex = ii + 1
						break
					}
				}
			}
			hodlList = hodlList[startIndex:lib.MinInt(startIndex+numToFetch, len(hodlList))]
		}
	}

	// Grab verified username map pointer
	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetHodlersForPublicKey: Error fetching verifiedMap: %v", err))
	}
	for _, balanceEntryResponse := range hodlList {
		publicKeyBase58Check := getHodlerOrHodlingPublicKey(balanceEntryResponse, requestData.FetchHodlings)

		profileEntry := utxoView.GetProfileEntryForPublicKey(lib.MustBase58CheckDecode(publicKeyBase58Check))
		if profileEntry != nil {
			balanceEntryResponse.ProfileEntryResponse = _profileEntryToResponse(
				profileEntry, fes.Params, verifiedMap, utxoView)
		}
	}
	// Return the last public key in this slice to simplify pagination.
	var resLastPublicKey string
	if len(hodlList) > 0 {
		resLastPublicKey = getHodlerOrHodlingPublicKey(hodlList[len(hodlList)-1], requestData.FetchHodlings)
	}
	res := &GetHodlersForPublicKeyResponse{
		Hodlers:                  hodlList,
		LastPublicKeyBase58Check: resLastPublicKey,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetHodlersForPublicKey: Problem encoding response as JSON: %v", err))
		return
	}
}

// A DiamondSenderSummaryResponse is a response struct that rolls up all diamonds
// received by a user from a single sender into a nice, simple summary struct.
type DiamondSenderSummaryResponse struct {
	SenderPublicKeyBase58Check   string
	ReceiverPublicKeyBase58Check string

	TotalDiamonds       uint64
	HighestDiamondLevel uint64

	DiamondLevelMap      map[uint64]uint64
	ProfileEntryResponse *ProfileEntryResponse
}

type GetDiamondsForPublicKeyRequest struct {
	// The user we are getting diamonds for.
	PublicKeyBase58Check string `safeForLogging:"true"`

	// If true, fetch the diamonds this public key gave out instead of the diamond this public key received
	FetchYouDiamonded bool
}

type GetDiamondsForPublicKeyResponse struct {
	DiamondSenderSummaryResponses []*DiamondSenderSummaryResponse
	TotalDiamonds                 uint64
}

func (fes *APIServer) GetDiamondsForPublicKey(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetDiamondsForPublicKeyRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetHodlersForPublicKey: Problem parsing request body: %v", err))
		return
	}

	// Get a view
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDiamondsForPublicKey: Error getting utxoView: %v", err))
		return
	}

	// Decode the public key for which we are fetching diamonds.
	publicKeyBytes, _, err := lib.Base58CheckDecode(requestData.PublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDiamondsForPublicKey: Problem decoding user public key: %v", err))
		return
	}

	// Get the DiamondEntries for this public key.
	pkidToDiamondEntriesMap, err := utxoView.GetDiamondEntryMapForPublicKey(publicKeyBytes, requestData.FetchYouDiamonded)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDiamondsForPublicKey: Problem getting diamond entries: %v", err))
		return
	}

	// Roll the DiamondEntries into summary responses.
	diamondSenderSummaryResponses := []*DiamondSenderSummaryResponse{}
	for pkidKeyIter, diamondEntryList := range pkidToDiamondEntriesMap {
		pkidKey := pkidKeyIter
		pubKey := utxoView.GetPublicKeyForPKID(&pkidKey)
		var receiverPubKey []byte
		var senderPubKey []byte
		if requestData.FetchYouDiamonded {
			receiverPubKey = pubKey
			senderPubKey = publicKeyBytes
		} else {
			receiverPubKey = publicKeyBytes
			senderPubKey = pubKey
		}
		diamondSenderSummary := &DiamondSenderSummaryResponse{
			SenderPublicKeyBase58Check:   lib.PkToString(senderPubKey, fes.Params),
			ReceiverPublicKeyBase58Check: lib.PkToString(receiverPubKey, fes.Params),
			DiamondLevelMap:              make(map[uint64]uint64),
		}
		for _, diamondEntry := range diamondEntryList {
			diamondLevel := uint64(diamondEntry.DiamondLevel)
			diamondSenderSummary.TotalDiamonds += diamondLevel
			if _, diamondLevelSeen := diamondSenderSummary.DiamondLevelMap[diamondLevel]; !diamondLevelSeen {
				diamondSenderSummary.DiamondLevelMap[diamondLevel] = 0
			}
			diamondSenderSummary.DiamondLevelMap[diamondLevel] += 1
			if diamondSenderSummary.HighestDiamondLevel < diamondLevel {
				diamondSenderSummary.HighestDiamondLevel = diamondLevel
			}
		}
		diamondSenderSummaryResponses = append(diamondSenderSummaryResponses, diamondSenderSummary)
	}

	// Grab verified username map pointer so we can verify the profiles.
	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetDiamondsForPublicKey: Error fetching verifiedMap: %v", err))
		return
	}
	totalDiamonds := uint64(0)
	for _, diamondSenderSummaryResponse := range diamondSenderSummaryResponses {
		var profilePK []byte
		if requestData.FetchYouDiamonded {
			profilePK = lib.MustBase58CheckDecode(diamondSenderSummaryResponse.ReceiverPublicKeyBase58Check)
		} else {
			profilePK = lib.MustBase58CheckDecode(diamondSenderSummaryResponse.SenderPublicKeyBase58Check)
		}
		profileEntry := utxoView.GetProfileEntryForPublicKey(profilePK)
		if profileEntry != nil {
			diamondSenderSummaryResponse.ProfileEntryResponse = _profileEntryToResponse(
				profileEntry, fes.Params, verifiedMap, utxoView)
		}
		totalDiamonds += diamondSenderSummaryResponse.TotalDiamonds
	}

	// Sort.
	sort.Slice(diamondSenderSummaryResponses, func(ii, jj int) bool {
		iiProfile := diamondSenderSummaryResponses[ii].ProfileEntryResponse
		jjProfile := diamondSenderSummaryResponses[jj].ProfileEntryResponse

		if iiProfile == nil && jjProfile == nil {
			return false
		}

		// If ii has a profile but jj doesn't, prioritize it.
		if iiProfile != nil && jjProfile == nil {
			return true
		}
		if jjProfile != nil && iiProfile == nil {
			return false
		}

		iiDeSoLocked := iiProfile.CoinEntry.DeSoLockedNanos
		jjDeSoLocked := jjProfile.CoinEntry.DeSoLockedNanos

		return iiDeSoLocked > jjDeSoLocked
	})

	res := &GetDiamondsForPublicKeyResponse{
		DiamondSenderSummaryResponses: diamondSenderSummaryResponses,
		TotalDiamonds:                 totalDiamonds,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetHodlersForPublicKey: Problem encoding response as JSON: %v", err))
		return
	}
}

// GetFollowsStatelessRequest ...
type GetFollowsStatelessRequest struct {
	// Either PublicKeyBase58Check or Username can be set by the client to specify
	// which user we're obtaining follows for
	// If both are specified, PublicKeyBase58Check will supercede
	PublicKeyBase58Check        string `safeForLogging:"true"`
	Username                    string `safeForLogging:"true"`
	GetEntriesFollowingUsername bool   `safeForLogging:"true"`

	// Public Key of the last follower / followee from the previous page
	LastPublicKeyBase58Check string `safeForLogging:"true"`
	// Number of records to fetch
	NumToFetch uint64 `safeForLogging:"true"`
}

// GetFollowsResponse ...
type GetFollowsResponse struct {
	PublicKeyToProfileEntry map[string]*ProfileEntryResponse `safeForLogging:"true"`
	NumFollowers            uint64
}

func (fes *APIServer) sortFollowEntries(followEntryPKIDii *lib.PKID, followEntryPKIDjj *lib.PKID, utxoView *lib.UtxoView, fetchValues bool) bool {
	followEntryPublicKeyii := utxoView.GetPublicKeyForPKID(followEntryPKIDii)
	followEntryPublicKeyjj := utxoView.GetPublicKeyForPKID(followEntryPKIDjj)
	// if we're fetching values, we want public keys that don't have profiles to be at the end.
	if fetchValues {
		profileEntryii := utxoView.GetProfileEntryForPublicKey(followEntryPublicKeyii)
		profileEntryjj := utxoView.GetProfileEntryForPublicKey(followEntryPublicKeyjj)
		// FollowEntries that have a profile should come before FollowEntries that do not have a profile.
		if profileEntryii == nil && profileEntryjj != nil {
			return false
		}
		if profileEntryjj == nil && profileEntryii != nil {
			return true
		}
		// If both FollowEntries have a profile, compare the two based on coin price.
		if profileEntryii != nil && profileEntryjj != nil {
			return profileEntryii.CoinEntry.DeSoLockedNanos > profileEntryjj.CoinEntry.DeSoLockedNanos
		}
	}
	// If we're not fetching values (meaning no profiles for public keys) or neither FollowEntry has a profile,
	// sort based on public key as a string.
	return lib.PkToString(followEntryPublicKeyii, fes.Params) < lib.PkToString(followEntryPublicKeyjj, fes.Params)
}

// Returns a map like {publicKey1: profileEntry1, publicKey2: profileEntry2, ...} for publicKeyBytes's
// followers / following
func (fes *APIServer) getPublicKeyToProfileEntryMapForFollows(publicKeyBytes []byte,
	getEntriesFollowingPublicKey bool, referenceUtxoView *lib.UtxoView,
	lastFollowPublicKeyBytes []byte, numToFetch uint64, fetchValues bool, fetchAllFollows bool) (
	_publicKeyToProfileEntry map[string]*ProfileEntryResponse, numFollowers uint64,
	_err error) {

	// Allow a reference view to be passed in. This speeds things up in the event we've already
	// created this view.
	var utxoView *lib.UtxoView
	var err error
	if referenceUtxoView != nil {
		utxoView = referenceUtxoView
	} else {
		utxoView, err = fes.backendServer.GetMempool().GetAugmentedUtxoViewForPublicKey(publicKeyBytes, nil)
		if err != nil {
			return nil, 0, errors.Wrapf(
				err, "getPublicKeyToProfileEntryMapForFollows: Error calling GetAugmentedUtxoViewForPublicKey: %v", err)
		}
	}

	followEntries := []*lib.FollowEntry{}
	followEntries, err = utxoView.GetFollowEntriesForPublicKey(publicKeyBytes, getEntriesFollowingPublicKey)

	if err != nil {
		return nil, 0, errors.Wrapf(
			err, "getPublicKeyToProfileEntryMapForFollows: Problem fetching FollowEntries from augmented UtxoView: ")
	}

	// If getEntriesFollowingUsername is set to true, this will be a map of
	//   {followerPubKey => ProfileEntryResponse}
	//
	// If getEntriesFollowingUsername is not set or set to false, this will be a map of
	//   {followedPubKey => ProfileEntryResponse}
	//
	// Sorry this is confusing
	publicKeyToProfileEntry := make(map[string]*ProfileEntryResponse)

	// Grab verified username map pointer
	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
	if err != nil {
		return nil, 0, errors.Wrapf(
			err, "getPublicKeyToProfileEntryMapForFollows: Problem fetching verifiedMap: ")
	}

	// We only need to sort if we are fetching values.  When we do not fetch values, we are getting all public keys and
	// their ordering doesn't mean anything.  Currently, fetchValues is only false for GetUsersStateless calls for which
	// we only care about getting an unordered list of public keys a user is following.
	if fetchValues {
		// Sort the follow entries for pagination purposes
		if getEntriesFollowingPublicKey {
			sort.Slice(followEntries, func(ii, jj int) bool {
				return fes.sortFollowEntries(followEntries[ii].FollowerPKID, followEntries[jj].FollowerPKID, utxoView, fetchValues)
			})
		} else {
			sort.Slice(followEntries, func(ii, jj int) bool {
				return fes.sortFollowEntries(followEntries[ii].FollowedPKID, followEntries[jj].FollowedPKID, utxoView, fetchValues)
			})
		}
	}

	// Track whether we've hit the start of the page.
	lastFollowKeySeen := false
	if lastFollowPublicKeyBytes == nil {
		// If we don't have a last follow public key, we are starting from the beginning.
		lastFollowKeySeen = true
	}

	for _, followEntry := range followEntries {
		// get the profile entry for each follower pubkey
		var followPKID *lib.PKID
		if getEntriesFollowingPublicKey {
			followPKID = followEntry.FollowerPKID
		} else {
			followPKID = followEntry.FollowedPKID
		}
		// Convert the followPKID to a public key using the view. The followPubKey should never
		// be nil.
		followPubKey := utxoView.GetPublicKeyForPKID(followPKID)
		// If we haven't seen the public key of the last followEntry from the previous page, skip ahead.
		if !lastFollowKeySeen {
			if reflect.DeepEqual(lastFollowPublicKeyBytes, followPubKey) {
				lastFollowKeySeen = true
			}
			continue
		}

		var followProfileEntry *ProfileEntryResponse
		if fetchValues {
			followProfileEntry = _profileEntryToResponse(
				utxoView.GetProfileEntryForPublicKey(followPubKey), fes.Params, verifiedMap, utxoView)
		}
		followPubKeyBase58Check := lib.PkToString(followPubKey, fes.Params)
		publicKeyToProfileEntry[followPubKeyBase58Check] = followProfileEntry

		// If we've fetched enough followers and we're not fetching all followers, break.
		if uint64(len(publicKeyToProfileEntry)) >= numToFetch && !fetchAllFollows {
			break
		}
	}
	return publicKeyToProfileEntry, uint64(len(followEntries)), nil
}

// GetFollowsStateless ...
// Equivalent to the following REST endpoints:
//   - GET /:username/followers
//   - GET /:username/following
func (fes *APIServer) GetFollowsStateless(ww http.ResponseWriter, rr *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(rr.Body, MaxRequestBodySizeBytes))
	getFollowsRequest := GetFollowsStatelessRequest{}
	if err := decoder.Decode(&getFollowsRequest); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetFollowsStateless: Error parsing request body: %v", err))
		return
	}

	// Get a view
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetFollowsStateless Error getting view: %v", err))
		return
	}

	var publicKeyBytes []byte
	if getFollowsRequest.PublicKeyBase58Check != "" {
		publicKeyBytes, _, err = lib.Base58CheckDecode(getFollowsRequest.PublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetFollowsStateless: Problem decoding user public key: %v", err))
			return
		}
	} else {
		username := getFollowsRequest.Username
		profileEntry := utxoView.GetProfileEntryForUsername([]byte(username))

		// Return an error if we failed to find a profile entry
		if profileEntry == nil {
			_AddNotFoundError(ww, fmt.Sprintf("GetFollowsStateless: could not find profile for username: %v", username))
			return
		}

		publicKeyBytes = profileEntry.PublicKey
	}

	var lastPublicKeySeenBytes []byte
	if getFollowsRequest.LastPublicKeyBase58Check != "" {
		lastPublicKeySeenBytes, _, err = lib.Base58CheckDecode(getFollowsRequest.LastPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetFollowsStateless: Problem decoding last public key seen: %v", err))
			return
		}
	}

	publicKeyToProfileEntry, numFollowers, err := fes.getPublicKeyToProfileEntryMapForFollows(
		publicKeyBytes,
		getFollowsRequest.GetEntriesFollowingUsername,
		utxoView,
		lastPublicKeySeenBytes,
		getFollowsRequest.NumToFetch, true, false)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetFollowsStateless: Problem fetching and decrypting follows: %v", err))
		return
	}

	res := GetFollowsResponse{
		PublicKeyToProfileEntry: publicKeyToProfileEntry,
		NumFollowers:            numFollowers,
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetFollows: Problem serializing object to JSON: %v", err))
		return
	}
}

// GetUserGlobalMetadataRequest...
type GetUserGlobalMetadataRequest struct {
	// The public key of the user who is trying to update their metadata.
	UserPublicKeyBase58Check string `safeForLogging:"true"`

	// JWT token authenticates the user
	JWT string
}

// GetUserGlobalMetadataResponse ...
type GetUserGlobalMetadataResponse struct {
	Email       string
	PhoneNumber string
}

// GetUserGlobalMetadata ...
// Allows a user to change the global metadata for a public key, if they prove ownership.
func (fes *APIServer) GetUserGlobalMetadata(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetUserGlobalMetadataRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetUserGlobalMetadata: Problem parsing request body: %v", err))
		return
	}

	if requestData.UserPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprintf("GetUserGlobalMetadataRequest: Must provide a valid public key."))
		return
	}

	// Validate their permissions
	isValid, err := fes.ValidateJWT(requestData.UserPublicKeyBase58Check, requestData.JWT)
	if !isValid {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateUserGlobalMetadataRequest: Invalid token: %v", err))
		return
	}

	userPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.UserPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateUserGlobalMetadataRequest: Invalid public key: %v", err))
		return
	}

	// Now that we have a public key, update get the global state object.
	userMetadata, err := fes.getUserMetadataFromGlobalState(lib.PkToString(userPublicKeyBytes, fes.Params))
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetUserGlobalMetadata: Problem getting metadata from global state: %v", err))
		return
	}

	// If we made it this far we were successful, return email and password.
	res := GetUserGlobalMetadataResponse{
		Email:       userMetadata.Email,
		PhoneNumber: userMetadata.PhoneNumber,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetUserGlobalMetadata: Problem encoding response as JSON: %v", err))
		return
	}
}

// UpdateUserGlobalMetadataRequest...
type UpdateUserGlobalMetadataRequest struct {
	// The public key of the user who is trying to update their metadata.
	UserPublicKeyBase58Check string `safeForLogging:"true"`

	// JWT token authenticates the user
	JWT string

	// User's email for receiving notifications.
	Email string

	// A map of ContactPublicKeyBase58Check keys and number of read messages int values.
	MessageReadStateUpdatesByContact map[string]int
}

// UpdateUserGlobalMetadataResponse ...
type UpdateUserGlobalMetadataResponse struct{}

// UpdateUserGlobalMetadata ...
// Allows a user to change the global metadata for a public key, if they prove ownership.
func (fes *APIServer) UpdateUserGlobalMetadata(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := UpdateUserGlobalMetadataRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateUserGlobalMetadata: Problem parsing request body: %v", err))
		return
	}

	if requestData.UserPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateUserGlobalMetadataRequest: Must provide a valid public key."))
		return
	}

	if requestData.Email == "" && requestData.MessageReadStateUpdatesByContact == nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateUserGlobalMetadataRequest: Must provide something to update."))
		return
	}

	// Validate their permissions
	isValid, err := fes.ValidateJWT(requestData.UserPublicKeyBase58Check, requestData.JWT)
	if !isValid {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateUserGlobalMetadataRequest: Invalid token: %v", err))
		return
	}

	userPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.UserPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateUserGlobalMetadataRequest: Invalid public key: %v", err))
		return
	}

	// Now that we have a public key, update the global state object.
	userMetadata, err := fes.getUserMetadataFromGlobalState(lib.PkToString(userPublicKeyBytes, fes.Params))
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateUserGlobalMetadata: Problem with getUserMetadataFromGlobalState: %v", err))
		return
	}

	// Now that we have a userMetadata object, update it based on the request.
	if requestData.Email != "" {
		// Send verification email if email changed
		if userMetadata.Email != requestData.Email {
			fes.sendVerificationEmail(requestData.Email, requestData.UserPublicKeyBase58Check)
			userMetadata.EmailVerified = false
		}

		userMetadata.Email = requestData.Email
	}

	if requestData.MessageReadStateUpdatesByContact != nil {
		if userMetadata.MessageReadStateByContact == nil {
			userMetadata.MessageReadStateByContact = make(map[string]int)
		}
		for contactPubKey, readMessageCount := range requestData.MessageReadStateUpdatesByContact {
			userMetadata.MessageReadStateByContact[contactPubKey] = readMessageCount
		}
	}

	// Stick userMetadata back into global state object.
	err = fes.putUserMetadataInGlobalState(userMetadata)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateUserGlobalMetadata: Problem putting updated user metadata: %v", err))
		return
	}

	// If we made it this far we were successful, return without error.
	res := UpdateUserGlobalMetadataResponse{}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateUserGlobalMetadata: Problem encoding response as JSON: %v", err))
		return
	}
}

type GetNotificationsRequest struct {
	// This is the index of the notification we want to start our paginated lookup at. We
	// will fetch up to "NumToFetch" notifications after it, ordered by index.  If no
	// index is provided we will return the most recent posts.
	PublicKeyBase58Check string
	FetchStartIndex      int64
	NumToFetch           int64
}

type GetNotificationsResponse struct {
	Notifications       []*TransactionMetadataResponse
	ProfilesByPublicKey map[string]*ProfileEntryResponse
	PostsByHash         map[string]*PostEntryResponse
}

func (fes *APIServer) GetNotifications(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetNotificationsRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetNotifications: Problem parsing request body: %v", err))
		return
	}
	finalTxnMetadataList, utxoView, err := fes._getNotifications(&requestData)
	if err != nil {
		_AddBadRequestError(ww, err.Error())
		return
	}

	var userPublicKeyBytes []byte
	userPublicKeyBytes, _, err = lib.Base58CheckDecode(requestData.PublicKeyBase58Check)
	if err != nil || len(userPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetNotifications: Problem decoding updater public key %s: %v",
			requestData.PublicKeyBase58Check, err))
		return
	}

	// Grab verified username map pointer
	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
	if err != nil {
		APIAddError(ww, err.Error())
		return
	}

	// At this point, finalTxnMetadata contains the proper list of transactions that we
	// want to notify the user about. In order to help the UI display this information,
	// we fetch a profile for each public key in each transaction that we're going to return
	// and include it in a map.
	profileEntryResponses := make(map[string]*ProfileEntryResponse)
	// Set up a view to fetch the ProfileEntrys from
	addProfileForPubKey := func(publicKeyBase58Check string) error {
		currentPkBytes, _, err := lib.Base58CheckDecode(publicKeyBase58Check)
		if err != nil {
			return errors.Errorf("GetNotifications: "+
				"Error decoding public key in txn metadata: %v",
				publicKeyBase58Check)
		}

		// Note we are recycling the UtxoView from previously.
		// Note also that if we didn't need to use the mempool to fetch notifications
		// then we won't have loaded any of the mempool transactions into the view, and
		// so the profile information could be out of date.
		profileEntry := utxoView.GetProfileEntryForPublicKey(currentPkBytes)
		if profileEntry != nil {
			profileEntryResponses[lib.PkToString(profileEntry.PublicKey, fes.Params)] =
				_profileEntryToResponse(profileEntry, fes.Params, verifiedMap, utxoView)
		}
		return nil
	}
	for _, txnMeta := range finalTxnMetadataList {
		if err := addProfileForPubKey(txnMeta.Metadata.TransactorPublicKeyBase58Check); err != nil {
			APIAddError(ww, err.Error())
			return
		}

		for _, affectedPk := range txnMeta.Metadata.AffectedPublicKeys {
			if err := addProfileForPubKey(affectedPk.PublicKeyBase58Check); err != nil {
				APIAddError(ww, err.Error())
				return
			}
		}
	}

	// To help the UI we fetch all posts that were involved in any notification
	// and index them by PostHashHex. This includes posts that were liked,
	// posts that mentioned us, or posts that replied to us.
	//
	// We also embed the ProfileEntryResponse of the poster in the post.
	// In the future we could de-duplicate this and make the frontend do more
	// heavy lifting.
	postEntryResponses := make(map[string]*PostEntryResponse)

	addPostForHash := func(postHashHex string, readerPK []byte) {
		postHashBytes, err := hex.DecodeString(postHashHex)
		if err != nil || len(postHashBytes) != lib.HashSizeBytes {
			return
		}
		postHash := &lib.BlockHash{}
		copy(postHash[:], postHashBytes)

		postEntry := utxoView.GetPostEntryForPostHash(postHash)
		if postEntry == nil {
			return
		}
		postEntryResponse, err := fes._postEntryToResponse(postEntry, false, fes.Params, utxoView, userPublicKeyBytes, 2)
		if err != nil {
			return
		}

		postEntryResponse.ProfileEntryResponse = profileEntryResponses[lib.PkToString(postEntry.PosterPublicKey, fes.Params)]
		if postEntryResponse.ProfileEntryResponse == nil {
			return
		}

		postEntryResponse.PostEntryReaderState = utxoView.GetPostEntryReaderState(readerPK, postEntry)

		postEntryResponses[postHashHex] = postEntryResponse
	}

	for _, txnMeta := range finalTxnMetadataList {
		postMetadata := txnMeta.Metadata.SubmitPostTxindexMetadata
		likeMetadata := txnMeta.Metadata.LikeTxindexMetadata
		transferCreatorCoinMetadata := txnMeta.Metadata.CreatorCoinTransferTxindexMetadata
		nftBidMetadata := txnMeta.Metadata.NFTBidTxindexMetadata
		acceptNFTBidMetadata := txnMeta.Metadata.AcceptNFTBidTxindexMetadata
		basicTransferMetadata := txnMeta.Metadata.BasicTransferTxindexMetadata

		if postMetadata != nil {
			addPostForHash(postMetadata.PostHashBeingModifiedHex, userPublicKeyBytes)
			addPostForHash(postMetadata.ParentPostHashHex, userPublicKeyBytes)
		} else if likeMetadata != nil {
			addPostForHash(likeMetadata.PostHashHex, userPublicKeyBytes)
		} else if transferCreatorCoinMetadata != nil {
			if transferCreatorCoinMetadata.PostHashHex != "" {
				addPostForHash(transferCreatorCoinMetadata.PostHashHex, userPublicKeyBytes)
			}
		} else if nftBidMetadata != nil {
			addPostForHash(nftBidMetadata.NFTPostHashHex, userPublicKeyBytes)
		} else if acceptNFTBidMetadata != nil {
			addPostForHash(acceptNFTBidMetadata.NFTPostHashHex, userPublicKeyBytes)
		} else if basicTransferMetadata != nil {
			txnOutputs := txnMeta.Metadata.TxnOutputs
			for _, output := range txnOutputs {
				txnMeta.TxnOutputResponses = append(
					txnMeta.TxnOutputResponses,
					&OutputResponse{
						PublicKeyBase58Check: lib.PkToString(output.PublicKey, fes.Params),
						AmountNanos:          output.AmountNanos,
					})
			}
			if basicTransferMetadata.PostHashHex != "" {
				addPostForHash(basicTransferMetadata.PostHashHex, userPublicKeyBytes)
			}
		}
	}

	// save the most recent notification into global state so we know
	// if we have any unread notifications later
	//
	// only try to update the index if we're requesting the first page of results
	// and we have at least one notification
	if requestData.FetchStartIndex < 0 && len(finalTxnMetadataList) > 0 {
		// global state does not have good support for concurrency. if someone
		// else fetches this user's data and writes at the same time we could
		// overwrite each other. there's a task in jira to investigate concurrency
		// issues with global state.
		userMetadata, err := fes.getUserMetadataFromGlobalState(lib.PkToString(userPublicKeyBytes, fes.Params))
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"GetNotifications: Problem getting metadata from global state: %v", err))
			return
		}

		// only update the index if it's greater than the current index we have stored
		lastSeenIndex := finalTxnMetadataList[0].Index
		if lastSeenIndex > userMetadata.NotificationLastSeenIndex {
			userMetadata.NotificationLastSeenIndex = lastSeenIndex

			// Place the update metadata into the global state
			err = fes.putUserMetadataInGlobalState(userMetadata)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf(
					"GetNotifications: Problem putting updated user metadata: %v", err))
				return
			}
		}
	}

	// At this point, we should have all the profiles and all the notifications
	// that the user requested so return them in the response.
	res := &GetNotificationsResponse{
		Notifications:       finalTxnMetadataList,
		ProfilesByPublicKey: profileEntryResponses,
		PostsByHash:         postEntryResponses,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetNotifications: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) _getNotifications(request *GetNotificationsRequest) ([]*TransactionMetadataResponse, *lib.UtxoView, error) {
	// If the TxIndex flag was not passed to this node then we can't compute
	// notifications.
	if fes.TXIndex == nil {
		return nil, nil, errors.Errorf(
			"GetNotifications: Cannot be called when TXIndexChain " +
				"is nil. This error occurs when --txindex was not passed to the program " +
				"on startup")
	}

	pkBytes, _, err := lib.Base58CheckDecode(request.PublicKeyBase58Check)
	if err != nil {
		return nil, nil, errors.Errorf("GetNotifications: Problem parsing public key: %v", err)
	}

	blockedPubKeys, err := fes.GetBlockedPubKeysForUser(pkBytes)
	if err != nil {
		return nil, nil, errors.Errorf("GetNotifications: Error getting blocked public keys for user: %v", err)
	}

	// A valid mempool object is used to compute the TransactionMetadata for the mempool
	// and to allow for things like: filtering notifications for a hidden post.
	utxoView, err := fes.mempool.GetAugmentedUniversalView()
	if err != nil {
		return nil, nil, errors.Errorf("GetNotifications: Problem getting view: %v", err)
	}

	// Iterate backward over the database to find as many keys as we can.
	//
	// Start by constructing the validForPrefix. It's just the public key.
	validForPrefix := lib.DbTxindexPublicKeyPrefix(pkBytes)
	// If FetchStartIndex is specified then the startPrefix is the public key
	// with FetchStartIndex appended. Otherwise, we leave off the index so that
	// the seek will start from the end of the transaction list.
	startPrefix := lib.DbTxindexPublicKeyPrefix(pkBytes)
	if request.FetchStartIndex >= 0 {
		startPrefix = lib.DbTxindexPublicKeyIndexToTxnKey(pkBytes, uint32(request.FetchStartIndex))
	}
	// The maximum key length is the length of the key with the public key
	// plus the size of the uint64 appended to it.
	maxKeyLen := len(lib.DbTxindexPublicKeyIndexToTxnKey(pkBytes, uint32(0)))

	// txnMetadataFound will contain TransactionMetadata objects, with the newest txns
	// showing up at the beginning of the list.
	dbTxnMetadataFound := []*TransactionMetadataResponse{}
	// Note that we are always guaranteed to hit one of the stopping conditions defined at
	// the end of this loop.
	for {
		keysFound, valsFound, err := lib.DBGetPaginatedKeysAndValuesForPrefix(
			fes.TXIndex.TXIndexChain.DB(), startPrefix, validForPrefix,
			maxKeyLen, int(request.NumToFetch), true, /*reverse*/
			true /*fetchValues*/)
		if err != nil {
			return nil, nil, errors.Errorf(
				"GetNotifications: Error fetching paginated TransactionMetadata for notifications: %v", err)
		}

		for ii, txIDBytes := range valsFound {
			txID := &lib.BlockHash{}
			copy(txID[:], txIDBytes)

			// In this case we need to look up the full transaction and convert
			// it into a proper transaction response.
			txnMeta := lib.DbGetTxindexTransactionRefByTxID(fes.TXIndex.TXIndexChain.DB(), txID)
			if txnMeta == nil {
				// We should never be missing a transaction for a given txid, but
				// just continue in this case.
				glog.Errorf("GetNotifications: Missing TransactionMetadata for txid %v", txID)
				continue
			}
			// Skip transactions that aren't notifications
			if !TxnMetaIsNotification(txnMeta, request.PublicKeyBase58Check, utxoView) {
				continue
			}
			transactorPkBytes, _, err := lib.Base58CheckDecode(txnMeta.TransactorPublicKeyBase58Check)
			if err != nil {
				glog.Errorf("GetNotifications: unable to decode public key %v", txnMeta.TransactorPublicKeyBase58Check)
				continue
			}
			// Skip transactions from blocked users.
			if _, ok := blockedPubKeys[lib.PkToString(transactorPkBytes, fes.Params)]; ok {
				continue
			}
			currentIndexBytes := keysFound[ii][len(lib.DbTxindexPublicKeyPrefix(pkBytes)):]
			res := &TransactionMetadataResponse{
				Metadata: txnMeta,
				Index:    int64(lib.DecodeUint32(currentIndexBytes)),
			}
			dbTxnMetadataFound = append(dbTxnMetadataFound, res)
		}

		// If we've found enough transactions then break.
		if len(dbTxnMetadataFound) >= int(request.NumToFetch) {
			dbTxnMetadataFound = dbTxnMetadataFound[:request.NumToFetch]
			break
		}

		// If we didn't find any keys then we're done here.
		if len(keysFound) == 0 {
			break
		}

		// If we get here then we have at least one key.
		// If the index of the last key we found is the zero index then we're done here.
		lastKey := keysFound[len(keysFound)-1]
		// The index comes after the <_Prefix, PublicKey> bytes.
		lastKeyIndexBytes := lastKey[len(lib.DbTxindexPublicKeyPrefix(pkBytes)):]
		lastKeyIndex := lib.DecodeUint32(lastKeyIndexBytes)
		if lastKeyIndex == 0 {
			break
		}

		// If we get here it means that we don't have enough transactions yet *and*
		// there are more keys to seek. It also means that the lastKeyIndex > 0. So
		// update the startPrefix to place it right after the index of the last key.
		startPrefix = lib.DbTxindexPublicKeyIndexToTxnKey(
			pkBytes, uint32(lastKeyIndex-1))
	}

	// Get the NextIndex from the db. This will be used to determine whether
	// or not it's appropriate to fetch txns from the mempool. It will also be
	// used to assign consistent index values to memppool txns.
	NextIndexVal := lib.DbGetTxindexNextIndexForPublicKey(fes.TXIndex.TXIndexChain.DB(), pkBytes)
	if NextIndexVal == nil {
		return nil, nil, fmt.Errorf("Unable to get next index for public key: %v", request.PublicKeyBase58Check)
	}
	NextIndex := int64(*NextIndexVal)
	// If the FetchStartIndex is unset *or* if it's set to a value that is larger
	// than what we have in the db then it means we need to augment our list with
	// txns from the mempool.
	combinedMempoolDBTxnMetadata := []*TransactionMetadataResponse{}
	if request.FetchStartIndex < 0 || request.FetchStartIndex >= NextIndex {
		// At this point we should have zero or more TransactionMetadata objects from
		// the database that could trigger a notification for the user.
		//
		// Create a new list of events from the mempool and augment the list we found
		// from the database with these transactions.
		//
		// Get all the txns from the mempool.
		//
		// TODO(performance): This could get slow if the mempool gets big. Fix is to organize everything
		// in the mempool by public key and only look up transactions that are relevant to this public key.
		poolTxns, _, err := fes.mempool.GetTransactionsOrderedByTimeAdded()
		if err != nil {
			return nil, nil, errors.Errorf("APITransactionInfo: Error getting txns from mempool: %v", err)
		}

		mempoolTxnMetadata := []*TransactionMetadataResponse{}
		for _, poolTx := range poolTxns {
			txnMeta := poolTx.TxMeta
			if txnMeta == nil {
				continue
			}

			// Set the current index we will use to identify this transaction.
			currentIndex := NextIndex

			// Increment the NextIndex if this transaction is associated with the user's
			// public key in any way. This is what the db would do when storing it, and so
			// this treatment should be consistent.
			if TxnIsAssociatedWithPublicKey(txnMeta, request.PublicKeyBase58Check) {
				NextIndex++
			}

			// If the transaction is a notification then add it to our list with the proper
			// index value if the transactor is not a blocked public key
			if TxnMetaIsNotification(txnMeta, request.PublicKeyBase58Check, utxoView) {
				transactorPkBytes, _, err := lib.Base58CheckDecode(txnMeta.TransactorPublicKeyBase58Check)
				if err != nil {
					glog.Errorf("GetNotifications: unable to decode public key %v", txnMeta.TransactorPublicKeyBase58Check)
					continue
				}

				// Skip transactions from blocked users.
				if _, ok := blockedPubKeys[lib.PkToString(transactorPkBytes, fes.Params)]; ok {
					continue
				}
				mempoolTxnMetadata = append(mempoolTxnMetadata, &TransactionMetadataResponse{
					Metadata: txnMeta,
					Index:    currentIndex,
				})
			}

			// TODO: Commenting this out for now because it causes incorrect behavior
			// in the event the user is asking to fetch the *latest* notifications via
			// a StartIndex < 0 where NumToFetch is less than the number of mempool txns.
			//
			// If we've found enough notification objects then break out.
			//if len(mempoolTxnMetadata) >= int(requestData.NumToFetch) {
			//	mempoolTxnMetadata = mempoolTxnMetadata[:requestData.NumToFetch]
			//	break
			//}
		}

		// Since the mempool transactions are ordered with the oldest transaction first,
		// we need to reverse them. Add them to the combinedMempoolDBTxnMetadata as we go.
		for ii := range mempoolTxnMetadata {
			currentMempoolTxnMetadata := mempoolTxnMetadata[len(mempoolTxnMetadata)-1-ii]
			combinedMempoolDBTxnMetadata = append(combinedMempoolDBTxnMetadata, currentMempoolTxnMetadata)
		}
	}

	// At this point, the combinedMempoolDBTxnMetadata either contains the latest transactions
	// from the mempool *or* it's empty. The latter occurs when the FetchStartIndex
	// is set to a value below the smallest index of any transaction in the mempool.
	// In either case, appending the transactions we found in the db is the correct
	// thing to do.
	combinedMempoolDBTxnMetadata = append(combinedMempoolDBTxnMetadata, dbTxnMetadataFound...)

	// If a start index was set, then only consider transactions whose indes is <=
	// this start index. This loop also enforces the final NumToFetch constraint.
	finalTxnMetadataList := []*TransactionMetadataResponse{}
	if request.FetchStartIndex >= 0 {
		for _, txnMeta := range combinedMempoolDBTxnMetadata {
			if txnMeta.Index <= request.FetchStartIndex {
				finalTxnMetadataList = append(finalTxnMetadataList, txnMeta)
			}

			if len(finalTxnMetadataList) >= int(request.NumToFetch) {
				break
			}
		}
	} else {
		// In this case, no start index is set and so we just return NumToFetch
		// txns from the combined list starting at the beginning, which holds the
		// latest txns.
		finalTxnMetadataList = combinedMempoolDBTxnMetadata
		if len(finalTxnMetadataList) > int(request.NumToFetch) {
			finalTxnMetadataList = finalTxnMetadataList[:request.NumToFetch]
		}
	}

	return finalTxnMetadataList, utxoView, nil
}

func TxnMetaIsNotification(txnMeta *lib.TransactionMetadata, publicKeyBase58Check string, utxoView *lib.UtxoView) bool {
	// Transactions initiated by the passed-in public key should not
	// trigger notifications.
	if txnMeta.TransactorPublicKeyBase58Check == publicKeyBase58Check {
		return false
	}

	// Transactions where the user's public key is not affected should not trigger
	// notifications.
	publicKeyIsAffected := false
	for _, affectedObj := range txnMeta.AffectedPublicKeys {
		if affectedObj.PublicKeyBase58Check == publicKeyBase58Check {
			publicKeyIsAffected = true
			break
		}
	}
	if !publicKeyIsAffected {
		return false
	}

	// If we get here, we know the user did not initiate the transaction and
	// we know that the user is affected by the transaction.
	//
	// Whitelist particular types of transactions for notification triggering.
	if txnMeta.FollowTxindexMetadata != nil {
		// Someone followed you. Don't include unfollows
		return !txnMeta.FollowTxindexMetadata.IsUnfollow
	} else if txnMeta.LikeTxindexMetadata != nil {
		// Someone liked a post/comment from you. Don't include unlikes
		return !txnMeta.LikeTxindexMetadata.IsUnlike
	} else if txnMeta.SubmitPostTxindexMetadata != nil {
		notificationPostHash, err := GetPostHashFromPostHashHex(txnMeta.SubmitPostTxindexMetadata.PostHashBeingModifiedHex)
		if err != nil {
			// If this post hash isn't valid, we don't need a notification.
			return false
		}
		notificationPostEntry := utxoView.GetPostEntryForPostHash(notificationPostHash)
		if notificationPostEntry == nil {
			// If this post entry doesn't exist, we don't need a notification.
			return false
		}

		// Someone commented on your post.  Notify, if it isn't hidden.
		return !notificationPostEntry.IsHidden
	} else if txnMeta.CreatorCoinTxindexMetadata != nil {
		// Someone bought your coin
		return txnMeta.CreatorCoinTxindexMetadata.OperationType == "buy"
	} else if txnMeta.CreatorCoinTransferTxindexMetadata != nil {
		// Someone transferred you creator coins
		return true
	} else if txnMeta.BitcoinExchangeTxindexMetadata != nil {
		// You got some DeSo from a BitcoinExchange txn
		return true
	} else if txnMeta.NFTBidTxindexMetadata != nil {
		// Someone bid on your NFT
		return true
	} else if txnMeta.AcceptNFTBidTxindexMetadata != nil {
		// Someone accepted your bid for an NFT
		return true
	} else if txnMeta.TxnType == lib.TxnTypeBasicTransfer.String() {
		// Someone paid you
		return true
	}

	return false
}

func TxnIsAssociatedWithPublicKey(txnMeta *lib.TransactionMetadata, publicKeyBase58Check string) bool {
	if txnMeta.TransactorPublicKeyBase58Check == publicKeyBase58Check {
		return true
	}
	for _, affectedObj := range txnMeta.AffectedPublicKeys {
		if affectedObj.PublicKeyBase58Check == publicKeyBase58Check {
			return true
		}
	}
	return false
}

type TransactionMetadataResponse struct {
	Metadata           *lib.TransactionMetadata
	TxnOutputResponses []*OutputResponse
	Txn                *TransactionResponse
	Index              int64
}

type BlockPublicKeyRequest struct {
	PublicKeyBase58Check      string
	BlockPublicKeyBase58Check string
	Unblock                   bool
	JWT                       string
}

type BlockPublicKeyResponse struct {
	BlockedPublicKeys map[string]struct{}
}

// This endpoint is used for blocking and unblocking users.  A boolean flag Unblock is passed to indicate whether
// a user should be blocked or unblocked.
func (fes *APIServer) BlockPublicKey(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := BlockPublicKeyRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"BlockPublicKey: Problem parsing request body: %v", err))
		return
	}

	var userPublicKeyBytes []byte
	var err error
	userPublicKeyBytes, _, err = lib.Base58CheckDecode(requestData.PublicKeyBase58Check)
	if err != nil || len(userPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		_AddBadRequestError(ww, fmt.Sprintf(
			"BlockPublicKey: Problem decoding user public key %s: %v",
			requestData.PublicKeyBase58Check, err))
		return
	}

	// Validate their permissions
	isValid, err := fes.ValidateJWT(requestData.PublicKeyBase58Check, requestData.JWT)
	if !isValid {
		_AddBadRequestError(ww, fmt.Sprintf("BlockPublicKey: Invalid token: %v", err))
		return
	}

	// Get the public key for the user that is being blocked / unblocked.
	var blockPublicKeyBytes []byte
	blockPublicKeyBytes, _, err = lib.Base58CheckDecode(requestData.BlockPublicKeyBase58Check)
	if err != nil || len(blockPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		_AddBadRequestError(ww, fmt.Sprintf(
			"BlockPublicKey: Problem decoding public key to block %s: %v",
			requestData.BlockPublicKeyBase58Check, err))
		return
	}

	userMetadata, err := fes.getUserMetadataFromGlobalState(requestData.PublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("BlockPublicKey: Problem with getUserMetadataFromGlobalState: %v", err))
		return
	}
	blockPublicKeyString := lib.PkToString(blockPublicKeyBytes, fes.Params)

	blockedPublicKeys := userMetadata.BlockedPublicKeys
	if blockedPublicKeys == nil {
		blockedPublicKeys = make(map[string]struct{})
	}
	// Check if the user is already blocked by the reader.
	_, keyExists := blockedPublicKeys[blockPublicKeyString]

	// Delete the public keys from the Reader's map of blocked public keys if we are unblocking and the public key is
	// in the map.  Add the public key to the User's map of blocked public keys if we are blocking and the public key is
	// not currently present in the User's map of blocked public keys.
	if keyExists && requestData.Unblock {
		delete(blockedPublicKeys, blockPublicKeyString)
	} else if !keyExists && !requestData.Unblock {
		blockedPublicKeys[blockPublicKeyString] = struct{}{}
	}
	userMetadata.BlockedPublicKeys = blockedPublicKeys
	err = fes.putUserMetadataInGlobalState(userMetadata)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("BlockPublicKey: Problem with putUserMetadataInGlobalState: %v", err))
		return
	}

	// Return the posts found.
	res := &BlockPublicKeyResponse{
		BlockedPublicKeys: blockedPublicKeys,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("BlockPublicKey: Problem encoding response as JSON: %v", err))
		return
	}
}

type IsFollowingPublicKeyRequest struct {
	PublicKeyBase58Check            string
	IsFollowingPublicKeyBase58Check string
}

type IsFolllowingPublicKeyResponse struct {
	IsFollowing bool
}

func (fes *APIServer) IsFollowingPublicKey(ww http.ResponseWriter, req *http.Request) {

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := IsFollowingPublicKeyRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"IsFollowingPublicKey: Problem parsing request body: %v", err))
		return
	}

	userPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.PublicKeyBase58Check)
	if err != nil || len(userPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		_AddBadRequestError(ww, fmt.Sprintf(
			"IsFollowingPublicKey: Problem decoding user public key %s: %v",
			requestData.PublicKeyBase58Check, err))
		return
	}

	// Get the public key for the user to check
	isFollowingPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.IsFollowingPublicKeyBase58Check)
	if err != nil || len(isFollowingPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		_AddBadRequestError(ww, fmt.Sprintf(
			"IsFollowingPublicKey: Problem decoding public key to check %s: %v",
			requestData.IsFollowingPublicKeyBase58Check, err))
		return
	}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("IsFollowingPublicKey Error getting view: %v", err))
		return
	}

	// Get the FollowEntry from the view.
	followEntry := utxoView.GetFollowEntryForFollowerPublicKeyCreatorPublicKey(userPublicKeyBytes, isFollowingPublicKeyBytes)

	res := IsFolllowingPublicKeyResponse{
		IsFollowing: followEntry != nil,
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("IsFollowingPublicKey: Problem serializing object to JSON: %v", err))
		return
	}
}

type IsHodlingPublicKeyRequest struct {
	PublicKeyBase58Check          string
	IsHodlingPublicKeyBase58Check string
}

type IsHodlingPublicKeyResponse struct {
	IsHodling    bool
	BalanceEntry *BalanceEntryResponse
}

func (fes *APIServer) IsHodlingPublicKey(ww http.ResponseWriter, req *http.Request) {

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := IsHodlingPublicKeyRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"IsHodlingPublicKey: Problem parsing request body: %v", err))
		return
	}

	var userPublicKeyBytes []byte
	var err error
	userPublicKeyBytes, _, err = lib.Base58CheckDecode(requestData.PublicKeyBase58Check)
	if err != nil || len(userPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		_AddBadRequestError(ww, fmt.Sprintf(
			"IsHodlingPublicKey: Problem decoding user public key %s: %v",
			requestData.PublicKeyBase58Check, err))
		return
	}

	// Get the public key for the user to check
	var isHodlingPublicKeyBytes []byte
	isHodlingPublicKeyBytes, _, err = lib.Base58CheckDecode(requestData.IsHodlingPublicKeyBase58Check)
	if err != nil || len(isHodlingPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		_AddBadRequestError(ww, fmt.Sprintf(
			"IsHodlingPublicKey: Problem decoding public key to check %s: %v",
			requestData.IsHodlingPublicKeyBase58Check, err))
		return
	}

	var utxoView *lib.UtxoView
	utxoView, err = fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("IsHodlingPublicKey: Error getting utxoView: %v", err))
		return
	}

	var IsHodling = false
	var BalanceEntry *BalanceEntryResponse

	hodlBalanceEntry, _, _ := utxoView.GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(userPublicKeyBytes, isHodlingPublicKeyBytes)
	if hodlBalanceEntry != nil {
		BalanceEntry = _balanceEntryToResponse(hodlBalanceEntry, hodlBalanceEntry.BalanceNanos, nil, fes.Params, utxoView, nil)
		IsHodling = true
	}

	res := IsHodlingPublicKeyResponse{
		IsHodling:    IsHodling,
		BalanceEntry: BalanceEntry,
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("IsHodlingPublicKey: Problem serializing object to JSON: %v", err))
		return
	}

}

// GetUserDerivedKeysRequest ...
type GetUserDerivedKeysRequest struct {
	// Public key which derived keys we want to query.
	PublicKeyBase58Check string `safeForLogging:"true"`
}

// UserDerivedKey ...
type UserDerivedKey struct {
	// This is the public key of the owner.
	OwnerPublicKeyBase58Check   string `safeForLogging:"true"`

	// This is the derived public key.
	DerivedPublicKeyBase58Check string `safeForLogging:"true"`

	// This is the expiration date of the derived key.
	ExpirationBlock             uint64 `safeForLogging:"true"`

	// This is the current state of the derived key.
	IsValid                     bool `safeForLogging:"true"`
}

// GetUserDerivedKeysResponse ...
type GetUserDerivedKeysResponse struct {
	// DerivedKeys contains user's derived keys indexed by public keys in base58Check
	DerivedKeys map[string]*UserDerivedKey `safeForLogging:"true"`
}

func (fes *APIServer) GetUserDerivedKeys(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetUserDerivedKeysRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetUserDerivedKeys: Problem parsing request body: %v", err))
		return
	}

	// Check if a valid public key was passed.
	var publicKeyBytes []byte
	var err error
	publicKeyBytes, _, err = lib.Base58CheckDecode(requestData.PublicKeyBase58Check)
	if err != nil || len(publicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetUserDerivedKeys: Problem decoding user public key %s: %v",
			requestData.PublicKeyBase58Check, err))
		return
	}

	// Get augmented utxoView.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUtxoViewForPublicKey(publicKeyBytes, nil)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetUserDerivedKeys: Problem getting augmented utxoView: %v", err))
		return
	}

	// Get all derived key entries for the owner public key.
	derivedKeyMappings, err := utxoView.GetAllDerivedKeyMappingsForOwner(publicKeyBytes)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetUserDerivedKeys: Problem getting derived key mappings for owner: %v", err))
		return
	}

	// Create the derivedKeys map, indexed by derivedPublicKeys in base58Check.
	// We use the UserDerivedKey struct instead of the lib.DerivedKeyEntry type
	// so that we can return public keys in base58Check.
	derivedKeys := make(map[string]*UserDerivedKey)
	for _, entry := range derivedKeyMappings {
		derivedPublicKey := lib.PkToString(entry.DerivedPublicKey[:], fes.Params)
		derivedKeys[derivedPublicKey] = &UserDerivedKey{
			OwnerPublicKeyBase58Check:   lib.PkToString(entry.OwnerPublicKey[:], fes.Params),
			DerivedPublicKeyBase58Check: lib.PkToString(entry.DerivedPublicKey[:], fes.Params),
			ExpirationBlock:             entry.ExpirationBlock,
			IsValid:                     entry.OperationType == lib.AuthorizeDerivedKeyOperationValid,
		}
	}

	res := GetUserDerivedKeysResponse{
		DerivedKeys: derivedKeys,
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetUserDerivedKeys: Problem serializing object to JSON: %v", err))
		return
	}
}
