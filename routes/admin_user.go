package routes

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/deso-protocol/core/lib"
	"github.com/pkg/errors"
)

// AdminUpdateUserGlobalMetadataRequest...
type AdminUpdateUserGlobalMetadataRequest struct {
	// The public key of the user to update. This will trump 'Username' if both are provided.
	UserPublicKeyBase58Check string `safeForLogging:"true"`
	// The username associated with the public key to update.
	Username string `safeForLogging:"true"`

	// Whether this is a blacklist update or not.
	IsBlacklistUpdate bool `safeForLogging:"true"`
	// Set to true if this user's content should not show up anywhere on the site.
	// Only set if IsBlacklistUpdate == true.
	RemoveEverywhere bool `safeForLogging:"true"`
	// Should be set to true if this user should not show up on the creator leaderboard.
	// Only set if IsBlacklistUpdate == true.
	RemoveFromLeaderboard bool `safeForLogging:"true"`

	// Whether this is a whitelist update or not.
	IsWhitelistUpdate bool `safeForLogging:"true"`
	// Set to true to automatically show this users posts in the global feed (max 5 per day).
	WhitelistPosts bool `safeForLogging:"true"`

	// Remove PhoneNumberMetadata to allow re-registration
	RemovePhoneNumberMetadata bool `safeForLogging:"true"`

	AdminPublicKey string
}

// AdminUpdateUserGlobalMetadata ...
//
// This endpoint differs from the standard "UpdateUserGlobalMetadata" in that it allows
// anyone with access to the node's shared_secret to update any part of a User's metadata.
func (fes *APIServer) AdminUpdateUserGlobalMetadata(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminUpdateUserGlobalMetadataRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateUserGlobalMetadata: Problem parsing request body: %v", err))
		return
	}

	if requestData.UserPublicKeyBase58Check == "" && requestData.Username == "" {
		_AddBadRequestError(ww,
			fmt.Sprintf("AdminUpdateUserGlobalMetadataRequest: Must provide a valid username or public key."))
		return
	}

	// Decode the user public key, if provided.
	var userPublicKeyBytes []byte
	var err error
	if requestData.UserPublicKeyBase58Check != "" {
		userPublicKeyBytes, _, err = lib.Base58CheckDecode(requestData.UserPublicKeyBase58Check)
		if err != nil || len(userPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
			_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateUserGlobalMetadata: Problem decoding updater public key %s: %v",
				requestData.UserPublicKeyBase58Check, err))
			return
		}
	}

	// If we do not have a public key by this point, try and get one from the profile associated with the username.
	if userPublicKeyBytes == nil && requestData.Username != "" {
		utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateUserGlobalMetadata: Problem fetching utxoView: %v", err))
			return
		}

		profile := utxoView.GetProfileEntryForUsername([]byte(requestData.Username))
		if profile == nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateUserGlobalMetadata: Problem getting profile for username: %v : %s", err, requestData.Username))
			return
		}
		userPublicKeyBytes = profile.PublicKey
	}

	// Now that we have a public key, set up the global state UserMetadata object.
	userMetadata, err := fes.getUserMetadataFromGlobalState(lib.PkToString(userPublicKeyBytes, fes.Params))
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateUserGlobalMetadata: Problem getting metadata from global state: %v", err))
		return
	}

	// If this request is to remove phone number metadata, do it and then return early.
	if requestData.RemovePhoneNumberMetadata {
		if len(userMetadata.PhoneNumber) == 0 {
			_AddBadRequestError(ww, "AdminUpdateUserGlobalMetadata: User does not have a phone number")
			return
		}
		multiPhoneNumberMetadata, err := fes.getMultiPhoneNumberMetadataFromGlobalState(userMetadata.PhoneNumber)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateUserGlobalMetadata: Error getting phone number metadata: %v", err))
			return
		}
		newMetadata := []*PhoneNumberMetadata{}
		for _, phoneNumberMetadata := range multiPhoneNumberMetadata {
			if !bytes.Equal(phoneNumberMetadata.PublicKey, userPublicKeyBytes) {
				newMetadata = append(newMetadata, phoneNumberMetadata)
			}
		}

		if err = fes.putPhoneNumberMetadataInGlobalState(newMetadata, userMetadata.PhoneNumber); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateUserGlobalMetadata: Error saving phone number metadata: %v", err))
			return
		}

		userMetadata.PhoneNumber = ""
		userMetadata.PhoneNumberCountryCode = ""

		if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateUserGlobalMetadata: Problem putting updated user metadata after deleting phone number: %v", err))
			return
		}

		// If we made it this far we were successful at removing phone metadata, return without error.
		// Simply return a 200 status code
		return
	}

	// Gather relevant information from filter logs
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateUserGlobalMetadata: Problem getting utxoView: %v", err))
		return
	}
	userPKIDEntry := utxoView.GetPKIDForPublicKey(userPublicKeyBytes)
	profileEntry := utxoView.GetProfileEntryForPKID(userPKIDEntry.PKID)

	// NOTE: for now, if pointing to a different global state, this will not be merged with the black/graylist from
	// the external source. This is a planned future enhancements.
	// Now that we have a userMetadata object, update it based on the request.
	if requestData.IsBlacklistUpdate {
		userMetadata.RemoveEverywhere = requestData.RemoveEverywhere
		blacklistKey := GlobalStateKeyForBlacklistedProfile(userPublicKeyBytes)
		blacklistVal := lib.NotBlacklisted
		blacklistAction := "removing from"
		if userMetadata.RemoveEverywhere {
			blacklistVal = lib.IsBlacklisted
			blacklistAction = "adding to"
		}
		if err = fes.GlobalState.Put(blacklistKey, blacklistVal); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateUserGlobalMetadata: Problem %v blacklist: %v", blacklistAction, err))
			return
		}
		// We update the logs accordingly
		if err = fes.UpdateFilterAuditLogs(
			string(profileEntry.Username),
			userPKIDEntry,
			Blacklist,
			!userMetadata.RemoveEverywhere,
			requestData.AdminPublicKey,
			utxoView); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateUserGlobalMetadata: Problem updating blacklist logs: %v", err))
			return
		}
		// We need to update global state's list of graylisted users.
		userMetadata.RemoveFromLeaderboard = requestData.RemoveFromLeaderboard
		graylistkey := GlobalStateKeyForGraylistedProfile(userPublicKeyBytes)
		graylistVal := lib.NotGraylisted
		graylistAction := "removing from"
		if userMetadata.RemoveFromLeaderboard {
			graylistVal = lib.IsGraylisted
			graylistAction = "adding to"
		}
		if err = fes.GlobalState.Put(graylistkey, graylistVal); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateUserGlobalMetadata: Problem %v graylist: %v", graylistAction, err))
			return
		}
		// We update the logs accordingly
		if err = fes.UpdateFilterAuditLogs(
			string(profileEntry.Username),
			userPKIDEntry,
			Graylist,
			!userMetadata.RemoveFromLeaderboard,
			requestData.AdminPublicKey,
			utxoView); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateUserGlobalMetadata: Problem updating graylist logs: %v", err))
			return
		}
		// Force Blacklist and Graylist to update instantly.
		fes.SetBlacklistedPKIDMap(utxoView)
		fes.SetGraylistedPKIDMap(utxoView)
	} else if requestData.IsWhitelistUpdate {
		userMetadata.WhitelistPosts = requestData.WhitelistPosts
		// We update the logs accordingly
		err = fes.UpdateFilterAuditLogs(string(profileEntry.Username), userPKIDEntry, Whitelist, !requestData.WhitelistPosts, requestData.AdminPublicKey, utxoView)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateUserGlobalMetadata: Problem updating whitelist logs: %v", err))
			return
		}
	}

	// Encode the updated entry and stick it in the database.
	if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateUserGlobalMetadata: Problem putting updated user metadata: %v", err))
		return
	}
	// Simply return with a 200 status code
}

type AdminResetPhoneNumberRequest struct {
	PhoneNumber string
}

// Clears all phone number metadata for a given phone number - thus allowing it to be used again.
func (fes *APIServer) AdminResetPhoneNumber(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminResetPhoneNumberRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminResetPhoneNumber: Problem parsing request body: %v", err))
		return
	}
	if err := fes.putPhoneNumberMetadataInGlobalState([]*PhoneNumberMetadata{}, requestData.PhoneNumber); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AdminResetPhoneNumber: Problem putting empty slice in global state for phone number %v: %v",
			requestData.PhoneNumber, err))
		return
	}
}

// AdminGetAllUserGlobalMetadataRequest...
type AdminGetAllUserGlobalMetadataRequest struct {
	NumToFetch int `safeForLogging:"true"`
}

// AdminGetAllUserGlobalMetadataResponse ...
type AdminGetAllUserGlobalMetadataResponse struct {
	// A mapping between the PublicKeyBase58Check string and the user's global metadata.
	PubKeyToUserGlobalMetadata map[string]*UserMetadata
	PubKeyToUsername           map[string]string
}

// getUserMetadataUsernameMaps acts as a helper function for AdminGetAllUserGlobalMetadata.
func (fes *APIServer) getUserMetadataUsernameMaps(numToFetch int) (_publicKeyToUserMetadata map[string]*UserMetadata,
	_publicKeyToUsername map[string]string, _err error) {
	// Seek the global state for the user metadata prefix.
	seekKey := _GlobalStatePrefixPublicKeyToUserMetadata
	keys, vals, err := fes.GlobalState.Seek(seekKey, seekKey, 0, numToFetch, false, true)
	if err != nil {
		return nil, nil,
			errors.Wrapf(err, "getUserMetadataUsernameMaps: problem with Seek")
	}

	// Sanity check that we got an appropriate number of keys and values.
	if len(keys) != len(vals) {
		return nil, nil,
			errors.Wrapf(err, "getUserMetadataUsernameMaps: GlobalState keys/vals length mismatch.")
	}

	// Get a view that includes the transaction we just processed.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return nil, nil,
			errors.Wrapf(err, "getUserMetadataUsernameMaps: problem with GetAugmentedUniversalView")
	}

	// Create public key mappings
	publicKeyToUserMetadata := make(map[string]*UserMetadata)
	publicKeyToUsername := make(map[string]string)
	for ii, dbKeyBytes := range keys {
		// Chop the public key out of the db key.
		pkBytes := make([]byte, btcec.PubKeyBytesLenCompressed)
		copy(pkBytes[:], dbKeyBytes[1 : 1+btcec.PubKeyBytesLenCompressed][:])
		pubKeyString := lib.PkToString(pkBytes, fes.Params)

		// Decode the user metadata associated with this key.
		userMetadata := UserMetadata{}
		err = gob.NewDecoder(bytes.NewReader(vals[ii])).Decode(&userMetadata)
		if err != nil {
			return nil, nil,
				errors.Wrapf(err, "getUserMetadataUsernameMaps: problem getting metadata from global state")
		}

		publicKeyToUserMetadata[pubKeyString] = &userMetadata

		profileEntry := utxoView.GetProfileEntryForPublicKey(pkBytes)
		if profileEntry != nil {
			publicKeyToUsername[pubKeyString] = string(profileEntry.Username)
		}
	}

	return publicKeyToUserMetadata, publicKeyToUsername, nil
}

// AdminGetAllUserGlobalMetadata ...
func (fes *APIServer) AdminGetAllUserGlobalMetadata(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminGetAllUserGlobalMetadataRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetAllUserGlobalMetadata: Problem parsing request body: %v", err))
		return
	}

	publicKeyToUserMetadata, publicKeyToUsername, err := fes.getUserMetadataUsernameMaps(requestData.NumToFetch)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetAllUserGlobalMetadata: Problem with getUserMetadataUsernameMaps: %v", err))
		return
	}

	// If we made it this far we were successful, return without error.
	res := AdminGetAllUserGlobalMetadataResponse{
		PubKeyToUserGlobalMetadata: publicKeyToUserMetadata,
		PubKeyToUsername:           publicKeyToUsername,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetAllUserGlobalMetadata: Problem encoding response as JSON: %v", err))
		return
	}
}

// AdminGetUserGlobalMetadataRequest...
type AdminGetUserGlobalMetadataRequest struct {
	UserPublicKeyBase58Check string `safeForLogging:"true"`
}

// AdminGetUserGlobalMetadataResponse ...
type AdminGetUserGlobalMetadataResponse struct {
	// the user's global metadata.
	UserMetadata UserMetadata

	// The User object
	UserProfileEntryResponse *ProfileEntryResponse
}

// AdminGetUserGlobalMetadata ...
func (fes *APIServer) AdminGetUserGlobalMetadata(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminGetUserGlobalMetadataRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetAllUserGlobalMetadata: Problem parsing request body: %v", err))
		return
	}
	// Decode the user public key provided.
	userPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.UserPublicKeyBase58Check)
	if err != nil || len(userPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetUserGlobalMetadata: Problem userPublicKeyBase58Check: %v", err))
		return
	}

	// Grab user's metadata from global state
	userMetadata, err := fes.getUserMetadataFromGlobalState(lib.PkToString(userPublicKeyBytes, fes.Params))
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetUserGlobalMetadata: Problem obtaining userMetadata from global state: %v", err))
	}

	// Get a view that includes the transaction we just processed.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("AdminGetUserGlobalMetadata: problem with GetAugmentedUniversalView: %v", err))
		return
	}

	profileEntry := utxoView.GetProfileEntryForPublicKey(userPublicKeyBytes)

	// If we made it this far we were successful, return without error.
	res := AdminGetUserGlobalMetadataResponse{
		UserMetadata:             *userMetadata,
		UserProfileEntryResponse: fes._profileEntryToResponse(profileEntry, utxoView),
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetUserGlobalMetadata: Problem encoding response as JSON: %v", err))
		return
	}
}

// Add a new audit log record to the history of username verification audit logs.
func (fes *APIServer) UpdateUsernameVerificationAuditLog(usernameToVerify string, pkidEntryToVerify *lib.PKIDEntry,
	isRemoval bool, verifierPublicKeyBase58Check string, utxoView *lib.UtxoView) (_err error) {
	verificationAuditLogs := []VerificationUsernameAuditLog{}
	// Get the key to look up the current list of audit logs for this username
	verificationAuditLogKey := GlobalStateKeyForUsernameVerificationAuditLogs(usernameToVerify)
	verificationAuditLogBytes, err := fes.GlobalState.Get(verificationAuditLogKey)
	if err != nil {
		return errors.Wrap(fmt.Errorf("UpdateUsernameVerificationAuditLog: Failed to log verification to audit log"), "")
	}
	if verificationAuditLogBytes != nil {
		err = gob.NewDecoder(bytes.NewReader(verificationAuditLogBytes)).Decode(&verificationAuditLogs)
		if err != nil {
			return errors.Wrap(fmt.Errorf("UpdateUsernameVerificationAuditLog: Failed decoding verification audit log"), "")
		}
	}
	// Decode the verifier's public key
	verifierPublicKeyBytes, _, err := lib.Base58CheckDecode(verifierPublicKeyBase58Check)
	if err != nil || len(verifierPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		return errors.Wrap(fmt.Errorf("UpdateUsernameVerificationAuditLog: Failed to decode verifier public key bytes"), "")
	}

	// Get verifier's PKID and then get profile entry -- This is separated into two steps since we save the
	// PKID in the VerificationUsernameAuditLog
	verifierPKID := utxoView.GetPKIDForPublicKey(verifierPublicKeyBytes)
	verifierProfileEntry := utxoView.GetProfileEntryForPKID(verifierPKID.PKID)
	verifierUsername := ""
	if verifierProfileEntry != nil {
		verifierUsername = string(verifierProfileEntry.Username)
	}
	tstamp := uint64(time.Now().UnixNano())
	newVerificationAuditLog := VerificationUsernameAuditLog{
		TimestampNanos:   tstamp,
		VerifierUsername: verifierUsername,
		VerifierPKID:     verifierPKID.PKID,
		VerifiedUsername: usernameToVerify,
		VerifiedPKID:     pkidEntryToVerify.PKID,
		IsRemoval:        isRemoval,
	}
	// Prepend this new audit log to the list of audit logs.
	verificationAuditLogs = append([]VerificationUsernameAuditLog{newVerificationAuditLog}, verificationAuditLogs...)
	verificationDataBuf := bytes.NewBuffer([]byte{})
	gob.NewEncoder(verificationDataBuf).Encode(verificationAuditLogs)
	err = fes.GlobalState.Put(verificationAuditLogKey, verificationDataBuf.Bytes())
	if err != nil {
		return errors.Wrap(fmt.Errorf("AdminGrantVerificationBadge: Failed to update verification audit logs"), "")
	}
	return nil
}

// Add a new audit log record to the history of filter audit logs.
func (fes *APIServer) UpdateFilterAuditLogs(usernameToUpdate string, pkidEntryToUpdate *lib.PKIDEntry, filterType FilterType,
	isRemoval bool, updaterPublicKeyBase58Check string, utxoView *lib.UtxoView) (_err error) {
	// Fetch the existing logs from global state
	filterLogs, err := fes.GetFilterAuditLogs(usernameToUpdate, filterType)
	if err != nil {
		return errors.Wrap(err, "UpdateFilterAuditLogs: Failed to call GetFilterAuditLogs")
	}

	// Decode the updater's public key
	updaterPublicKeyBytes, _, err := lib.Base58CheckDecode(updaterPublicKeyBase58Check)
	if err != nil || len(updaterPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		return errors.Wrap(fmt.Errorf("UpdateFilterAuditLogs: Failed to decode verifier public key bytes"), "")
	}
	updaterPKID := utxoView.GetPKIDForPublicKey(updaterPublicKeyBytes)
	updaterProfileEntry := utxoView.GetProfileEntryForPKID(updaterPKID.PKID)
	updaterUsername := ""
	if updaterProfileEntry != nil {
		updaterUsername = string(updaterProfileEntry.Username)
	}
	tstamp := uint64(time.Now().UnixNano())
	newFilterLog := FilterAuditLog{
		TimestampNanos:  tstamp,
		Filter:          filterType,
		UpdaterUsername: updaterUsername,
		UpdaterPKID:     updaterPKID.PKID,
		UpdatedUsername: usernameToUpdate,
		UpdatedPKID:     pkidEntryToUpdate.PKID,
		IsRemoval:       isRemoval,
	}
	// Prepend this new audit log to the list of audit logs.
	filterLogs = append([]FilterAuditLog{newFilterLog}, filterLogs...)
	filterLogsBuf := bytes.NewBuffer([]byte{})
	err = gob.NewEncoder(filterLogsBuf).Encode(filterLogs)
	if err != nil {
		return errors.Wrap(err, "UpdateFilterAuditLogs: Failed to gob encode filter logs")
	}

	// Get the correct filter key
	filterLogsKey, err := GetFilterLogsKey(usernameToUpdate, filterType)
	if err != nil {
		return errors.Wrap(err, "UpdateFilterAuditLogs: Failed to get filter logs")
	}

	err = fes.GlobalState.Put(filterLogsKey, filterLogsBuf.Bytes())
	if err != nil {
		return errors.Wrap(fmt.Errorf("UpdateFilterAuditLogs: Failed to update filter logs"), "")
	}
	return nil
}

// Gives the filter logs key for a specific filter type and username.
func GetFilterLogsKey(username string, filterType FilterType) (_filterLogsKey []byte, _err error) {
	var filterLogsKey []byte
	switch filterType {
	case Blacklist:
		filterLogsKey = GlobalStateKeyForBlacklistAuditLogs(username)
	case Graylist:
		filterLogsKey = GlobalStateKeyForGraylistAuditLogs(username)
	case Whitelist:
		filterLogsKey = GlobalStateKeyForWhitelistAuditLogs(username)
	default:
		return nil, fmt.Errorf("GetFilterLogsKey: Invalid filter type: %v", filterType)
	}
	return filterLogsKey, nil
}

// Fetch the filter audit logs for a given username and filter type.
func (fes *APIServer) GetFilterAuditLogs(username string, filterType FilterType) (_logs []FilterAuditLog, _err error) {
	filterLogs := []FilterAuditLog{}

	// Get the correct filter key
	filterLogsKey, err := GetFilterLogsKey(username, filterType)
	if err != nil {
		return nil, errors.Wrap(err, "GetFilterAuditLogs: Failed to get filter logs")
	}

	// Fetch the logs from global state
	filterLogsBytes, err := fes.GlobalState.Get(filterLogsKey)
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf("GetFilterAuditLogs: Failed to fetch filter audit logs from globalstate"), "")
	}
	if filterLogsBytes != nil {
		err = gob.NewDecoder(bytes.NewReader(filterLogsBytes)).Decode(&filterLogs)
		if err != nil {
			return nil, errors.Wrap(fmt.Errorf("GetFilterAuditLogs: Failed decoding filter audit logs"), "")
		}
	}
	return filterLogs, nil
}

// Type used for gob decoding and encoding verification mapping
type VerifiedUsernameToPKID struct {
	VerifiedUsernameToPKID map[string]*lib.PKID
}

type VerificationUsernameAuditLog struct {
	// Time at which the verification was granted or removed.
	TimestampNanos uint64
	// Username and PKID of the admin who verified the user.
	VerifierUsername string
	VerifierPKID     *lib.PKID
	// The user who was verified or had their verification removed.
	VerifiedUsername string
	VerifiedPKID     *lib.PKID
	// Indicator of whether this request granted verification or removed verification.
	IsRemoval bool
}

type FilterType uint32

const (
	// The filter type associated with a filter audit log
	Whitelist FilterType = iota
	Graylist
	Blacklist
)

type FilterAuditLog struct {
	// Time at which the filter status was granted or removed.
	TimestampNanos uint64
	// The filter type being updated
	Filter FilterType
	// Username and PKID of the admin who filtered the user.
	UpdaterUsername string
	UpdaterPKID     *lib.PKID
	// The user who was filtered or had their filter removed.
	UpdatedUsername string
	UpdatedPKID     *lib.PKID
	// Indicator of whether this request granted the filter status or removed it.
	IsRemoval bool
}

// AdminGrantVerificationBadgeRequest ...
type AdminGrantVerificationBadgeRequest struct {
	UsernameToVerify string `safeForLogging:"true"`
	AdminPublicKey   string
}

// AdminGrantVerificationBadgeResponse ...
type AdminGrantVerificationBadgeResponse struct {
	Message string
}

// AdminGrantVerificationBadge
//
// This endpoint enables anyone with access to a node's shared secret to grant a verification
// badge to a particular username.
// This operates on this node's global state and does not interact with the configured GlobalStateAPIUrl.
func (fes *APIServer) AdminGrantVerificationBadge(ww http.ResponseWriter, req *http.Request) {
	requestData := AdminGrantVerificationBadgeRequest{}
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGrantVerificationBadge: Problem parsing request body: %v", err))
		return
	}
	usernameToVerify := requestData.UsernameToVerify

	// Verify the username adheres to the consensus username criteria
	if len(usernameToVerify) == 0 || len(usernameToVerify) > lib.MaxUsernameLengthBytes || !lib.UsernameRegex.Match([]byte(usernameToVerify)) {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGrantVerificationBadge: Must provide a valid username"))
		return
	}

	// Verify the username has an underlying profile
	pubKey, err := fes.getPublicKeyFromUsernameOrPublicKeyString(usernameToVerify)
	if err != nil {
		_AddBadRequestError(ww,
			fmt.Sprintf("AdminGrantVerificationBadge: Username %s has no associated underlying publickey.", usernameToVerify))
		return
	}

	// Use a utxoView to get the pkid for this pub key.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGrantVerificationBadge: Problem getting utxoView: %v", err))
		return
	}
	pkidEntryToVerify := utxoView.GetPKIDForPublicKey(pubKey)
	if pkidEntryToVerify == nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGrantVerificationBadge: PKID not found for username: %s", usernameToVerify))
		return
	}

	// Pull the verified map from global state
	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMapFromGlobalState()
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("AdminGrantVerificationBadge: Failed fetching verified map from database: %v", err))
		return
	}
	verifiedMapStruct := VerifiedUsernameToPKID{}
	if verifiedMap != nil {
		verifiedMapStruct.VerifiedUsernameToPKID = verifiedMap
	} else {
		verifiedMapStruct.VerifiedUsernameToPKID = make(map[string]*lib.PKID)
	}

	// Add a new audit log record for this verification request.
	err = fes.UpdateUsernameVerificationAuditLog(usernameToVerify, pkidEntryToVerify, false, requestData.AdminPublicKey, utxoView)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGrantVerificationBadge: error updating audit log of username verification: %v", err))
		return
	}
	// Add username -> PKID mapping
	// A username must map to a specific PKID, as someone could change their username
	// and impersonate someone else. For example:
	// @elonmusk changes his username to @jeffbezos
	// We verify the username still matches or else it would transfer over
	// to @jeffbezos.
	verifiedMapStruct.VerifiedUsernameToPKID[strings.ToLower(usernameToVerify)] = pkidEntryToVerify.PKID

	// Encode the updated entry and stick it in the database.
	metadataDataBuf := bytes.NewBuffer([]byte{})
	if err = gob.NewEncoder(metadataDataBuf).Encode(verifiedMapStruct); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGrantVerificationBadge: failed to encode verified map struct: %v", err))
		return
	}
	err = fes.GlobalState.Put(_GlobalStatePrefixForVerifiedMap, metadataDataBuf.Bytes())
	if err != nil {
		_AddBadRequestError(ww, "AdminGrantVerificationBadge: Failed placing new verification map into the database.")
		return
	}

	// Force a refresh of the Verified Username map.
	fes.SetVerifiedUsernameMap()

	// Return a success message
	res := AdminGrantVerificationBadgeResponse{
		Message: "Successfully added verification badge for: " + usernameToVerify,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AdminGrantVerificationBadge: Problem encoding response as JSON: %v", err))
		return
	}
}

// AdminRemoveVerificationBadgeRequest ...
type AdminRemoveVerificationBadgeRequest struct {
	UsernameForWhomToRemoveVerification string `safeForLogging:"true"`
	AdminPublicKey                      string
}

// AdminGrantVerificationBadgeResponse ...
type AdminRemoveVerificationBadgeResponse struct {
	Message string
}

// AdminRemoveVerificationBadge
//
// A valid verification mapping will have an element where map[PKID] = username.
// If the public key still has the same username, the user is considered verified.
// In order to "delete" a user efficiently, we simply map their public key to an empty string.
// Since their public key can never have an underlying username of "", it will never show up as verified.
// This operates on this node's global state and does not interact with the configured GlobalStateAPIUrl.
func (fes *APIServer) AdminRemoveVerificationBadge(ww http.ResponseWriter, req *http.Request) {
	requestData := AdminRemoveVerificationBadgeRequest{}
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminRemoveVerificationBadge: Problem parsing request body: %v", err))
		return
	}
	usernameToRemove := requestData.UsernameForWhomToRemoveVerification

	// Verify the username adheres to the consensus username criteria
	if len(usernameToRemove) == 0 || len(usernameToRemove) > lib.MaxUsernameLengthBytes || !lib.UsernameRegex.Match([]byte(usernameToRemove)) {
		_AddBadRequestError(ww, fmt.Sprintf("AdminRemoveVerificationBadge: Must provide a valid username"))
		return
	}

	// Verify the username has an underlying profile
	pubKey, err := fes.getPublicKeyFromUsernameOrPublicKeyString(usernameToRemove)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminRemoveVerificationBadge: Username has no associated underlying publickey"))
		return
	}

	// Use a utxoView to get the pkid for this pub key.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminRemoveVerificationBadge: Problem getting utxoView: %v", err))
		return
	}
	pkidEntryToUnverify := utxoView.GetPKIDForPublicKey(pubKey)
	if pkidEntryToUnverify == nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminRemoveVerificationBadge: PKID not found for username: %s", usernameToRemove))
		return
	}

	// Pull the verified map from global state
	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMapFromGlobalState()
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("AdminRemoveVerificationBadge: Failed fetching verified map from database: %v", err))
		return
	}
	// We can exit early if there are no users in the verified map.
	if verifiedMap == nil || len(verifiedMap) == 0 {
		res := AdminRemoveVerificationBadgeResponse{
			Message: "Couldn't find a verified username map in global state.  Nothing to delete.",
		}
		if err = json.NewEncoder(ww).Encode(res); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminRemoveVerificationBadge: Problem encoding response as "+
				"JSON: %v", err))
		}
		return
	}
	verifiedMapStruct := VerifiedUsernameToPKID{
		VerifiedUsernameToPKID: verifiedMap,
	}

	// Add a new audit log for this verification removal request.
	err = fes.UpdateUsernameVerificationAuditLog(usernameToRemove, pkidEntryToUnverify, true, requestData.AdminPublicKey, utxoView)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminRemoveVerificationBadge: error updating audit log of username verification: %v", err))
		return
	}

	// We set the value for this username to an empty PKID to signify that it has been removed.
	verifiedMapStruct.VerifiedUsernameToPKID[strings.ToLower(usernameToRemove)] = &lib.ZeroPKID

	// Encode the updated entry and stick it in the database.
	metadataDataBuf := bytes.NewBuffer([]byte{})
	if err = gob.NewEncoder(metadataDataBuf).Encode(verifiedMapStruct); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminRemoveVerificationBadge: Failed encoding new verification map: %v", err))
	}

	if err = fes.GlobalState.Put(_GlobalStatePrefixForVerifiedMap, metadataDataBuf.Bytes()); err != nil {
		_AddBadRequestError(ww, "AdminRemoveVerificationBadge: Failed placing new verification map into the database.")
		return
	}

	// Force a refresh of the Verified Username map.
	fes.SetVerifiedUsernameMap()

	// Return a success message
	res := AdminRemoveVerificationBadgeResponse{
		Message: "Successfully removed verification badge for: " + usernameToRemove,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminRemoveVerificationBadge: Problem encoding response as JSON: %v", err))
		return
	}
}

// AdminGetVerifiedUsersRequest ...
type AdminGetVerifiedUsersRequest struct{}

// AdminGetVerifiedUsersResponse ...
type AdminGetVerifiedUsersResponse struct {
	VerifiedUsers []string
}

// AdminGetVerifiedUsers gets a list of all verified users from this node's global state.
func (fes *APIServer) AdminGetVerifiedUsers(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminGetVerifiedUsersRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetVerifiedUsers: Problem parsing request body: %v", err))
		return
	}

	// Pull the verified map from global state
	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMapFromGlobalState()
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("AdminGetVerifiedUsers: Failed fetching verified map from database: %v", err))
		return
	}
	if verifiedMap == nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetVerifiedUsers: No verified user map in global state."))
		return
	}

	verifiedUsers := []string{}
	for userName := range verifiedMap {
		verifiedUsers = append(verifiedUsers, userName)
	}

	// Return a success message
	res := AdminGetVerifiedUsersResponse{VerifiedUsers: verifiedUsers}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminRemoveVerificationBadge: Problem encoding response as JSON: %v", err))
		return
	}
}

// VerificationUsernameAuditLogResponse format
type VerificationUsernameAuditLogResponse struct {
	TimestampNanos               uint64
	VerifierUsername             string
	VerifierPublicKeyBase58Check string
	VerifiedUsername             string
	VerifiedPublicKeyBase58Check string
	IsRemoval                    bool
}

// AdminGetUsernameVerificationAuditLogsRequest ...
type AdminGetUsernameVerificationAuditLogsRequest struct {
	Username string
}

// AdminGetUsernameVerificationAuditLogsResponse ...
type AdminGetUsernameVerificationAuditLogsResponse struct {
	VerificationAuditLogs []VerificationUsernameAuditLogResponse
}

// AdminGetUsernameVerificationAuditLogs gets the verification audit logs for a given username from this node's global
// state.  It does not look at the configured GlobalStateAPIUrl to fetch this information.
func (fes *APIServer) AdminGetUsernameVerificationAuditLogs(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminGetUsernameVerificationAuditLogsRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetVerifiedUsers: Problem parsing request body: %v", err))
		return
	}
	// Get the verification audit logs from global state.
	key := GlobalStateKeyForUsernameVerificationAuditLogs(requestData.Username)
	verificationUsernameAuditLogBytes, err := fes.GlobalState.Get(key)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetUsernameVerificationAuditLogs: Problem getting audit logs for this username: %v", err))
		return
	}

	verificationAuditLogs := []VerificationUsernameAuditLog{}
	if verificationUsernameAuditLogBytes != nil {
		err = gob.NewDecoder(bytes.NewReader(verificationUsernameAuditLogBytes)).Decode(&verificationAuditLogs)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminGetUsernameVerificationAuditLogs: Problem decoding username verification logs for this user: %v", err))
			return
		}
	}

	// Convert the verification username audit logs to response format.
	verificationAuditLogsResponse := []VerificationUsernameAuditLogResponse{}
	for _, verificationAuditLog := range verificationAuditLogs {
		verificationAuditLogsResponse = append(verificationAuditLogsResponse,
			VerificationUsernameAuditLogResponse{
				TimestampNanos:               verificationAuditLog.TimestampNanos,
				VerifierUsername:             verificationAuditLog.VerifierUsername,
				VerifierPublicKeyBase58Check: lib.PkToString(lib.PKIDToPublicKey(verificationAuditLog.VerifierPKID), fes.Params),
				VerifiedUsername:             verificationAuditLog.VerifiedUsername,
				VerifiedPublicKeyBase58Check: lib.PkToString(lib.PKIDToPublicKey(verificationAuditLog.VerifiedPKID), fes.Params),
				IsRemoval:                    verificationAuditLog.IsRemoval,
			})
	}
	res := AdminGetUsernameVerificationAuditLogsResponse{
		VerificationAuditLogs: verificationAuditLogsResponse,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetUsernameVerificationAuditLogs: Problem encoding response as JSON: #{err}"))
		return
	}
}

// AdminGetUserMetadataRequest...
type AdminGetUserAdminDataRequest struct {
	UserPublicKeyBase58Check string
}

// AdminGetUserMetadataResponse...
type AdminGetUserAdminDataResponse struct {
	// Profile Data
	Username string

	// Verifiers
	IsVerified                 bool
	LastVerifierPublicKey      string
	LastVerifyRemoverPublicKey string

	// White/Gray/Black list
	IsWhitelisted                 bool
	LastWhitelisterPublicKey      string
	LastWhitelistRemoverPublicKey string
	IsGraylisted                  bool
	LastGraylisterPublicKey       string
	LastGraylistRemoverPublicKey  string
	IsBlacklisted                 bool
	LastBlacklisterPublicKey      string
	LastBlacklistRemoverPublicKey string

	// Phone number verification
	PhoneNumber string
	Email       string

	// Referral Code
	ReferralHashBase58Check            string
	JumioStarterDeSoTxnHashBase58Check string
	ReferrerDeSoTxnHashBase58Check     string
}

// AdminGetUserAdminData gets the audit logs for a particular public key and their associated metadata from this node's
// global state. This does not use verifications fetched from other APIs.
func (fes *APIServer) AdminGetUserAdminData(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminGetUserAdminDataRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetUserMetadata: Problem parsing request body: %v", err))
		return
	}

	// Gather relevant information for logs
	userPublicKeyBase58Check := requestData.UserPublicKeyBase58Check
	userPublicKeyBytes, _, err := lib.Base58CheckDecode(userPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetUserMetadata: Failed decoding user public key: %v", err))
		return
	}
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetUserMetadata: Problem getting utxoView: %v", err))
		return
	}
	userPKIDEntry := utxoView.GetPKIDForPublicKey(userPublicKeyBytes)
	userPKID := userPKIDEntry.PKID
	profileEntry := utxoView.GetProfileEntryForPKID(userPKIDEntry.PKID)
	getPublicKeyFromPKID := func(pkid *lib.PKID) string {
		return lib.PkToString(lib.PKIDToPublicKey(pkid), fes.Params)
	}

	// Pull the verified map from global state and check if verified.
	isVerified := false
	lastVerifierPublicKey := ""
	lastVerifyRemoverPublicKey := ""
	if profileEntry != nil {
		username := strings.ToLower(string(profileEntry.Username))
		verifiedMap, err := fes.GetVerifiedUsernameToPKIDMapFromGlobalState()
		if err != nil {
			_AddInternalServerError(ww, fmt.Sprintf("AdminGetUserMetadata: Failed fetching verified map from database: %v", err))
			return
		}
		if verifiedMap == nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminGetUserMetadata: No verified user map in global state."))
			return
		}
		if _, hasEntry := verifiedMap[username]; hasEntry {
			isVerified = reflect.DeepEqual(verifiedMap[username], userPKID)
		}

		// Get the verification audit logs from global state.
		key := GlobalStateKeyForUsernameVerificationAuditLogs(string(profileEntry.Username))
		verificationUsernameAuditLogBytes, err := fes.GlobalState.Get(key)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminGetUserMetadata: Problem getting audit logs for this username: %v", err))
			return
		}
		verificationAuditLogs := []VerificationUsernameAuditLog{}
		if verificationUsernameAuditLogBytes != nil {
			err = gob.NewDecoder(bytes.NewReader(verificationUsernameAuditLogBytes)).Decode(&verificationAuditLogs)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("AdminGetUserMetadata: Problem decoding username verification logs for this user: %v", err))
				return
			}
		}

		// Iterate through the logs to and gather the most recent verification actions on this profile.
		for ii := range verificationAuditLogs {
			if !verificationAuditLogs[ii].IsRemoval && lastVerifierPublicKey == "" {
				lastVerifierPublicKey = getPublicKeyFromPKID(verificationAuditLogs[ii].VerifierPKID)
			} else if verificationAuditLogs[ii].IsRemoval && lastVerifyRemoverPublicKey == "" {
				lastVerifyRemoverPublicKey = getPublicKeyFromPKID(verificationAuditLogs[ii].VerifierPKID)
			}
		}
	}

	// Gather userMetadata
	userMetadata, err := fes.getUserMetadataFromGlobalState(userPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetUserMetadata: Problem fetching user metadata: %v", err))
		return
	}

	// Get username if a profile exists
	username := ""
	if profileEntry != nil {
		username = string(profileEntry.Username)
	}

	// Get whitelist information
	isWhitelisted := userMetadata.WhitelistPosts
	lastWhitelisterPublicKey := ""
	lastWhitelistRemoverPublicKey := ""
	if profileEntry != nil {
		filterLogs, err := fes.GetFilterAuditLogs(string(profileEntry.Username), Whitelist)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminGetUserMetadata: Problem fetching whitelist logs: %v", err))
			return
		}
		for ii := range filterLogs {
			if !filterLogs[ii].IsRemoval && lastWhitelisterPublicKey == "" {
				lastWhitelisterPublicKey = getPublicKeyFromPKID(filterLogs[ii].UpdaterPKID)
			} else if filterLogs[ii].IsRemoval && lastWhitelistRemoverPublicKey == "" {
				lastWhitelistRemoverPublicKey = getPublicKeyFromPKID(filterLogs[ii].UpdaterPKID)
			}
		}
	}

	// Gather graylist information
	isGraylisted := userMetadata.RemoveFromLeaderboard
	lastGraylisterPublicKey := ""
	lastGraylistRemoverPublicKey := ""
	if profileEntry != nil {
		filterLogs, err := fes.GetFilterAuditLogs(string(profileEntry.Username), Graylist)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminGetUserMetadata: Problem fetching graylist logs: %v", err))
			return
		}
		for ii := range filterLogs {
			if !filterLogs[ii].IsRemoval && lastGraylisterPublicKey == "" {
				lastGraylisterPublicKey = getPublicKeyFromPKID(filterLogs[ii].UpdaterPKID)
			} else if filterLogs[ii].IsRemoval && lastGraylistRemoverPublicKey == "" {
				lastGraylistRemoverPublicKey = getPublicKeyFromPKID(filterLogs[ii].UpdaterPKID)
			}
		}
	}

	// Gather blacklist information
	isBlacklisted := userMetadata.RemoveEverywhere
	lastBlacklisterPublicKey := ""
	lastBlacklistRemoverPublicKey := ""
	if profileEntry != nil {
		filterLogs, err := fes.GetFilterAuditLogs(string(profileEntry.Username), Blacklist)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminGetUserMetadata: Problem fetching whitelist logs: %v", err))
			return
		}
		for ii := range filterLogs {
			if !filterLogs[ii].IsRemoval && lastBlacklisterPublicKey == "" {
				lastBlacklisterPublicKey = getPublicKeyFromPKID(filterLogs[ii].UpdaterPKID)
			} else if filterLogs[ii].IsRemoval && lastBlacklistRemoverPublicKey == "" {
				lastBlacklistRemoverPublicKey = getPublicKeyFromPKID(filterLogs[ii].UpdaterPKID)
			}
		}
	}

	// Get verified phone/email information
	phoneNumber := userMetadata.PhoneNumber
	email := userMetadata.Email

	var jumioStarterDeSoTxnHashBase58Check string
	if userMetadata.JumioStarterDeSoTxnHashHex != "" {
		jumioStarterDeSoTxnHashBase58Check, err = fes.HashHexToBase58Check(userMetadata.JumioStarterDeSoTxnHashHex)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminGetUserMetadata: Problem converting JumioStarterDeSoTxnHashHex to base58check: %v", err))
			return
		}
	}

	var referrerDeSoTxnHashBase58Check string
	if userMetadata.ReferrerDeSoTxnHash != "" {
		referrerDeSoTxnHashBase58Check, err = fes.HashHexToBase58Check(userMetadata.ReferrerDeSoTxnHash)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminGetUserMetadata: Problem converting ReferrerDeSoTxnHash to base58check: %v", err))
			return
		}
	}

	res := AdminGetUserAdminDataResponse{
		Username:                           username,
		IsVerified:                         isVerified,
		LastVerifierPublicKey:              lastVerifierPublicKey,
		LastVerifyRemoverPublicKey:         lastVerifyRemoverPublicKey,
		IsWhitelisted:                      isWhitelisted,
		LastWhitelisterPublicKey:           lastWhitelisterPublicKey,
		LastWhitelistRemoverPublicKey:      lastWhitelistRemoverPublicKey,
		IsGraylisted:                       isGraylisted,
		LastGraylisterPublicKey:            lastGraylisterPublicKey,
		LastGraylistRemoverPublicKey:       lastGraylistRemoverPublicKey,
		IsBlacklisted:                      isBlacklisted,
		LastBlacklisterPublicKey:           lastBlacklisterPublicKey,
		LastBlacklistRemoverPublicKey:      lastBlacklistRemoverPublicKey,
		PhoneNumber:                        phoneNumber,
		Email:                              email,
		ReferralHashBase58Check:            userMetadata.ReferralHashBase58Check,
		JumioStarterDeSoTxnHashBase58Check: jumioStarterDeSoTxnHashBase58Check,
		ReferrerDeSoTxnHashBase58Check:     referrerDeSoTxnHashBase58Check,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetUserMetadata: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) HashHexToBase58Check(hashHex string) (base58Check string, _err error) {
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		return "", fmt.Errorf("AdminGetUserMetadata: Problem decoding JumioStarterDeSoTxnHashHex: %v", err)
	}
	return lib.PkToString(hashBytes, fes.Params), nil
}
