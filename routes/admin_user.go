package routes

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"github.com/bitclout/core/lib"
	"github.com/btcsuite/btcd/btcec"
	"github.com/pkg/errors"
	"io"
	"net/http"
	"strings"
	"time"
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
}

// AdminUpdateUserGlobalMetadataResponse ...
type AdminUpdateUserGlobalMetadataResponse struct{}

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

	// If we do not have a public key, try and get one from the username.
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
		phoneNumberMetadata, err := fes.getPhoneNumberMetadataFromGlobalState(userMetadata.PhoneNumber)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateUserGlobalMetadata: Error getting phone number metadata: %v", err))
			return
		}
		phoneNumberMetadata.PublicKey = nil
		err = fes.putPhoneNumberMetadataInGlobalState(phoneNumberMetadata)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateUserGlobalMetadata: Error saving phone number metadata: %v", err))
			return
		}

		// If we made it this far we were successful at removing phone metadata, return without error.
		res := AdminUpdateUserGlobalMetadataResponse{}
		if err := json.NewEncoder(ww).Encode(res); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateUserGlobalMetadata: Problem encoding response as JSON: %v", err))
			return
		}
		return
	}

	// Now that we have a userMetadata object, update it based on the request.
	if requestData.IsBlacklistUpdate {
		userMetadata.RemoveEverywhere = requestData.RemoveEverywhere
		blacklistKey := GlobalStateKeyForBlacklistedProfile(userPublicKeyBytes)
		if userMetadata.RemoveEverywhere {
			err = fes.GlobalStatePut(blacklistKey, lib.IsBlacklisted)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateUserGlobalMetadata: Problem updating blacklist: %v", err))
			}
		} else {
			err = fes.GlobalStateDelete(blacklistKey)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateUserGlobalMetadata: Problem deleting from blacklist: %v", err))
				return
			}
		}
		// We need to update global state's list of blacklisted users.

		userMetadata.RemoveFromLeaderboard = requestData.RemoveFromLeaderboard
		graylistkey := GlobalStateKeyForGraylistedProfile(userPublicKeyBytes)
		if userMetadata.RemoveFromLeaderboard {
			// We need to update global state's list of graylisted users.
			err = fes.GlobalStatePut(graylistkey, lib.IsGraylisted)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateUserGlobalMetadata: Problem updating graylist: %v", err))
				return
			}
		} else {
			err = fes.GlobalStateDelete(graylistkey)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateUserGlobalMetadata: Problem deleting from graylist: %v", err))
				return
			}
		}
	} else if requestData.IsWhitelistUpdate {
		userMetadata.WhitelistPosts = requestData.WhitelistPosts
	}

	// Encode the updated entry and stick it in the database.
	err = fes.putUserMetadataInGlobalState(userMetadata)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateUserGlobalMetadata: Problem putting updated user metadata: %v", err))
		return
	}

	// If we made it this far we were successful, return without error.
	res := AdminUpdateUserGlobalMetadataResponse{}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateUserGlobalMetadata: Problem encoding response as JSON: %v", err))
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

// AdminGetAllUserGlobalMetadata ...
func (fes *APIServer) AdminGetAllUserGlobalMetadata(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminGetAllUserGlobalMetadataRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetAllUserGlobalMetadata: Problem parsing request body: %v", err))
		return
	}

	// Seek the global state for the user metadata prefix.
	seekKey := _GlobalStatePrefixPublicKeyToUserMetadata
	keys, vals, err := fes.GlobalStateSeek(seekKey /*startPrefix*/, seekKey, /*validForPrefix*/
		0 /*maxKeyLen -- ignored since reverse is false*/, requestData.NumToFetch, false, /*reverse*/
		true /*fetchValues*/)
	if err != nil {
		_AddInternalServerError(
			ww, fmt.Sprintf("AdminGetAllUserGlobalMetadata: %v", err))
		return
	}

	// Sanity check that we got an appropriate number of keys and values.
	if len(keys) != len(vals) {
		_AddInternalServerError(
			ww, "AdminGetAllUserGlobalMetadata: GlobalState keys/vals length mismatch.")
		return
	}

	// Get a view that includes the transaction we just processed.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddInternalServerError(
			ww, fmt.Sprintf("AdminGetAllUserGlobalMetadata: problem with GetAugmentedUniversalView: %v", err))
		return
	}

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
			_AddBadRequestError(ww, fmt.Sprintf("AdminGetAllUserGlobalMetadata: Problem getting metadata from global state: %v", err))
			return
		}

		publicKeyToUserMetadata[pubKeyString] = &userMetadata

		profileEntry := utxoView.GetProfileEntryForPublicKey(pkBytes)
		if profileEntry != nil {
			publicKeyToUsername[pubKeyString] = string(profileEntry.Username)
		}
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
		UserProfileEntryResponse: _profileEntryToResponse(profileEntry, fes.Params, nil, utxoView),
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetUserGlobalMetadata: Problem encoding response as JSON: %v", err))
		return
	}
}

// Add a new audit log record to the history of username verification audit logs.
func (fes *APIServer) UpdateUsernameVerificationAuditLog(usernameToVerify string, pkidEntryToVerify *lib.PKIDEntry, isRemoval bool, verifierPublicKeyBase58Check string, utxoView *lib.UtxoView) (_err error) {
	verificationAuditLogs := []VerificationUsernameAuditLog{}
	// Get the key to look up the current list of audit logs for this username
	verificationAuditLogKey := GlobalStateKeyForUsernameVerificationAuditLogs(usernameToVerify)
	verificationAuditLogBytes, err := fes.GlobalStateGet(verificationAuditLogKey)
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
	err = fes.GlobalStatePut(verificationAuditLogKey, verificationDataBuf.Bytes())
	if err != nil {
		return errors.Wrap(fmt.Errorf("AdminGrantVerificationBadge: Failed to update verification audit logs"), "")
	}
	return nil
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
// This endpoint enables anyone with access to a node's shared secret to grant a verifiaction
// badge to a particular username.
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
	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
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
	gob.NewEncoder(metadataDataBuf).Encode(verifiedMapStruct)
	err = fes.GlobalStatePut(_GlobalStatePrefixForVerifiedMap, metadataDataBuf.Bytes())
	if err != nil {
		_AddBadRequestError(ww, "AdminGrantVerificationBadge: Failed placing new verification map into the database.")
		return
	}

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
	verifiedMapBytes, err := fes.GlobalStateGet(_GlobalStatePrefixForVerifiedMap)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminRemoveVerificationBadge: Failed fetching verified map from database."))
		return
	}
	verifiedMapStruct := VerifiedUsernameToPKID{}
	if verifiedMapBytes != nil {
		err = gob.NewDecoder(bytes.NewReader(verifiedMapBytes)).Decode(&verifiedMapStruct)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminRemoveVerificationBadge: Failed decoding verified map from database."))
			return
		}
	} else {
		// If we don't find a map in global state, return early.
		res := AdminRemoveVerificationBadgeResponse{
			Message: "Couldn't find a verified username map in global state.  Nothing to delete.",
		}
		if err := json.NewEncoder(ww).Encode(res); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminRemoveVerificationBadge: Problem encoding response as "+
				"JSON: %v", err))
			return
		}
		return
	}

	// Add a new audit log for this verification removal request.
	err = fes.UpdateUsernameVerificationAuditLog(usernameToRemove, pkidEntryToUnverify, true, requestData.AdminPublicKey, utxoView)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminRemoveVerificationBadge: error updating audit log of username verification: %v", err))
		return
	}

	// Kill the key in our map.
	delete(verifiedMapStruct.VerifiedUsernameToPKID, strings.ToLower(usernameToRemove))

	// Encode the updated entry and stick it in the database.
	metadataDataBuf := bytes.NewBuffer([]byte{})
	gob.NewEncoder(metadataDataBuf).Encode(verifiedMapStruct)
	err = fes.GlobalStatePut(_GlobalStatePrefixForVerifiedMap, metadataDataBuf.Bytes())
	if err != nil {
		_AddBadRequestError(ww, "AdminRemoveVerificationBadge: Failed placing new verification map into the database.")
		return
	}

	// Return a success message
	res := AdminRemoveVerificationBadgeResponse{
		Message: "Successfully removed verification badge for: " + usernameToRemove,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
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

// AdminGetVerifiedUsers
//
// Gets a list of all verified users.
func (fes *APIServer) AdminGetVerifiedUsers(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminGetVerifiedUsersRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetVerifiedUsers: Problem parsing request body: %v", err))
		return
	}

	// Pull the verified map from global state
	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
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

// Get the verification audit logs for a given username
func (fes *APIServer) AdminGetUsernameVerificationAuditLogs(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminGetUsernameVerificationAuditLogsRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetVerifiedUsers: Problem parsing request body: %v", err))
		return
	}
	// Get the verification audit logs from global state.
	key := GlobalStateKeyForUsernameVerificationAuditLogs(requestData.Username)
	verificationUsernameAuditLogBytes, err := fes.GlobalStateGet(key)
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
