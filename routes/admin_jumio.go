package routes

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"github.com/deso-protocol/backend/countries"
	"github.com/deso-protocol/core/lib"
	"github.com/golang/glog"
	"io"
	"net/http"
	"strings"
)

type AdminResetJumioRequest struct {
	PublicKeyBase58Check string
	Username             string
	JWT                  string
}

func (fes *APIServer) AdminResetJumioForPublicKey(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminResetJumioRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminResetJumioForPublicKey: Problem parsing request body: %v", err))
		return
	}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminResetJumioForPublicKey: error getting utxoview: %v", err))
		return
	}

	var userMetadata *UserMetadata
	if requestData.PublicKeyBase58Check != "" {
		userMetadata, err = fes.getUserMetadataFromGlobalState(requestData.PublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminResetJumioForPublicKey: error getting usermetadata for public key: %v", err))
			return
		}
	} else if requestData.Username != "" {
		profileEntry := utxoView.GetProfileEntryForUsername([]byte(requestData.Username))
		if profileEntry == nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminResetJumioForPublicKey: error getting profile entry for username %v", requestData.Username))
			return
		}
		userMetadata, err = fes.getUserMetadataFromGlobalStateByPublicKeyBytes(profileEntry.PublicKey)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminResetJumioForPublicKey: Problem getting UserMetadata from global state: %v", err))
			return
		}
	} else {
		_AddBadRequestError(ww, "AdminResetJumioForPublicKey: must provide either a public key or username")
		return
	}

	// Delete the Document Key from global state if it exists
	if userMetadata.JumioDocumentKey != nil {
		if err = fes.GlobalState.Delete(userMetadata.JumioDocumentKey); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminResetJumioForPublicKey: Error deleting key from global state: %v", err))
			return
		}
	}

	pkid := utxoView.GetPKIDForPublicKey(userMetadata.PublicKey)
	if pkid == nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminResetJumioForPublicKey: No PKID found for public key: %v", requestData.PublicKeyBase58Check))
		return
	}
	prefix := GlobalStatePrefixforPKIDTstampnanosToJumioTransaction(pkid.PKID)
	// Key is prefix + pkid + tstampnanos (8 bytes)
	maxKeyLen := 1 + len(pkid.PKID[:]) + 8
	keys, _, err := fes.GlobalState.Seek(prefix, prefix, maxKeyLen, 100, true, true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminResetJumioForPublicKey: Error seeking global state for verification attempts: %v", err))
		return
	}

	// Delete the history of jumio callback payloads.
	for _, key := range keys {
		if err = fes.GlobalState.Delete(key); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminResetJumioForPublicKey: Error deleting keys from global state: %v", err))
			return
		}
	}

	// Reset all userMetadata values related to jumio.
	userMetadata.JumioVerified = false
	userMetadata.JumioReturned = false
	userMetadata.JumioTransactionID = ""
	userMetadata.JumioDocumentKey = nil
	userMetadata.RedoJumio = true
	userMetadata.JumioStarterDeSoTxnHashHex = ""
	userMetadata.JumioShouldCompProfileCreation = false
	userMetadata.JumioFinishedTime = 0
	userMetadata.JumioInternalReference = ""
	userMetadata.MustCompleteTutorial = false
	if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminResetJumioForPublicKey: Problem putting updated user metadata in Global state: %v", err))
		return
	}
}

type AdminUpdateJumioDeSoRequest struct {
	JWT       string
	DeSoNanos uint64
}

type AdminUpdateJumioDeSoResponse struct {
	DeSoNanos uint64
}

func (fes *APIServer) AdminUpdateJumioDeSo(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminUpdateJumioDeSoRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateJumioDeSo: Problem parsing request body: %v", err))
		return
	}

	if err := fes.GlobalState.Put(
		GlobalStateKeyForJumioDeSoNanos(),
		lib.UintToBuf(requestData.DeSoNanos)); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateJumioDeSo: Problem putting premium basis points in global state: %v", err))
		return
	}

	res := AdminUpdateJumioDeSoResponse{
		DeSoNanos: requestData.DeSoNanos,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateJumioDeSo: Problem encoding response as JSON: %v", err))
		return
	}
}

type AdminUpdateJumioUSDCentsRequest struct {
	JWT      string
	USDCents uint64
}

type AdminUpdateJumioUSDCentsResponse struct {
	USDCents uint64
}

func (fes *APIServer) AdminUpdateJumioUSDCents(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminUpdateJumioUSDCentsRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateJumioDeSo: Problem parsing request body: %v", err))
		return
	}

	if err := fes.GlobalState.Put(
		GlobalStateKeyForJumioUSDCents(),
		lib.UintToBuf(requestData.USDCents)); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateJumioDeSo: Problem putting premium basis points in global state: %v", err))
		return
	}

	// Update the cache of all country level sign up bonus metadata explicitly in case
	// some are using the default amount
	fes.SetAllCountrySignUpBonusMetadata()

	res := AdminUpdateJumioUSDCentsResponse{
		USDCents: requestData.USDCents,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateJumioDeSo: Problem encoding response as JSON: %v", err))
		return
	}
}

type AdminSetJumioVerifiedRequest struct {
	PublicKeyBase58Check string
	Username             string
}

type AdminJumioCallback struct {
	PublicKeyBase58Check string
	Username             string
	CountryAlpha3        string
}

// AdminJumioCallback Note: this endpoint is mainly for testing purposes.
func (fes *APIServer) AdminJumioCallback(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminJumioCallback{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminJumioCallback: Problem parsing request body: %v", err))
		return
	}
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: error getting utxoview: %v", err))
		return
	}

	// Look up the user metadata
	var userMetadata *UserMetadata
	var publicKeyBytes []byte
	if requestData.PublicKeyBase58Check != "" {
		publicKeyBytes, _, err = lib.Base58CheckDecode(requestData.PublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminJumioCallback: Problem with lib.Base58CheckDecode: %v", err))
			return
		}
		userMetadata, err = fes.getUserMetadataFromGlobalState(requestData.PublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminJumioCallback: error getting usermetadata for public key: %v", err))
			return
		}
	} else if requestData.Username != "" {
		profileEntry := utxoView.GetProfileEntryForUsername([]byte(requestData.Username))
		if profileEntry == nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminJumioCallback: error getting profile entry for username %v", requestData.Username))
			return
		}
		publicKeyBytes = profileEntry.PublicKey
		userMetadata, err = fes.getUserMetadataFromGlobalStateByPublicKeyBytes(profileEntry.PublicKey)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminJumioCallback: Problem getting UserMetadata from global state: %v", err))
			return
		}
	} else {
		_AddBadRequestError(ww, "AdminJumioCallback: must provide either a public key or username")
		return
	}

	if userMetadata.JumioVerified {
		_AddBadRequestError(ww, fmt.Sprintf("AdminJumioCallback: User is already JumioVerified"))
		return
	}

	if _, exists := countries.Alpha3CountryCodes[requestData.CountryAlpha3]; requestData.CountryAlpha3 != "" && !exists {
		_AddBadRequestError(ww, fmt.Sprintf("AdminJumioCallback: Invalid country alpha-3: %s", requestData.CountryAlpha3))
		return
	}
	userMetadata.JumioReturned = true
	userMetadata, err = fes.JumioVerifiedHandler(userMetadata, "admin-jumio-call", requestData.CountryAlpha3, publicKeyBytes, utxoView)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminJumioCallback: Error in JumioVerifiedHandler: %v", err))
		return
	}

	if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminJumioCallback: Error updating user metadata in global state: %v", err))
		return
	}
}

type AdminUpdateJumioCountrySignUpBonusRequest struct {
	CountryCode             string
	CountryLevelSignUpBonus CountryLevelSignUpBonus
}

// AdminUpdateJumioCountrySignUpBonus allows admins to adjust the configuration of sign up bonuses at a country level
func (fes *APIServer) AdminUpdateJumioCountrySignUpBonus(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminUpdateJumioCountrySignUpBonusRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateJumioCountrySignUpBonusMetadata: "+
			"Problem parsing request body: %v", err))
		return
	}
	var countryCodeDetails countries.Alpha3CountryCodeDetails
	var exists bool
	// Validate the country code
	if countryCodeDetails, exists = countries.Alpha3CountryCodes[requestData.CountryCode]; !exists {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateJumioCountrySignUpBonus: "+
			"invalid country code: %v", requestData.CountryCode))
		return
	}

	// Encode the updated entry and stick it in the database.
	countryCodeSignUpBonusMetadataBuf := bytes.NewBuffer([]byte{})
	if err := gob.NewEncoder(countryCodeSignUpBonusMetadataBuf).Encode(
		requestData.CountryLevelSignUpBonus); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateJumioCountrySignUpBonus: "+
			"error encoding country level sign up bonus metadata: %v", err))
		return
	}

	// Update global state
	key := GlobalStateKeyForCountryCodeToCountrySignUpBonus(requestData.CountryCode)
	if err := fes.GlobalState.Put(key, countryCodeSignUpBonusMetadataBuf.Bytes()); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateJumioCountrySignUpBonus: "+
			"error putting country level sign up bonus metadata in global state: %v", err))
		return
	}
	// Update the cache
	fes.SetSingleCountrySignUpBonus(countryCodeDetails, requestData.CountryLevelSignUpBonus)
}

type GetAllCountryLevelSignUpBonusResponse struct {
	SignUpBonusMetadata        map[string]CountrySignUpBonusResponse
	DefaultSignUpBonusMetadata CountryLevelSignUpBonus
}

func (fes *APIServer) AdminGetAllCountryLevelSignUpBonuses(ww http.ResponseWriter, req *http.Request) {
	res := GetAllCountryLevelSignUpBonusResponse{
		SignUpBonusMetadata:        fes.AllCountryLevelSignUpBonuses,
		DefaultSignUpBonusMetadata: fes.GetDefaultJumioCountrySignUpBonus(),
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAllCountryLevelSignUpBonuses: Encode failed: %v", err))
		return
	}
}

type CountrySignUpBonusResponse struct {
	CountryLevelSignUpBonus CountryLevelSignUpBonus
	CountryCodeDetails      countries.Alpha3CountryCodeDetails
}

// SetAllCountrySignUpBonusMetadata goes through all countries in map of CountryCodes in utils and sets the sign-up
// bonus config in cache.
func (fes *APIServer) SetAllCountrySignUpBonusMetadata() {
	for countryCode, countryDetails := range countries.Alpha3CountryCodes {
		signUpBonus, err := fes.GetJumioCountrySignUpBonus(countryCode)
		if err != nil {
			glog.Errorf("SetAllCountrySignUpBonusMetadata: %v", err)
			// If there was an error, look up the current value in the map and use that.
			signUpBonus = fes.GetSingleCountrySignUpBonus(countryCode)
		}
		fes.SetSingleCountrySignUpBonus(countryDetails, signUpBonus)
	}
}

// SetSingleCountrySignUpBonus sets the sign up bonus configuration for a given country in the cached map.
func (fes *APIServer) SetSingleCountrySignUpBonus(countryDetails countries.Alpha3CountryCodeDetails,
	signUpBonus CountryLevelSignUpBonus) {
	fes.AllCountryLevelSignUpBonuses[countryDetails.Name] = CountrySignUpBonusResponse{
		CountryLevelSignUpBonus: signUpBonus,
		CountryCodeDetails:      countryDetails,
	}
}

// GetSingleCountrySignUpBonus returns the current value of the sign-up bonus configuration stored in the cached map.
func (fes *APIServer) GetSingleCountrySignUpBonus(countryCode string) CountryLevelSignUpBonus {
	// Convert country code to uppercase just in case.
	countryCodeDetails := countries.Alpha3CountryCodes[strings.ToUpper(countryCode)]
	// If we can't find the signup bonus from the map, return the default. Else, return the sign up bonus we found in
	// the map.
	if countrySignUpBonusResponse, exists := fes.AllCountryLevelSignUpBonuses[countryCodeDetails.Name]; !exists {
		return fes.GetDefaultJumioCountrySignUpBonus()
	} else {
		return countrySignUpBonusResponse.CountryLevelSignUpBonus
	}
}
