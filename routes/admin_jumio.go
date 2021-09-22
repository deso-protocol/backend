package routes

import (
	"encoding/json"
	"fmt"
	"github.com/deso-protocol/core/lib"
	"io"
	"net/http"
)

type AdminResetJumioRequest struct {
	PublicKeyBase58Check string
	Username             string
	JWT       string
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
		if err = fes.GlobalStateDelete(userMetadata.JumioDocumentKey); err != nil {
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
	keys, _, err := fes.GlobalStateSeek(prefix, prefix, maxKeyLen, 100, true, true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminResetJumioForPublicKey: Error seeking global state for verification attempts: %v", err))
		return
	}

	// Delete the history of jumio callback payloads.
	for _, key := range keys {
		if err = fes.GlobalStateDelete(key); err != nil {
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
	JWT string
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

	if err := fes.GlobalStatePut(
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

type AdminSetJumioVerifiedRequest struct {
	PublicKeyBase58Check string
	Username             string
}

type AdminJumioCallback struct {
	PublicKeyBase58Check string
	Username             string
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
	userMetadata.JumioReturned = true
	userMetadata, err = fes.JumioVerifiedHandler(userMetadata, "admin-jumio-call", publicKeyBytes, utxoView)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminJumioCallback: Error in JumioVerifiedHandler: %v", err))
		return
	}

	if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminJumioCallback: Error updating user metadata in global state: %v", err))
		return
	}
}
