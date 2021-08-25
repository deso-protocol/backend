package routes

import (
	"encoding/json"
	"fmt"
	"github.com/bitclout/core/lib"
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
	userMetadata.JumioStarterBitCloutTxnHashHex = ""
	userMetadata.JumioShouldCompProfileCreation = false
	userMetadata.JumioFinishedTime = 0
	userMetadata.JumioInternalReference = ""
	userMetadata.MustCompleteTutorial = false
	if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminResetJumioForPublicKey: Problem putting updated user metadata in Global state: %v", err))
		return
	}
}

type AdminUpdateJumioBitCloutRequest struct {
	JWT string
	BitCloutNanos uint64
}

type AdminUpdateJumioBitCloutResponse struct {
	BitCloutNanos uint64
}

func (fes *APIServer) AdminUpdateJumioBitClout(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminUpdateJumioBitCloutRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateJumioBitClout: Problem parsing request body: %v", err))
		return
	}

	if err := fes.GlobalStatePut(
		GlobalStateKeyForJumioBitCloutNanos(),
		lib.UintToBuf(requestData.BitCloutNanos)); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateJumioBitClout: Problem putting premium basis points in global state: %v", err))
		return
	}

	res := AdminUpdateJumioBitCloutResponse{
		BitCloutNanos: requestData.BitCloutNanos,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateJumioBitClout: Problem encoding response as JSON: %v", err))
		return
	}
}
