package routes

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type AdminUpdateTutorialCreatorRequest struct {
	PublicKeyBase58Check string
	IsRemoval bool
	IsWellKnown bool
	JWT       string
}

func (fes *APIServer) AdminUpdateTutorialCreator(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminUpdateTutorialCreatorRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateTutorialCreator: Problem parsing request body: %v", err))
		return
	}
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateTutorialCreator: error getting utxoview: %v", err))
		return
	}

	var userMetadata *UserMetadata
	userMetadata, err = fes.getUserMetadataFromGlobalState(requestData.PublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateTutorialCreator: error getting usermetadata for public key: %v", err))
		return
	}

	if !requestData.IsRemoval && (userMetadata.IsFeaturedTutorialWellKnownCreator || userMetadata.IsFeaturedTutorialUpAndComingCreator) {
		var tableCreatorIn string
		if userMetadata.IsFeaturedTutorialWellKnownCreator {
			tableCreatorIn = "well known"
		} else {
			tableCreatorIn = "up and coming"
		}
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateTutorialCreator: cannot add creator to %v, user already exists in %v", tableCreatorIn))
		return
	}

	pkid := utxoView.GetPKIDForPublicKey(userMetadata.PublicKey)
	if pkid == nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateTutorialCreator: No PKID found for public key: %v", requestData.PublicKeyBase58Check))
		return
	}
	var prefix []byte
	wellKnownPrefix := GlobalStateKeyWellKnownTutorialCreators(pkid.PKID)
	upAndComingPrefix := GlobalStateKeyUpAndComingTutorialCreators(pkid.PKID)
	if requestData.IsWellKnown {
		prefix = wellKnownPrefix
	} else {
		prefix = upAndComingPrefix
	}

	if requestData.IsRemoval {
		if err := fes.GlobalStateDelete(prefix); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"AdminUpdateTutorialCreator: Error processing GlobalStateDelete: %v", err))
			return
		}
	} else {
		if err := fes.GlobalStatePut(prefix, []byte{1}); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"AdminUpdateTutorialCreator: Error processing GlobalStatePut: %v", err))
			return
		}
	}

	// Reset all userMetadata values related to tutorial featured status.
	if requestData.IsWellKnown {
		userMetadata.IsFeaturedTutorialWellKnownCreator = !requestData.IsRemoval
		userMetadata.IsFeaturedTutorialUpAndComingCreator = false
	} else {
		userMetadata.IsFeaturedTutorialUpAndComingCreator = !requestData.IsRemoval
		userMetadata.IsFeaturedTutorialWellKnownCreator = false
	}

	if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminResetJumioForPublicKey: Problem putting updated user metadata in Global state: %v", err))
		return
	}
}
