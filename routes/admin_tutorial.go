package routes

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type AdminUpdateTutorialCreatorRequest struct {
	PublicKeyBase58Check string
	isRemoval bool
	isWellKnown bool
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

	if !requestData.isRemoval && ((userMetadata.IsFeaturedTutorialWellKnownCreator && requestData.isWellKnown) || (userMetadata.IsFeaturedTutorialUndiscoveredCreator && !requestData.isWellKnown)) {
		var currentList string
		var newList string
		if requestData.isWellKnown {
			newList = "well known creators"
			currentList = "undiscovered creators"
		} else {
			currentList = "well known creators"
			newList = "undiscovered creators"
		}
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateTutorialCreator: cannot add creator to %v, user already exists in %v", newList, currentList))
		return
	}

	pkid := utxoView.GetPKIDForPublicKey(userMetadata.PublicKey)
	if pkid == nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateTutorialCreator: No PKID found for public key: %v", requestData.PublicKeyBase58Check))
		return
	}
	var prefix []byte
	if requestData.isWellKnown {
		prefix = GlobalStateKeyWellKnownTutorialCreators(pkid.PKID)
	} else {
		prefix = GlobalStateKeyUndiscoveredTutorialCreators(pkid.PKID)
	}

	if requestData.isRemoval {
		fes.GlobalStateDelete(prefix)
	} else {
		fes.GlobalStatePut(prefix, nil)
	}

	// Reset all userMetadata values related to tutorial featured status.
	if requestData.isWellKnown {
		userMetadata.IsFeaturedTutorialWellKnownCreator = !requestData.isRemoval
		userMetadata.IsFeaturedTutorialUndiscoveredCreator = false
	} else {
		userMetadata.IsFeaturedTutorialUndiscoveredCreator = !requestData.isRemoval
		userMetadata.IsFeaturedTutorialWellKnownCreator = false
	}

	if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminResetJumioForPublicKey: Problem putting updated user metadata in Global state: %v", err))
		return
	}
}
