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
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateTutorialCreator: cannot add creator, user already exists in %v index", tableCreatorIn))
		return
	}

	pkid := utxoView.GetPKIDForPublicKey(userMetadata.PublicKey)
	if pkid == nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateTutorialCreator: No PKID found for public key: %v", requestData.PublicKeyBase58Check))
		return
	}
	var key []byte
	if requestData.IsWellKnown {
		key = GlobalStateKeyWellKnownTutorialCreators(pkid.PKID)
	} else {
		key = GlobalStateKeyUpAndComingTutorialCreators(pkid.PKID)
	}

	if requestData.IsRemoval {
		if err = fes.GlobalStateDelete(key); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"AdminUpdateTutorialCreator: Error processing GlobalStateDelete: %v", err))
			return
		}
	} else {
		if err = fes.GlobalStatePut(key, []byte{1}); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"AdminUpdateTutorialCreator: Error processing GlobalStatePut: %v", err))
			return
		}
	}

	// Reset all userMetadata values related to tutorial featured status.
	userMetadata.IsFeaturedTutorialWellKnownCreator = requestData.IsWellKnown && !requestData.IsRemoval
	userMetadata.IsFeaturedTutorialUpAndComingCreator = !requestData.IsWellKnown && !requestData.IsRemoval

	if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateTutorialCreator: Problem putting updated user metadata in Global state: %v", err))
		return
	}
}

type AdminResetTutorialStatusRequest struct {
	PublicKeyBase58Check string
}

func (fes *APIServer) AdminResetTutorialStatus(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminResetTutorialStatusRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminResetTutorialStatus: Problem parsing request body: %v", err))
		return
	}

	userMetadata, err := fes.getUserMetadataFromGlobalState(requestData.PublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminResetTutorialStatus: Error getting user metadata from global state: %v", err))
		return
	}

	if userMetadata.TutorialStatus != EMPTY || userMetadata.CreatorPurchasedInTutorialPKID != nil || userMetadata.CreatorCoinsPurchasedInTutorial != 0 {
		userMetadata.TutorialStatus = EMPTY
		userMetadata.CreatorPurchasedInTutorialPKID = nil
		userMetadata.CreatorCoinsPurchasedInTutorial = 0
		if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminResetTutorialStatus: Error putting user metadata in global state: %v", err))
			return
		}
	}
}

func (fes *APIServer) AdminGetTutorialCreators(ww http.ResponseWriter, req *http.Request) {
	fes.GetTutorialCreatorsByFR(ww, req, true)
}
