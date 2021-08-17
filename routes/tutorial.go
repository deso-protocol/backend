package routes

import (
	"encoding/json"
	"fmt"
	"github.com/bitclout/core/lib"
	"github.com/btcsuite/btcd/btcec"
	"io"
	"net/http"
)

type GetTutorialCreatorsRequest struct {
	ResponseLimit int
}


type GetTutorialCreatorResponse struct {
	UpAndComingProfileEntryResponses []ProfileEntryResponse
	WellKnownProfileEntryResponses []ProfileEntryResponse
}

func (fes *APIServer) GetTutorialCreators(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetTutorialCreatorsRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetTutorialCreators: Problem parsing request body: %v", err))
		return
	}
	wellKnownSeekKey := _GlobalStateKeyWellKnownTutorialCreators
	upAndComingSeekKey := _GlobalStateKeyUpAndComingTutorialCreators

	// Get a view
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetTutorialCreators: Error getting utxoView: %v", err))
		return
	}
	// Grab verified username map pointer
	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetTutorialCreators: Problem fetching verifiedMap: %v", err))
		return
	}
	upAndComingProfileEntryResponses, err := fes.GetFeaturedCreators(utxoView, requestData.ResponseLimit, upAndComingSeekKey, verifiedMap)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetTutorialCreators: Problem getting up and coming tutorial creators: %v", err))
		return
	}
	wellKnownProfileEntryResponses, err := fes.GetFeaturedCreators(utxoView, requestData.ResponseLimit, wellKnownSeekKey, verifiedMap)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetTutorialCreators: Problem getting well known tutorial creators: %v", err))
		return
	}

	res := GetTutorialCreatorResponse{
		UpAndComingProfileEntryResponses: upAndComingProfileEntryResponses,
		WellKnownProfileEntryResponses:   wellKnownProfileEntryResponses,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetTutorialCreators: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) GetFeaturedCreators(utxoView *lib.UtxoView, responseLimit int, seekKey []byte, verifiedMap map[string]*lib.PKID) (_profileEntryResponses []ProfileEntryResponse, _err error) {
	maxKeyLen := 1 + btcec.PubKeyBytesLenCompressed
	keys, _, err := fes.GlobalStateSeek(
		seekKey,
		seekKey,
		maxKeyLen,
		300,
		true,
		false,
	)

	if err != nil {
		return nil, fmt.Errorf("GetFeaturedCreators: Problem seeking through global state keys: #{err}")
	}

	var publicKeysUpperBound int
	if len(keys) < responseLimit {
		publicKeysUpperBound = len(keys)
	} else {
		publicKeysUpperBound = responseLimit
	}

	var profileEntryResponses []ProfileEntryResponse
	ShuffleKeys(&keys)
	for _, dbKeyBytes := range keys[:publicKeysUpperBound] {
		// Chop the public key out of the db key.
		// The dbKeyBytes are: [One Prefix Byte][btcec.PubKeyBytesLenCompressed]
		publicKeyBytes := dbKeyBytes[1:][:]
		profileEntryy := utxoView.GetProfileEntryForPublicKey(publicKeyBytes)
		profileEntryResponse := _profileEntryToResponse(profileEntryy, fes.Params, verifiedMap, utxoView)
		profileEntryResponses = append(profileEntryResponses, *profileEntryResponse)
	}
	return profileEntryResponses, nil
}

type StartOrSkipTutorialRequest struct {
	PublicKeyBase58Check string
	JWT string
	IsSkip bool
}

func (fes *APIServer) StartOrSkipTutorial(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := StartOrSkipTutorialRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"StartOrSkipTutorial: Problem parsing request body: %v", err))
		return
	}
	isValid, err := fes.ValidateJWT(requestData.PublicKeyBase58Check, requestData.JWT)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("StartOrSkipTutorialioBegin: Error validating JWT: %v", err))
		return
	}
	if !isValid {
		_AddBadRequestError(ww, fmt.Sprintf("StartOrSkipTutorial: Invalid token: %v", err))
		return
	}

	userMetadata, err := fes.getUserMetadataFromGlobalState(requestData.PublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("StartOrSkipTutorial: Error getting user metadata from global state: %v", err))
		return
	}

	if requestData.IsSkip && userMetadata.TutorialStatus != EMPTY {
		_AddBadRequestError(ww, fmt.Sprintf("StartOrSkipTutorial: Can only skip tutorial from empty state"))
		return
	}
	if !requestData.IsSkip && userMetadata.TutorialStatus != EMPTY && userMetadata.TutorialStatus != SKIPPED {
		_AddBadRequestError(ww, fmt.Sprintf("StartOrSkipTutorial: Can only start tutorial from empty or skipped state"))
		return
	}

	if requestData.IsSkip {
		userMetadata.TutorialStatus = SKIPPED
	} else {
		userMetadata.TutorialStatus = STARTED
	}
	if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("StartOrSkipTutorial: err putting user metdata in global state: %v", err))
		return
	}
}
