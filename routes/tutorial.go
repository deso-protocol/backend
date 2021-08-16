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
	JWT       string
}


type GetTutorialCreatorResponse struct {
	UpAndComingProfileEntryResponses []ProfileEntryResponse
	WellKnownProfileEntryResponses []ProfileEntryResponse
}

func (fes *APIServer) GetTutorialCreators(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetTutorialCreatorsRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateTutorialCreator: Problem parsing request body: %v", err))
		return
	}
	wellKnownSeekKey := _GlobalStateKeyWellKnownTutorialCreators
	upAndComingSeekKey := _GlobalStateKeyUpAndComingTutorialCreators

	// Get a view
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetSingleProfile: Error getting utxoView: %v", err))
		return
	}
	upAndComingProfileEntryResponses, err := fes.GetFeaturedCreators(utxoView, requestData.ResponseLimit, upAndComingSeekKey)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetTutorialCreators: Problem getting up and coming tutorial creators: %v", err))
		return
	}
	wellKnownProfileEntryResponses, err := fes.GetFeaturedCreators(utxoView, requestData.ResponseLimit, wellKnownSeekKey)
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

func (fes *APIServer) GetFeaturedCreators(utxoView *lib.UtxoView, responseLimit int, seekKey []byte) (_profileEntryResponses []ProfileEntryResponse, _err error) {
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
		publicKeyBytes := dbKeyBytes[1 :][:]
		profileEntryy := utxoView.GetProfileEntryForPublicKey(publicKeyBytes)
		// Grab verified username map pointer
		verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
		if err != nil {
			return nil, fmt.Errorf("GetFeaturedCreators: Problem fetching verifiedMap: %v", err)
		}
		profileEntryResponse := _profileEntryToResponse(profileEntryy, fes.Params, verifiedMap, utxoView)
		profileEntryResponses = append(profileEntryResponses, *profileEntryResponse)
	}
	return profileEntryResponses, nil
}
