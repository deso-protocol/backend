package routes

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/deso-protocol/core/lib"
)

type GetTutorialCreatorsRequest struct {
	ResponseLimit int
}

type UpdateTutorialStatusRequest struct {
	PublicKeyBase58Check                string
	TutorialStatus                      TutorialStatus
	CreatorPurchasedInTutorialPublicKey string
	ClearCreatorCoinPurchasedInTutorial bool
	JWT                                 string
}

type GetTutorialCreatorResponse struct {
	UpAndComingProfileEntryResponses []ProfileEntryResponse
	WellKnownProfileEntryResponses   []ProfileEntryResponse
}

func (fes *APIServer) GetTutorialCreators(ww http.ResponseWriter, req *http.Request) {
	fes.GetTutorialCreatorsByFR(ww, req, false)
}

func (fes *APIServer) UpdateTutorialStatus(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := UpdateTutorialStatusRequest{}

	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminResetTutorialStatus: Problem parsing request body: %v", err))
		return
	}
	// Validate the JWT is legit.
	isValid, err := fes.ValidateJWT(requestData.PublicKeyBase58Check, requestData.JWT)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetReferralInfoForUser: Error validating JWT: %v", err))
		return
	}
	if !isValid {
		_AddBadRequestError(ww, fmt.Sprintf("GetReferralInfoForUser: Invalid token: %v", err))
		return
	}

	// Get a view
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateTutorialStatus: Error getting utxoView: %v", err))
		return
	}

	userMetadata, err := fes.getUserMetadataFromGlobalState(requestData.PublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateTutorialStatus: Error getting user metadata from global state: %v", err))
		return
	}

	if userMetadata.TutorialStatus != requestData.TutorialStatus {
		userMetadata.TutorialStatus = requestData.TutorialStatus
		// We need to set this to false once the user completes the tutorial, so any actions aren't blocked
		if requestData.TutorialStatus == COMPLETE {
			userMetadata.MustCompleteTutorial = false
		}
		// If a user is skipping the buy step, we need to set this to 0
		if requestData.ClearCreatorCoinPurchasedInTutorial {
			userMetadata.CreatorCoinsPurchasedInTutorial = 0
		}
		if requestData.CreatorPurchasedInTutorialPublicKey != "" {
			CreatorPurchasedInTutorialPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.CreatorPurchasedInTutorialPublicKey)
			if err != nil || len(CreatorPurchasedInTutorialPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
				_AddBadRequestError(ww, fmt.Sprintf("UpdateTutorialStatus: Failed to decode public key bytes"))
				return
			}
			pkid := utxoView.GetPKIDForPublicKey(CreatorPurchasedInTutorialPublicKeyBytes)
			if pkid == nil {
				_AddBadRequestError(ww, fmt.Sprintf("UpdateTutorialStatus: No PKID found for public key: %v", requestData.CreatorPurchasedInTutorialPublicKey))
				return
			}
			userMetadata.CreatorPurchasedInTutorialPKID = pkid.PKID
		}
		if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminResetTutorialStatus: Error putting user metadata in global state: %v", err))
			return
		}
	}
}

func (fes *APIServer) GetTutorialCreatorsByFR(ww http.ResponseWriter, req *http.Request, disregardFR bool) {
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

	upAndComingProfileEntryResponses, err := fes.GetFeaturedCreators(utxoView, requestData.ResponseLimit, upAndComingSeekKey, disregardFR)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetTutorialCreators: Problem getting up and coming tutorial creators: %v", err))
		return
	}
	wellKnownProfileEntryResponses, err := fes.GetFeaturedCreators(utxoView, requestData.ResponseLimit, wellKnownSeekKey, disregardFR)
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

func ShuffleKeys(records *[][]byte) {
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(*records), func(i, j int) {
		(*records)[i], (*records)[j] = (*records)[j], (*records)[i]
	})
}

func (fes *APIServer) GetFeaturedCreators(utxoView *lib.UtxoView, responseLimit int, seekKey []byte, disregardFR bool) (_profileEntryResponses []ProfileEntryResponse, _err error) {
	maxKeyLen := 1 + btcec.PubKeyBytesLenCompressed
	keys, _, err := fes.GlobalState.Seek(
		seekKey,
		seekKey,
		maxKeyLen,
		300,
		true,
		false,
	)

	if err != nil {
		return nil, fmt.Errorf("GetFeaturedCreators: Problem seeking through global state keys: %v", err)
	}

	var publicKeysUpperBound int
	if len(keys) < responseLimit {
		publicKeysUpperBound = len(keys)
	} else {
		publicKeysUpperBound = responseLimit
	}

	var profileEntryResponses []ProfileEntryResponse
	ShuffleKeys(&keys)
	ii := 0
	for len(profileEntryResponses) <= publicKeysUpperBound && ii < len(keys) {
		dbKeyBytes := keys[ii]
		// Chop the PKID out of the db key.
		// The dbKeyBytes are: [One Prefix Byte][btcec.PubKeyBytesLenCompressed]
		pkidBytes := dbKeyBytes[1:]
		profileEntry := utxoView.GetProfileEntryForPKID(lib.NewPKID(pkidBytes))

		// Only add creator if FR is 10% or less
		if profileEntry != nil && (profileEntry.CoinEntry.CreatorBasisPoints <= 10*100 || disregardFR) {
			profileEntryResponse := fes._profileEntryToResponse(profileEntry, utxoView)
			profileEntryResponses = append(profileEntryResponses, *profileEntryResponse)
		}
		ii++
	}
	return profileEntryResponses, nil
}

type StartOrSkipTutorialRequest struct {
	PublicKeyBase58Check string
	JWT                  string
	IsSkip               bool
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
		_AddBadRequestError(ww, fmt.Sprintf("StartOrSkipTutorial: Error validating JWT: %v", err))
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

	if isAdmin, _ := fes.UserAdminStatus(requestData.PublicKeyBase58Check); !isAdmin && requestData.IsSkip && userMetadata.MustCompleteTutorial {
		_AddBadRequestError(ww, fmt.Sprintf("StartOrSkipTutorial: You are not permitted to skip the tutorial"))
		return
	}

	if !requestData.IsSkip && userMetadata.TutorialStatus != EMPTY && userMetadata.TutorialStatus != SKIPPED && userMetadata.TutorialStatus != COMPLETE {
		_AddBadRequestError(ww, fmt.Sprintf("StartOrSkipTutorial: Can only start tutorial from empty, skipped, or completed state"))
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
