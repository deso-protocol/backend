package routes

import (
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"io"
	"net/http"
)

type AdminUpdateTutorialCreatorRequest struct {
	PublicKeyBase58Check string
	IsRemoval bool
	IsWellKnown bool
	JWT       string
}

type AdminGetTutorialCreatorsRequest struct {
	JWT       string
}


type AdminGetTutorialCreatorResponse struct {
	UndiscoveredPublicKeysBase58Check [][]byte
	WellKnownPublicKeysBase58Check [][]byte
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

	if !requestData.IsRemoval && ((userMetadata.IsFeaturedTutorialWellKnownCreator && requestData.IsWellKnown) || (userMetadata.IsFeaturedTutorialUndiscoveredCreator && !requestData.IsWellKnown)) {
		var currentList string
		var newList string
		if requestData.IsWellKnown {
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
	wellKnownPrefix := GlobalStateKeyWellKnownTutorialCreators(pkid.PKID)
	undiscoveredPrefix := GlobalStateKeyUndiscoveredTutorialCreators(pkid.PKID)
	if requestData.IsWellKnown {
		prefix = wellKnownPrefix
	} else {
		prefix = undiscoveredPrefix
	}

	// If adding a new creator, make sure they aren't already in the database
	if (!requestData.IsRemoval) {
		creatorExistsInWellKnown, err := fes.GlobalStateGet(wellKnownPrefix)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"AdminUpdateTutorialCreator: Error processing GlobalStateGet: %v", err))
			return
		}

	creatorExistsInUndiscovered, err := fes.GlobalStateGet(wellKnownPrefix)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"AdminUpdateTutorialCreator: Error processing GlobalStateGet: %v", err))
			return
		}

		if creatorExistsInWellKnown != nil || creatorExistsInUndiscovered != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"AdminUpdateTutorialCreator: User already exists in database"))
			return
		}
	}

	if requestData.IsRemoval {
		fes.GlobalStateDelete(prefix)
	} else {
		fes.GlobalStatePut(prefix, []byte{1})
	}

	// Reset all userMetadata values related to tutorial featured status.
	if requestData.IsWellKnown {
		userMetadata.IsFeaturedTutorialWellKnownCreator = !requestData.IsRemoval
		userMetadata.IsFeaturedTutorialUndiscoveredCreator = false
	} else {
		userMetadata.IsFeaturedTutorialUndiscoveredCreator = !requestData.IsRemoval
		userMetadata.IsFeaturedTutorialWellKnownCreator = false
	}

	if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminResetJumioForPublicKey: Problem putting updated user metadata in Global state: %v", err))
		return
	}
}

func (fes *APIServer) AdminGetTutorialCreators(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminGetTutorialCreatorsRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateTutorialCreator: Problem parsing request body: %v", err))
		return
	}
	wellKnownSeekKey := _GlobalStateKeyWellKnownTutorialCreators
	undiscoveredSeekKey := _GlobalStateKeyWellKnownTutorialCreators
	maxKeyLen := 1 + btcec.PubKeyBytesLenCompressed
	// TODO: Get all of them, do a randomized sample
	wellKnownKeys, _, err :=fes.GlobalStateSeek(
		wellKnownSeekKey,
		wellKnownSeekKey,
		maxKeyLen,
		5,
		false,
		false,
	)

	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AdminGetTutorialCreators: Problem seeking through global state keys: #{err}"))
		return
	}

	undiscoveredKeys, _, err := fes.GlobalStateSeek(
		undiscoveredSeekKey,
		undiscoveredSeekKey,
		maxKeyLen,
		5,
		true,
		false,
	)

	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AdminGetTutorialCreators: Problem seeking through global state keys: #{err}"))
		return
	}

	var undiscoveredPublicKeysBase58Check [][]byte
	for first, dbKeyBytes := range undiscoveredKeys {
		// Chop the public key out of the db key.
		// The dbKeyBytes are: [One Prefix Byte][btcec.PubKeyBytesLenCompressed]
		fmt.Printf("Here are the first, dbkeybytes, and chopped %v | %v | %v", first, dbKeyBytes, dbKeyBytes[1 :][:])
		undiscoveredPublicKeysBase58Check = append(undiscoveredPublicKeysBase58Check, dbKeyBytes[1 :][:])
		fmt.Printf("Here is the array %v", undiscoveredPublicKeysBase58Check)
	}

	var wellKnownPublicKeysBase58Check [][]byte
	for _, dbKeyBytes := range wellKnownKeys {
		// Chop the public key out of the db key.
		// The dbKeyBytes are: [One Prefix Byte][btcec.PubKeyBytesLenCompressed]
		wellKnownPublicKeysBase58Check = append(wellKnownPublicKeysBase58Check, dbKeyBytes[1 :][:])
	}

	fmt.Printf("Here are the undiscovered keys %v", undiscoveredPublicKeysBase58Check)

	res := AdminGetTutorialCreatorResponse{
		UndiscoveredPublicKeysBase58Check: undiscoveredPublicKeysBase58Check,
		WellKnownPublicKeysBase58Check: wellKnownPublicKeysBase58Check,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetUserMetadata: Problem encoding response as JSON: %v", err))
		return
	}
}
