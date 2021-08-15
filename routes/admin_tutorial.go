package routes

import (
	"encoding/json"
	"fmt"
	"github.com/bitclout/core/lib"
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
	ResponseLimit int
	JWT       string
}


type AdminGetTutorialCreatorResponse struct {
	UndiscoveredPublicKeysBase58Check []string
	WellKnownPublicKeysBase58Check []string
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
		err := fes.GlobalStateDelete(prefix)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"AdminUpdateTutorialCreator: Error processing GlobalStateDelete: %v", err))
			return
		}
	} else {
		err := fes.GlobalStatePut(prefix, []byte{1})
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"AdminUpdateTutorialCreator: Error processing GlobalStatePut: %v", err))
			return
		}
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
	undiscoveredSeekKey := _GlobalStateKeyUndiscoveredTutorialCreators
	maxKeyLen := 1 + btcec.PubKeyBytesLenCompressed

	wellKnownKeys, _, err :=fes.GlobalStateSeek(
		wellKnownSeekKey,
		wellKnownSeekKey,
		maxKeyLen,
		300,
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
		300,
		true,
		false,
	)

	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AdminGetTutorialCreators: Problem seeking through global state keys: #{err}"))
		return
	}
	var undiscoveredLimit int
	if len(undiscoveredKeys) < requestData.ResponseLimit {
		undiscoveredLimit = len(undiscoveredKeys)
	} else {
		undiscoveredLimit = requestData.ResponseLimit
	}

	var undiscoveredPublicKeysBase58Check []string
	ShuffleKeys(&undiscoveredKeys)
	for _, dbKeyBytes := range undiscoveredKeys[:undiscoveredLimit] {
		// Chop the public key out of the db key.
		// The dbKeyBytes are: [One Prefix Byte][btcec.PubKeyBytesLenCompressed]
		publicKeyBytes := dbKeyBytes[1 :][:]
		publicKeyBase58Check := lib.Base58CheckEncode(publicKeyBytes, false, fes.Params)
		undiscoveredPublicKeysBase58Check = append(undiscoveredPublicKeysBase58Check, publicKeyBase58Check)
	}

	var wellKnownLimit int
	if len(wellKnownKeys) < requestData.ResponseLimit {
		wellKnownLimit = len(wellKnownKeys)
	} else {
		wellKnownLimit = requestData.ResponseLimit
	}
	var wellKnownPublicKeysBase58Check []string
	ShuffleKeys(&wellKnownKeys)
	for _, dbKeyBytes := range wellKnownKeys[:wellKnownLimit] {
		// Chop the public key out of the db key.
		// The dbKeyBytes are: [One Prefix Byte][btcec.PubKeyBytesLenCompressed]
		publicKeyBytes := dbKeyBytes[1 :][:]
		publicKeyBase58Check := lib.Base58CheckEncode(publicKeyBytes, false, fes.Params)
		wellKnownPublicKeysBase58Check = append(wellKnownPublicKeysBase58Check, publicKeyBase58Check)
	}

	res := AdminGetTutorialCreatorResponse{
		UndiscoveredPublicKeysBase58Check: undiscoveredPublicKeysBase58Check,
		WellKnownPublicKeysBase58Check: wellKnownPublicKeysBase58Check,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetUserMetadata: Problem encoding response as JSON: %v", err))
		return
	}
}
