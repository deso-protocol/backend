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
	UpAndComingPublicKeysBase58Check []string
	WellKnownPublicKeysBase58Check []string
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

	upAndComingPublicKeysBase58Check, err := fes.GetFeaturedCreators(requestData.ResponseLimit, upAndComingSeekKey)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetTutorialCreators: Problem getting up and coming tutorial creators: %v", err))
		return
	}
	wellKnownPublicKeysBase58Check, err := fes.GetFeaturedCreators(requestData.ResponseLimit, wellKnownSeekKey)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetTutorialCreators: Problem getting well known tutorial creators: %v", err))
		return
	}

	res := GetTutorialCreatorResponse{
		UpAndComingPublicKeysBase58Check: upAndComingPublicKeysBase58Check,
		WellKnownPublicKeysBase58Check: wellKnownPublicKeysBase58Check,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetTutorialCreators: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) GetFeaturedCreators(responseLimit int, seekKey []byte) (_publicKeysBase58Check []string, _err error) {
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

	var publicKeysBase58Check []string
	ShuffleKeys(&keys)
	for _, dbKeyBytes := range keys[:publicKeysUpperBound] {
		// Chop the public key out of the db key.
		// The dbKeyBytes are: [One Prefix Byte][btcec.PubKeyBytesLenCompressed]
		publicKeyBytes := dbKeyBytes[1 :][:]
		publicKeyBase58Check := lib.Base58CheckEncode(publicKeyBytes, false, fes.Params)
		publicKeysBase58Check = append(publicKeysBase58Check, publicKeyBase58Check)
	}
	return publicKeysBase58Check, nil
}
