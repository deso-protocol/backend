package routes

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"

	"github.com/deso-protocol/core/lib"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
)

// decodeBlockHashFromHex Decodes a BlockHash given a valid hex encoding. If the input does not represent a valid
// BlockHash, this returns the corresponding error
func decodeBlockHashFromHex(hexEncoding string) (*lib.BlockHash, error) {
	if hexEncoding == "" {
		return nil, errors.Errorf("expected valid hex encoded string but received empty string")
	}

	decodedBytes, err := hex.DecodeString(hexEncoding)
	if err != nil {
		return nil, errors.Errorf("error decoding block hash from hex encoded string %v: %v", hexEncoding, err)
	}

	if len(decodedBytes) != lib.HashSizeBytes {
		return nil, errors.Errorf("the hex encoded string %v does not decode into a valid block hash", hexEncoding)
	}
	return lib.NewBlockHash(decodedBytes), nil
}

func parseRequestBodyParams[TRequestParams any](request *http.Request) (*TRequestParams, error) {
	var requestParams TRequestParams

	decoder := json.NewDecoder(io.LimitReader(request.Body, MaxRequestBodySizeBytes))
	if err := decoder.Decode(&requestParams); err != nil {
		return nil, errors.Errorf("Error parsing request body: %v", err)
	}

	return &requestParams, nil
}

func parseRequestQueryParams[TRequestParams any](request *http.Request) (*TRequestParams, error) {
	var requestParams TRequestParams

	serializedJson, err := json.Marshal(mux.Vars(request))
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(serializedJson, requestParams); err != nil {
		return nil, err
	}

	return &requestParams, nil
}
