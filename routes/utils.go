package routes

import (
	"encoding/hex"
	"github.com/deso-protocol/core/lib"
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
