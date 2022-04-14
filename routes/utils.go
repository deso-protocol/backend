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
		return &lib.ZeroBlockHash, errors.Errorf("expected valid hex encoded string but received empty string")
	}

	decodedBytes, err := hex.DecodeString(hexEncoding)
	if err != nil {
		return &lib.ZeroBlockHash, errors.Errorf("error decoding block hash hex: %v", hexEncoding)
	}

	if len(decodedBytes) != lib.HashSizeBytes {
		return &lib.ZeroBlockHash, errors.Errorf("block hash hex %v does not decode into a valid block has", hexEncoding)
	}
	return lib.NewBlockHash(decodedBytes), nil
}
