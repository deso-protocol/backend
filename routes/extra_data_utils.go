package routes

import (
	"encoding/hex"
	"github.com/deso-protocol/core/lib"
	"strconv"
)

type DecoderFunc func([]byte) string

type ExtraDataDecoder struct {
	Key     string
	Decoder DecoderFunc
}

// GetExtraDataDecoderFunc Values in ExtraData field
// in transaction may have special encoding. In such cases
// we'll need specialized decoders too
func GetExtraDataDecoderFunc(key string) DecoderFunc {
	var decoders = []ExtraDataDecoder{
		{
			lib.DiamondLevelKey,
			ByteArrTo64BitInt,
		},
	}
	for _, decoder := range decoders {
		if decoder.Key == key {
			return decoder.Decoder
		}
	}
	// Default, just return hex encoding for bytes
	return hex.EncodeToString
}

func ByteArrTo64BitInt(bytes []byte) string {
	var decoded, _ = lib.Varint(bytes)
	return strconv.FormatInt(decoded, 10)
}
