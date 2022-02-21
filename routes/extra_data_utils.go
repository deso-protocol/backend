package routes

import (
	"encoding/hex"
	"fmt"
	"github.com/deso-protocol/core/lib"
	"strconv"
)

type ExtraDataDecoder func([]byte) string

var ExtraDataKeyToDecoder = map[string]ExtraDataDecoder{
	lib.RepostedPostHash:  hex.EncodeToString,
	lib.IsQuotedRepostKey: Decode64BitIntString,

	lib.USDCentsPerBitcoinKey:      Decode64BitIntString,
	lib.MinNetworkFeeNanosPerKBKey: Decode64BitIntString,
	lib.CreateProfileFeeNanosKey:   Decode64BitIntString,
	lib.CreateNFTFeeNanosKey:       Decode64BitIntString,
	lib.MaxCopiesPerNFTKey:         Decode64BitIntString,

	lib.ForbiddenBlockSignaturePubKeyKey: hex.EncodeToString,

	lib.DiamondLevelKey:    Decode64BitIntString,
	lib.DiamondPostHashKey: hex.EncodeToString,

	lib.DerivedPublicKey: hex.EncodeToString,

	lib.MessagingPublicKey:             hex.EncodeToString,
	lib.SenderMessagingPublicKey:       hex.EncodeToString,
	lib.SenderMessagingGroupKeyName:    hex.EncodeToString,
	lib.RecipientMessagingPublicKey:    hex.EncodeToString,
	lib.RecipientMessagingGroupKeyName: hex.EncodeToString,

	lib.DESORoyaltiesMapKey: DecodePubKeyToUint64MapString,
	lib.CoinRoyaltiesMapKey: DecodePubKeyToUint64MapString,

	lib.MessagesVersionString: Decode64BitIntString,

	lib.NodeSourceMapKey: DecodePubKeyToUint64MapString,
}

// GetExtraDataDecoder Values in ExtraData field
// in transaction may have special encoding. In such cases
// we'll need specialized decoders too
func GetExtraDataDecoder(key string) ExtraDataDecoder {
	if decoder, exists := ExtraDataKeyToDecoder[key]; exists {
		return decoder
	}

	// Default, just return hex encoding for bytes
	return hex.EncodeToString
}

func Decode64BitIntString(bytes []byte) string {
	var decoded, _ = lib.Varint(bytes)
	return strconv.FormatInt(decoded, 10)
}

func DecodePubKeyToUint64MapString(bytes []byte) string {
	var decoded, _ = lib.DeserializePubKeyToUint64Map(bytes)
	// output will have the format "map[key1:val1 key2:val2]"
	return fmt.Sprint(decoded)
}
