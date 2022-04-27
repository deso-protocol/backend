package routes

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/deso-protocol/core/lib"
	"github.com/golang/glog"
	"strconv"
)

type ExtraDataEncoderFunc func(string) ([]byte, error)
type ExtraDataDecoderFunc func([]byte, *lib.DeSoParams, *lib.UtxoView) (string, error)

// ExtraDataKeysToEncoders A subset of user-provided extra data fields need custom encoding as they're used in core. We
// special-case these keys
var ExtraDataKeysToEncoders = map[string]ExtraDataEncoderFunc{
	lib.DerivedPublicKey: EncodePkStringToBytes,
}

// ExtraDataKeysToDecoders A subset of extra data keys have custom encoding. Some are populated in core with special
// encoding schemes. Others are user-provided through the API and require custom encoding schemes. For consistency with
// the encoding used in core, and with the custom encoding used when provided to this API, we want to be able to properly
// decode them.
var ExtraDataKeysToDecoders = map[string]ExtraDataDecoderFunc{
	lib.RepostedPostHash:  DecodeHexString,
	lib.IsQuotedRepostKey: DecodeBoolString,

	lib.USDCentsPerBitcoinKey:      Decode64BitUintString,
	lib.MinNetworkFeeNanosPerKBKey: Decode64BitUintString,
	lib.CreateProfileFeeNanosKey:   Decode64BitUintString,
	lib.CreateNFTFeeNanosKey:       Decode64BitUintString,
	lib.MaxCopiesPerNFTKey:         Decode64BitUintString,

	lib.ForbiddenBlockSignaturePubKeyKey: DecodePkToString,

	lib.DiamondLevelKey:    Decode64BitIntString,
	lib.DiamondPostHashKey: DecodeHexString,

	lib.DerivedPublicKey: DecodePkToString,

	lib.MessagingPublicKey:             DecodePkToString,
	lib.SenderMessagingPublicKey:       DecodePkToString,
	lib.SenderMessagingGroupKeyName:    DecodeString,
	lib.RecipientMessagingPublicKey:    DecodePkToString,
	lib.RecipientMessagingGroupKeyName: DecodeString,

	lib.DESORoyaltiesMapKey: DecodePubKeyToUint64MapString,
	lib.CoinRoyaltiesMapKey: DecodePubKeyToUint64MapString,

	lib.MessagesVersionString: Decode64BitIntString,

	lib.NodeSourceMapKey: Decode64BitUintString,

	lib.DerivedKeyMemoKey: DecodeHexString,

	lib.TransactionSpendingLimitKey: DecodeTransactionSpendingLimit,
}

// GetExtraDataEncoder A subset of user-provided extra data fields need custom encoding as they're used in core. We
// special-case these keys. We only use this map for
func GetExtraDataEncoder(key string) ExtraDataEncoderFunc {
	if encoder, exists := ExtraDataKeysToEncoders[key]; exists {
		return encoder
	}
	return EncodeString
}

// GetExtraDataDecoder Values in the ExtraData map can have custom encoding. In those isolated cases, we want matching
// custom decoders. For all other cases, we use raw string <-> []byte casting for encoding & decoding.
func GetExtraDataDecoder(key string) ExtraDataDecoderFunc {
	if decoder, exists := ExtraDataKeysToDecoders[key]; exists {
		return decoder
	}
	return DecodeString
}

func EncodeString(str string) ([]byte, error) {
	return []byte(str), nil
}

func DecodeString(bytes []byte, _ *lib.DeSoParams, _ *lib.UtxoView) (string, error) {
	return string(bytes), nil
}

// Decode64BitIntString supports decoding integers up to a length of 8 bytes
func Decode64BitIntString(bytes []byte, _ *lib.DeSoParams, _ *lib.UtxoView) (string, error) {
	var decoded, _ = lib.Varint(bytes)
	return strconv.FormatInt(decoded, 10), nil
}

// Decode64BitUintString supports decoding integers up to a length of 8 bytes
func Decode64BitUintString(bytes []byte, _ *lib.DeSoParams, _ *lib.UtxoView) (string, error) {
	var decoded, _ = lib.Uvarint(bytes)
	return strconv.FormatUint(decoded, 10), nil
}

func DecodeBoolString(bytes []byte, params *lib.DeSoParams, utxoView *lib.UtxoView) (string, error) {
	return Decode64BitUintString(bytes, params, utxoView)
}

func DecodeHexString(bytes []byte, _ *lib.DeSoParams, _ *lib.UtxoView) (string, error) {
	return hex.EncodeToString(bytes), nil
}

func EncodePkStringToBytes(str string) ([]byte, error) {
	result, _, err := lib.Base58CheckDecode(str)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func DecodePkToString(bytes []byte, params *lib.DeSoParams, _ *lib.UtxoView) (string, error) {
	return lib.PkToString(bytes, params), nil
}

func DecodePubKeyToUint64MapString(bytes []byte, params *lib.DeSoParams, _ *lib.UtxoView) (string, error) {
	var decoded, _ = lib.DeserializePubKeyToUint64Map(bytes)
	mapWithDecodedKeys := map[string]uint64{}
	for k, v := range decoded {
		mapWithDecodedKeys[lib.PkToString(k.ToBytes(), params)] = v
	}
	return fmt.Sprint(mapWithDecodedKeys), nil
}

func DecodeTransactionSpendingLimit(spendingBytes []byte, params *lib.DeSoParams, utxoView *lib.UtxoView) (string, error) {
	var transactionSpendingLimit *lib.TransactionSpendingLimit
	rr := bytes.NewReader(spendingBytes)
	if err := transactionSpendingLimit.FromBytes(rr); err != nil {
		glog.Errorf("Error decoding transaction spending limits: %v", err)
		return "", err
	}
	response := TransactionSpendingLimitToResponse(transactionSpendingLimit, utxoView, params)
	responseJSON, err := json.Marshal(response)
	if err != nil {
		glog.Errorf("Error marshaling transaction limit response: %v", err)
		return "", err
	}
	return string(responseJSON), nil
}
