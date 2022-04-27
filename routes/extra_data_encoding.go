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
type ExtraDataDecoderFunc func([]byte, *lib.DeSoParams, *lib.UtxoView) string

// ExtraDataKeysToEncoders A subset of user-provided extra data fields need custom encoding as they're used in core. We
// special-case these keys
var ExtraDataKeysToEncoders = map[string]ExtraDataEncoderFunc{
	lib.DerivedPublicKey: EncodePkStringToBytes,
}

// ExtraDataKeysToDecoders Reserved extra data fields within core that require special decoding when being exposed to clients
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

// GetExtraDataEncoder A subset of client-provided extra data fields are reserved and are used in core. The API will
// require special encoding for these keys. For all others, we default to an agnostic string -> []byte cast
func GetExtraDataEncoder(extraDataKey string) ExtraDataEncoderFunc {
	if encoder, exists := ExtraDataKeysToEncoders[extraDataKey]; exists {
		return encoder
	}
	return EncodeString
}

// GetExtraDataDecoder A subset of extra data fields are populated directly in core and have special use-cases.
// The API will provide special decoding schemes when exposing these fields to clients. For all others, we use an agnostic
// []byte -> string cast
func GetExtraDataDecoder(extraDataKey string) ExtraDataDecoderFunc {
	if decoder, exists := ExtraDataKeysToDecoders[extraDataKey]; exists {
		return decoder
	}
	return DecodeString
}

func EncodeString(str string) ([]byte, error) {
	return []byte(str), nil
}

func DecodeString(bytes []byte, _ *lib.DeSoParams, _ *lib.UtxoView) string {
	return string(bytes)
}

// Decode64BitIntString supports decoding integers up to a length of 8 bytes
func Decode64BitIntString(bytes []byte, _ *lib.DeSoParams, _ *lib.UtxoView) string {
	var decoded, _ = lib.Varint(bytes)
	return strconv.FormatInt(decoded, 10)
}

// Decode64BitUintString supports decoding integers up to a length of 8 bytes
func Decode64BitUintString(bytes []byte, _ *lib.DeSoParams, _ *lib.UtxoView) string {
	var decoded, _ = lib.Uvarint(bytes)
	return strconv.FormatUint(decoded, 10)
}

func DecodeBoolString(bytes []byte, params *lib.DeSoParams, utxoView *lib.UtxoView) string {
	return Decode64BitUintString(bytes, params, utxoView)
}

func DecodeHexString(bytes []byte, _ *lib.DeSoParams, _ *lib.UtxoView) string {
	return hex.EncodeToString(bytes)
}

func EncodePkStringToBytes(str string) ([]byte, error) {
	result, _, err := lib.Base58CheckDecode(str)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func DecodePkToString(bytes []byte, params *lib.DeSoParams, _ *lib.UtxoView) string {
	return lib.PkToString(bytes, params)
}

func DecodePubKeyToUint64MapString(bytes []byte, params *lib.DeSoParams, utxoView *lib.UtxoView) string {
	var decoded, err = lib.DeserializePubKeyToUint64Map(bytes)
	if err != nil {
		glog.Errorf("Error marshaling public key to uint64 map to string: %v", err)
		return DecodeString(bytes, params, utxoView)
	}
	mapWithDecodedKeys := map[string]uint64{}
	for k, v := range decoded {
		mapWithDecodedKeys[lib.PkToString(k.ToBytes(), params)] = v
	}
	return fmt.Sprint(mapWithDecodedKeys)
}

func DecodeTransactionSpendingLimit(bytes []byte, params *lib.DeSoParams, utxoView *lib.UtxoView) (string, error) {
	var transactionSpendingLimit *lib.TransactionSpendingLimit
	rr := bytes.NewReader(spendingBytes)
	if err := transactionSpendingLimit.FromBytes(rr); err != nil {
		glog.Errorf("Error decoding transaction spending limits: %v", err)
		return DecodeString(bytes, params, utxoView)
	}
	response := TransactionSpendingLimitToResponse(transactionSpendingLimit, utxoView, params)
	responseJSON, err := json.Marshal(response)
	if err != nil {
		glog.Errorf("Error marshaling transaction limit to string: %v", err)
		return DecodeString(bytes, params, utxoView)
	}
	return string(responseJSON)
}
