package routes

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/deso-protocol/core/lib"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"strconv"
)

type ExtraDataDecoderFunc func([]byte, *lib.DeSoParams, *lib.UtxoView) string
type ExtraDataEncoderFunc func(string) ([]byte, error)

type ExtraDataEncoding struct {
	Decode ExtraDataDecoderFunc
	Encode ExtraDataEncoderFunc
}

// specialExtraDataKeysToEncoding These are reserved extra data fields used in core that have special encoding. These
// fields are populated directly in core, but we still want to allow clients to be able to populate them directly using
// the ExtraData map through the API. In such cases, we'll want to use the same encoding mechanism as what's used in core
var specialExtraDataKeysToEncoding = map[string]ExtraDataEncoding{
	lib.RepostedPostHash:  {Decode: DecodeHexString, Encode: EncodeHexString},
	lib.IsQuotedRepostKey: {Decode: DecodeBoolString, Encode: EncodeBoolString},
	lib.IsFrozenKey:       {Decode: DecodeBoolString, Encode: EncodeBoolString},

	lib.USDCentsPerBitcoinKey:      {Decode: Decode64BitUintString, Encode: Encode64BitUintString},
	lib.MinNetworkFeeNanosPerKBKey: {Decode: Decode64BitUintString, Encode: Encode64BitUintString},
	lib.CreateProfileFeeNanosKey:   {Decode: Decode64BitUintString, Encode: Encode64BitUintString},
	lib.CreateNFTFeeNanosKey:       {Decode: Decode64BitUintString, Encode: Encode64BitUintString},
	lib.MaxCopiesPerNFTKey:         {Decode: Decode64BitUintString, Encode: Encode64BitUintString},

	lib.ForbiddenBlockSignaturePubKeyKey: {Decode: DecodePkToString, Encode: EncodePkStringToBytes},

	lib.DiamondLevelKey:    {Decode: Decode64BitIntString, Encode: Encode64BitIntString},
	lib.DiamondPostHashKey: {Decode: DecodeHexString, Encode: EncodeHexString},

	lib.DerivedPublicKey: {Decode: DecodePkToString, Encode: EncodePkStringToBytes},

	lib.MessagingPublicKey:             {Decode: DecodePkToString, Encode: EncodePkStringToBytes},
	lib.SenderMessagingPublicKey:       {Decode: DecodePkToString, Encode: EncodePkStringToBytes},
	lib.SenderMessagingGroupKeyName:    {Decode: DecodeString, Encode: EncodeString},
	lib.RecipientMessagingPublicKey:    {Decode: DecodePkToString, Encode: EncodePkStringToBytes},
	lib.RecipientMessagingGroupKeyName: {Decode: DecodeString, Encode: EncodeString},

	lib.BuyNowPriceKey: {Decode: Decode64BitUintString, Encode: Encode64BitUintString},

	lib.DESORoyaltiesMapKey: {Decode: DecodePubKeyToUint64MapString, Encode: ReservedFieldCannotEncode},
	lib.CoinRoyaltiesMapKey: {Decode: DecodePubKeyToUint64MapString, Encode: ReservedFieldCannotEncode},

	lib.MessagesVersionString: {Decode: Decode64BitUintString, Encode: Encode64BitUintString},

	lib.NodeSourceMapKey: {Decode: Decode64BitUintString, Encode: Encode64BitUintString},

	lib.DerivedKeyMemoKey: {Decode: DecodeDerivedKeyMemo, Encode: EncodeDerivedKeyMemo},

	lib.TransactionSpendingLimitKey: {Decode: DecodeTransactionSpendingLimit, Encode: ReservedFieldCannotEncode},
}

func EncodeExtraDataMap(extraData map[string]string) (map[string][]byte, error) {
	extraDataProcessed := make(map[string][]byte)
	for k, v := range extraData {
		encodedValue, err := GetExtraDataFieldEncoding(k).Encode(v)
		if err != nil {
			return nil, errors.Errorf("Problem encoding to extra data field %v: %v", k, err)
		}
		extraDataProcessed[k] = encodedValue
	}
	return extraDataProcessed, nil
}

func DecodeExtraDataMap(params *lib.DeSoParams, utxoView *lib.UtxoView, extraData map[string][]byte) map[string]string {
	if extraData == nil || len(extraData) == 0 {
		return nil
	}
	extraDataResponse := make(map[string]string)
	for k, v := range extraData {
		encoding := GetExtraDataFieldEncoding(k)
		extraDataResponse[k] = encoding.Decode(v, params, utxoView)
	}
	return extraDataResponse
}

// GetExtraDataFieldEncoding For special fields, this gets the encoding used for that field. For all others, it uses an
// agnostic []byte <-> string cast for encoding / decoding.
func GetExtraDataFieldEncoding(extraDataKey string) ExtraDataEncoding {
	if encoding, exists := specialExtraDataKeysToEncoding[extraDataKey]; exists {
		return encoding
	}
	return ExtraDataEncoding{Decode: DecodeString, Encode: EncodeString}
}

func ReservedFieldCannotEncode(_ string) ([]byte, error) {
	return nil, errors.Errorf("Reserved extra data field. This field cannot be written to directly.")
}

func DecodeString(bytes []byte, _ *lib.DeSoParams, _ *lib.UtxoView) string {
	return string(bytes)
}

func EncodeString(str string) ([]byte, error) {
	return []byte(str), nil
}

// Decode64BitIntString supports decoding integers up to a length of 8 bytes
func Decode64BitIntString(bytes []byte, _ *lib.DeSoParams, _ *lib.UtxoView) string {
	var decoded, _ = lib.Varint(bytes)
	return strconv.FormatInt(decoded, 10)
}

// Encode64BitIntString supports encoding integers up to a length of 8 bytes
func Encode64BitIntString(str string) ([]byte, error) {
	var encoded, err = strconv.ParseInt(str, 10, 64)
	if err != nil {
		return nil, err
	}
	buffer := make([]byte, lib.MaxVarintLen64)
	lib.PutVarint(buffer, encoded)
	return buffer, nil
}

// Decode64BitUintString supports decoding unsigned integers up to a length of 8 bytes
func Decode64BitUintString(bytes []byte, _ *lib.DeSoParams, _ *lib.UtxoView) string {
	var decoded, _ = lib.Uvarint(bytes)
	return strconv.FormatUint(decoded, 10)
}

// Encode64BitUintString supports decoding unsigned integers up to a length of 8 bytes
func Encode64BitUintString(str string) ([]byte, error) {
	var encoded, err = strconv.ParseUint(str, 10, 64)
	if err != nil {
		return nil, err
	}
	buffer := make([]byte, lib.MaxVarintLen64)
	lib.PutUvarint(buffer, encoded)
	return buffer, nil
}

func DecodeBoolString(inputBytes []byte, params *lib.DeSoParams, utxoView *lib.UtxoView) string {
	if bytes.Equal(inputBytes, []byte{1}) {
		return "1"
	}
	return "0"
}

func EncodeBoolString(str string) ([]byte, error) {
	if str == "0" {
		return []byte{0}, nil
	}
	if str == "1" {
		return []byte{1}, nil
	}
	return nil, errors.Errorf("%v is not a boolean string. Only values \"0\" or \"1\" are supported", str)
}

func DecodeHexString(bytes []byte, _ *lib.DeSoParams, _ *lib.UtxoView) string {
	return hex.EncodeToString(bytes)
}

func EncodeHexString(str string) ([]byte, error) {
	return hex.DecodeString(str)
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

func DecodePubKeyToUint64MapString(bytes []byte, params *lib.DeSoParams, _ *lib.UtxoView) string {
	var decoded, _ = lib.DeserializePubKeyToUint64Map(bytes)
	mapWithDecodedKeys := map[string]uint64{}
	for k, v := range decoded {
		mapWithDecodedKeys[lib.PkToString(k.ToBytes(), params)] = v
	}
	return fmt.Sprint(mapWithDecodedKeys)
}

func DecodeTransactionSpendingLimit(spendingBytes []byte, params *lib.DeSoParams, utxoView *lib.UtxoView) string {
	var transactionSpendingLimit lib.TransactionSpendingLimit
	blockHeight, err := lib.GetBlockTipHeight(utxoView.Handle, false)
	if err != nil {
		glog.Errorf("Error getting block tip height from the db")
		return ""
	}
	rr := bytes.NewReader(spendingBytes)
	if err := transactionSpendingLimit.FromBytes(blockHeight, rr); err != nil {
		glog.Errorf("Error decoding transaction spending limits: %v", err)
		return ""
	}
	response := TransactionSpendingLimitToResponse(&transactionSpendingLimit, utxoView, params)
	responseJSON, err := json.Marshal(response)
	if err != nil {
		glog.Errorf("Error marshaling transaction limit response: %v", err)
		return ""
	}
	return string(responseJSON)
}

func EncodeDerivedKeyMemo(str string) ([]byte, error) {
	memo := make([]byte, hex.EncodedLen(len([]byte(str))))
	_ = hex.Encode(memo, []byte(str))
	return memo, nil
}

func DecodeDerivedKeyMemo(encodedBytes []byte, _ *lib.DeSoParams, _ *lib.UtxoView) string {
	decodedBytes := make([]byte, hex.DecodedLen(len(encodedBytes)))
	_, _ = hex.Decode(decodedBytes, encodedBytes)
	return string(decodedBytes)
}
