package routes

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/deso-protocol/core/lib"
	"github.com/golang/glog"
	"strconv"
)

type ExtraDataDecoder func([]byte, *lib.DeSoParams, *lib.UtxoView) string

var ExtraDataKeyToDecoders = map[string]ExtraDataDecoder{
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

// GetExtraDataDecoder Values in ExtraData field
// in transaction may have special encoding. In such cases
// we'll need specialized decoders too
func GetExtraDataDecoder(txnType lib.TxnType, key string) ExtraDataDecoder {
	if decoder, exists := ExtraDataKeyToDecoders[key]; exists {
		return decoder
	}
	if txnType == lib.TxnTypeSubmitPost {
		return DecodeString
	}
	// Default, just return hex encoding for bytes
	return DecodeHexString
}

// Decode64BitIntString supports decoding integers up to a length of 8 bytes
func Decode64BitIntString(bytes []byte, _ *lib.DeSoParams, _ *lib.UtxoView) string {
	var decoded, _ = lib.Varint(bytes)
	return strconv.FormatInt(decoded, 10)
}

// Decode64BitUintString supports decoding integers up to a length of 8 bytes
func Decode64BitUintString(bytes []byte, _ *lib.DeSoParams,  _ *lib.UtxoView) string {
	var decoded, _ = lib.Uvarint(bytes)
	return strconv.FormatUint(decoded, 10)
}

func DecodeBoolString(bytes []byte, params *lib.DeSoParams, utxoView *lib.UtxoView) string {
	return Decode64BitUintString(bytes, params, utxoView)
}

func DecodeHexString(bytes []byte, _ *lib.DeSoParams, _ *lib.UtxoView) string {
	return hex.EncodeToString(bytes)
}

func DecodePkToString(bytes []byte, params *lib.DeSoParams,  _ *lib.UtxoView) string {
	return lib.PkToString(bytes, params)
}

func DecodePubKeyToUint64MapString(bytes []byte, params *lib.DeSoParams,  _ *lib.UtxoView) string {
	var decoded, _ = lib.DeserializePubKeyToUint64Map(bytes)
	mapWithDecodedKeys := map[string]uint64{}
	for k, v := range decoded {
		mapWithDecodedKeys[lib.PkToString(k.ToBytes(), params)] = v
	}
	return fmt.Sprint(mapWithDecodedKeys)
}

func DecodeString(bytes []byte, _ *lib.DeSoParams,  _ *lib.UtxoView) string {
	return string(bytes)
}

func DecodeTransactionSpendingLimit(bytes []byte, params *lib.DeSoParams, utxoView *lib.UtxoView) string {
	var transactionSpendingLimit *lib.TransactionSpendingLimit
	if err := transactionSpendingLimit.FromBytes(bytes); err != nil {
		glog.Errorf("Error decoding transaction spending limits: %v", err)
		return ""
	}
	response := TransactionSpendingLimitToResponse(transactionSpendingLimit, utxoView, params)
	responseJSON, err := json.Marshal(response)
	if err != nil {
		glog.Errorf("Error marshaling transaction limit response: %v", err)
		return ""
	}
	return string(responseJSON)
}
