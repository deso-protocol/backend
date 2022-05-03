package routes

import (
	"github.com/deso-protocol/core/lib"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestExtraDataEncodingDecodingSuccess(t *testing.T) {
	successTestCases := map[string]string{
		lib.RepostedPostHash:                 "00001dd90015139e385143d40a2c77c890ec207a6c8f3394f0d5af5ce3e00f15",
		lib.IsQuotedRepostKey:                "1",
		lib.USDCentsPerBitcoinKey:            "123456789",
		lib.MinNetworkFeeNanosPerKBKey:       "0",
		lib.CreateProfileFeeNanosKey:         "1",
		lib.CreateNFTFeeNanosKey:             "2",
		lib.MaxCopiesPerNFTKey:               "3",
		lib.ForbiddenBlockSignaturePubKeyKey: "tBCKVERmG9nZpHTk2AVPqknWc1Mw9HHAnqrTpW1RnXpXMQ4PsQgnmV",
		lib.DiamondLevelKey:                  "6",
		lib.DiamondPostHashKey:               "00001dd90015139e385143d40a2c77c890ec207a6c8f3394f0d5af5ce3e00f15",
		lib.DerivedPublicKey:                 "tBCKVERmG9nZpHTk2AVPqknWc1Mw9HHAnqrTpW1RnXpXMQ4PsQgnmV",
		lib.MessagingPublicKey:               "tBCKVERmG9nZpHTk2AVPqknWc1Mw9HHAnqrTpW1RnXpXMQ4PsQgnmV",
		lib.SenderMessagingPublicKey:         "tBCKVERmG9nZpHTk2AVPqknWc1Mw9HHAnqrTpW1RnXpXMQ4PsQgnmV",
		lib.SenderMessagingGroupKeyName:      "arbitrary random group name",
		lib.RecipientMessagingPublicKey:      "tBCKVERmG9nZpHTk2AVPqknWc1Mw9HHAnqrTpW1RnXpXMQ4PsQgnmV",
		lib.RecipientMessagingGroupKeyName:   "group name",
		lib.MessagesVersionString:            "3",
		lib.NodeSourceMapKey:                 "123234",
		lib.DerivedKeyMemoKey:                "00001dd90015139e385143d40a2c77c890ec207a6c8f3394f0d5af5ce3e00f15",
		"random key":                         "random value",
	}

	params := lib.DeSoTestnetParams

	encodedMap, err := EncodeExtraDataMap(successTestCases)
	require.NoError(t, err)
	require.Equal(t, len(successTestCases), len(encodedMap))

	decodedMap := DecodeExtraDataMap(&params, nil, encodedMap)
	require.Equal(t, len(successTestCases), len(decodedMap))
}

func TestExtraDataEncodingDecodingErrors(t *testing.T) {
	errorTestCases := map[string]string{
		lib.RepostedPostHash:                 "zzz", // not a hex-encoded string
		lib.IsQuotedRepostKey:                "2",   // not a boolean string value
		lib.USDCentsPerBitcoinKey:            "-1",  // uvarint can't be negative
		lib.MinNetworkFeeNanosPerKBKey:       "-1",  // uvarint can't be negative
		lib.CreateProfileFeeNanosKey:         "-1",  // uvarint can't be negative
		lib.CreateNFTFeeNanosKey:             "-1",  // uvarint can't be negative
		lib.MaxCopiesPerNFTKey:               "-1",  // uvarint can't be negative
		lib.ForbiddenBlockSignaturePubKeyKey: "1",   // not a valid public key
		lib.DiamondLevelKey:                  "zzz", // not an integer
		lib.DiamondPostHashKey:               "zzz", // not a hex-encoded string
		lib.DerivedPublicKey:                 "1",   // not a valid public key
		lib.MessagingPublicKey:               "1",   // not a valid public key
		lib.SenderMessagingPublicKey:         "1",   // not a valid public key
		lib.RecipientMessagingPublicKey:      "1",   // not a valid public key
		lib.DESORoyaltiesMapKey:              "",    // encoding not supported
		lib.CoinRoyaltiesMapKey:              "",    // encoding not supported
		lib.NodeSourceMapKey:                 "-1",  // uint64 can't be negative
		lib.DerivedKeyMemoKey:                "zzz", // non-hex encoded string
		lib.TransactionSpendingLimitKey:      "",    // encoding not supported
	}

	for k, v := range errorTestCases {
		// create a new map to test each field in isolation
		var inputMapToEncode = map[string]string{
			k: v,
		}
		_, err := EncodeExtraDataMap(inputMapToEncode)
		require.Error(t, err)
	}
}
