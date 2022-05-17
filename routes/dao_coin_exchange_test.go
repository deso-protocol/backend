package routes

import (
	"github.com/deso-protocol/core/lib"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
	"testing"
)

const (
	desoPubKeyBase58Check    = DESOCoinIdentifierString // represents $DESO
	daoCoinPubKeyBase58Check = "TestDAOCoinPubKey"      // represents valid DAO coin public key
)

func TestCalculateScaledExchangeRate(t *testing.T) {
	// equivalent to 1e9
	desoToDaoCoinBaseUnitsScalingFactor := getDESOToDAOCoinBaseUnitsScalingFactor()

	type testCaseType struct {
		floatValue                float64
		expectedWholeNumberDigits int64
		decimalDigitExponent      int64
	}

	// Convenience type to define exchange rates and expected uint256 scaled exchange rates.
	// Given a test case {100.1, 100, -1}, it means that our float exchangeRate is 100.1
	// and the expected uint256 scaled exchange rate is (1e38 * 100) + (1e38 / 10). This is an easy
	// way to test a sliding window of precision with both large and small numbers
	successTestCases := []testCaseType{
		{1.1, 1, -10},                                 // 2 digits
		{0.00000000000001, 0, -100000000000000},       // smallest supported number
		{1.0000000000001, 1, -10000000000000},         // 15 digits, no truncate
		{1000000000000.1, 1000000000000, -10},         // 15 digits, no truncate
		{10000000000000.01, 10000000000000, 0},        // 16 digits, which truncates everything after decimal point
		{100000000000001, 100000000000001, 0},         // 15 digits, no truncate
		{1000000000000001, 1000000000000000, 0},       // 16 digits, truncates everything below top 15 digits
		{1234567890123456789, 1234567890123450000, 0}, // 19 digits, truncates everything below top 15 digits
	}

	// Test when buying coin is a DAO coin and selling coin is a DAO coin, for various exchange rates
	for _, testCase := range successTestCases {
		exchangeRate := testCase.floatValue
		expectedScaledExchangeRate := uint256.NewInt()
		if testCase.expectedWholeNumberDigits > 0 {
			expectedScaledExchangeRate = uint256.NewInt().Mul(
				lib.OneE38, uint256.NewInt().SetUint64(uint64(testCase.expectedWholeNumberDigits)),
			)
		}

		if testCase.decimalDigitExponent < 0 {
			expectedScaledExchangeRate.Add(
				expectedScaledExchangeRate,
				uint256.NewInt().Div(lib.OneE38, uint256.NewInt().SetUint64(uint64(-testCase.decimalDigitExponent))),
			)
		}
		scaledExchangeRate, err := CalculateScaledExchangeRate(
			daoCoinPubKeyBase58Check,
			daoCoinPubKeyBase58Check,
			exchangeRate,
		)
		require.NoError(t, err)
		require.Equal(t, expectedScaledExchangeRate, scaledExchangeRate)
	}

	// Test when buying coin is a DAO coin and selling coin is $DESO
	{
		scaledExchangeRate, err := CalculateScaledExchangeRate(
			daoCoinPubKeyBase58Check,
			desoPubKeyBase58Check,
			1.0,
		)
		require.NoError(t, err)
		// expectedScaledExchangeRate / 1e9
		expectedScaledExchangeRate := uint256.NewInt().Div(lib.OneE38, desoToDaoCoinBaseUnitsScalingFactor)
		require.Equal(t, expectedScaledExchangeRate, scaledExchangeRate)
	}

	// Test when buying coin is $DESO and selling coin is DAO coin
	{
		scaledExchangeRate, err := CalculateScaledExchangeRate(
			desoPubKeyBase58Check,
			daoCoinPubKeyBase58Check,
			1.0,
		)
		require.NoError(t, err)
		expectedScaledExchangeRate := uint256.NewInt().Mul(
			lib.OneE38,
			desoToDaoCoinBaseUnitsScalingFactor,
		)
		require.Equal(t, expectedScaledExchangeRate, scaledExchangeRate)
	}

	failingTestCases := []float64{
		0.0000000000000001,                        // 1e-16 is too small
		10000000000000000000000000000000000000000, // 1e40 is too big
	}

	for _, exchangeRate := range failingTestCases {
		_, err := CalculateScaledExchangeRate(
			daoCoinPubKeyBase58Check,
			daoCoinPubKeyBase58Check,
			exchangeRate,
		)
		require.Error(t, err)
	}
}

func TestCalculateExchangeRateAsFloat(t *testing.T) {
	desoToDaoCoinBaseUnitsScalingFactor := getDESOToDAOCoinBaseUnitsScalingFactor()

	// equivalent to 100.00000001
	scaledExchangeRate := uint256.NewInt().Add(
		uint256.NewInt().Mul(lib.OneE38, uint256.NewInt().SetUint64(100)),       // 100
		uint256.NewInt().Div(lib.OneE38, uint256.NewInt().SetUint64(100000000)), // 0.00000001
	)
	expectedExchangeRate := 100.00000001

	// Test when buying coin is a DAO coin and selling coin is a DAO coin order
	{
		scaledValue, err := CalculateExchangeRateAsFloat(
			daoCoinPubKeyBase58Check,
			daoCoinPubKeyBase58Check,
			scaledExchangeRate,
		)
		require.NoError(t, err)
		require.Equal(t, expectedExchangeRate, scaledValue)
	}

	// Test when buying coin is a DAO coin and selling coin is $DESO
	{
		exchangeRate, err := CalculateExchangeRateAsFloat(
			daoCoinPubKeyBase58Check,
			desoPubKeyBase58Check,
			scaledExchangeRate,
		)
		require.NoError(t, err)
		expectedReScaledExchangeRate := expectedExchangeRate * float64(desoToDaoCoinBaseUnitsScalingFactor.Uint64())
		require.Equal(t, expectedReScaledExchangeRate, exchangeRate)
	}

	// Test when buying coin is $DESO coin and buying coin is $DESO
	{
		exchangeRate, err := CalculateExchangeRateAsFloat(
			desoPubKeyBase58Check,
			daoCoinPubKeyBase58Check,
			scaledExchangeRate,
		)
		require.NoError(t, err)
		expectedReScaledExchangeRate := expectedExchangeRate / float64(desoToDaoCoinBaseUnitsScalingFactor.Uint64())
		require.Equal(t, expectedReScaledExchangeRate, exchangeRate)
	}
}

func TestCalculateQuantityToFillAsBaseUnits(t *testing.T) {
	expectedValueIfDESO := uint256.NewInt().SetUint64(lib.NanosPerUnit)
	expectedValueIfDAOCoin := &(*lib.BaseUnitsPerCoin)

	quantity := float64(1)

	// Bid order to buy $DESO using a DAO coin
	{
		scaledQuantity, err := CalculateQuantityToFillAsBaseUnits(
			desoPubKeyBase58Check,
			daoCoinPubKeyBase58Check,
			DAOCoinLimitOrderOperationTypeStringBID,
			quantity,
		)
		require.NoError(t, err)
		require.Equal(t, expectedValueIfDESO, scaledQuantity)
	}

	// Bid order to buy a DAO coin using $DESO
	{
		scaledQuantity, err := CalculateQuantityToFillAsBaseUnits(
			daoCoinPubKeyBase58Check,
			desoPubKeyBase58Check,
			DAOCoinLimitOrderOperationTypeStringBID,
			quantity,
		)
		require.NoError(t, err)
		require.Equal(t, expectedValueIfDAOCoin, scaledQuantity)
	}

	// Ask order to sell $DESO for a DAO coin
	{
		scaledQuantity, err := CalculateQuantityToFillAsBaseUnits(
			daoCoinPubKeyBase58Check,
			desoPubKeyBase58Check,
			DAOCoinLimitOrderOperationTypeStringASK,
			quantity,
		)
		require.NoError(t, err)
		require.Equal(t, expectedValueIfDESO, scaledQuantity)
	}

	// Ask order to sell a DAO coin for $DESO
	{
		scaledQuantity, err := CalculateQuantityToFillAsBaseUnits(
			desoPubKeyBase58Check,
			daoCoinPubKeyBase58Check,
			DAOCoinLimitOrderOperationTypeStringASK,
			quantity,
		)
		require.NoError(t, err)
		require.Equal(t, expectedValueIfDAOCoin, scaledQuantity)
	}
}

func TestCalculateQuantityToFillAsFloat(t *testing.T) {
	scaledQuantity := lib.BaseUnitsPerCoin
	expectedValueIfDESO := float64(getDESOToDAOCoinBaseUnitsScalingFactor().Uint64()) // 1e9
	expectedValueIfDAOCoin := float64(1)

	// Bid order to buy $DESO using a DAO coin
	{
		quantity, err := CalculateQuantityToFillAsFloat(
			desoPubKeyBase58Check,
			daoCoinPubKeyBase58Check,
			DAOCoinLimitOrderOperationTypeStringBID,
			scaledQuantity,
		)
		require.NoError(t, err)
		require.Equal(t, expectedValueIfDESO, quantity)
	}

	// Bid order to buy a DAO coin using $DESO
	{
		quantity, err := CalculateQuantityToFillAsFloat(
			daoCoinPubKeyBase58Check,
			desoPubKeyBase58Check,
			DAOCoinLimitOrderOperationTypeStringBID,
			scaledQuantity,
		)
		require.NoError(t, err)
		require.Equal(t, expectedValueIfDAOCoin, quantity)
	}

	// Ask order to sell $DESO for a DAO coin
	{
		quantity, err := CalculateQuantityToFillAsFloat(
			daoCoinPubKeyBase58Check,
			desoPubKeyBase58Check,
			DAOCoinLimitOrderOperationTypeStringASK,
			scaledQuantity,
		)
		require.NoError(t, err)
		require.Equal(t, expectedValueIfDESO, quantity)
	}

	// Ask order to sell a DAO coin for $DESO
	{
		quantity, err := CalculateQuantityToFillAsFloat(
			desoPubKeyBase58Check,
			daoCoinPubKeyBase58Check,
			DAOCoinLimitOrderOperationTypeStringASK,
			scaledQuantity,
		)
		require.NoError(t, err)
		require.Equal(t, expectedValueIfDAOCoin, quantity)
	}
}
