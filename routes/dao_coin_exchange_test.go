package routes

import (
	"github.com/deso-protocol/core/lib"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
	"math"
	"testing"
)

const (
	desoPubKeyBase58Check    = ""                  // represents $DESO
	daoCoinPubKeyBase58Check = "TestDAOCoinPubKey" // represents valid DAO coin public key
)

func TestCalculateScaledExchangeRate(t *testing.T) {
	// scaling factor = 1e18 / 1e9
	desoToDaoCoinBaseUnitsScalingFactor := getDESOToDAOCoinBaseUnitsScalingFactor()

	exchangeRate := 100.00000001
	// equivalent to 100.00000001
	expectedScaledExchangeRate := uint256.NewInt().Add(
		uint256.NewInt().Mul(lib.OneE38, uint256.NewInt().SetUint64(100)),       // 100
		uint256.NewInt().Div(lib.OneE38, uint256.NewInt().SetUint64(100000000)), // 0.00000001
	)

	// Test successful scaling when buying coin is a DAO coin, and selling coin is a DAO coin order. Exchange rate should be 1e38
	{
		scaledExchangeRate, err := CalculateScaledExchangeRate(
			daoCoinPubKeyBase58Check,
			daoCoinPubKeyBase58Check,
			exchangeRate,
		)
		require.NoError(t, err)
		require.Equal(t, expectedScaledExchangeRate, scaledExchangeRate)
	}

	// Test successful scaling when buying coin is a DAO coin, and selling coin  is $DESO. Exchange rate should be 1e38 / 1e9
	{
		scaledExchangeRate, err := CalculateScaledExchangeRate(
			daoCoinPubKeyBase58Check,
			desoPubKeyBase58Check,
			exchangeRate,
		)
		require.NoError(t, err)
		expectedScaledExchangeRate := uint256.NewInt().Div(expectedScaledExchangeRate, desoToDaoCoinBaseUnitsScalingFactor)
		require.Equal(t, expectedScaledExchangeRate, scaledExchangeRate)
	}

	// Test successful scaling when buying coin is $DESO coin, and buying coin is $DESO. Exchange rate should be 1e38 * 1e9
	{
		scaledExchangeRate, err := CalculateScaledExchangeRate(
			desoPubKeyBase58Check,
			daoCoinPubKeyBase58Check,
			exchangeRate,
		)
		require.NoError(t, err)
		expectedScaledExchangeRate := uint256.NewInt().Mul(
			expectedScaledExchangeRate,
			desoToDaoCoinBaseUnitsScalingFactor,
		)
		require.Equal(t, expectedScaledExchangeRate, scaledExchangeRate)
	}

	// Test failed scaling when buying coin is a DAO coin, selling coin  is $DESO, but exchange rate is too small
	{
		exchangeRate := 0.0000000000000000000000000000001 // 1e-31
		_, err := CalculateScaledExchangeRate(
			daoCoinPubKeyBase58Check,
			desoPubKeyBase58Check,
			exchangeRate,
		)
		require.Error(t, err) // expected to fail because the resulting value 1e-39 is too small to be represented
	}

	// Test failed scaling when buying coin is a DAO coin, selling coin  is $DESO, but exchange rate is too small
	{
		exchangeRate := math.Exp(260)
		_, err := CalculateScaledExchangeRate(
			daoCoinPubKeyBase58Check,
			desoPubKeyBase58Check,
			exchangeRate,
		)
		require.Error(t, err) // expected to fail because 2^260 overflows
	}
}

func TestCalculateExchangeRateAsFloat(t *testing.T) {
	// scaling factor = 1e18 / 1e9
	desoToDaoCoinBaseUnitsScalingFactor := getDESOToDAOCoinBaseUnitsScalingFactor()

	// equivalent to 100.00000001
	scaledExchangeRate := uint256.NewInt().Add(
		uint256.NewInt().Mul(lib.OneE38, uint256.NewInt().SetUint64(100)),       // 100
		uint256.NewInt().Div(lib.OneE38, uint256.NewInt().SetUint64(100000000)), // 0.00000001
	)
	expectedExchangeRate := 100.00000001

	// Test when buying coin is a DAO coin, and selling coin is a DAO coin order. Exchange rate should be 1
	{
		scaledValue, err := CalculateExchangeRateAsFloat(
			daoCoinPubKeyBase58Check,
			daoCoinPubKeyBase58Check,
			scaledExchangeRate,
		)
		require.NoError(t, err)
		require.Equal(t, expectedExchangeRate, scaledValue)
	}

	// Test when buying coin is a DAO coin, and selling coin  is $DESO. Exchange rate should be 1e9
	{
		scaledExchangeRate, err := CalculateExchangeRateAsFloat(
			daoCoinPubKeyBase58Check,
			desoPubKeyBase58Check,
			scaledExchangeRate,
		)
		require.NoError(t, err)
		expectedReScaledExchangeRate := expectedExchangeRate * float64(desoToDaoCoinBaseUnitsScalingFactor.Uint64())
		require.Equal(t, expectedReScaledExchangeRate, scaledExchangeRate)
	}

	// Test when buying coin is $DESO coin, and buying coin is $DESO. Exchange rate should be 1e-9
	{
		scaledExchangeRate, err := CalculateExchangeRateAsFloat(
			desoPubKeyBase58Check,
			daoCoinPubKeyBase58Check,
			scaledExchangeRate,
		)
		require.NoError(t, err)
		expectedReScaledExchangeRate := expectedExchangeRate / float64(desoToDaoCoinBaseUnitsScalingFactor.Uint64())
		require.Equal(t, expectedReScaledExchangeRate, scaledExchangeRate)
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

	// Bid order to buy DAO coin using $DESO
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

	// Ask order to sell DAO coin for $DESO
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

	// Bid order to buy DAO coin using $DESO
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

	// Ask order to sell DAO coin for $DESO
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
