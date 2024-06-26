package routes

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/deso-protocol/core/lib"
	"github.com/stretchr/testify/require"
)

func TestUpdateGlobalParams(t *testing.T) {
	// Hard-coded test constants
	adminPublicKeyBase58Check := "tBCKWVydPvhXyxSVhntXCw7wUev2fUx64h84FLAfz4JStsdBAq4v9r"
	adminJWT := "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NDQ3MDU1Mzh9.LXA2uT8tm-6DXDwTXaCRyqqbFNa96jLl_02LXyAwq58PbVPe28hrICP3P-D5g9mktPJolSVXK_UebRcL5oYCWg"

	// Init api server
	apiServer := newTestApiServer(t)
	apiServer.Config.SuperAdminPublicKeys = []string{adminPublicKeyBase58Check}
	senderPkBytes, _, err := lib.Base58CheckDecode(senderPkString)
	require.NoError(t, err)
	apiServer.Params.ExtraRegtestParamUpdaterKeys[lib.MakePkMapKey(senderPkBytes)] = true

	// Helper utils
	getGlobalParams := func() *GetGlobalParamsResponse {
		// Send POST request.
		body := GetGlobalParamsRequest{}
		bodyJSON, err := json.Marshal(body)
		require.NoError(t, err)
		request, _ := http.NewRequest("POST", RoutePathGetGlobalParams, bytes.NewBuffer(bodyJSON))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		require.NotContains(t, string(response.Body.Bytes()), "error")

		// Decode response.
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		globalParams := GetGlobalParamsResponse{}
		err = decoder.Decode(&globalParams)
		return &globalParams
	}

	updateGlobalParams := func(body *UpdateGlobalParamsRequest) {
		// Add JWT auth to body of request.
		type MergedBody struct {
			AdminRequest
			UpdateGlobalParamsRequest
		}
		mergedBody := MergedBody{
			AdminRequest: AdminRequest{
				JWT: adminJWT, AdminPublicKey: adminPublicKeyBase58Check,
			},
			UpdateGlobalParamsRequest: *body,
		}

		// Send POST request.
		bodyJSON, err := json.Marshal(mergedBody)
		require.NoError(t, err)
		request, _ := http.NewRequest("POST", RoutePathUpdateGlobalParams, bytes.NewBuffer(bodyJSON))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		require.NotContains(t, string(response.Body.Bytes()), "error")

		// Decode response.
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		updateGlobalParamsResponse := UpdateGlobalParamsResponse{}
		err = decoder.Decode(&updateGlobalParamsResponse)
		require.NoError(t, err)
		txn := updateGlobalParamsResponse.Transaction

		// Sign txn.
		require.Nil(t, txn.Signature.Sign)
		signTxn(t, txn, senderPrivString)
		require.NotNil(t, txn.Signature.Sign)

		// Submit txn.
		_, err = submitTxn(t, apiServer, txn)
		require.NoError(t, err)
	}

	// Tests
	{
		// Confirm default GlobalParams.
		globalParams := getGlobalParams()
		require.Zero(t, globalParams.MinimumNetworkFeeNanosPerKB)
		require.Equal(t, globalParams.StakeLockupEpochDuration, uint64(3))
		require.Equal(t, globalParams.ValidatorJailEpochDuration, uint64(3))
		require.Equal(t, globalParams.LeaderScheduleMaxNumValidators, uint64(100))
		require.Equal(t, globalParams.EpochDurationNumBlocks, uint64(144))
		require.Equal(t, globalParams.JailInactiveValidatorGracePeriodEpochs, uint64(3))
	}
	{
		// Update all GlobalParam fields.
		updateGlobalParams(&UpdateGlobalParamsRequest{
			UpdaterPublicKeyBase58Check:            senderPkString,
			MinimumNetworkFeeNanosPerKB:            1000,
			StakeLockupEpochDuration:               4,
			ValidatorJailEpochDuration:             4,
			LeaderScheduleMaxNumValidators:         101,
			ValidatorSetMaxNumValidators:           102,
			EpochDurationNumBlocks:                 3601,
			JailInactiveValidatorGracePeriodEpochs: 49,
			MinFeeRateNanosPerKB:                   1000,
		})
	}
	{
		// Verify all updated GlobalParam fields.
		globalParams := getGlobalParams()
		require.Equal(t, globalParams.MinimumNetworkFeeNanosPerKB, uint64(1000))
		require.Equal(t, globalParams.StakeLockupEpochDuration, uint64(4))
		require.Equal(t, globalParams.ValidatorJailEpochDuration, uint64(4))
		require.Equal(t, globalParams.LeaderScheduleMaxNumValidators, uint64(101))
		require.Equal(t, globalParams.ValidatorSetMaxNumValidators, uint64(102))
		require.Equal(t, globalParams.EpochDurationNumBlocks, uint64(3601))
		require.Equal(t, globalParams.JailInactiveValidatorGracePeriodEpochs, uint64(49))
	}
	{
		// Update only one GlobalParam field.
		updateGlobalParams(&UpdateGlobalParamsRequest{
			UpdaterPublicKeyBase58Check:            senderPkString,
			MinimumNetworkFeeNanosPerKB:            1000,
			JailInactiveValidatorGracePeriodEpochs: 50,
			MinFeeRateNanosPerKB:                   1000,
		})
	}
	{
		// Verify updated GlobalParam field. And other fields retain old values.
		globalParams := getGlobalParams()
		require.Equal(t, globalParams.MinimumNetworkFeeNanosPerKB, uint64(1000))
		require.Equal(t, globalParams.StakeLockupEpochDuration, uint64(4))
		require.Equal(t, globalParams.ValidatorJailEpochDuration, uint64(4))
		require.Equal(t, globalParams.LeaderScheduleMaxNumValidators, uint64(101))
		require.Equal(t, globalParams.ValidatorSetMaxNumValidators, uint64(102))
		require.Equal(t, globalParams.EpochDurationNumBlocks, uint64(3601))
		require.Equal(t, globalParams.JailInactiveValidatorGracePeriodEpochs, uint64(50))
	}
}
