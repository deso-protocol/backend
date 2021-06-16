package routes

import (
	"encoding/json"
	"fmt"
	"github.com/bitclout/core/lib"
	"io"
	"net/http"
)

type SetUSDCentsToBitCloutExchangeRateRequest struct {
	USDCentsPerBitClout uint64
	AdminPublicKey string
}

type SetUSDCentsToBitCloutExchangeRateResponse struct {
	USDCentsPerBitClout uint64
}

func (fes *APIServer) CheckSuperAdminPublicKey(superAdminPublicKey string) bool {
	for _, publicKey := range fes.SuperAdminPublicKeys {
		if publicKey == superAdminPublicKey {
			return true
		}
	}
	return false
}

func (fes *APIServer) SetUSDCentsToBitCloutReserveExchangeRate(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := SetUSDCentsToBitCloutExchangeRateRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SetUSDCentsToBitCloutReserveExchangeRate: Problem parsing request body: %v", err))
		return
	}

	if err := fes.GlobalStatePut(
		GlobalStateKeyForUSDCentsToBitCloutReserveExchangeRate(),
		lib.UintToBuf(requestData.USDCentsPerBitClout)); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SetUSDCentsToBitCloutReserveExchangeRate: Problem putting exchange rate in global state: %v", err))
		return
	}

	fes.UpdateUSDCentsToBitCloutExchangeRate()

	res := SetUSDCentsToBitCloutExchangeRateResponse{
		USDCentsPerBitClout: requestData.USDCentsPerBitClout,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SetUSDCentsToBitCloutReserveExchangeRate: Problem encoding response as JSON: %v", err))
		return
	}
}

type GetUSDCentsToBitCloutExchangeRateResponse struct {
	USDCentsPerBitClout uint64
}

func (fes *APIServer) GetUSDCentsToBitCloutReserveExchangeRate(ww http.ResponseWriter, req *http.Request) {
	exchangeRate, err := fes.GetUSDCentsToBitCloutReserveExchangeRateFromGlobalState()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetUSDCentsToBitCloutExchangeRate: error getting exchange rate: %v", err))
		return
	}
	res := GetUSDCentsToBitCloutExchangeRateResponse{
		USDCentsPerBitClout: exchangeRate,
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetUSDCentsToBitCloutExchangeRate: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) GetUSDCentsToBitCloutReserveExchangeRateFromGlobalState() (uint64, error) {
	val, err := fes.GlobalStateGet(GlobalStateKeyForUSDCentsToBitCloutReserveExchangeRate())
	if err != nil {
		return 0, fmt.Errorf("Problem getting bitclout to usd exchange rate from global state: %v", err)
	}
	usdCentsPerBitClout, bytesRead :=  lib.Uvarint(val)
	if bytesRead <= 0 {
		return 0, fmt.Errorf("Problem reading bytes from global state: %v", err)
	}
	return usdCentsPerBitClout, nil
}

type SetBuyBitCloutFeeBasisPointsRequest struct {
	BuyBitCloutFeeBasisPoints uint64
	AdminPublicKey string
}

type SetBuyBitCloutFeeBasisPointsResponse struct {
	BuyBitCloutFeeBasisPoints uint64
}

func (fes *APIServer) SetBuyBitCloutFeeBasisPoints(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := SetBuyBitCloutFeeBasisPointsRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SetBuyBitCloutFeeBasisPoints: Problem parsing request body: %v", err))
		return
	}

	if err := fes.GlobalStatePut(
		GlobalStateKeyForBuyBitCloutFeeBasisPoints(),
		lib.UintToBuf(requestData.BuyBitCloutFeeBasisPoints)); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SetBuyBitCloutFeeBasisPoints: Problem putting premium basis points in global state: %v", err))
		return
	}

	res := SetBuyBitCloutFeeBasisPointsResponse{
		BuyBitCloutFeeBasisPoints: requestData.BuyBitCloutFeeBasisPoints,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SetBuyBitCloutFeeBasisPoints: Problem encoding response as JSON: %v", err))
		return
	}
}

type GetBuyBitCloutFeeBasisPointsResponse struct {
	BuyBitCloutFeeBasisPoints uint64
}

func (fes *APIServer) GetBuyBitCloutFeeBasisPoints(ww http.ResponseWriter, req *http.Request) {
	feeBasisPoints, err := fes.GetBuyBitCloutFeeBasisPointsResponseFromGlobalState()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetBuyBitCloutFeeBasisPoints: error getting exchange rate: %v", err))
		return
	}
	res := GetBuyBitCloutFeeBasisPointsResponse{
		BuyBitCloutFeeBasisPoints: feeBasisPoints,
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetBuyBitCloutFeeBasisPoints: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) GetBuyBitCloutFeeBasisPointsResponseFromGlobalState() (uint64, error) {
	val, err := fes.GlobalStateGet(GlobalStateKeyForBuyBitCloutFeeBasisPoints())
	if err != nil {
		return 0, fmt.Errorf("Problem getting buy bitclout premium basis points from global state: %v", err)
	}
	feeBasisPoints, bytesRead :=  lib.Uvarint(val)
	if bytesRead <= 0 {
		return 0, fmt.Errorf("Problem reading bytes from global state: %v", err)
	}
	return feeBasisPoints, nil
}
