package routes

import (
	"encoding/json"
	"fmt"
	"github.com/deso-protocol/core/lib"
	"io"
	"net/http"
)

type SetUSDCentsToDeSoExchangeRateRequest struct {
	USDCentsPerDeSo uint64
	AdminPublicKey      string
}

type SetUSDCentsToDeSoExchangeRateResponse struct {
	USDCentsPerDeSo uint64
}

// SetUSDCentsToDeSoReserveExchangeRate sets the minimum price to buy DeSo from this node.
func (fes *APIServer) SetUSDCentsToDeSoReserveExchangeRate(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := SetUSDCentsToDeSoExchangeRateRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SetUSDCentsToDeSoReserveExchangeRate: Problem parsing request body: %v", err))
		return
	}

	// Put the new value in global state
	if err := fes.GlobalStatePut(
		GlobalStateKeyForUSDCentsToDeSoReserveExchangeRate(),
		lib.UintToBuf(requestData.USDCentsPerDeSo)); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SetUSDCentsToDeSoReserveExchangeRate: Problem putting exchange rate in global state: %v", err))
		return
	}

	// Force refresh the USD Cent to DeSo exchange rate
	fes.UpdateUSDCentsToDeSoExchangeRate()

	res := SetUSDCentsToDeSoExchangeRateResponse{
		USDCentsPerDeSo: requestData.USDCentsPerDeSo,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SetUSDCentsToDeSoReserveExchangeRate: Problem encoding response as JSON: %v", err))
		return
	}
}

type GetUSDCentsToDeSoExchangeRateResponse struct {
	USDCentsPerDeSo uint64
}

// GetUSDCentsToDeSoReserveExchangeRate get the current reserve exchange rate
func (fes *APIServer) GetUSDCentsToDeSoReserveExchangeRate(ww http.ResponseWriter, req *http.Request) {
	exchangeRate, err := fes.GetUSDCentsToDeSoReserveExchangeRateFromGlobalState()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetUSDCentsToDeSoExchangeRate: error getting exchange rate: %v", err))
		return
	}
	res := GetUSDCentsToDeSoExchangeRateResponse{
		USDCentsPerDeSo: exchangeRate,
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetUSDCentsToDeSoExchangeRate: Problem encoding response as JSON: %v", err))
		return
	}
}

// GetUSDCentsToDeSoReserveExchangeRateFromGlobalState is a helper function to get the current USD cents to DeSo exchange rate
func (fes *APIServer) GetUSDCentsToDeSoReserveExchangeRateFromGlobalState() (uint64, error) {
	val, err := fes.GlobalStateGet(GlobalStateKeyForUSDCentsToDeSoReserveExchangeRate())
	if err != nil {
		return 0, fmt.Errorf("Problem getting deso to usd exchange rate from global state: %v", err)
	}
	usdCentsPerDeSo, bytesRead := lib.Uvarint(val)
	if bytesRead <= 0 {
		return 0, fmt.Errorf("Problem reading bytes from global state: %v", err)
	}
	return usdCentsPerDeSo, nil
}

type SetBuyDeSoFeeBasisPointsRequest struct {
	BuyDeSoFeeBasisPoints uint64
	AdminPublicKey            string
}

type SetBuyDeSoFeeBasisPointsResponse struct {
	BuyDeSoFeeBasisPoints uint64
}

// SetBuyDeSoFeeBasisPoints sets the percentage fee applied to all DeSo buys on this node.
func (fes *APIServer) SetBuyDeSoFeeBasisPoints(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := SetBuyDeSoFeeBasisPointsRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SetBuyDeSoFeeBasisPoints: Problem parsing request body: %v", err))
		return
	}

	if err := fes.GlobalStatePut(
		GlobalStateKeyForBuyDeSoFeeBasisPoints(),
		lib.UintToBuf(requestData.BuyDeSoFeeBasisPoints)); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SetBuyDeSoFeeBasisPoints: Problem putting premium basis points in global state: %v", err))
		return
	}

	res := SetBuyDeSoFeeBasisPointsResponse{
		BuyDeSoFeeBasisPoints: requestData.BuyDeSoFeeBasisPoints,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SetBuyDeSoFeeBasisPoints: Problem encoding response as JSON: %v", err))
		return
	}
}

type GetBuyDeSoFeeBasisPointsResponse struct {
	BuyDeSoFeeBasisPoints uint64
}

// GetBuyDeSoFeeBasisPoints gets the current value of the buy DeSo fee.
func (fes *APIServer) GetBuyDeSoFeeBasisPoints(ww http.ResponseWriter, req *http.Request) {
	feeBasisPoints, err := fes.GetBuyDeSoFeeBasisPointsResponseFromGlobalState()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetBuyDeSoFeeBasisPoints: error getting exchange rate: %v", err))
		return
	}
	res := GetBuyDeSoFeeBasisPointsResponse{
		BuyDeSoFeeBasisPoints: feeBasisPoints,
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetBuyDeSoFeeBasisPoints: Problem encoding response as JSON: %v", err))
		return
	}
}

// GetBuyDeSoFeeBasisPointsResponseFromGlobalState is a utility to get the current buy DeSo fee from global state.
func (fes *APIServer) GetBuyDeSoFeeBasisPointsResponseFromGlobalState() (uint64, error) {
	val, err := fes.GlobalStateGet(GlobalStateKeyForBuyDeSoFeeBasisPoints())
	if err != nil {
		return 0, fmt.Errorf("Problem getting buy deso premium basis points from global state: %v", err)
	}
	feeBasisPoints, bytesRead := lib.Uvarint(val)
	if bytesRead <= 0 {
		return 0, fmt.Errorf("Problem reading bytes from global state: %v", err)
	}
	return feeBasisPoints, nil
}
