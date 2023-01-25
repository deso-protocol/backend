package routes

import (
	"encoding/json"
	"fmt"
	"github.com/deso-protocol/core/lib"
	"github.com/golang/glog"
	"io"
	"net/http"
)

type SetUSDCentsToDeSoExchangeRateRequest struct {
	USDCentsPerDeSo uint64
	AdminPublicKey  string
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
	if err := fes.GlobalState.Put(
		GlobalStateKeyForUSDCentsToDeSoReserveExchangeRate(),
		lib.UintToBuf(requestData.USDCentsPerDeSo)); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SetUSDCentsToDeSoReserveExchangeRate: Problem putting exchange rate in global state: %v", err))
		return
	}

	fes.USDCentsToDESOReserveExchangeRate = requestData.USDCentsPerDeSo

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
	res := GetUSDCentsToDeSoExchangeRateResponse{
		USDCentsPerDeSo: fes.USDCentsToDESOReserveExchangeRate,
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetUSDCentsToDeSoExchangeRate: Problem encoding response as JSON: %v", err))
		return
	}
}

// SetUSDCentsToDeSoReserveExchangeRateFromGlobalState is a helper function to set the cached value of the current USD
// cents to DeSo exchange rate
func (fes *APIServer) SetUSDCentsToDeSoReserveExchangeRateFromGlobalState() {
	val, err := fes.GlobalState.Get(GlobalStateKeyForUSDCentsToDeSoReserveExchangeRate())
	if err != nil {
		glog.Errorf("SetUSDCentsToDeSoReserveExchangeRateFromGlobalState: Error getting Reserve exchange rate "+
			"from global state: %v", err)
		return
	}
	// If there was no value found, this node has not set the Fee Basis points yet so we return.
	if val == nil {
		return
	}
	usdCentsPerDeSo, bytesRead := lib.Uvarint(val)
	if bytesRead <= 0 {
		glog.Errorf("SetUSDCentsToDeSoReserveExchangeRateFromGlobalState: invalid bytes read: %v", bytesRead)
		return
	}
	fes.USDCentsToDESOReserveExchangeRate = usdCentsPerDeSo
}

type SetBuyDeSoFeeBasisPointsRequest struct {
	BuyDeSoFeeBasisPoints uint64
	AdminPublicKey        string
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

	if err := fes.GlobalState.Put(
		GlobalStateKeyForBuyDeSoFeeBasisPoints(),
		lib.UintToBuf(requestData.BuyDeSoFeeBasisPoints)); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SetBuyDeSoFeeBasisPoints: Problem putting premium basis points in global state: %v", err))
		return
	}

	fes.BuyDESOFeeBasisPoints = requestData.BuyDeSoFeeBasisPoints

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
	res := GetBuyDeSoFeeBasisPointsResponse{
		BuyDeSoFeeBasisPoints: fes.BuyDESOFeeBasisPoints,
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetBuyDeSoFeeBasisPoints: Problem encoding response as JSON: %v", err))
		return
	}
}

// SetBuyDeSoFeeBasisPointsResponseFromGlobalState is a utility to set the cached value of the current buy DeSo fee
// from global state.
func (fes *APIServer) SetBuyDeSoFeeBasisPointsResponseFromGlobalState() {
	val, err := fes.GlobalState.Get(GlobalStateKeyForBuyDeSoFeeBasisPoints())
	if err != nil {
		glog.Errorf("SetBuyDeSoFeeBasisPointsResponseFromGlobalState: Error getting Buy DESO Fee Basis Points "+
			"from global state: %v", err)
		return
	}
	// If there was no value found, this node has not set the Fee Basis points yet so we return 0.
	if val == nil {
		return
	}
	feeBasisPoints, bytesRead := lib.Uvarint(val)
	if bytesRead <= 0 {
		glog.Errorf("SetBuyDeSoFeeBasisPointsResponseFromGlobalState: invalid bytes read: %v", bytesRead)
		return
	}
	fes.BuyDESOFeeBasisPoints = feeBasisPoints
}
