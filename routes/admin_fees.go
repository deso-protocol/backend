package routes

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/deso-protocol/core/lib"
	"github.com/golang/glog"
	"io"
	"net/http"
)

type TransactionFee struct {
	PublicKeyBase58Check string
	ProfileEntryResponse *ProfileEntryResponse
	AmountNanos          uint64
}

type AdminSetTransactionFeeForTransactionTypeRequest struct {
	TransactionType     lib.TxnString
	NewTransactionFees  []TransactionFee
}

type AdminSetTransactionFeeForTransactionTypeResponse struct {
	TransactionFeeMap map[string][]TransactionFee
}

// AdminSetTransactionFeeForTransactionType sets the minimum price to buy DeSo from this node.
func (fes *APIServer) AdminSetTransactionFeeForTransactionType(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminSetTransactionFeeForTransactionTypeRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminSetTransactionFeeForTransactionType: Problem parsing request body: %v", err))
		return
	}
	txnType := lib.GetTxnTypeFromString(requestData.TransactionType)
	if txnType == lib.TxnTypeUnset {
		_AddBadRequestError(ww, fmt.Sprintf("AdminSetTransactionFeeForTransactionType: %v is not a valid TxnType", requestData.TransactionType))
		return
	}

	// TODO: validate that no public key appears more than once

	outputs, err := TransformTransactionFeesToOutputs(requestData.NewTransactionFees)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminSetTransactionFeeForTransactionType: Error transforming transaction fees to DeSo outputs: %v", err))
		return
	}

	transactionFeeBuf := bytes.NewBuffer([]byte{})
	if err = gob.NewEncoder(transactionFeeBuf).Encode(outputs); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminSetTransactionFeeForTransactionType: Problem encoding Outputs before putting them in global state: %v", err))
		return
	}

	// Put new value in global state
	if err = fes.GlobalStatePut(GlobalStateKeyTransactionFeeOutputsFromTxnType(txnType), transactionFeeBuf.Bytes()); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminSetTransactionFeeForTransactionType: Problem putting fee outputs in global state: %v", err))
		return
	}

	// Update cache
	fes.TransactionFeeMap[txnType] = outputs

	res := AdminSetTransactionFeeForTransactionTypeResponse{
		TransactionFeeMap: fes.TxnFeeMapToResponse(false),
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminSetTransactionFeeForTransactionType: Problem encoding response as JSON: %v", err))
		return
	}
}

type AdminSetAllTransactionFeesRequest struct {
	NewTransactionFees []TransactionFee
}

type AdminSetAllTransactionFeesResponse struct {
	TransactionFeeMap map[string][]TransactionFee
}

func (fes *APIServer) AdminSetAllTransactionFees(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminSetAllTransactionFeesRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminSetAllTransactionFees: Problem parsing request body: %v", err))
		return
	}
	outputs, err := TransformTransactionFeesToOutputs(requestData.NewTransactionFees)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminSetAllTransactionFees: Error transforming transaction fees to DeSo outputs: %v", err))
		return
	}
	// TODO: validate that no public key appears more than once

	transactionFeeBuf := bytes.NewBuffer([]byte{})
	if err = gob.NewEncoder(transactionFeeBuf).Encode(outputs); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminSetAllTransactionFees: Problem encoding Outputs before putting them in global state: %v", err))
		return
	}

	for _, txnType := range lib.AllTxnTypes {
		// Put new value in global state
		if err = fes.GlobalStatePut(GlobalStateKeyTransactionFeeOutputsFromTxnType(txnType), transactionFeeBuf.Bytes()); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminSetAllTransactionFees: Problem putting fee outputs in global state: %v", err))
			return
		}
		fes.TransactionFeeMap[txnType] = outputs
	}

	res := AdminSetAllTransactionFeesResponse{
		TransactionFeeMap: fes.TxnFeeMapToResponse(false),
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminSetAllTransactionFees: Problem encoding response as JSON: %v", err))
		return
	}
}

type AdminGetTransactionFeeMapResponse struct {
	TransactionFeeMap map[string][]TransactionFee
}

func (fes *APIServer) AdminGetTransactionFeeMap(ww http.ResponseWriter, req *http.Request) {
	res := AdminGetTransactionFeeMapResponse{
		TransactionFeeMap: fes.TxnFeeMapToResponse(false),
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGEtTransactionFeeMap: Problem encoding response as JSON: %v", err))
		return
	}
}

func TransformTransactionFeesToOutputs(transactionFees []TransactionFee) (_outputs []*lib.DeSoOutput, _err error) {
	var outputs []*lib.DeSoOutput
	for _, output := range transactionFees {
		outputPublicKeyBytes, _, err := lib.Base58CheckDecode(output.PublicKeyBase58Check)
		if err != nil || len(outputPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
			return nil, fmt.Errorf("TransformTransactionFeesToOutputs: Problem decoding output public key %s: %v",
				output.PublicKeyBase58Check, err)
		}
		outputs = append(outputs, &lib.DeSoOutput{
			PublicKey: outputPublicKeyBytes,
			AmountNanos: output.AmountNanos,
		})
	}
	return outputs, nil
}


func (fes *APIServer) TxnFeeMapToResponse(skipProfileEntryResponses bool) map[string][]TransactionFee{
	txnFeeResponseMap := make(map[string][]TransactionFee)
	var utxoView *lib.UtxoView
	if !skipProfileEntryResponses {
		var err error
		utxoView, err = fes.backendServer.GetMempool().GetAugmentedUniversalView()
		if err != nil {
			// TODO: this is bad if this happens? we can just skip profileEntryResponses I guess
			glog.Errorf("TxnFeeMapToResponse: Unable to get utxoView - you won't be able to see ")
		}
	}
	profileEntryResponseMap := make(map[*lib.PKID]*ProfileEntryResponse)
	for txnType, outputs := range fes.TransactionFeeMap {
		var txnOutputs []TransactionFee
		for _, output := range outputs {
			var profileEntryResponse *ProfileEntryResponse
			if !skipProfileEntryResponses && utxoView != nil {
				pkid := utxoView.GetPKIDForPublicKey(output.PublicKey)
				var exists bool
				profileEntryResponse, exists = profileEntryResponseMap[pkid.PKID]
				if !exists {
					profileEntry := utxoView.GetProfileEntryForPKID(pkid.PKID)
					if profileEntry != nil {
						profileEntryResponse = _profileEntryToResponse(profileEntry, fes.Params, nil, utxoView)
					}
					profileEntryResponseMap[pkid.PKID] = profileEntryResponse
				}
			}
			txnOutputs = append(txnOutputs, TransactionFee{
				PublicKeyBase58Check: lib.PkToString(output.PublicKey, fes.Params),
				AmountNanos: output.AmountNanos,
				ProfileEntryResponse: profileEntryResponse,
			})
		}
		txnFeeResponseMap[txnType.String()] = txnOutputs
	}
	return txnFeeResponseMap
}

func (fes *APIServer) GetTransactionFeeMapFromGlobalState() map[lib.TxnType][]*lib.DeSoOutput {
	transactionFeeMap := make(map[lib.TxnType][]*lib.DeSoOutput)
	for _, txnType := range lib.AllTxnTypes {
		desoOutputBytes, err := fes.GlobalStateGet(GlobalStateKeyTransactionFeeOutputsFromTxnType(txnType))
		if err != nil {
			glog.Errorf("Error getting Transaction Fee bytes from global state for transaction type %v (%d): %v - defaulting to no additional fees", txnType.String(), txnType, err)
			transactionFeeMap[txnType] = []*lib.DeSoOutput{}
		} else {
			var feeOutputs []*lib.DeSoOutput
			if err = gob.NewDecoder(bytes.NewReader(desoOutputBytes)).Decode(&feeOutputs); err != nil {
				glog.Errorf("Error decoding desoOutputBytes to slice of DeSoOutputs: %v - default to no additional fees", err)
				transactionFeeMap[txnType] = []*lib.DeSoOutput{}
			} else {
				transactionFeeMap[txnType] = feeOutputs
			}
		}
	}
	return transactionFeeMap
}
