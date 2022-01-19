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

// TransactionFee is a struct representing a user who should receive a fee.
type TransactionFee struct {
	// PublicKeyBase58Check is the public key of the user who receives the fee.
	PublicKeyBase58Check string
	// ProfileEntryResponse is only non-nil when TransactionFees are retrieved through admin endpoints.
	// The ProfileEntryResponse is only used to display usernames and avatars in the admin dashboard and thus is
	// excluded in other places to reduce payload sizes and improve performance.
	ProfileEntryResponse *ProfileEntryResponse
	// AmountNanos is the amount PublicKeyBase58Check receives when this fee is incurred.
	AmountNanos uint64
}

type AdminSetTransactionFeeForTransactionTypeRequest struct {
	// TransactionType is the type of transaction for which we are setting the fees.
	TransactionType lib.TxnString
	// NewTransactionFees is a slice of TransactionFee structs that tells us who should receive a fee and how much
	// when a transaction of TransactionType is performed.
	NewTransactionFees []TransactionFee
}

type AdminSetTransactionFeeForTransactionTypeResponse struct {
	// TransactionFeeMap is the current state of Transaction fees on this node after the fees defined in
	// AdminSetTransactionFeeForTransactionTypeRequest have been set.
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

	// Transform and encode transaction fees
	outputs, transactionFeeBuf, err := TransformAndEncodeTransactionFees(requestData.NewTransactionFees)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminSetTransactionFeeForTransactionType: Error Transforming and encoding transaction fees: %v", err))
		return
	}

	// Log the fee updates in datadog
	if err = fes.LogFeeSet(txnType, requestData.NewTransactionFees); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminSetTransactionFeeForTransactionType: Error logging fees in datadog for %v transactions: %v", txnType, err))
		return
	}

	// Put new value in global state
	if err = fes.GlobalState.Put(GlobalStateKeyTransactionFeeOutputsFromTxnType(txnType), transactionFeeBuf.Bytes()); err != nil {
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

// AdminSetAllTransactionFeesRequest  applies NewTransactionFees to each TransactionType.
type AdminSetAllTransactionFeesRequest struct {
	// NewTransactionFees is a slice of TransactionFees that should be applied to all transaction types.
	// This overwrites all transaction types.
	NewTransactionFees []TransactionFee
}

type AdminSetAllTransactionFeesResponse struct {
	// TransactionFeeMap is the current state of Transaction fees on this node after the fees defined in
	// AdminSetAllTransactionFeesRequest have been set.
	TransactionFeeMap map[string][]TransactionFee
}

// AdminSetAllTransactionFees overwrites transaction fees for all transaction types.
func (fes *APIServer) AdminSetAllTransactionFees(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminSetAllTransactionFeesRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminSetAllTransactionFees: Problem parsing request body: %v", err))
		return
	}

	// Transform and encode transaction fees
	outputs, transactionFeeBuf, err := TransformAndEncodeTransactionFees(requestData.NewTransactionFees)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminSetAllTransactionFees: Error Transforming and encoding transaction fees: %v", err))
		return
	}

	// For each txnType, log the fee update and put the new transaction fees in global state.
	for _, txnType := range lib.AllTxnTypes {
		// Log the fee update in datadog
		if err = fes.LogFeeSet(txnType, requestData.NewTransactionFees); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminSetAllTransactionFees: Error logging fees in datadog for %v transactions: %v", txnType, err))
			return
		}
		// Put new value in global state
		if err = fes.GlobalState.Put(GlobalStateKeyTransactionFeeOutputsFromTxnType(txnType), transactionFeeBuf.Bytes()); err != nil {
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
	// TransactionFeeMap is the current state of Transaction fees on this node.
	TransactionFeeMap map[string][]TransactionFee
}

// AdminGetTransactionFeeMap is an endpoint that returns the TransactionFeeMap with ProfileEntryResponses.
func (fes *APIServer) AdminGetTransactionFeeMap(ww http.ResponseWriter, req *http.Request) {
	res := AdminGetTransactionFeeMapResponse{
		TransactionFeeMap: fes.TxnFeeMapToResponse(false),
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetTransactionFeeMap: Problem encoding response as JSON: %v", err))
		return
	}
}

// TransformAndEncodeTransactionFees checks transaction fees for duplicate public keys, transform TransactionFee structs
// to DeSoOutputs, and then encodes that slice of DeSoOutputs.
func TransformAndEncodeTransactionFees(transactionFees []TransactionFee) (_outputs []*lib.DeSoOutput, _buf *bytes.Buffer, _err error) {
	// Check for duplicate public keys
	if err := CheckTransactionFeeForDuplicatePublicKeys(transactionFees); err != nil {
		return nil, nil, err
	}
	// Transform TransactionFees to DesoOutputs
	outputs, err := TransformTransactionFeesToOutputs(transactionFees)
	if err != nil {
		return nil, nil, err
	}

	// Encode the outputs
	transactionFeeBuf := bytes.NewBuffer([]byte{})
	if err = gob.NewEncoder(transactionFeeBuf).Encode(outputs); err != nil {
		return nil, nil, err
	}
	return outputs, transactionFeeBuf, nil
}

// TransformTransactionFeesToOutputs takes in a slice of TransactionFees and returns a slice of DeSoOutputs
func TransformTransactionFeesToOutputs(transactionFees []TransactionFee) (_outputs []*lib.DeSoOutput, _err error) {
	var outputs []*lib.DeSoOutput
	for _, output := range transactionFees {
		// Convert the PublicKeyBase58Check string to a public key byte slice.
		outputPublicKeyBytes, _, err := lib.Base58CheckDecode(output.PublicKeyBase58Check)
		if err != nil || len(outputPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
			return nil, fmt.Errorf("TransformTransactionFeesToOutputs: Problem decoding output public key %s: %v",
				output.PublicKeyBase58Check, err)
		}
		// Construct and append the DeSoOutput to the slice of outputs.
		outputs = append(outputs, &lib.DeSoOutput{
			PublicKey:   outputPublicKeyBytes,
			AmountNanos: output.AmountNanos,
		})
	}
	return outputs, nil
}

// TxnFeeMapToResponse converts the transaction fee map to a format that is usable by the frontend.
func (fes *APIServer) TxnFeeMapToResponse(skipProfileEntryResponses bool) map[string][]TransactionFee {
	txnFeeResponseMap := make(map[string][]TransactionFee)
	var utxoView *lib.UtxoView
	// If we're including ProfileEntryResponses, we need to get a utxoView.
	if !skipProfileEntryResponses {
		var err error
		if utxoView, err = fes.backendServer.GetMempool().GetAugmentedUniversalView(); err != nil {
			// Since we only need ProfileEntryResponses in the admin panel, it's okay to swallow this errors. The admin
			// will just see public keys instead of usernames + avatars.
			glog.Errorf("TxnFeeMapToResponse: Unable to get utxoView - you won't be able to see usernames and avatars")
		}
	}
	profileEntryResponseMap := make(map[*lib.PKID]*ProfileEntryResponse)
	for txnType, outputs := range fes.TransactionFeeMap {
		var txnOutputs []TransactionFee
		// For each output that needs to be added for this transaction type, construct the TransactionFee struct
		for _, output := range outputs {
			var profileEntryResponse *ProfileEntryResponse
			// Get the ProfileEntryResponse if we need it. Save it in the profileEntryResponseMap to expedite lookup
			// if we have duplicates.
			if !skipProfileEntryResponses && utxoView != nil {
				// Get the PKID
				pkid := utxoView.GetPKIDForPublicKey(output.PublicKey)
				var exists bool
				// Check if the PKID exists in the map
				profileEntryResponse, exists = profileEntryResponseMap[pkid.PKID]
				// If it doesn't exist, try to get the ProfileEntry and convert it to a response and save it in the map.
				if !exists {
					profileEntry := utxoView.GetProfileEntryForPKID(pkid.PKID)
					if profileEntry != nil {
						profileEntryResponse = fes._profileEntryToResponse(profileEntry, utxoView)
					}
					profileEntryResponseMap[pkid.PKID] = profileEntryResponse
				}
			}
			// Append the transaction fee to the slice of txnOutputs
			txnOutputs = append(txnOutputs, TransactionFee{
				PublicKeyBase58Check: lib.PkToString(output.PublicKey, fes.Params),
				AmountNanos:          output.AmountNanos,
				ProfileEntryResponse: profileEntryResponse,
			})
		}
		txnFeeResponseMap[txnType.String()] = txnOutputs
	}
	return txnFeeResponseMap
}

// GetTransactionFeeMapFromGlobalState extracts the transaction fee map from global state.
func (fes *APIServer) GetTransactionFeeMapFromGlobalState() map[lib.TxnType][]*lib.DeSoOutput {
	transactionFeeMap := make(map[lib.TxnType][]*lib.DeSoOutput)
	// For each transaction type, get the list of DeSoOutputs we want to add when performing this type of transaction
	for _, txnType := range lib.AllTxnTypes {
		// Get the bytes from global state
		desoOutputBytes, err := fes.GlobalState.Get(GlobalStateKeyTransactionFeeOutputsFromTxnType(txnType))
		if err != nil {
			glog.Errorf("Error getting Transaction Fee bytes from global state for transaction type %v (%d): %v - defaulting to no additional fees", txnType.String(), txnType, err)
			// Default to an empty slice.
			transactionFeeMap[txnType] = []*lib.DeSoOutput{}
		} else {
			var feeOutputs []*lib.DeSoOutput
			// Decode the bytes into the slice of DeSoOutputs
			if err = gob.NewDecoder(bytes.NewReader(desoOutputBytes)).Decode(&feeOutputs); err != nil {
				glog.Errorf("Error decoding desoOutputBytes to slice of DeSoOutputs: %v - default to no additional fees", err)
				// Default to an empty slice.
				transactionFeeMap[txnType] = []*lib.DeSoOutput{}
			} else {
				// Set the value to the decoded list of DeSoOutputs for this transaction type
				transactionFeeMap[txnType] = feeOutputs
			}
		}
	}
	return transactionFeeMap
}

// CheckTransactionFeeForDuplicatePublicKeys checks that a slice of TransactionFees does not contain a duplicate
// PublicKey
func CheckTransactionFeeForDuplicatePublicKeys(newTransactionFees []TransactionFee) error {
	publicKeyToTransactionFeeMap := make(map[string]TransactionFee)
	// We won't allow more than one output for a given public key.
	for _, transactionFee := range newTransactionFees {
		if _, exists := publicKeyToTransactionFeeMap[transactionFee.PublicKeyBase58Check]; exists {
			return fmt.Errorf("duplicate public key detected: %v", transactionFee.PublicKeyBase58Check)
		}
		publicKeyToTransactionFeeMap[transactionFee.PublicKeyBase58Check] = transactionFee
	}
	return nil
}

type AdminAddExemptPublicKey struct {
	// PublicKeyBase58Check is the public key for which we are adding or removing an exemption from node fees.
	PublicKeyBase58Check string
	// IsRemoval is a boolean that when true means we should remove the exemption from a public key, when false means we
	// should add an exemption.
	IsRemoval bool
}

// AdminAddExemptPublicKey adds or removes a public key from the list of public keys exempt from node fees.
func (fes *APIServer) AdminAddExemptPublicKey(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminAddExemptPublicKey{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminAddExemptPublicKey: Problem parsing request body: %v", err))
		return
	}

	// Convert the PublicKeyBase58Check string to a public key byte slice.
	publicKeyBytes, _, err := lib.Base58CheckDecode(requestData.PublicKeyBase58Check)
	if err != nil || len(publicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		_AddBadRequestError(ww, fmt.Sprintf("AdminAddExemptPublicKey: Problem decoding public key %s: %v",
			requestData.PublicKeyBase58Check, err))
	}

	dbKey := GlobalStateKeyExemptPublicKey(publicKeyBytes)

	if requestData.IsRemoval {
		// Delete the key from global state
		if err = fes.GlobalState.Delete(dbKey); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminAddExemptPublicKey: Error deleting key from global state: %v", err))
			return
		}
		delete(fes.ExemptPublicKeyMap, lib.PkToString(publicKeyBytes, fes.Params))
	} else {
		// Add the key to global state
		if err = fes.GlobalState.Put(dbKey, []byte{1}); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminAddExemptPublicKey: Error adding key to global state: %v", err))
			return
		}
		fes.ExemptPublicKeyMap[lib.PkToString(publicKeyBytes, fes.Params)] = []byte{}
	}
}

type AdminGetExemptPublicKeysResponse struct {
	// ExemptPublicKeyMap is a map of PublicKeyBase58Check to ProfileEntryResponse. These public keys do not have to pay
	// node fees.
	ExemptPublicKeyMap map[string]*ProfileEntryResponse
}

// AdminGetExemptPublicKeys gets a map of public key to ProfileEntryResponse that represents the public keys that are
// exempt from node fees.
func (fes *APIServer) AdminGetExemptPublicKeys(ww http.ResponseWriter, req *http.Request) {
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetExemptPublicKeys: Error getting utxoView: %v", err))
		return
	}
	exemptPublicKeyMap := make(map[string]*ProfileEntryResponse)
	for publicKeyBase58Check, _ := range fes.ExemptPublicKeyMap {
		var publicKeyBytes []byte
		// Convert the PublicKeyBase58Check string to a public key byte slice.
		publicKeyBytes, _, err = lib.Base58CheckDecode(publicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminGetExemptPublicKeys: Unable to decode PublicKeyBase58Check: %v", publicKeyBase58Check))
			return
		}
		profileEntry := utxoView.GetProfileEntryForPublicKey(publicKeyBytes)
		var profileEntryResponse *ProfileEntryResponse
		if profileEntry != nil {
			profileEntryResponse = fes._profileEntryToResponse(profileEntry, utxoView)
		}
		exemptPublicKeyMap[publicKeyBase58Check] = profileEntryResponse
	}

	res := AdminGetExemptPublicKeysResponse{
		ExemptPublicKeyMap: exemptPublicKeyMap,
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetExemptPublicKeyMap: Problem encoding response as JSON: %v", err))
		return
	}
}

// GetExemptPublicKeyMapFromGlobalState gets a map where the keys represent the list of public keys exempt from node fees
func (fes *APIServer) GetExemptPublicKeyMapFromGlobalState() map[string]interface{} {
	exemptPublicKeyMap := make(map[string]interface{})
	// For each transaction type, get the list of DeSoOutputs we want to add when performing this type of transaction
	prefix := append([]byte{}, _GlobalStatePrefixExemptPublicKeys...)
	maxKeyLen := 1 + btcec.PubKeyBytesLenCompressed
	keys, _, err := fes.GlobalState.Seek(prefix, prefix, maxKeyLen, 300, true, false)
	if err != nil {
		// if we encounter an error, just return an empty map.
		return exemptPublicKeyMap
	}

	for _, key := range keys {
		// Chop the publicKeyBytes out of the db key.
		// The dbKeyBytes are: [One Prefix Byte][btcec.PubKeyBytesLenCompressed]
		publicKeyBytes := key[1:]
		exemptPublicKeyMap[lib.PkToString(publicKeyBytes, fes.Params)] = []byte{}
	}

	return exemptPublicKeyMap
}

func (fes *APIServer) LogFeeSet(txnType lib.TxnType, transactionFees []TransactionFee) (_err error) {
	if fes.backendServer == nil || fes.backendServer.GetStatsdClient() == nil {
		return nil
	}
	var totalFees uint64
	for _, transactionFee := range transactionFees {
		totalFees += transactionFee.AmountNanos
	}
	tags := []string{}
	if err := fes.backendServer.GetStatsdClient().Gauge(fmt.Sprintf("NODE_FEE_TOTAL.%v", txnType.GetTxnString()), float64(totalFees), tags, 1); err != nil {
		return err
	}
	return nil
}
