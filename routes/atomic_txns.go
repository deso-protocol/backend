package routes

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/deso-protocol/core/lib"
	"io"
	"net/http"
)

type CreateAtomicTxnsWrapperRequest struct {
	Transactions         []*lib.MsgDeSoTxn
	ExtraData            map[string]string
	MinFeeRateNanosPerKB uint64 `safeForLogging:"true"`
}

type CreateAtomicTxnsWrapperResponse struct {
	// TransactionsWrapped as a helpful sanity check for the caller of the
	// CreateAtomicTxnsWrapper endpoint. That being said, the caller should
	// also sanity check that the returned wrapper transaction has the atomic
	// transactions ordered correctly.
	TransactionsWrapped uint64 `safeForLogging:"true"`

	// TotalFeeNanos represents the total fees paid cumulatively by all
	// wrapper atomic transactions and is consistent with the
	// returned Transaction.TxnFeeNanos field.
	TotalFeeNanos  uint64
	Transaction    *lib.MsgDeSoTxn
	TransactionHex string
}

func (fes *APIServer) CreateAtomicTxnsWrapper(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := CreateAtomicTxnsWrapperRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateAtomicTxnsWrapper: Error parsing request body: %v", err))
		return
	}

	// Grab a view (needed for getting global params, etc).
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateAtomicTxnsWrapper: Error getting utxoView: %v", err))
		return
	}

	// Validate the request data.
	if len(requestData.Transactions) == 0 {
		_AddBadRequestError(ww, fmt.Sprint("CreateAtomicTxnsWrapper: must have at least one transaction "+
			"in Transactions"))
		return
	}

	// Encode the ExtraData map.
	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateAtomicTxnsWrapper: Problem encoding ExtraData: %v", err))
		return
	}

	// Construct the atomic transactions wrapper transaction type.
	txn, totalFees, err := fes.blockchain.CreateAtomicTxnsWrapper(
		requestData.Transactions, extraData, fes.backendServer.GetMempool(), requestData.MinFeeRateNanosPerKB)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateAtomicTxnsWrapper: Problem constructing transaction: %v", err))
		return
	}

	// Serialize the transaction.
	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateAtomicTxnsWrapper: Problem serializing transaction: %v", err))
		return
	}
	txnSizeBytes := uint64(len(txnBytes))

	// Validate that:
	// 	(1) The resulting transaction is not over the size limit of an atomic transaction.
	// 	(2) The resulting wrapper transactions have sufficient fees to cover the wrapper.
	if txnSizeBytes > utxoView.GetCurrentGlobalParamsEntry().MaxTxnSizeBytesPoS {
		_AddBadRequestError(ww, fmt.Sprint("CreateAtomicTxnsWrapper: Resulting wrapper transaction too large"))
		return
	}
	if txnSizeBytes != 0 && utxoView.GetCurrentGlobalParamsEntry().MinimumNetworkFeeNanosPerKB != 0 {
		// Check for overflow or minimum network fee not met.
		if totalFees != ((totalFees*1000)/1000) ||
			(totalFees*1000)/uint64(txnSizeBytes) < utxoView.GetCurrentGlobalParamsEntry().MinimumNetworkFeeNanosPerKB {
			_AddBadRequestError(ww, fmt.Sprint("CreateAtomicTxnsWrapper: Transactions used to construct"+
				" atomic transaction do not cumulatively pay sufficient network fees to cover wrapper"))
			return
		}
	}

	// Construct a response.
	res := CreateAtomicTxnsWrapperResponse{
		TransactionsWrapped: uint64(len(txn.TxnMeta.(*lib.AtomicTxnsWrapperMetadata).Txns)),
		TotalFeeNanos:       totalFees,
		Transaction:         txn,
		TransactionHex:      hex.EncodeToString(txnBytes),
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww,
			fmt.Sprintf("CreateAtomicTxnsWrapper: Problem serializing object to JSON: %v", err))
		return
	}
}
