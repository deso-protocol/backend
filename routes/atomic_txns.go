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

	// Alternatively, instead of submitting the Transactions as MsgDeSoTxn, the user can submit
	// the unsigned transactions in hex form. This is useful in cases where the
	// client does not have the ability to intelligently encode a transaction. The effect will be
	// the same as if they had submitted the Transactions field populated with the encoded
	// UnsignedTransactionHexes.
	UnsignedTransactionHexes []string
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

	// InnerTransactionHexes is a list of hex-encoded inner transactions
	// contained in Transaction above.
	InnerTransactionHexes []string
}

func (fes *APIServer) CreateAtomicTxnsWrapper(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := CreateAtomicTxnsWrapperRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateAtomicTxnsWrapper: Error parsing request body: %v", err))
		return
	}

	if len(requestData.Transactions) > 0 && len(requestData.UnsignedTransactionHexes) > 0 {
		_AddBadRequestError(ww, fmt.Sprintf("CreateAtomicTxnsWrapper: "+
			"Cannot have both Transactions and UnsignedTransactionHexes populated."))
		return
	}

	// Set encodedTransactions from UnsignedTransactionHexes only if the latter is provided.
	encodedTransactions := requestData.Transactions
	if len(requestData.UnsignedTransactionHexes) > 0 {
		encodedTransactions = make([]*lib.MsgDeSoTxn, len(requestData.UnsignedTransactionHexes))
		for ii, unsignedTxnHex := range requestData.UnsignedTransactionHexes {
			// Decode the unsigned transaction.
			unsignedTxnBytes, err := hex.DecodeString(unsignedTxnHex)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf(
					"CreateAtomicTxnsWrapper: Problem decoding unsigned transaction hex at index %v: %v", ii, err))
				return
			}

			// Deserialize the unsigned transaction.
			unsignedTxn := &lib.MsgDeSoTxn{}
			if err := unsignedTxn.FromBytes(unsignedTxnBytes); err != nil {
				_AddBadRequestError(ww, fmt.Sprintf(
					"CreateAtomicTxnsWrapper: Problem deserializing unsigned transaction %d from bytes: %v",
					ii, err))
				return
			}

			encodedTransactions[ii] = unsignedTxn
		}
	}

	// Grab a view (needed for getting global params, etc).
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateAtomicTxnsWrapper: Error getting utxoView: %v", err))
		return
	}

	// Validate the request data.
	if len(encodedTransactions) == 0 {
		_AddBadRequestError(ww, fmt.Sprint("CreateAtomicTxnsWrapper: must have at least one transaction "+
			"in Transactions or UnsignedTransactionHexes"))
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
		encodedTransactions, extraData, fes.backendServer.GetMempool(), requestData.MinFeeRateNanosPerKB)
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

	innerTransactionHexes, err := GetInnerTransactionHexesFromAtomicTxn(txn)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateAtomicTxnsWrapper: Problem getting inner transaction hexes: %v", err))
		return
	}

	// Construct a response.
	res := CreateAtomicTxnsWrapperResponse{
		TransactionsWrapped:   uint64(len(txn.TxnMeta.(*lib.AtomicTxnsWrapperMetadata).Txns)),
		TotalFeeNanos:         totalFees,
		Transaction:           txn,
		TransactionHex:        hex.EncodeToString(txnBytes),
		InnerTransactionHexes: innerTransactionHexes,
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww,
			fmt.Sprintf("CreateAtomicTxnsWrapper: Problem serializing object to JSON: %v", err))
		return
	}
}

func GetInnerTransactionHexesFromAtomicTxn(txn *lib.MsgDeSoTxn) ([]string, error) {
	if txn.TxnMeta.GetTxnType() != lib.TxnTypeAtomicTxnsWrapper {
		return nil,
			fmt.Errorf("GetInnerTransactionHexesFromAtomicTxn: Transaction is not an atomic transaction wrapper")
	}
	innerTransactionHexes := []string{}
	for _, innerTxn := range txn.TxnMeta.(*lib.AtomicTxnsWrapperMetadata).Txns {
		innerTxnBytes, err := innerTxn.ToBytes(true)
		if err != nil {
			return nil,
				fmt.Errorf("GetInnerTransactionHexesFromAtomicTxn: Problem serializing inner transaction: %v", err)
		}
		innerTransactionHexes = append(innerTransactionHexes, hex.EncodeToString(innerTxnBytes))
	}
	return innerTransactionHexes, nil
}
