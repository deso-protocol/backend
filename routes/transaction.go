package routes

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	ecdsa2 "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"io"
	"math/big"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/deso-protocol/uint256"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/deso-protocol/core/lib"
	"github.com/golang/glog"
	"github.com/pkg/errors"
)

type TxnStatus string

const (
	TxnStatusInMempool TxnStatus = "InMempool"
	TxnStatusCommitted TxnStatus = "Committed"
	// TODO: It would be useful to have one that is "UnconfirmedBlocks" or something like that, which
	// means we'll consider txns that are in unconfirmed blocks but will *not* consider txns
	// that are in the mempool. It's a kindof middle-ground.
)

type GetTxnRequest struct {
	// TxnHashHex to fetch.
	TxnHashHex string `safeForLogging:"true"`
	// If unset, defaults to TxnStatusInMempool
	TxnStatus TxnStatus `safeForLogging:"true"`
}

type GetTxnResponse struct {
	TxnFound bool
}

func (fes *APIServer) GetTxn(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetTxnRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetTxn: Problem parsing request body: %v", err))
		return
	}

	// Decode the postHash.
	var txnHash *lib.BlockHash
	if requestData.TxnHashHex == "" {
		_AddBadRequestError(ww, fmt.Sprintf("GetTxn: Must provide a TxnHashHex."))
		return
	} else {
		txnHashBytes, err := hex.DecodeString(requestData.TxnHashHex)
		if err != nil || len(txnHashBytes) != lib.HashSizeBytes {
			_AddBadRequestError(ww, fmt.Sprintf("GetTxn: Error parsing post hash %v: %v",
				requestData.TxnHashHex, err))
			return
		}
		txnHash = &lib.BlockHash{}
		copy(txnHash[:], txnHashBytes)
	}

	// The order of operations is tricky here. We need to do the following in this
	// exact order:
	// 1. Check the mempool for the txn
	// 2. Wait for txindex to fully sync
	// 3. Then check txindex
	//
	// If we instead check the mempool afterward, then there is a chance that the txn
	// has been removed by a new block that is not yet in txindex. This would cause the
	// endpoint to incorrectly report that the txn doesn't exist on the node, when in
	// fact it is in "limbo" between the mempool and txindex.
	txnStatus := requestData.TxnStatus
	if txnStatus == "" {
		txnStatus = TxnStatusInMempool
	}
	txnInMempool := fes.backendServer.GetMempool().IsTransactionInPool(txnHash)
	startTime := time.Now()
	// We have to wait until txindex has reached the uncommitted tip height, not the
	// committed tip height. Otherwise we'll be missing ~2 blocks in limbo.
	coreChainTipHeight := fes.TXIndex.CoreChain.BlockTip().Height
	for fes.TXIndex.TXIndexChain.BlockTip().Height < coreChainTipHeight {
		if time.Since(startTime) > 30*time.Second {
			_AddBadRequestError(ww, fmt.Sprintf("GetTxn: Timed out waiting for txindex to sync."))
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	txnInTxindex := lib.DbCheckTxnExistence(fes.TXIndex.TXIndexChain.DB(), nil, txnHash)
	txnFound := false
	switch txnStatus {
	case TxnStatusInMempool:
		// In this case, we're fine if the txn is either in the mempool or in txindex.
		txnFound = txnInMempool || txnInTxindex
	case TxnStatusCommitted:
		// In this case we will not consider a txn until it shows up in txindex, which means that
		// it is committed.
		txnFound = txnInTxindex
	default:
		_AddBadRequestError(ww, fmt.Sprintf("GetTxn: Invalid TxnStatus: %v. Options are "+
			"{InMempool, Committed}", txnStatus))
		return
	}

	res := &GetTxnResponse{
		TxnFound: txnFound,
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetSinglePost: Problem encoding response as JSON: %v", err))
		return
	}
}

const GetTxnsRequestCountMax = 500

type GetTxnsRequest struct {
	TxnHashHexes []string  `safeForLogging:"true"`
	TxnStatus    TxnStatus `safeForLogging:"true"` // If unset, defaults to TxnStatusInMempool.
}

type GetTxnsResponse struct {
	// Map of TxnHashHex strings -> TxnFound booleans
	TxnsFound map[string]bool
}

func (fes *APIServer) GetTxns(ww http.ResponseWriter, req *http.Request) {
	// Parse JSON request body.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetTxnsRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetTxns: Problem parsing request body: %v", err))
		return
	}

	// Validate the TxnHashHexes param.
	if len(requestData.TxnHashHexes) == 0 {
		_AddBadRequestError(ww, fmt.Sprintf("GetTxns: TxnHashHexes is empty."))
		return
	}
	if len(requestData.TxnHashHexes) > GetTxnsRequestCountMax {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetTxns: TxnHashHexes length %d is greater than %d.",
			len(requestData.TxnHashHexes),
			GetTxnsRequestCountMax,
		))
		return
	}

	// Validate the TxnStatus param.
	txnStatus := requestData.TxnStatus
	if txnStatus == "" {
		txnStatus = TxnStatusInMempool
	}
	if txnStatus != TxnStatusInMempool && txnStatus != TxnStatusCommitted {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetTxns: Invalid TxnStatus: %s. Options are {InMempool, Committed}.", txnStatus,
		))
		return
	}

	// Decode the TxnHashHexes.
	txnHashes := make(map[string]*lib.BlockHash, len(requestData.TxnHashHexes))
	for _, txnHashHex := range requestData.TxnHashHexes {
		txnHashBytes, err := hex.DecodeString(txnHashHex)
		if err != nil || len(txnHashBytes) != lib.HashSizeBytes {
			_AddBadRequestError(ww, fmt.Sprintf("GetTxns: Error parsing txn hash %s: %v", txnHashHex, err))
			return
		}
		txnHashes[txnHashHex] = lib.NewBlockHash(txnHashBytes)
	}

	// The order of operations is tricky here. We need to do the following in this
	// exact order:
	// 1. Check the mempool for each txn
	// 2. Wait for txindex to fully sync
	// 3. Then check txindex
	//
	// If we instead check the mempool afterward, then there is a chance that a txn
	// has been removed by a new block that is not yet in txindex. This would cause the
	// endpoint to incorrectly report that the txn doesn't exist on the node, when in
	// fact it is in "limbo" between the mempool and txindex.
	res := &GetTxnsResponse{TxnsFound: make(map[string]bool)}

	// 1. Check the mempool for each txn if TxnStatusInMempool.
	if txnStatus == TxnStatusInMempool {
		mempool := fes.backendServer.GetMempool()
		for txnHashHex, txnHash := range txnHashes {
			res.TxnsFound[txnHashHex] = mempool.IsTransactionInPool(txnHash)
		}
	}

	// 2. We have to wait until txindex has reached the uncommitted tip height, not
	//    the committed tip height. Otherwise, we'll be missing ~2 blocks in limbo.
	startTime := time.Now()
	coreChainTipHeight := fes.TXIndex.CoreChain.BlockTip().Height
	for fes.TXIndex.TXIndexChain.BlockTip().Height < coreChainTipHeight {
		if time.Since(startTime) > 30*time.Second {
			_AddBadRequestError(ww, fmt.Sprintf("GetTxns: Timed out waiting for txindex to sync."))
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 3. Check the txindex for each txn.
	for txnHashHex, txnHash := range txnHashes {
		if res.TxnsFound[txnHashHex] {
			continue // Skip if TxnStatusInMempool and we already found the txn in the mempool.
		}
		res.TxnsFound[txnHashHex] = lib.DbCheckTxnExistence(fes.TXIndex.TXIndexChain.DB(), nil, txnHash)
	}

	// Encode response as JSON.
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetTxns: Problem encoding response as JSON: %v", err))
		return
	}
}

// SubmitAtomicTransactionRequest is meant to aid in the submission of atomic transactions
// with identity service signed transactions. Specifically, it takes an incomplete atomic transaction
// and "completes" the transaction by adding in identity service signed transactions.
type SubmitAtomicTransactionRequest struct {
	// IncompleteAtomicTransactionHex is a hex encoded transaction of type TxnTypeAtomicTxnsWrapper who
	// is "incomplete" only by missing the signature fields of various inner transactions.
	IncompleteAtomicTransactionHex string `safeForLogging:"true"`

	// SignedInnerTransactionsHex are the hex-encoded signed inner transactions that
	// will be used to complete the atomic transaction.
	SignedInnerTransactionsHex []string `safeForLogging:"true"`

	// Alternatively, instead of submitting the signed inner transactions, the user can submit
	// the unsigned transactions and the signatures separately. This is useful in cases where the
	// client does not have the ability to intelligently decode a transaction and embed the signature
	// within it. The effect will be the same as if they had submitted the SignedInnerTransactionsHex
	// of the UnsignedInnerTranactions with the TransactionSignaturesHex embedded within them.
	UnsignedInnerTransactionsHex []string
	TransactionSignaturesHex     []string
}

type SubmitAtomicTransactionResponse struct {
	Transaction              *lib.MsgDeSoTxn
	TxnHashHex               string
	TransactionIDBase58Check string
}

func (fes *APIServer) SubmitAtomicTransaction(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := SubmitAtomicTransactionRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitAtomicTransaction: Problem parsing request body: %v", err))
		return
	}

	if len(requestData.SignedInnerTransactionsHex) > 0 && len(requestData.UnsignedInnerTransactionsHex) > 0 {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitAtomicTransaction: "+
			"Cannot submit both SignedInnerTransactionsHex and UnsignedInnerTransactionsHex. You must pick "+
			"one or the other."))
		return
	}
	if len(requestData.UnsignedInnerTransactionsHex) > 0 &&
		len(requestData.UnsignedInnerTransactionsHex) != len(requestData.TransactionSignaturesHex) {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitAtomicTransaction: "+
			"Number of UnsignedInnerTransactionsHex must match number of TransactionSignaturesHex."))
		return
	}

	signedInnerTransactionHexes := requestData.SignedInnerTransactionsHex
	if len(requestData.UnsignedInnerTransactionsHex) > 0 {
		// When the user is submitting the signatures separately, then we ignore whatever
		// was set in SignedInnerTransactionsHex and embed the signatures manually for the
		// user.
		signedInnerTransactionHexes = make([]string, len(requestData.UnsignedInnerTransactionsHex))
		for ii, unsignedInnerTxnHex := range requestData.UnsignedInnerTransactionsHex {
			// Decode the unsigned inner transaction.
			unsignedTxnBytes, err := hex.DecodeString(unsignedInnerTxnHex)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf(
					"SubmitAtomicTransaction: Problem decoding unsigned transaction hex: %v", err))
				return
			}

			// Deserialize the unsigned transaction.
			unsignedInnerTxn := &lib.MsgDeSoTxn{}
			if err := unsignedInnerTxn.FromBytes(unsignedTxnBytes); err != nil {
				_AddBadRequestError(ww, fmt.Sprintf(
					"SubmitAtomicTransaction: Problem deserializing unsigned transaction %d from bytes: %v",
					ii, err))
				return
			}

			// Decode the signature
			signatureBytes, err := hex.DecodeString(requestData.TransactionSignaturesHex[ii])
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf(
					"SubmitAtomicTransaction: Problem decoding signature hex: %v", err))
				return
			}
			signature := lib.DeSoSignature{}
			if err := signature.FromBytes(signatureBytes); err != nil {
				_AddBadRequestError(ww, fmt.Sprintf(
					"SubmitAtomicTransaction: Problem deserializing signature %d from bytes: %v",
					ii, err))
				return
			}

			// Embed the signature within the transaction
			unsignedInnerTxn.Signature = signature

			// Serialize the unsignedInnerTxn with the signature
			signedInnerTxnBytes, err := unsignedInnerTxn.ToBytes(false)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf(
					"SubmitAtomicTransaction: Problem serializing "+
						"unsigned transaction %d with signature: %v", ii, err))
				return
			}

			// Encode the signed inner transaction.
			signedInnerTransactionHexes[ii] = hex.EncodeToString(signedInnerTxnBytes)
		}
	}

	// Fetch the incomplete atomic transaction.
	atomicTxnBytes, err := hex.DecodeString(requestData.IncompleteAtomicTransactionHex)
	if err != nil {
		_AddBadRequestError(ww,
			fmt.Sprintf("SubmitAtomicTransaction: "+
				"Problem deserializing atomic transaction hex: %v", err))
		return
	}
	atomicTxn := &lib.MsgDeSoTxn{}
	err = atomicTxn.FromBytes(atomicTxnBytes)
	if err != nil {
		_AddBadRequestError(ww,
			fmt.Sprintf("SubmitAtomicTransaction: "+
				"Problem deserializing atomic transaction from bytes: %v", err))
		return
	}
	if atomicTxn.TxnMeta.GetTxnType() != lib.TxnTypeAtomicTxnsWrapper {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitAtomicTransaction: "+
			"IncompleteAtomicTransaction must be an atomic transaction"))
		return
	}

	// Create a map from the pre-signature inner transaction hash to DeSo signature.
	innerTxnPreSignatureHashToSignature := make(map[lib.BlockHash]lib.DeSoSignature)
	for ii, signedInnerTxnHex := range signedInnerTransactionHexes {
		// Decode the signed inner transaction.
		signedTxnBytes, err := hex.DecodeString(signedInnerTxnHex)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"SubmitAtomicTransaction: Problem decoding signed transaction hex: %v", err))
			return
		}

		// Deserialize the signed transaction.
		signedInnerTxn := &lib.MsgDeSoTxn{}
		if err := signedInnerTxn.FromBytes(signedTxnBytes); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"SubmitAtomicTransaction: Problem deserializing signed transaction %d from bytes: %v",
				ii, err))
			return
		}

		// Verify the signature is present.
		if signedInnerTxn.Signature.Sign == nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"SubmitAtomicTransaction: Signed transaction %d hex missing signature", ii))
			return
		}

		// Find the pre-signature DeSo transaction hash.
		// NOTE: We do not use the lib.MsgDeSoTxn.Hash() function here as
		// the transactions included in the atomic transaction do not yet
		// have their signature fields set.
		preSignatureInnerTxnBytes, err := signedInnerTxn.ToBytes(true)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"SubmitAtomicTransaction: Problem serializing "+
					"signed transaction %d without signature: %v", ii, err))
			return
		}
		preSignatureInnerTxnHash := lib.Sha256DoubleHash(preSignatureInnerTxnBytes)
		innerTxnPreSignatureHashToSignature[*preSignatureInnerTxnHash] = signedInnerTxn.Signature
	}

	// Based on the provided signatures, complete the atomic transaction.
	for jj, innerTxn := range atomicTxn.TxnMeta.(*lib.AtomicTxnsWrapperMetadata).Txns {
		// Skip signed inner transactions.
		if innerTxn.Signature.Sign != nil {
			continue
		}

		// Find the pre-signature DeSo transaction hash for this transaction.
		preSignatureInnerTxnBytes, err := innerTxn.ToBytes(true)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"SubmitAtomicTransaction: Problem serializing "+
					"transaction %d of atomic transaction wrapper without signature: %v", jj, err))
			return
		}
		preSignatureInnerTxnHash := lib.Sha256DoubleHash(preSignatureInnerTxnBytes)

		// Check that we have the signature.
		if _, exists := innerTxnPreSignatureHashToSignature[*preSignatureInnerTxnHash]; !exists {
			_AddBadRequestError(ww, fmt.Sprintf(
				"SubmitAtomicTransaction: Transaction %d in atomic transaction still missing signature", jj))
			return
		}

		// Set the signature in the atomic transaction.
		atomicTxn.TxnMeta.(*lib.AtomicTxnsWrapperMetadata).Txns[jj].Signature =
			innerTxnPreSignatureHashToSignature[*preSignatureInnerTxnHash]
	}

	atomicTxnLen, err := atomicTxn.ToBytes(false)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"SubmitAtomicTransaction: Problem serializing completed atomic transaction: %v", err))
		return
	}
	if TransactionFeeRateTooHigh(atomicTxn, uint64(len(atomicTxnLen))) {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitAtomicTransaction: Transaction fee rate too high"))
		return
	}

	// Verify and broadcast the completed atomic transaction.
	if err := fes.backendServer.VerifyAndBroadcastTransaction(atomicTxn); err != nil {
		_AddBadRequestError(ww,
			fmt.Sprintf("SubmitAtomicTransaction: Problem broadcasting transaction: %v", err))
		return
	}

	res := &SubmitAtomicTransactionResponse{
		Transaction:              atomicTxn,
		TxnHashHex:               atomicTxn.Hash().String(),
		TransactionIDBase58Check: lib.PkToString(atomicTxn.Hash()[:], fes.Params),
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"SubmitAtomicTransaction: Problem encoding response as JSON: %v", err))
		return
	}
}

type SubmitTransactionRequest struct {
	TransactionHex string `safeForLogging:"true"`

	// Alternatively, instead of submitting the transaction hex, the user can submit
	// the unsigned transaction and the signature separately. This is useful in cases
	// where the client does not have the ability to intelligently decode a transaction
	// and embed the signature within it. The effect will be the same as if they had
	// submitted the TransactionHex of the UnsignedTransaction with the TransactionSignature
	// embedded within it.
	UnsignedTransactionHex  string `safeForLogging:"true"`
	TransactionSignatureHex string `safeForLogging:"true"`
}

type SubmitTransactionResponse struct {
	Transaction              *lib.MsgDeSoTxn
	TxnHashHex               string
	TransactionIDBase58Check string

	// include the PostEntryResponse if a post was submitted
	PostEntryResponse *PostEntryResponse
}

// FeeRateNanosPerKBThreshold is the threshold above which transactions will be rejected if the fee rate exceeds it.
const FeeRateNanosPerKBThreshold = 1e8

func TransactionFeeRateTooHigh(txn *lib.MsgDeSoTxn, txnLen uint64) bool {
	// Handle base cases.
	if txn.TxnFeeNanos == 0 || txnLen == 0 {
		return false
	}
	// Compute the fee rate in nanos per KB.
	feeRateNanosPerKB := (txn.TxnFeeNanos * 1000) / txnLen
	return feeRateNanosPerKB > FeeRateNanosPerKBThreshold
}

func (fes *APIServer) SubmitTransaction(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := SubmitTransactionRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitTransactionRequest: Problem parsing request body: %v", err))
		return
	}

	if requestData.TransactionHex != "" && requestData.UnsignedTransactionHex != "" {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitTransactionRequest: "+
			"Cannot submit both TransactionHex and UnsignedTransactionHex. You must pick one or the other."))
		return
	}

	signedTransactionHex := requestData.TransactionHex
	if requestData.UnsignedTransactionHex != "" {
		if requestData.TransactionSignatureHex == "" {
			_AddBadRequestError(ww, fmt.Sprintf("SubmitTransactionRequest: "+
				"Must provide TransactionSignatureHex when submitting UnsignedTransactionHex."))
			return
		}
		// When the user is submitting the signature separately, then we ignore whatever
		// was set in TransactionHex and embed the signature manually for the user.

		// Decode the unsigned transaction.
		unsignedTxnBytes, err := hex.DecodeString(requestData.UnsignedTransactionHex)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SubmitTransactionRequest: Problem decoding unsigned transaction hex: %v", err))
			return
		}

		// Deserialize the unsigned transaction.
		unsignedTxn := &lib.MsgDeSoTxn{}
		if err := unsignedTxn.FromBytes(unsignedTxnBytes); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SubmitTransactionRequest: Problem deserializing unsigned transaction from bytes: %v", err))
			return
		}

		// Decode the signature
		signatureBytes, err := hex.DecodeString(requestData.TransactionSignatureHex)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SubmitTransactionRequest: Problem decoding signature hex: %v", err))
			return
		}

		signature := lib.DeSoSignature{}
		if err := signature.FromBytes(signatureBytes); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SubmitTransactionRequest: Problem deserializing signature from bytes: %v", err))
			return
		}

		// Embed the signature within the transaction
		unsignedTxn.Signature = signature

		// Serialize the unsignedTxn with the signature
		signedTxnBytes, err := unsignedTxn.ToBytes(false)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SubmitTransactionRequest: Problem serializing unsigned transaction with signature: %v", err))
			return
		}

		// Encode the signed transaction.
		signedTransactionHex = hex.EncodeToString(signedTxnBytes)
	}

	txnBytes, err := hex.DecodeString(signedTransactionHex)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitTransactionRequest: Problem deserializing transaction hex: %v", err))
		return
	}

	txn := &lib.MsgDeSoTxn{}
	err = txn.FromBytes(txnBytes)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitTransactionRequest: Problem deserializing transaction from bytes: %v", err))
		return
	}

	if TransactionFeeRateTooHigh(txn, uint64(len(txnBytes))) {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitTransactionRequest: Transaction fee rate too high"))
		return
	}

	if err = fes.backendServer.VerifyAndBroadcastTransaction(txn); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitTransaction: Problem processing transaction: %v", err))
		return
	}

	res := &SubmitTransactionResponse{
		Transaction:              txn,
		TxnHashHex:               txn.Hash().String(),
		TransactionIDBase58Check: lib.PkToString(txn.Hash()[:], fes.Params),
	}

	if txn.TxnMeta.GetTxnType() == lib.TxnTypeSubmitPost {
		if err = fes._afterProcessSubmitPostTransaction(txn, res); err != nil {
			glog.Errorf("_afterSubmitPostTransaction: %v", err)
			//_AddBadRequestError(ww, fmt.Sprintf("_afterSubmitPostTransaction: %v", err))
		}
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitTransactionResponse: Problem encoding response as JSON: %v", err))
		return
	}
}

// After we submit a new post transaction we need to do run a few callbacks
// 1. Attach the PostEntry to the response so the client can render it
// 2. Attempt to auto-whitelist the post for the global feed
func (fes *APIServer) _afterProcessSubmitPostTransaction(txn *lib.MsgDeSoTxn, response *SubmitTransactionResponse) error {
	fes.backendServer.GetMempool().BlockUntilReadOnlyViewRegenerated()
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return errors.Errorf("Problem with GetAugmentedUniversalView: %v", err)
	}

	// The post hash is either the hash of the transaction that was added or
	// the hash of the post that this request was modifying.
	postHashToModify := txn.TxnMeta.(*lib.SubmitPostMetadata).PostHashToModify
	postHash := txn.Hash()
	if len(postHashToModify) == lib.HashSizeBytes {
		postHash = &lib.BlockHash{}
		copy(postHash[:], postHashToModify[:])
	}

	postEntry := utxoView.GetPostEntryForPostHash(postHash)
	if postEntry == nil {
		return errors.Errorf("Problem finding post after adding to view")
	}

	updaterPublicKeyBytes := txn.PublicKey
	postEntryResponse, err := fes._postEntryToResponse(postEntry, false, fes.Params, utxoView, updaterPublicKeyBytes, 2)
	if err != nil {
		return errors.Errorf("Problem obtaining post entry response: %v", err)
	}

	profileEntry := utxoView.GetProfileEntryForPublicKey(postEntry.PosterPublicKey)
	postEntryResponse.ProfileEntryResponse = fes._profileEntryToResponse(profileEntry, utxoView)

	// attach everything to the response
	response.PostEntryResponse = postEntryResponse

	// Try to whitelist a post if it is not a comment and is not a vanilla repost.
	if len(postHashToModify) == 0 && !lib.IsVanillaRepost(postEntry) {
		// If this is a new post, let's try and auto-whitelist it now that it has been broadcast.
		// First we need to figure out if the user is whitelisted.
		userMetadata, err := fes.getUserMetadataFromGlobalState(lib.PkToString(updaterPublicKeyBytes, fes.Params))
		if err != nil {
			return errors.Wrapf(err, "Get error: Problem getting "+
				"metadata from global state.")
		}

		// Only whitelist posts for users that are auto-whitelisted and the post is not a comment or a vanilla repost.
		if userMetadata.WhitelistPosts && len(postEntry.ParentStakeID) == 0 && (postEntry.IsQuotedRepost || postEntry.RepostedPostHash == nil) {
			minTimestampNanos := time.Now().UTC().AddDate(0, 0, -1).UnixNano() // last 24 hours
			_, dbPostAndCommentHashes, _, err := lib.DBGetAllPostsAndCommentsForPublicKeyOrderedByTimestamp(
				fes.blockchain.DB(), fes.blockchain.Snapshot(), updaterPublicKeyBytes, false, /*fetchEntries*/
				uint64(minTimestampNanos), 0, /*maxTimestampNanos*/
			)
			if err != nil {
				return errors.Errorf("Problem fetching last 24 hours of user posts: %v", err)
			}

			// Collect all the posts the user made in the last 24 hours.
			maxAutoWhitelistPostsPerDay := 5
			postEntriesInLastDay := 0
			for _, dbPostOrCommentHash := range dbPostAndCommentHashes {
				if existingPostEntry := utxoView.GetPostEntryForPostHash(dbPostOrCommentHash); len(existingPostEntry.ParentStakeID) == 0 && !lib.IsVanillaRepost(existingPostEntry) {
					postEntriesInLastDay += 1
				}
				if maxAutoWhitelistPostsPerDay >= postEntriesInLastDay {
					break
				}
			}

			// If the whitelited user has made <5 posts in the last 24hrs add this post to the feed.
			if postEntriesInLastDay < maxAutoWhitelistPostsPerDay {
				dbKey := GlobalStateKeyForTstampPostHash(postEntry.TimestampNanos, postHash)
				// Encode the post entry and stick it in the database.
				if err = fes.GlobalState.Put(dbKey, []byte{1}); err != nil {
					return errors.Errorf("Problem adding post to global state: %v", err)
				}
			}
		}
	}

	return nil
}

// UpdateProfileRequest ...
type UpdateProfileRequest struct {
	// The public key of the user who is trying to update their profile.
	UpdaterPublicKeyBase58Check string `safeForLogging:"true"`

	// This is only set when the user wants to modify a profile
	// that isn't theirs. Otherwise, the UpdaterPublicKeyBase58Check is
	// assumed to own the profile being updated.
	ProfilePublicKeyBase58Check string `safeForLogging:"true"`

	NewUsername    string `safeForLogging:"true"`
	NewDescription string `safeForLogging:"true"`
	// The profile pic string encoded as a link e.g.
	// data:image/png;base64,<data in base64>
	NewProfilePic               string
	NewCreatorBasisPoints       uint64 `safeForLogging:"true"`
	NewStakeMultipleBasisPoints uint64 `safeForLogging:"true"`

	IsHidden bool `safeForLogging:"true"`

	// ExtraData
	ExtraData map[string]string `safeForLogging:"true"`

	MinFeeRateNanosPerKB uint64 `safeForLogging:"true"`

	// No need to specify ProfileEntryResponse in each TransactionFee
	TransactionFees []TransactionFee `safeForLogging:"true"`

	OptionalPrecedingTransactions []*lib.MsgDeSoTxn `safeForLogging:"true"`
}

// UpdateProfileResponse ...
type UpdateProfileResponse struct {
	TotalInputNanos               uint64
	ChangeAmountNanos             uint64
	FeeNanos                      uint64
	Transaction                   *lib.MsgDeSoTxn
	TransactionHex                string
	TxnHashHex                    string
	CompProfileCreationTxnHashHex string
}

// UpdateProfile ...
func (fes *APIServer) UpdateProfile(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := UpdateProfileRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateProfile: Problem parsing request body: %v", err))
		return
	}

	// Decode the public key
	updaterPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.UpdaterPublicKeyBase58Check)
	if err != nil || len(updaterPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		_AddBadRequestError(ww, fmt.Sprintf(
			"UpdateProfile: Problem decoding public key %s: %v",
			requestData.UpdaterPublicKeyBase58Check, err))
		return
	}

	// Compute the additional transaction fees as specified by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(lib.TxnTypeUpdateProfile, updaterPublicKeyBytes, requestData.TransactionFees)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateProfile: TransactionFees specified in Request body are invalid: %v", err))
		return
	}

	// Validate that the user can create a profile
	userMetadata, err := fes.getUserMetadataFromGlobalState(requestData.UpdaterPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateProfile: Problem with getUserMetadataFromGlobalState: %v", err))
		return
	}
	utxoView, err := lib.GetAugmentedUniversalViewWithAdditionalTransactions(
		fes.backendServer.GetMempool(),
		requestData.OptionalPrecedingTransactions,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateProfile: Error fetching mempool view: %v", err))
		return
	}
	canCreateProfile, err := fes.canUserCreateProfile(userMetadata, utxoView)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateProfile: Problem with canUserCreateProfile: %v", err))
		return
	}
	if !canCreateProfile {
		_AddBadRequestError(ww, fmt.Sprintf(
			"UpdateProfile: Not allowed to update profile. Please verify your phone number or buy DeSo."))
		return
	}

	// When this is nil then the UpdaterPublicKey is assumed to be the owner of
	// the profile.
	var profilePublicKeyBytess []byte
	if requestData.ProfilePublicKeyBase58Check != "" {
		profilePublicKeyBytess, _, err = lib.Base58CheckDecode(requestData.ProfilePublicKeyBase58Check)
		if err != nil || len(profilePublicKeyBytess) != btcec.PubKeyBytesLenCompressed {
			_AddBadRequestError(ww, fmt.Sprintf(
				"UpdateProfile: Problem decoding public key %s: %v",
				requestData.ProfilePublicKeyBase58Check, err))
			return
		}
	}

	// Get the public key.
	profilePublicKey := updaterPublicKeyBytes
	if requestData.ProfilePublicKeyBase58Check != "" {
		profilePublicKey = profilePublicKeyBytess
	}

	// Validate the request.
	if err := fes.ValidateAndConvertUpdateProfileRequest(&requestData, profilePublicKey, utxoView); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateProfile: Problem validating request: %v", err))
		return
	}

	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateProfile: Problem encoding ExtraData: %v", err))
		return
	}

	additionalFees, compProfileCreationTxnHash, err := fes.CompProfileCreation(profilePublicKey, userMetadata, utxoView)
	if err != nil {
		_AddBadRequestError(ww, err.Error())
		return
	}

	var compProfileCreationTxnHashHex string
	if compProfileCreationTxnHash != nil {
		compProfileCreationTxnHashHex = compProfileCreationTxnHash.String()
	}

	// Try and create the UpdateProfile txn for the user.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateUpdateProfileTxn(
		updaterPublicKeyBytes,
		profilePublicKeyBytess,
		requestData.NewUsername,
		requestData.NewDescription,
		requestData.NewProfilePic,
		requestData.NewCreatorBasisPoints,
		requestData.NewStakeMultipleBasisPoints,
		requestData.IsHidden,
		additionalFees,
		extraData,
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool(), additionalOutputs)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateProfile: Problem creating transaction: %v", err))
		return
	}

	// Add node source to txn metadata
	fes.AddNodeSourceToTxnMetadata(txn)

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateProfile: Problem serializing transaction: %v", err))
		return
	}

	// TODO: for consistency, should we add InTutorial to the request data. It doesn't save us much since we need fetch the user metadata regardless.
	if userMetadata.TutorialStatus == STARTED || userMetadata.TutorialStatus == INVEST_OTHERS_SELL {
		userMetadata.TutorialStatus = CREATE_PROFILE
		if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("UpdateProfile: Problem updating tutorial status to update profile completed: %v", err))
			return
		}
	}

	// Return all the data associated with the transaction in the response
	res := UpdateProfileResponse{
		TotalInputNanos:               totalInput,
		ChangeAmountNanos:             changeAmount,
		FeeNanos:                      fees,
		Transaction:                   txn,
		TransactionHex:                hex.EncodeToString(txnBytes),
		TxnHashHex:                    txn.Hash().String(),
		CompProfileCreationTxnHashHex: compProfileCreationTxnHashHex,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendMessage: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) ValidateAndConvertUpdateProfileRequest(
	requestData *UpdateProfileRequest,
	profilePublicKey []byte,
	utxoView *lib.UtxoView,
) error {
	if len(requestData.NewUsername) > 0 && strings.Index(requestData.NewUsername, fes.PublicKeyBase58Prefix) == 0 {
		return fmt.Errorf(
			"ValidateAndConvertUpdateProfileRequest: Username cannot start with %s", fes.PublicKeyBase58Prefix)
	}

	if uint64(len([]byte(requestData.NewUsername))) > utxoView.Params.MaxUsernameLengthBytes {
		return errors.Wrap(lib.RuleErrorProfileUsernameTooLong, "ValidateAndConvertUpdateProfileRequest")
	}

	if uint64(len([]byte(requestData.NewDescription))) > utxoView.Params.MaxUserDescriptionLengthBytes {
		return errors.Wrap(lib.RuleErrorProfileDescriptionTooLong, "ValidateAndConvertUpdateProfileRequest")
	}

	// If an image is set on the request then resize it.
	// Convert image to base64 by stripping the data: prefix.
	if requestData.NewProfilePic != "" {
		// split on base64 to get the extension
		extensionSplit := strings.Split(requestData.NewProfilePic, ";base64")
		if len(extensionSplit) != 2 {
			return fmt.Errorf("ValidateAndConvertUpdateProfileRequest: " +
				"Problem parsing profile pic extension; invalid extension split")
		}
		extension := extensionSplit[0]
		switch {
		case strings.Contains(extension, "image/png"):
			extension = ".png"
		case strings.Contains(extension, "image/jpeg"):
			extension = ".jpeg"
		case strings.Contains(extension, "image/webp"):
			extension = ".webp"
		case strings.Contains(extension, "image/gif"):
			extension = ".gif"
		default:
			return fmt.Errorf(
				"ValidateAndConvertUpdateProfileRequest: Unsupported image type: %v", extension)
		}
		var resizedImageBytes []byte
		resizedImageBytes, err := resizeAndConvertToWebp(
			requestData.NewProfilePic, uint(fes.Params.MaxProfilePicDimensions), extension)
		if err != nil {
			return fmt.Errorf(
				"ValidateAndConvertUpdateProfileRequest: Problem resizing profile picture: %v", err)
		}
		// Convert the image back into base64
		webpBase64 := base64.StdEncoding.EncodeToString(resizedImageBytes)
		requestData.NewProfilePic = "data:image/webp;base64," + webpBase64
		if uint64(len([]byte(requestData.NewProfilePic))) > utxoView.Params.MaxProfilePicLengthBytes {
			return errors.Wrap(lib.RuleErrorMaxProfilePicSize, "ValidateAndConvertUpdateProfileRequest")
		}
	}

	// CreatorBasisPoints > 0 < max, uint64 can't be less than zero
	if requestData.NewCreatorBasisPoints > fes.Params.MaxCreatorBasisPoints {
		return fmt.Errorf(
			"ValidateAndConvertUpdateProfileRequest: Creator percentage must be less than %v percent",
			fes.Params.MaxCreatorBasisPoints/100)
	}

	// Verify that this username doesn't exist in the mempool.
	if len(requestData.NewUsername) > 0 {

		utxoView.GetProfileEntryForUsername([]byte(requestData.NewUsername))
		existingProfile, usernameExists :=
			utxoView.ProfileUsernameToProfileEntry[lib.MakeUsernameMapKey([]byte(requestData.NewUsername))]
		if usernameExists && existingProfile != nil && !existingProfile.IsDeleted() {
			// Check that the existing profile does not belong to the profile public key
			if utxoView.GetPKIDForPublicKey(profilePublicKey) !=
				utxoView.GetPKIDForPublicKey(existingProfile.PublicKey) {
				return fmt.Errorf(
					"ValidateAndConvertUpdateProfileRequest: Username %v already exists",
					string(existingProfile.Username))
			}

		}
		if !lib.UsernameRegex.Match([]byte(requestData.NewUsername)) {
			return errors.Wrap(lib.RuleErrorInvalidUsername, "ValidateAndConvertUpdateProfileRequest")
		}
	}

	return nil
}

func (fes *APIServer) CompProfileCreation(profilePublicKey []byte, userMetadata *UserMetadata, utxoView *lib.UtxoView) (_additionalFee uint64, _txnHash *lib.BlockHash, _err error) {
	// Determine if this is a profile creation request and if we need to comp the user for creating the profile.
	existingProfileEntry := utxoView.GetProfileEntryForPublicKey(profilePublicKey)
	// If we are updating an existing profile, there is no fee and we do not comp anything.
	if existingProfileEntry != nil {
		return 0, nil, nil
	}
	// Additional fee is set to the create profile fee when we are creating a profile
	additionalFees := utxoView.GetCurrentGlobalParamsEntry().CreateProfileFeeNanos
	if additionalFees == 0 {
		return 0, nil, nil
	}
	existingMetamaskAirdropMetadata, err := fes.GetMetamaskAirdropMetadata(profilePublicKey)
	if err != nil {
		return 0, nil, fmt.Errorf("Error geting metamask airdrop metadata from global state: %v", err)
	}
	// Only comp create profile fee if frontend server has both twilio and starter deso seed configured and the user
	// has verified their profile.
	if !fes.Config.CompProfileCreation || fes.Config.StarterDESOSeed == "" || (fes.Config.HCaptchaSecret == "" && fes.Twilio == nil) || (userMetadata.PhoneNumber == "" && !userMetadata.JumioVerified && existingMetamaskAirdropMetadata == nil && userMetadata.LastHcaptchaBlockHeight == 0) {
		return additionalFees, nil, nil
	}
	var currentBalanceNanos uint64
	currentBalanceNanos, err = GetBalanceForPublicKeyUsingUtxoView(profilePublicKey, utxoView)
	if err != nil {
		return 0, nil, errors.Wrap(fmt.Errorf("UpdateProfile: error getting current balance: %v", err), "")
	}
	createProfileFeeNanos := utxoView.GetCurrentGlobalParamsEntry().CreateProfileFeeNanos

	// If a user is jumio verified, we just comp the profile even if their balance is greater than the create profile fee.
	// If a user has a phone number verified but is not jumio verified, we need to check that they haven't spent all their
	// starter deso already and that ShouldCompProfileCreation is true
	var multiPhoneNumberMetadata []*PhoneNumberMetadata
	var updateMetamaskAirdropMetadata bool
	if userMetadata.PhoneNumber != "" && !userMetadata.JumioVerified {
		multiPhoneNumberMetadata, err = fes.getMultiPhoneNumberMetadataFromGlobalState(userMetadata.PhoneNumber)
		if err != nil {
			return 0, nil, fmt.Errorf("UpdateProfile: error getting phone number metadata for public key %v: %v", profilePublicKey, err)
		}
		if len(multiPhoneNumberMetadata) == 0 {
			return 0, nil, fmt.Errorf("UpdateProfile: no phone number metadata for phone number %v", userMetadata.PhoneNumber)
		}
		var phoneNumberMetadata *PhoneNumberMetadata
		for _, phoneNumMetadata := range multiPhoneNumberMetadata {
			if bytes.Equal(phoneNumMetadata.PublicKey, profilePublicKey) {
				phoneNumberMetadata = phoneNumMetadata
				break
			}
		}
		if phoneNumberMetadata == nil {
			return 0, nil, fmt.Errorf("UpdateProfile: phone number metadata not found in slice for public key")
		}
		if !phoneNumberMetadata.ShouldCompProfileCreation || currentBalanceNanos > createProfileFeeNanos {
			return additionalFees, nil, nil
		}
	} else if existingMetamaskAirdropMetadata != nil {
		if !existingMetamaskAirdropMetadata.ShouldCompProfileCreation {
			return additionalFees, nil, nil
		}
		updateMetamaskAirdropMetadata = true
	} else if userMetadata.JumioVerified {
		// User has been Jumio verified but should comp profile creation is false, just return
		if !userMetadata.JumioShouldCompProfileCreation {
			return additionalFees, nil, nil
		}
	} else if userMetadata.LastHcaptchaBlockHeight != 0 {
		// User has been captcha verified but should comp profile creation is false, just return
		if !userMetadata.HcaptchaShouldCompProfileCreation {
			return additionalFees, nil, nil
		}
	}

	// Find the minimum starter bit deso amount
	minStarterDESONanos := fes.Config.StarterDESONanos
	if len(fes.Config.StarterPrefixNanosMap) > 0 {
		for _, starterDeSo := range fes.Config.StarterPrefixNanosMap {
			if starterDeSo < minStarterDESONanos {
				minStarterDESONanos = starterDeSo
			}
		}
	}
	// If metamask airdrop is less than min phone number amount, we set the min amount to the airdrop value
	if fes.Config.MetamaskAirdropDESONanosAmount != 0 && minStarterDESONanos > fes.Config.MetamaskAirdropDESONanosAmount {
		minStarterDESONanos = fes.Config.MetamaskAirdropDESONanosAmount
	}
	// We comp the create profile fee minus the minimum starter deso amount divided by 2.
	// This discourages botting while covering users who verify a phone number.
	compAmount := createProfileFeeNanos - (minStarterDESONanos / 2)
	if (minStarterDESONanos / 2) > createProfileFeeNanos {
		compAmount = createProfileFeeNanos
	}

	// If the user won't have enough deso to cover the fee, this is an error.
	if currentBalanceNanos+compAmount < createProfileFeeNanos {
		return 0, nil, fmt.Errorf("Creating a profile requires DeSo.  Please purchase some to create a profile.")
	}
	// Set should comp to false so we don't continually comp a public key.  PhoneNumberMetadata is only non-nil if
	// a user verified their phone number but is not jumio verified.
	if len(multiPhoneNumberMetadata) > 0 {
		newPhoneNumberMetadata := []*PhoneNumberMetadata{}
		for _, phoneNumMetadata := range multiPhoneNumberMetadata {
			if bytes.Equal(phoneNumMetadata.PublicKey, profilePublicKey) {
				phoneNumMetadata.ShouldCompProfileCreation = false
			}
			newPhoneNumberMetadata = append(newPhoneNumberMetadata, phoneNumMetadata)
		}
		if err = fes.putPhoneNumberMetadataInGlobalState(newPhoneNumberMetadata, userMetadata.PhoneNumber); err != nil {
			return 0, nil, fmt.Errorf("UpdateProfile: Error setting ShouldComp to false for phone number metadata: %v", err)
		}
	} else if userMetadata.LastHcaptchaBlockHeight != 0 {
		userMetadata.HcaptchaShouldCompProfileCreation = false
		if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
			return 0, nil, fmt.Errorf("UpdateProfile: Error setting ShouldComp to false for jumio user metadata: %v", err)
		}
	} else {
		// Set JumioShouldCompProfileCreation to false so we don't continue to comp profile creation.
		userMetadata.JumioShouldCompProfileCreation = false
		if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
			return 0, nil, fmt.Errorf("UpdateProfile: Error setting ShouldComp to false for jumio user metadata: %v", err)
		}
		if existingMetamaskAirdropMetadata != nil && updateMetamaskAirdropMetadata {
			existingMetamaskAirdropMetadata.ShouldCompProfileCreation = false
			if err = fes.PutMetamaskAirdropMetadata(existingMetamaskAirdropMetadata); err != nil {
				return 0, nil, fmt.Errorf("UpdateProfile: Error updating metamask airdrop metadata in global state: %v", err)
			}
		}
	}

	// Send the comp amount to the public key
	txnHash, err := fes.SendSeedDeSo(profilePublicKey, compAmount, false)
	if err != nil {
		return 0, nil, errors.Wrap(fmt.Errorf("UpdateProfile: error comping create profile fee: %v", err), "")
	}
	return additionalFees, txnHash, nil
}

func GetBalanceForPublicKeyUsingUtxoView(
	publicKeyBytes []byte, utxoView *lib.UtxoView) (_balance uint64, _err error) {

	return utxoView.GetDeSoBalanceNanosForPublicKey(publicKeyBytes)
}

// ExchangeBitcoinRequest ...
type ExchangeBitcoinRequest struct {
	// The public key of the user who we're creating the burn for.
	PublicKeyBase58Check string `safeForLogging:"true"`
	// If passed, we will check if the user intends to burn btc through a derived key.
	DerivedPublicKeyBase58Check string `safeForLogging:"true"`

	// Note: When BurnAmountSatoshis is negative, we assume that the user wants
	// to burn the maximum amount of satoshi she has available.
	BurnAmountSatoshis   int64 `safeForLogging:"true"`
	FeeRateSatoshisPerKB int64 `safeForLogging:"true"`

	// We rely on the frontend to query the API and give us the response.
	// Doing it this way makes it so that we don't exhaust our quota on the
	// free tier.
	LatestBitcionAPIResponse *lib.BlockCypherAPIFullAddressResponse
	// The Bitcoin address we will be processing this transaction for.
	BTCDepositAddress string `safeForLogging:"true"`

	// Whether or not we should broadcast the transaction after constructing
	// it. This will also validate the transaction if it's set.
	// The client must provide SignedHashes which it calculates by signing
	// all the UnsignedHashes in the identity service
	Broadcast bool `safeForLogging:"true"`

	// Signed hashes from the identity service
	// One for each transaction input
	SignedHashes []string
}

// ExchangeBitcoinResponse ...
type ExchangeBitcoinResponse struct {
	TotalInputSatoshis   uint64
	BurnAmountSatoshis   uint64
	ChangeAmountSatoshis uint64
	FeeSatoshis          uint64
	BitcoinTransaction   *wire.MsgTx

	SerializedTxnHex string
	TxnHashHex       string
	DeSoTxnHashHex   string

	UnsignedHashes []string
}

// ExchangeBitcoinStateless ...
func (fes *APIServer) ExchangeBitcoinStateless(ww http.ResponseWriter, req *http.Request) {
	if fes.Config.BuyDESOSeed == "" {
		_AddBadRequestError(ww, "ExchangeBitcoinStateless: This node is not configured to sell DeSo for Bitcoin")
		return
	}
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := ExchangeBitcoinRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("ExchangeBitcoinStateless: Problem parsing request body: %v", err))
		return
	}

	// Make sure the fee rate isn't negative.
	if requestData.FeeRateSatoshisPerKB < 0 {
		_AddBadRequestError(ww, fmt.Sprintf("ExchangeBitcoinStateless: BurnAmount %d or "+
			"FeeRateSatoshisPerKB %d cannot be negative",
			requestData.BurnAmountSatoshis, requestData.FeeRateSatoshisPerKB))
		return
	}

	// If BurnAmountSatoshis is negative, set it to the maximum amount of satoshi
	// that can be burned while accounting for the fee.
	burnAmountSatoshis := requestData.BurnAmountSatoshis
	if burnAmountSatoshis < 0 {
		bitcoinUtxos, err := lib.BlockCypherExtractBitcoinUtxosFromResponse(
			requestData.LatestBitcionAPIResponse, requestData.BTCDepositAddress,
			fes.Params)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("ExchangeBitcoinStateless: Problem getting "+
				"Bitcoin UTXOs: %v", err))
			return
		}
		totalInput := int64(0)
		for _, utxo := range bitcoinUtxos {
			totalInput += utxo.AmountSatoshis
		}
		// We have one output in this case because we're sending all of the Bitcoin to
		// the burn address with no change left over.
		txFee := lib.EstimateBitcoinTxFee(
			len(bitcoinUtxos), 1, uint64(requestData.FeeRateSatoshisPerKB))
		if int64(txFee) > totalInput {
			_AddBadRequestError(ww, fmt.Sprintf("ExchangeBitcoinStateless: Transaction fee %d is "+
				"so high that we can't spend the inputs total=%d", txFee, totalInput))
			return
		}

		burnAmountSatoshis = totalInput - int64(txFee)
		glog.V(2).Infof("ExchangeBitcoinStateless: Getting ready to burn %d Satoshis", burnAmountSatoshis)
	}

	// Prevent the user from creating a burn transaction with a dust output since
	// this will result in the transaction being rejected by Bitcoin nodes.
	if burnAmountSatoshis < 10000 {
		_AddBadRequestError(ww, fmt.Sprintf("ExchangeBitcoinStateless: You must burn at least .0001 Bitcoins "+
			"or else Bitcoin nodes will reject your transaction as \"dust.\""))
		return
	}

	// Get a UtxoSource from the user's BitcoinAPI data. Note we could change the API
	// around a bit to not have to do this but oh well.
	utxoSource := func(spendAddr string, params *lib.DeSoParams) ([]*lib.BitcoinUtxo, error) {
		if spendAddr != requestData.BTCDepositAddress {
			return nil, fmt.Errorf("ExchangeBitcoinStateless.UtxoSource: Expecting deposit address %s "+
				"but got unrecognized address %s", requestData.BTCDepositAddress, spendAddr)
		}
		return lib.BlockCypherExtractBitcoinUtxosFromResponse(
			requestData.LatestBitcionAPIResponse, requestData.BTCDepositAddress, fes.Params)
	}

	// Get the pubKey from the request
	pkBytes, _, err := lib.Base58CheckDecode(requestData.PublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, "ExchangeBitcoinStateless: Invalid public key")
		return
	}
	addressPubKey, err := btcutil.NewAddressPubKey(pkBytes, fes.Params.BitcoinBtcdParams)
	if err != nil {
		_AddBadRequestError(ww, "ExchangeBitcoinStateless: Invalid public key")
		return
	}
	// If a derived key was passed, we will look for deposits in the derived btc address.
	if requestData.DerivedPublicKeyBase58Check != "" {
		// First decode the derived key.
		derivedPkBytes, _, err := lib.Base58CheckDecode(requestData.DerivedPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, errors.Wrapf(err, "ExchangeBitcoinStateless: Invalid derived public key").Error())
			return
		}
		// Verify that the derived key has been authorized by the provided owner public key.
		utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
		if err != nil {
			_AddBadRequestError(ww, errors.Wrapf(err, "ExchangeBitcoinStateless: Problem getting universal view from mempool").Error())
			return
		}
		// Get the current block height for the derived key validation.
		blockHeight := fes.blockchain.BlockTip().Height
		// Now verify that the derived key has been authorized and hasn't expired.
		if err := utxoView.ValidateDerivedKey(pkBytes, derivedPkBytes, uint64(blockHeight)); err != nil {
			_AddBadRequestError(ww, errors.Wrapf(err, "ExchangeBitcoinStateless: Problem verifying the derived key").Error())
			return
		}
		// If we get here it means a valid derived key was passed in the request. We will now get it's btc address for the deposit.
		// FIXME (delete): At this point derived key deposits are pretty much done. The rest of this function stays the same,
		// 	 note that SendSeedDeSo will use the owner public key for the transaction recipient.
		addressPubKey, err = btcutil.NewAddressPubKey(derivedPkBytes, fes.Params.BitcoinBtcdParams)
		if err != nil {
			_AddBadRequestError(ww, errors.Wrapf(err, "ExchangeBitcoinStateless: Problem while getting btc address "+
				"for the derived key").Error())
			return
		}
	}
	pubKey := addressPubKey.PubKey()

	bitcoinTxn, totalInputSatoshis, fee, unsignedHashes, bitcoinSpendErr := lib.CreateBitcoinSpendTransaction(
		uint64(burnAmountSatoshis),
		uint64(requestData.FeeRateSatoshisPerKB),
		pubKey,
		fes.Config.BuyDESOBTCAddress,
		fes.Params,
		utxoSource)

	if bitcoinSpendErr != nil {
		_AddBadRequestError(ww, fmt.Sprintf("ExchangeBitcoinStateless: Problem creating Bitcoin spend "+
			"transaction given input: %v", bitcoinSpendErr))
		return
	}

	// Add all the signatures to the inputs. If the burned btc is coming from a derived key, the signatures must also be
	// made by that derived key.
	pkData := pubKey.SerializeCompressed()
	for ii, signedHash := range requestData.SignedHashes {
		sig, err := hex.DecodeString(signedHash)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("ExchangeBitcoinStateless: Failed to decode hash: %v", err))
			return
		}
		parsedSig, err := ecdsa2.ParseDERSignature(sig)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("ExchangeBitcoinStateless: Parsing "+
				"signature failed: %v: %v", signedHash, err))
			return
		}
		sigWithLowS := parsedSig.Serialize()
		glog.Errorf("ExchangeBitcoinStateless: Bitcoin sig from frontend: %v; Bitcoin "+
			"sig with low S breaker: %v; Equal? %v",
			hex.EncodeToString(sig), hex.EncodeToString(sigWithLowS), reflect.DeepEqual(sig, sigWithLowS))
		sig = sigWithLowS

		sig = append(sig, byte(txscript.SigHashAll))

		sigScript, err := txscript.NewScriptBuilder().AddData(sig).AddData(pkData).Script()
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("ExchangeBitcoinStateless: Failed to generate signature: %v", err))
			return
		}

		bitcoinTxn.TxIn[ii].SignatureScript = sigScript
	}

	// Serialize the Bitcoin transaction the hex so that the FE can trigger
	// a rebroadcast later.
	bitcoinTxnBuffer := bytes.Buffer{}
	err = bitcoinTxn.SerializeNoWitness(&bitcoinTxnBuffer)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("ExchangeBitcoinStateless: Problem serializing Bitcoin transaction: %v", err))
		return
	}
	bitcoinTxnBytes := bitcoinTxnBuffer.Bytes()
	bitcoinTxnHash := bitcoinTxn.TxHash()

	// Update the current exchange price.
	fes.UpdateUSDCentsToDeSoExchangeRate()

	// Check that DeSo purchased they would get does not exceed current balance.
	nanosPurchased := fes.GetNanosFromSats(uint64(burnAmountSatoshis), fes.BuyDESOFeeBasisPoints)
	balanceInsufficient, err := fes.ExceedsDeSoBalance(nanosPurchased, fes.Config.BuyDESOSeed)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("ExchangeBitcoinStateless: Error checking if send deso balance is sufficient: %v", err))
		return
	}
	if balanceInsufficient {
		_AddBadRequestError(ww, fmt.Sprintf("ExchangeBitcoinStateless: SendDeSo wallet balance is below nanos purchased"))
		return
	}

	var desoTxnHash *lib.BlockHash
	if requestData.Broadcast {
		glog.Infof("ExchangeBitcoinStateless: Broadcasting Bitcoin txn: %v", bitcoinTxn.TxHash())

		// Check whether the deposits being used to construct this transaction have RBF enabled.
		// If they do then we force the user to wait until those deposits have been mined into a
		// block before allowing this transaction to go through. This prevents double-spend
		// attacks where someone replaces a dependent transaction with a higher fee.
		//
		// TODO: We use a pretty janky API to check for this, and if it goes down then
		// BitcoinExchange txns break. But without it we're vulnerable to double-spends
		// so we keep it for now.
		isRBF, err := lib.CheckRBF(bitcoinTxn, bitcoinTxnHash, fes.Params)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("Error checking RBF for txn: %v", err))
			return
		}
		if isRBF {
			_AddBadRequestError(ww, fmt.Sprintf(
				"Your deposit has \"replace by fee\" set, "+
					"which means we must wait for one confirmation on the Bitcoin blockchain before "+
					"allowing you to buy. This usually takes about ten minutes.<br><br>"+
					"You can see how many confirmations your deposit has by "+
					"<a target=\"_blank\" href=\"https://www.blockchain.com/btc/tx/%v\">clicking here</a>.", bitcoinTxnHash.String()))
			return
		}

		// If a BlockCypher API key is set then use BlockCypher to do the checks. Otherwise
		// use Bitcoin nodes to do it. Note that BLockCypher tends to be the more reliable path.
		if fes.BlockCypherAPIKey != "" {
			// Push the transaction to BlockCypher and ensure no error occurs.
			if isDoubleSpend, err := lib.BlockCypherPushAndWaitForTxn(
				hex.EncodeToString(bitcoinTxnBytes), &bitcoinTxnHash,
				fes.BlockCypherAPIKey, fes.Params.BitcoinDoubleSpendWaitSeconds,
				fes.Params); err != nil {

				if !isDoubleSpend {
					_AddBadRequestError(ww, fmt.Sprintf("ExchangeBitcoinStateless: Error broadcasting "+
						"transaction - not double spend: %v", err))
					return
				}
				// If we hit an error, kick off a goroutine to retry this txn every
				// minute for a few hours.
				//
				// TODO: This code is very ugly and highly error-prone. If you write it
				// incorrectly, it will send infinite money to someone. Don't change it
				// unless you absolutely have to...
				go func() {
					endTime := time.Now().Add(3 * time.Hour)
					for time.Now().Before(endTime) {
						err = lib.CheckBitcoinDoubleSpend(
							&bitcoinTxnHash, fes.BlockCypherAPIKey, fes.Params)
						if err == nil {
							// If we get here then it means the txn *finally* worked. Blast
							// out the DESO in this case and return.
							glog.Infof("Eventually mined Bitcoin txn %v. Sending DESO...", bitcoinTxnHash)
							desoTxnHash, err = fes.SendSeedDeSo(pkBytes, nanosPurchased, true)
							if err != nil {
								glog.Errorf("Error sending DESO for Bitcoin txn %v", bitcoinTxnHash)
							}
							// Note that if we don't return we'll send money to this person infinitely...
							return
						} else {
							glog.Infof("Error when re-checking double-spend for Bitcoin txn %v: %v", bitcoinTxnHash, err)
						}

						// Sleep for a bit each time.
						glog.Infof("Sleeping for 1 minute while waiting for Bitcoin "+
							"txn %v to mine...", bitcoinTxnHash)
						sleepTime := time.Minute
						time.Sleep(sleepTime)
					}
					glog.Infof("Bitcoin txn %v did not end up mining after several hours", bitcoinTxnHash)
				}()

				_AddBadRequestError(ww, fmt.Sprintf("ExchangeBitcoinStateless: Error broadcasting transaction: %v", err))
				return
			}

		} else {
			_AddBadRequestError(ww, fmt.Sprintf("ExchangeBitcoinStateless: BlockCypher API is required for bitcoin transactions"))
			return
		}

		desoTxnHash, err = fes.SendSeedDeSo(pkBytes, nanosPurchased, true)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("ExchangeBitcoinStateless: Error sending DeSo: %v", err))
			return
		}
	}

	desoTxnHashString := ""
	if desoTxnHash != nil {
		desoTxnHashString = desoTxnHash.String()
	}

	res := &ExchangeBitcoinResponse{
		TotalInputSatoshis:   totalInputSatoshis,
		BurnAmountSatoshis:   uint64(burnAmountSatoshis),
		FeeSatoshis:          fee,
		ChangeAmountSatoshis: totalInputSatoshis - uint64(burnAmountSatoshis) - fee,
		BitcoinTransaction:   bitcoinTxn,

		SerializedTxnHex: hex.EncodeToString(bitcoinTxnBytes),
		TxnHashHex:       bitcoinTxn.TxHash().String(),
		DeSoTxnHashHex:   desoTxnHashString,

		UnsignedHashes: unsignedHashes,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("BurnBitcoin: Problem encoding response as JSON: %v", err))
		return
	}
}

// GetNanosFromSats - convert Satoshis to DeSo nanos
func (fes *APIServer) GetNanosFromSats(satoshis uint64, feeBasisPoints uint64) uint64 {
	usdCentsPerBitcoin := fes.UsdCentsPerBitCoinExchangeRate
	// If we don't have a valid value from monitoring at this time, use the price from the protocol
	if usdCentsPerBitcoin == 0 {
		readUtxoView, _ := fes.backendServer.GetMempool().GetAugmentedUniversalView()
		usdCentsPerBitcoin = float64(readUtxoView.GetCurrentUSDCentsPerBitcoin())
	}
	usdCents := (float64(satoshis) * usdCentsPerBitcoin) / lib.SatoshisPerBitcoin
	return fes.GetNanosFromUSDCents(usdCents, feeBasisPoints)
}

// GetNanosFromETH - convert ETH to DESO nanos
func (fes *APIServer) GetNanosFromETH(eth *big.Float, feeBasisPoints uint64) uint64 {
	usdCentsPerETH := big.NewFloat(float64(fes.UsdCentsPerETHExchangeRate))
	usdCentsETH := big.NewFloat(0).Mul(eth, usdCentsPerETH)
	// This number should always fit into a float64 so we shouldn't have a problem
	// with overflow.
	usdCentsFloat, _ := usdCentsETH.Float64()

	return fes.GetNanosFromUSDCents(usdCentsFloat, feeBasisPoints)
}

// GetNanosFromUSDCents - convert USD cents to DeSo nanos
func (fes *APIServer) GetNanosFromUSDCents(usdCents float64, feeBasisPoints uint64) uint64 {
	// Get Exchange Price gets the max of price from blockchain.com and the reserve price.
	// TODO: This function isn't using the Coinbase price. We should make it consistent with other
	// places that use the Coinbase price, but it's fine for now because the places that call this
	// function are deprecated.
	usdCentsPerDeSo := fes.GetExchangeDeSoPrice()
	conversionRateAfterFee := float64(usdCentsPerDeSo) * (1 + (float64(feeBasisPoints) / (100.0 * 100.0)))
	nanosPurchased := uint64(usdCents * float64(lib.NanosPerUnit) / conversionRateAfterFee)
	return nanosPurchased
}

func (fes *APIServer) GetUSDFromNanos(nanos uint64) float64 {
	usdCentsPerDeSo := float64(fes.GetExchangeDeSoPrice())
	return usdCentsPerDeSo * float64(nanos/lib.NanosPerUnit) / 100
}

// ExceedsSendDeSoBalance - Check if nanosPurchased is greater than the balance of the BuyDESO wallet.
func (fes *APIServer) ExceedsDeSoBalance(nanosPurchased uint64, seed string) (bool, error) {
	buyDeSoSeedBalance, err := fes.getBalanceForSeed(seed)
	if err != nil {
		return false, fmt.Errorf("Error getting buy deso balance: %v", err)
	}
	return nanosPurchased > buyDeSoSeedBalance, nil
}

// SendDeSoRequest ...
type SendDeSoRequest struct {
	SenderPublicKeyBase58Check   string            `safeForLogging:"true"`
	RecipientPublicKeyOrUsername string            `safeForLogging:"true"`
	AmountNanos                  int64             `safeForLogging:"true"`
	MinFeeRateNanosPerKB         uint64            `safeForLogging:"true"`
	ExtraData                    map[string]string `safeForLogging:"true"`

	// No need to specify ProfileEntryResponse in each TransactionFee
	TransactionFees []TransactionFee `safeForLogging:"true"`

	OptionalPrecedingTransactions []*lib.MsgDeSoTxn `safeForLogging:"true"`
}

// SendDeSoResponse ...
type SendDeSoResponse struct {
	TotalInputNanos          uint64
	SpendAmountNanos         uint64
	ChangeAmountNanos        uint64
	FeeNanos                 uint64
	TransactionIDBase58Check string
	Transaction              *lib.MsgDeSoTxn
	TransactionHex           string
	TxnHashHex               string
}

func (fes *APIServer) CreateSendDesoTxn(
	amountNanos int64,
	senderPkBytes []byte,
	recipientPkBytes []byte,
	extraData map[string][]byte,
	minFeeRateNanosPerKb uint64,
	additionalOutputs []*lib.DeSoOutput,
) (
	_txn *lib.MsgDeSoTxn,
	_totalInput uint64,
	_spendAmount uint64,
	_changeAmount uint64,
	_feeNanos uint64,
	_err error,
) {
	// If the AmountNanos is less than zero then we have a special case where we create
	// a transaction with the maximum spend.
	var txnn *lib.MsgDeSoTxn
	var totalInputt uint64
	var spendAmountt uint64
	var changeAmountt uint64
	var feeNanoss uint64
	var err error
	if amountNanos < 0 {
		// Create a MAX transaction
		txnn, totalInputt, spendAmountt, feeNanoss, err = fes.blockchain.CreateMaxSpend(
			senderPkBytes, recipientPkBytes, extraData, minFeeRateNanosPerKb,
			fes.backendServer.GetMempool(), additionalOutputs)
		if err != nil {
			return nil, 0, 0, 0, 0, fmt.Errorf("CreateSendDesoTxn: Error creating max spend: %v", err)
		}

	} else {
		// In this case, we are spending what the user asked us to spend as opposed to
		// spending the maximum amount possible.

		// Create the transaction outputs and add the recipient's public key and the
		// amount we want to pay them
		txnOutputs := append(additionalOutputs, &lib.DeSoOutput{
			PublicKey: recipientPkBytes,
			// If we get here we know the amount is non-negative.
			AmountNanos: uint64(amountNanos),
		})

		// Assemble the transaction so that inputs can be found and fees can
		// be computed.
		txnn = &lib.MsgDeSoTxn{
			// The inputs will be set below.
			TxInputs:  []*lib.DeSoInput{},
			TxOutputs: txnOutputs,
			PublicKey: senderPkBytes,
			TxnMeta:   &lib.BasicTransferMetadata{},
			// We wait to compute the signature until we've added all the
			// inputs and change.
		}

		if len(extraData) > 0 {
			txnn.ExtraData = extraData
		}

		// Add inputs to the transaction and do signing, validation, and broadcast
		// depending on what the user requested.
		totalInputt, spendAmountt, changeAmountt, feeNanoss, err =
			fes.blockchain.AddInputsAndChangeToTransaction(
				txnn, minFeeRateNanosPerKb, fes.backendServer.GetMempool())
		if err != nil {
			return nil, 0, 0, 0, 0, fmt.Errorf("CreateSendDesoTxn: Error adding inputs and change to transaction: %v", err)
		}
	}
	return txnn, totalInputt, spendAmountt, changeAmountt, feeNanoss, nil
}

// SendDeSo ...
func (fes *APIServer) SendDeSo(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := SendDeSoRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendDeSo: Problem parsing request body: %v", err))
		return
	}

	// If the string starts with the public key characters than interpret it as
	// a public key. Otherwise we interpret it as a username and try to look up
	// the corresponding profile.
	var recipientPkBytes []byte
	if strings.Index(requestData.RecipientPublicKeyOrUsername, fes.PublicKeyBase58Prefix) == 0 {

		// Decode the recipient's public key.
		var err error
		recipientPkBytes, _, err = lib.Base58CheckDecode(requestData.RecipientPublicKeyOrUsername)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SendDeSo: Problem decoding recipient "+
				"base58 public key %s: %v", requestData.RecipientPublicKeyOrUsername, err))
			return
		}
	} else {
		// TODO(performance): This is inefficient because it loads all mempool
		// transactions.
		utxoView, err := lib.GetAugmentedUniversalViewWithAdditionalTransactions(
			fes.backendServer.GetMempool(),
			requestData.OptionalPrecedingTransactions,
		)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SendDeSo: Error generating "+
				"view to verify username: %v", err))
			return
		}
		profileEntry := utxoView.GetProfileEntryForUsername(
			[]byte(requestData.RecipientPublicKeyOrUsername))
		if profileEntry == nil {
			_AddBadRequestError(ww, fmt.Sprintf("SendDeSo: Profile with username "+
				"%v does not exist", requestData.RecipientPublicKeyOrUsername))
			return
		}
		recipientPkBytes = profileEntry.PublicKey
	}
	if len(recipientPkBytes) == 0 {
		_AddBadRequestError(ww, fmt.Sprintf("SendDeSo: Unknown error parsing public key."))
		return
	}

	// Decode the sender public key.
	senderPkBytes, _, err := lib.Base58CheckDecode(requestData.SenderPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendDeSo: Problem decoding sender base58 public key %s: %v", requestData.SenderPublicKeyBase58Check, err))
		return
	}

	// Compute the additional transaction fees as specified by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(lib.TxnTypeBasicTransfer, senderPkBytes, requestData.TransactionFees)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendDESO: TransactionFees specified in Request body are invalid: %v", err))
		return
	}

	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendDeSo: Problem encoding ExtraData: %v", err))
		return
	}

	txnn, totalInputt, spendAmountt, changeAmountt, feeNanoss, err := fes.CreateSendDesoTxn(
		requestData.AmountNanos,
		senderPkBytes,
		recipientPkBytes,
		extraData,
		requestData.MinFeeRateNanosPerKB,
		additionalOutputs)

	// Sanity check that the input is equal to:
	//   (spend amount + change amount + fees)
	if totalInputt != (spendAmountt + changeAmountt + feeNanoss) {
		_AddBadRequestError(ww, fmt.Sprintf("SendDeSo: totalInput=%d is not equal "+
			"to the sum of the (spend amount=%d, change=%d, and fees=%d) which sums "+
			"to %d. This means there was likely a problem with CreateMaxSpend",
			totalInputt, spendAmountt, changeAmountt, feeNanoss, (spendAmountt+changeAmountt+feeNanoss)))
		return
	}

	// If we got here and if broadcast was requested then it means the
	// transaction passed validation and it's therefore reasonable to
	// update the user objects to reflect that.
	txID := lib.PkToString(txnn.Hash()[:], fes.Params)

	txnBytes, err := txnn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendDeSo: Problem serializing transaction: %v", err))
		return
	}

	// Return the transaction in the response along with some metadata. If we
	// get to this point and if the user requested that the transaction be
	// validated or broadcast, the user can assume that those operations
	// occurred successfully.
	res := SendDeSoResponse{
		TotalInputNanos:          totalInputt,
		SpendAmountNanos:         spendAmountt,
		ChangeAmountNanos:        changeAmountt,
		FeeNanos:                 feeNanoss,
		TransactionIDBase58Check: txID,
		Transaction:              txnn,
		TransactionHex:           hex.EncodeToString(txnBytes),
		TxnHashHex:               txnn.Hash().String(),
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendDeSo: Problem encoding response as JSON: %v", err))
		return
	}
}

// CreateLikeStatelessRequest ...
type CreateLikeStatelessRequest struct {
	ReaderPublicKeyBase58Check string `safeForLogging:"true"`
	LikedPostHashHex           string `safeForLogging:"true"`
	IsUnlike                   bool   `safeForLogging:"true"`
	MinFeeRateNanosPerKB       uint64 `safeForLogging:"true"`

	// No need to specify ProfileEntryResponse in each TransactionFee
	TransactionFees []TransactionFee `safeForLogging:"true"`
}

// CreateLikeStatelessResponse ...
type CreateLikeStatelessResponse struct {
	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgDeSoTxn
	TransactionHex    string
}

// CreateLikeStateless ...
func (fes *APIServer) CreateLikeStateless(ww http.ResponseWriter, req *http.Request) {

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := CreateLikeStatelessRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateLikeStateless: Problem parsing request body: %v", err))
		return
	}

	// Decode the post hash for the liked post.
	postHashBytes, err := hex.DecodeString(requestData.LikedPostHashHex)
	if err != nil || len(postHashBytes) != lib.HashSizeBytes {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetLikesStateless: Error parsing post hash %v: %v",
			requestData.LikedPostHashHex, err))
		return
	}

	// Decode the reader public key.
	readerPkBytes, _, err := lib.Base58CheckDecode(requestData.ReaderPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateLikeStateless: Problem decoding sender "+
			"base58 public key %s: %v", requestData.ReaderPublicKeyBase58Check, err))
		return
	}

	// Compute the additional transaction fees as specified by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(lib.TxnTypeLike, readerPkBytes, requestData.TransactionFees)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateLikeStateless: TransactionFees specified in Request body are invalid: %v", err))
		return
	}

	// We need to make the postHashBytes into a block hash in order to create the txn.
	postHash := lib.BlockHash{}
	copy(postHash[:], postHashBytes)

	// Try and create the message for the user.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateLikeTxn(
		readerPkBytes, postHash, requestData.IsUnlike,
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool(), additionalOutputs)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateLikeStateless: Problem creating transaction: %v", err))
		return
	}

	// Add node source to txn metadata
	fes.AddNodeSourceToTxnMetadata(txn)

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateLikeStateless: Problem serializing transaction: %v", err))
		return
	}

	res := CreateLikeStatelessResponse{
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateLikeStateless: Problem encoding response as JSON: %v", err))
		return
	}
}

// SubmitPostRequest ...
type SubmitPostRequest struct {
	// The public key of the user who made the post or the user
	// who is subsequently is modifying the post.
	UpdaterPublicKeyBase58Check string `safeForLogging:"true"`

	// Optional. Set when modifying a post as opposed to creating one
	// from scratch.
	PostHashHexToModify string `safeForLogging:"true"`

	// The parent post or profile. This is used for comments.
	ParentStakeID string `safeForLogging:"true"`
	// The body of this post.
	BodyObj *lib.DeSoBodySchema

	// The PostHashHex of the post being reposted
	RepostedPostHashHex string `safeForLogging:"true"`

	// ExtraData object to hold arbitrary attributes of a post.
	PostExtraData map[string]string `safeForLogging:"true"`

	// When set to true the post will be hidden.
	IsHidden bool `safeForLogging:"true"`

	MinFeeRateNanosPerKB uint64 `safeForLogging:"true"`

	// No need to specify ProfileEntryResponse in each TransactionFee
	TransactionFees []TransactionFee `safeForLogging:"true"`

	InTutorial bool `safeForLogging:"true"`

	// If true, the post will be "frozen", i.e. no longer editable.
	IsFrozen bool `safeForLogging:"true"`

	OptionalPrecedingTransactions []*lib.MsgDeSoTxn `safeForLogging:"true"`
}

// SubmitPostResponse ...
type SubmitPostResponse struct {
	TstampNanos uint64 `safeForLogging:"true"`
	PostHashHex string `safeForLogging:"true"`

	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgDeSoTxn
	TransactionHex    string
}

// SubmitPost ...
func (fes *APIServer) SubmitPost(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := SubmitPostRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitPost: Problem parsing request body: %v", err))
		return
	}

	// Decode the public key
	updaterPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.UpdaterPublicKeyBase58Check)
	if err != nil || len(updaterPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		_AddBadRequestError(ww, fmt.Sprintf(
			"SubmitPost: Problem decoding public key %s: %v",
			requestData.UpdaterPublicKeyBase58Check, err))
		return
	}

	// Compute the additional transaction fees as specified by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(lib.TxnTypeSubmitPost, updaterPublicKeyBytes, requestData.TransactionFees)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitPost: TransactionFees specified in Request body are invalid: %v", err))
		return
	}

	// Decode the parent stake ID. Default to empty block hash.
	var parentStakeID []byte
	if requestData.ParentStakeID != "" {
		// The length tells us this is a block hash.
		if len(requestData.ParentStakeID) == lib.HashSizeBytes*2 {
			parentStakeID, err = hex.DecodeString(requestData.ParentStakeID)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf(
					"SubmitPost: Problem decoding parent stake ID %v: %v",
					requestData.ParentStakeID, err))
				return
			}
		} else if strings.Index(requestData.ParentStakeID, fes.PublicKeyBase58Prefix) == 0 {

			parentStakeID, _, err = lib.Base58CheckDecode(requestData.ParentStakeID)
			if err != nil || len(parentStakeID) != btcec.PubKeyBytesLenCompressed {
				_AddBadRequestError(ww, fmt.Sprintf(
					"SubmitPost: Problem decoding parent stake ID as public key %v: %v",
					requestData.ParentStakeID, err))
				return
			}

		} else {
			_AddBadRequestError(ww, fmt.Sprintf(
				"SubmitPost: Unrecognized parent stake ID: %v",
				requestData.ParentStakeID))
			return
		}
	}
	// At this point the parent Stake ID is either set or it's nil.

	// Decode the post hash to modify if it's set.
	var postHashToModify []byte
	if requestData.PostHashHexToModify != "" {
		postHashToModifyBytes, err := hex.DecodeString(requestData.PostHashHexToModify)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"SubmitPost: Problem decoding PostHashHexToModify %v: %v",
				requestData.PostHashHexToModify, err))
			return
		}
		if len(postHashToModifyBytes) != lib.HashSizeBytes {
			_AddBadRequestError(ww, fmt.Sprintf(
				"SubmitPost: Invalid length for PostHashHexToModify %v",
				requestData.PostHashHexToModify))
			return
		}
		postHashToModify = postHashToModifyBytes
	}

	utxoView, err := lib.GetAugmentedUniversalViewWithAdditionalTransactions(
		fes.backendServer.GetMempool(),
		requestData.OptionalPrecedingTransactions,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitPost: Error getting utxoView"))
		return
	}

	// If we're not modifying a post then do a bunch of checks.
	var bodyBytes []byte
	var repostPostHashBytes []byte
	isQuotedRepost := false
	isRepost := false
	if len(postHashToModify) == 0 {
		// Verify that the body length is greater than the minimum.
		if requestData.BodyObj == nil {
			_AddBadRequestError(ww, fmt.Sprintf("SubmitPost: BodyObj is required"))
			return
		}

		// If a post is reposting another post, we set a boolean value to indicates that this posts is a repost and
		// convert the PostHashHex to bytes.
		if requestData.RepostedPostHashHex != "" {
			isRepost = true
			// Convert the post hash hex of the reposted post to bytes
			repostPostHashBytes, err = hex.DecodeString(requestData.RepostedPostHashHex)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("SubmitPost: Could not decode Repost Post Hash Hex"))
			}
			// Check that the post being reposted isn't a repost without a comment.  A user should only be able to repost
			// a repost post if it is a quote repost.
			if requestData.BodyObj.Body == "" && len(requestData.BodyObj.ImageURLs) == 0 {
				// Convert repost post hash from bytes to block hash and look up postEntry by postHash.
				repostPostHash := &lib.BlockHash{}
				copy(repostPostHash[:], repostPostHashBytes)
				repostPostEntry := utxoView.GetPostEntryForPostHash(repostPostHash)

				// If the body of the post that we are trying to repost is empty, this is an error as
				// we do not want to allow a user to repost
				if lib.IsVanillaRepost(repostPostEntry) {
					_AddBadRequestError(ww, fmt.Sprintf("SubmitPost: Cannot repost a post that is a repost without a quote"))
					return
				}
			} else {
				isQuotedRepost = true
			}
		}
		bodyBytes, err = fes.cleanBody(requestData.BodyObj, isRepost)

		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"SubmitPost: Error validating body bytes: %v", err))
			return
		}
	} else {
		// In this case we're updating an existing post so just parse the body.
		// TODO: It's probably fine for the other fields to be updated.
		if requestData.RepostedPostHashHex != "" {
			repostPostHashBytes, err = hex.DecodeString(requestData.RepostedPostHashHex)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("SubmitPost: Could not decode Repost Post Hash Hex"))
			}
			isRepost = true
			if requestData.BodyObj.Body != "" || len(requestData.BodyObj.ImageURLs) > 0 {
				isQuotedRepost = true
			}
		}
		if requestData.BodyObj != nil {
			bodyBytes, err = fes.cleanBody(requestData.BodyObj, isRepost /*isRepost*/)
			if err != nil {
				_AddBadRequestError(ww, err.Error())
				return
			}
		}
	}

	postExtraData, err := EncodeExtraDataMap(requestData.PostExtraData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitPost: Problem decoding ExtraData: %v", err))
		return
	}
	if requestData.IsFrozen {
		if _, exists := postExtraData[lib.IsFrozenKey]; exists {
			_AddBadRequestError(ww, "SubmitPost: Cannot specify both IsFrozen and PostExtraData.IsFrozen")
			return
		}
		postExtraData[lib.IsFrozenKey] = lib.IsFrozenPostVal
	}

	// Try and create the SubmitPost for the user.
	tstamp := uint64(time.Now().UnixNano())
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateSubmitPostTxn(
		updaterPublicKeyBytes,
		postHashToModify,
		parentStakeID,
		bodyBytes,
		repostPostHashBytes,
		isQuotedRepost,
		tstamp,
		postExtraData,
		requestData.IsHidden,
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool(), additionalOutputs)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitPost: Problem creating transaction: %v", err))
		return
	}

	// Add node source to txn metadata
	fes.AddNodeSourceToTxnMetadata(txn)

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitPost: Problem serializing transaction: %v", err))
		return
	}

	if requestData.InTutorial {
		var userMetadata *UserMetadata
		userMetadata, err = fes.getUserMetadataFromGlobalStateByPublicKeyBytes(updaterPublicKeyBytes)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SubmitPost: Problem getting user metadata from global state: %v", err))
			return
		}

		if userMetadata.TutorialStatus != DIAMOND {
			_AddBadRequestError(ww, fmt.Sprintf("SubmitPost: Must be in the GiveADiamondComplete status in tutorial in order to post at this point in the tutorial: %v", err))
			return
		}
		userMetadata.TutorialStatus = COMPLETE
		// Since the user has now completed the tutorial, we set must complete to false.
		// Users are able to restart the tutorial, so we can't rely on tutorial status being COMPLETE to verify that
		// they have done the tutorial.
		userMetadata.MustCompleteTutorial = false
		if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SubmitPost: Error putting user metadata in global state: %v", err))
			return
		}
	}
	/******************************************************************************************/

	// Return all the data associated with the transaction in the response
	res := SubmitPostResponse{
		TstampNanos:       tstamp,
		PostHashHex:       hex.EncodeToString(txn.Hash()[:]),
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendMessage: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) cleanBody(bodyObj *lib.DeSoBodySchema, isRepost bool) ([]byte, error) {
	// Sanitize the Body field on the body object, which should exist.
	if bodyObj.Body == "" && len(bodyObj.ImageURLs) == 0 && len(bodyObj.VideoURLs) == 0 && !isRepost {
		return nil, fmt.Errorf("SubmitPost: Body or Image or Video is required if not reposting.")
	}

	desoBodySchema := &lib.DeSoBodySchema{
		Body:      bodyObj.Body,
		ImageURLs: bodyObj.ImageURLs,
		VideoURLs: bodyObj.VideoURLs,
	}
	// Serialize the body object to JSON.
	bodyBytes, err := json.Marshal(desoBodySchema)
	if err != nil {
		return nil, fmt.Errorf("SubmitPost: Error serializing body to JSON %v", err)
	}

	// Validate that the body isn't too long.
	if uint64(len(bodyBytes)) > fes.Params.MaxPostBodyLengthBytes {
		return nil, fmt.Errorf(
			"SubmitPost: Body is too long. Length is %v but must be no more than %v",
			len(bodyBytes), fes.Params.MaxPostBodyLengthBytes)
	}

	return bodyBytes, nil
}

// CreateFollowTxnStatelessRequest ...
type CreateFollowTxnStatelessRequest struct {
	FollowerPublicKeyBase58Check string `safeForLogging:"true"`
	FollowedPublicKeyBase58Check string `safeForLogging:"true"`
	IsUnfollow                   bool   `safeForLogging:"true"`
	MinFeeRateNanosPerKB         uint64 `safeForLogging:"true"`

	// No need to specify ProfileEntryResponse in each TransactionFee
	TransactionFees []TransactionFee `safeForLogging:"true"`
}

// CreateFollowTxnStatelessResponse ...
type CreateFollowTxnStatelessResponse struct {
	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgDeSoTxn
	TransactionHex    string
}

// CreateFollowTxnStateless ...
func (fes *APIServer) CreateFollowTxnStateless(ww http.ResponseWriter, req *http.Request) {
	// TODO: we should acquire a lock on pubKey here. Otherwise there's a race as follows:
	// - miner acquires a global lock (lock on mempool or chain or something)
	// - multiple create follow txn requests get queued up on that lock
	// - miner releases lock
	// - multiple create follow txns execute simultaneously, leading to errors like
	//   lib.RuleErrorInputSpendsNonexistentUtxo or TxErrorDoubleSpend
	//
	// ------------------------------------------------------------------------------------------------
	//
	// Separately, here's another possibly-unexpected behavior: if a user creates a chain
	// of follows/unfollows, eventually there are too many. The mempool sets MaxTransactionDependenciesToProcess
	// to 100. After we get 101 transactions, each new transaction starts looking identical to
	// transaction #101, which causes TxErrorDuplicate.
	//
	// This isn't necessarily a bug, but just flagging in case it comes up.

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := CreateFollowTxnStatelessRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateFollowTxnStateless: Problem parsing request body: %v", err))
		return
	}

	// Decode the follower public key.
	followerPkBytes, _, err := lib.Base58CheckDecode(requestData.FollowerPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateFollowTxnStateless: Problem decoding sender "+
			"base58 public key %s: %v", requestData.FollowerPublicKeyBase58Check, err))
		return
	}

	// Compute the additional transaction fees as specified by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(lib.TxnTypeFollow, followerPkBytes, requestData.TransactionFees)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateFollowTxnStateless: TransactionFees specified in Request body are invalid: %v", err))
		return
	}

	// Decode the followed person's public key.
	followedPkBytes, _, err := lib.Base58CheckDecode(requestData.FollowedPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateFollowTxnStateless: Problem decoding recipient "+
			"base58 public key %s: %v", requestData.FollowedPublicKeyBase58Check, err))
		return
	}

	// Try and create the follow for the user.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateFollowTxn(
		followerPkBytes, followedPkBytes, requestData.IsUnfollow,
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool(), additionalOutputs)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateFollowTxnStateless: Problem creating transaction: %v", err))
		return
	}

	// Add node source to txn metadata
	fes.AddNodeSourceToTxnMetadata(txn)

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateFollowTxnStateless: Problem serializing transaction: %v", err))
		return
	}

	// Return all the data associated with the transaction in the response
	res := CreateFollowTxnStatelessResponse{
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateFollowTxnStateless: Problem encoding response as JSON: %v", err))
		return
	}
}

// BuyOrSellCreatorCoinRequest ...
type BuyOrSellCreatorCoinRequest struct {
	// The public key of the user who is making the buy/sell.
	UpdaterPublicKeyBase58Check string `safeForLogging:"true"`

	// The public key of the profile that the purchaser is trying
	// to buy.
	CreatorPublicKeyBase58Check string `safeForLogging:"true"`

	// Whether this is a "buy" or "sell"
	OperationType string `safeForLogging:"true"`

	// Generally, only one of these will be used depending on the OperationType
	// set. In a Buy transaction, DeSoToSellNanos will be converted into
	// creator coin on behalf of the user. In a Sell transaction,
	// CreatorCoinToSellNanos will be converted into DeSo. In an AddDeSo
	// operation, DeSoToAddNanos will be aded for the user. This allows us to
	// support multiple transaction types with same meta field.
	DeSoToSellNanos        uint64 `safeForLogging:"true"`
	CreatorCoinToSellNanos uint64 `safeForLogging:"true"`
	DeSoToAddNanos         uint64 `safeForLogging:"true"`

	// When a user converts DeSo into CreatorCoin, MinCreatorCoinExpectedNanos
	// specifies the minimum amount of creator coin that the user expects from their
	// transaction. And vice versa when a user is converting CreatorCoin for DeSo.
	// Specifying these fields prevents the front-running of users' buy/sell. Setting
	// them to zero turns off the check. Give it your best shot, Ivan.
	MinDeSoExpectedNanos        uint64 `safeForLogging:"true"`
	MinCreatorCoinExpectedNanos uint64 `safeForLogging:"true"`

	MinFeeRateNanosPerKB uint64 `safeForLogging:"true"`

	// No need to specify ProfileEntryResponse in each TransactionFee
	TransactionFees []TransactionFee `safeForLogging:"true"`

	InTutorial bool `safeForLogging:"true"`

	BitCloutToSellNanos      uint64 `safeForLogging:"true"` // Deprecated
	BitCloutToAddNanos       uint64 `safeForLogging:"true"` // Deprecated
	MinBitCloutExpectedNanos uint64 `safeForLogging:"true"` // Deprecated

	OptionalPrecedingTransactions []*lib.MsgDeSoTxn `safeForLogging:"true"`
}

// BuyOrSellCreatorCoinResponse ...
type BuyOrSellCreatorCoinResponse struct {
	// The amount of DeSo
	ExpectedDeSoReturnedNanos        uint64
	ExpectedCreatorCoinReturnedNanos uint64
	FounderRewardGeneratedNanos      uint64

	// Spend is defined as DeSo that's specified as input that winds up as "output not
	// belonging to you." In the case of a creator coin sell, your input is creator coin (not
	// DeSo), so this ends up being 0. In the case of a creator coin buy,
	// it should equal the amount of DeSo you put in to buy the creator coin
	SpendAmountNanos  uint64
	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgDeSoTxn
	TransactionHex    string
	TxnHashHex        string
}

// BuyOrSellCreatorCoin ...
func (fes *APIServer) BuyOrSellCreatorCoin(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := BuyOrSellCreatorCoinRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("BuyOrSellCreatorCoin: Problem parsing request body: %v", err))
		return
	}

	// Decode the updater public key
	updaterPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.UpdaterPublicKeyBase58Check)
	if err != nil || len(updaterPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		_AddBadRequestError(ww, fmt.Sprintf(
			"BuyOrSellCreatorCoin: Problem decoding updater public key %s: %v",
			requestData.UpdaterPublicKeyBase58Check, err))
		return
	}

	// Compute the additional transaction fees as specified by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(lib.TxnTypeCreatorCoin, updaterPublicKeyBytes, requestData.TransactionFees)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("BuyOrSellCreatorCoin: TransactionFees specified in Request body are invalid: %v", err))
		return
	}

	// Decode the creator public key
	creatorPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.CreatorPublicKeyBase58Check)
	if err != nil || len(creatorPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		_AddBadRequestError(ww, fmt.Sprintf(
			"BuyOrSellCreatorCoin: Problem decoding creator public key %s: %v",
			requestData.CreatorPublicKeyBase58Check, err))
		return
	}

	// Deprecated: backwards compatability
	if requestData.BitCloutToSellNanos > 0 {
		requestData.DeSoToSellNanos = requestData.BitCloutToSellNanos
	}

	// Deprecated: backwards compatability
	if requestData.BitCloutToAddNanos > 0 {
		requestData.DeSoToAddNanos = requestData.BitCloutToAddNanos
	}

	// Deprecated: backwards compatability
	if requestData.MinBitCloutExpectedNanos > 0 {
		requestData.MinDeSoExpectedNanos = requestData.MinBitCloutExpectedNanos
	}

	if requestData.DeSoToSellNanos == 0 && requestData.CreatorCoinToSellNanos == 0 {
		_AddBadRequestError(ww, fmt.Sprintf(
			"BuyOrSellCreatorCoin: One of the following is required: "+
				"{DeSoToSellNanos, CreatorCoinToSellNanos}"))
		return
	}
	if requestData.DeSoToAddNanos != 0 {
		_AddBadRequestError(ww, fmt.Sprintf("BuyOrSellCreatorCoin: DeSoToAddNanos not yet supported"))
		return
	}

	var operationType lib.CreatorCoinOperationType
	if requestData.OperationType == "buy" {
		operationType = lib.CreatorCoinOperationTypeBuy
	} else if requestData.OperationType == "sell" {
		operationType = lib.CreatorCoinOperationTypeSell
	} else {
		_AddBadRequestError(ww, fmt.Sprintf("BuyOrSellCreatorCoin: OperationType \"%v\" not supported",
			requestData.OperationType))
		return
	}
	// At this point, we should have stakeID and stakeType set properly.

	// Try and create the BuyOrSellCreatorCoin transaction for the user.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateCreatorCoinTxn(
		updaterPublicKeyBytes,
		creatorPublicKeyBytes,
		operationType,
		requestData.DeSoToSellNanos,
		requestData.CreatorCoinToSellNanos,
		requestData.DeSoToAddNanos,
		requestData.MinDeSoExpectedNanos,
		requestData.MinCreatorCoinExpectedNanos,
		// Standard transaction fields
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool(), additionalOutputs)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("BuyOrSellCreatorCoin: Problem adding inputs and change transaction: %v", err))
		return
	}

	// Add node source to txn metadata
	fes.AddNodeSourceToTxnMetadata(txn)

	utxoView, err := lib.GetAugmentedUniversalViewWithAdditionalTransactions(
		fes.backendServer.GetMempool(),
		requestData.OptionalPrecedingTransactions,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("BuyOrSellCreatorCoin: Problem computing view for transaction: %v", err))
		return
	}

	// Compute how much CreatorCoin or DeSo we expect to be returned
	// from applying this transaction. This helps the UI display an estimated
	// price.
	ExpectedDeSoReturnedNanos := uint64(0)
	ExpectedCreatorCoinReturnedNanos := uint64(0)
	FounderRewardGeneratedNanos := uint64(0)
	{
		txHash := txn.Hash()
		blockHeight := fes.blockchain.BlockTip().Height + 1
		if operationType == lib.CreatorCoinOperationTypeBuy {
			_, _, creatorCoinReturnedNanos, founderRewardNanos, _, err :=
				utxoView.HelpConnectCreatorCoinBuy(txn, txHash, blockHeight, false /*verifySignatures*/)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("BuyOrSellCreatorCoin: Problem connecting buy transaction: %v", err))
				return
			}
			ExpectedCreatorCoinReturnedNanos = creatorCoinReturnedNanos
			FounderRewardGeneratedNanos = founderRewardNanos
		} else if operationType == lib.CreatorCoinOperationTypeSell {
			_, _, desoreturnedNanos, _, err :=
				utxoView.HelpConnectCreatorCoinSell(txn, txHash, blockHeight, false /*verifySignatures*/)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("BuyOrSellCreatorCoin: Problem connecting sell transaction: %v", err))
				return
			}
			ExpectedDeSoReturnedNanos = desoreturnedNanos

		} else {
			_AddBadRequestError(ww, fmt.Sprintf(
				"BuyOrSellCreatorCoin: OperationType \"%v\" not supported",
				requestData.OperationType))
			return
		}
	}

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("BuyOrSellCreatorCoin: Problem serializing transaction: %v", err))
		return
	}

	if requestData.InTutorial {
		var userMetadata *UserMetadata
		userMetadata, err = fes.getUserMetadataFromGlobalStateByPublicKeyBytes(updaterPublicKeyBytes)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("BuyOrSellCreatorCoin: Problem getting user metadata from global state: %v", err))
			return
		}

		var updateUserMetadata bool
		// TODO: check that user is buying from list of creators included in tutorial
		// TODO: Save which creator a user purchased by PKID in user metadata so we can bring them to the same place in the flow
		// TODO: Do we need to save how much they bought for usage in tutorial?
		if operationType == lib.CreatorCoinOperationTypeBuy && (userMetadata.TutorialStatus == CREATE_PROFILE || userMetadata.TutorialStatus == STARTED) && requestData.CreatorPublicKeyBase58Check != requestData.UpdaterPublicKeyBase58Check {
			if reflect.DeepEqual(updaterPublicKeyBytes, creatorPublicKeyBytes) {
				_AddBadRequestError(ww, fmt.Sprintf("BuyOrSellCreatorCoin: Cannot purchase your own coin in the Invest in others step"))
				return
			}
			creatorPKID := utxoView.GetPKIDForPublicKey(creatorPublicKeyBytes)
			if creatorPKID == nil {
				_AddBadRequestError(ww, fmt.Sprintf("BuyOrSellCreatorCoin: No PKID found for public key: %v", requestData.CreatorPublicKeyBase58Check))
				return
			}
			wellKnownVal, err := fes.GlobalState.Get(GlobalStateKeyWellKnownTutorialCreators(creatorPKID.PKID))
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("BuyOrSellCreatorCoin: Error trying to look up creator in well known index: %v", err))
				return
			}
			if wellKnownVal == nil {
				upAndComing, err := fes.GlobalState.Get(GlobalStateKeyUpAndComingTutorialCreators(creatorPKID.PKID))
				if err != nil {
					_AddBadRequestError(ww, fmt.Sprintf("BuyOrSellCreatorCoin: Error trying to look up creator in up and coming index: %v", err))
					return
				}
				if upAndComing == nil {
					_AddBadRequestError(ww, fmt.Sprintf("BuyOrSellCreatorCoin: Creator is not in either of the featured creators indexes"))
					return
				}
			}
			userMetadata.TutorialStatus = INVEST_OTHERS_BUY
			userMetadata.CreatorPurchasedInTutorialPKID = creatorPKID.PKID
			userMetadata.CreatorCoinsPurchasedInTutorial = ExpectedCreatorCoinReturnedNanos
			updateUserMetadata = true
		}

		// Tutorial state: user is investing in themselves
		if operationType == lib.CreatorCoinOperationTypeBuy && (userMetadata.TutorialStatus == INVEST_OTHERS_SELL || userMetadata.TutorialStatus == CREATE_PROFILE) && requestData.CreatorPublicKeyBase58Check == requestData.UpdaterPublicKeyBase58Check {
			userMetadata.TutorialStatus = INVEST_SELF
			updateUserMetadata = true
		}

		if operationType == lib.CreatorCoinOperationTypeSell && userMetadata.TutorialStatus == INVEST_OTHERS_BUY {
			creatorPKID := utxoView.GetPKIDForPublicKey(creatorPublicKeyBytes)
			if !reflect.DeepEqual(creatorPKID.PKID, userMetadata.CreatorPurchasedInTutorialPKID) {
				_AddBadRequestError(ww, fmt.Sprintf("BuyOrSellCreatorCoin: Must sell the same creator as purchased in previous step"))
				return
			}
			userMetadata.TutorialStatus = INVEST_OTHERS_SELL
			updateUserMetadata = true
		}

		if !updateUserMetadata {
			_AddBadRequestError(ww, fmt.Sprintf("BuyOrSellCreatorCoin: Current tutorial status (%v) does not allow this %v transaction", userMetadata.TutorialStatus, requestData.OperationType))
			return
		}

		if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("BuyOrSellCreatorCoin: Problem updating user metadata's tutorial status in global state: %v", err))
			return
		}
	}

	// Return all the data associated with the transaction in the response
	res := BuyOrSellCreatorCoinResponse{
		ExpectedDeSoReturnedNanos:        ExpectedDeSoReturnedNanos,
		ExpectedCreatorCoinReturnedNanos: ExpectedCreatorCoinReturnedNanos,
		FounderRewardGeneratedNanos:      FounderRewardGeneratedNanos,

		SpendAmountNanos:  totalInput - changeAmount - fees,
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
		TxnHashHex:        txn.Hash().String(),
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("BuyOrSellCreatorCoin: Problem encoding response as JSON: %v", err))
		return
	}
}

// TransferCreatorCoinRequest ...
type TransferCreatorCoinRequest struct {
	// The public key of the user who is making the transfer.
	SenderPublicKeyBase58Check string `safeForLogging:"true"`

	// The public key of the profile for the creator coin that the user is transferring.
	CreatorPublicKeyBase58Check string `safeForLogging:"true"`

	// The public key or username of the user receiving the transferred creator coin.
	ReceiverUsernameOrPublicKeyBase58Check string `safeForLogging:"true"`

	// The amount of creator coins to transfer in nanos.
	CreatorCoinToTransferNanos uint64 `safeForLogging:"true"`

	MinFeeRateNanosPerKB uint64 `safeForLogging:"true"`

	// No need to specify ProfileEntryResponse in each TransactionFee
	TransactionFees []TransactionFee `safeForLogging:"true"`

	OptionalPrecedingTransactions []*lib.MsgDeSoTxn `safeForLogging:"true"`
}

// TransferCreatorCoinResponse ...
type TransferCreatorCoinResponse struct {
	SpendAmountNanos  uint64
	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgDeSoTxn
	TransactionHex    string
	TxnHashHex        string
}

// TransferCreatorCoin ...
func (fes *APIServer) TransferCreatorCoin(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := TransferCreatorCoinRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("TransferCreatorCoin: Problem parsing request body: %v", err))
		return
	}

	if requestData.SenderPublicKeyBase58Check == "" ||
		requestData.CreatorPublicKeyBase58Check == "" ||
		requestData.ReceiverUsernameOrPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprintf("TransferCreatorCoin: Must provide a sender, a creator, and a receiver."))
		return
	}

	// Decode the updater public key
	senderPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.SenderPublicKeyBase58Check)
	if err != nil || len(senderPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		_AddBadRequestError(ww, fmt.Sprintf("TransferCreatorCoin: Problem decoding sender public key %s: %v",
			requestData.SenderPublicKeyBase58Check, err))
		return
	}

	// Compute the additional transaction fees as specified by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(lib.TxnTypeCreatorCoinTransfer, senderPublicKeyBytes, requestData.TransactionFees)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("TransferCreatorCoin: TransactionFees specified in Request body are invalid: %v", err))
		return
	}

	// Decode the creator public key
	creatorPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.CreatorPublicKeyBase58Check)
	if err != nil || len(creatorPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		_AddBadRequestError(ww, fmt.Sprintf("TransferCreatorCoin: Problem decoding creator public key %s: %v",
			requestData.CreatorPublicKeyBase58Check, err))
		return
	}

	// Get the public key for the receiver.
	var receiverPublicKeyBytes []byte
	if uint64(len(requestData.ReceiverUsernameOrPublicKeyBase58Check)) <= fes.Params.MaxUsernameLengthBytes {
		// The receiver string is too short to be a public key.  Lookup the username.
		utxoView, err := lib.GetAugmentedUniversalViewWithAdditionalTransactions(
			fes.backendServer.GetMempool(),
			requestData.OptionalPrecedingTransactions,
		)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("TransferCreatorCoin: Problem fetching utxoView: %v", err))
			return
		}

		profile := utxoView.GetProfileEntryForUsername([]byte(requestData.ReceiverUsernameOrPublicKeyBase58Check))
		if profile == nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"TransferCreatorCoin: Problem getting profile for username: %v : %s", err, requestData.ReceiverUsernameOrPublicKeyBase58Check))
			return
		}
		receiverPublicKeyBytes = profile.PublicKey
	} else {
		// Decode the receiver public key
		receiverPublicKeyBytes, _, err = lib.Base58CheckDecode(requestData.ReceiverUsernameOrPublicKeyBase58Check)
		if err != nil || len(receiverPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
			_AddBadRequestError(ww, fmt.Sprintf(
				"TransferCreatorCoin: Problem decoding receiver public key %s: %v",
				requestData.ReceiverUsernameOrPublicKeyBase58Check, err))
			return
		}
	}

	if reflect.DeepEqual(senderPublicKeyBytes, receiverPublicKeyBytes) {
		_AddBadRequestError(ww, fmt.Sprintf("TransferCreatorCoin: Sender and receiver cannot be the same."))
		return
	}

	if requestData.CreatorCoinToTransferNanos < fes.Params.CreatorCoinAutoSellThresholdNanos {
		_AddBadRequestError(ww, fmt.Sprintf(
			"TransferCreatorCoin: CreatorCoinToTransferNanos must be greater than %d nanos",
			fes.Params.CreatorCoinAutoSellThresholdNanos))
		return
	}

	// Try and create the TransferCreatorCoin transaction for the user.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateCreatorCoinTransferTxn(
		senderPublicKeyBytes,
		creatorPublicKeyBytes,
		requestData.CreatorCoinToTransferNanos,
		receiverPublicKeyBytes,
		// Standard transaction fields
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool(), additionalOutputs)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("TransferCreatorCoin: Problem creating transaction: %v", err))
		return
	}

	// Add node source to txn metadata
	fes.AddNodeSourceToTxnMetadata(txn)

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("TransferCreatorCoin: Problem serializing transaction: %v", err))
		return
	}

	// Return all the data associated with the transaction in the response
	res := TransferCreatorCoinResponse{
		SpendAmountNanos:  totalInput - changeAmount - fees,
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
		TxnHashHex:        txn.Hash().String(),
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("TransferCreatorCoin: Problem encoding response as JSON: %v", err))
		return
	}
}

// SendDiamondsRequest ...
type SendDiamondsRequest struct {
	// The public key of the user who is making the transfer.
	SenderPublicKeyBase58Check string `safeForLogging:"true"`

	// The public key or username of the user receiving the transferred creator coin.
	ReceiverPublicKeyBase58Check string `safeForLogging:"true"`

	// The number of diamonds to give the post.
	DiamondPostHashHex string `safeForLogging:"true"`

	// The number of diamonds to give the post.
	DiamondLevel int64 `safeForLogging:"true"`

	MinFeeRateNanosPerKB uint64 `safeForLogging:"true"`

	ExtraData map[string]string `safeForLogging:"true"`

	// No need to specify ProfileEntryResponse in each TransactionFee
	TransactionFees []TransactionFee `safeForLogging:"true"`

	InTutorial bool `safeForLogging:"true"`
}

// SendDiamondsResponse ...
type SendDiamondsResponse struct {
	SpendAmountNanos  uint64
	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgDeSoTxn
	TransactionHex    string
	TxnHashHex        string
}

// SendDiamonds ...
func (fes *APIServer) SendDiamonds(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := SendDiamondsRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendDiamonds: Problem parsing request body: %v", err))
		return
	}

	if requestData.SenderPublicKeyBase58Check == "" ||
		requestData.ReceiverPublicKeyBase58Check == "" ||
		requestData.DiamondPostHashHex == "" {
		_AddBadRequestError(ww, fmt.Sprintf("SendDiamonds: Must provide a sender, a receiver, and a post hash to diamond."))
		return
	}

	// Decode the sender public key
	senderPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.SenderPublicKeyBase58Check)
	if err != nil || len(senderPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		_AddBadRequestError(ww, fmt.Sprintf(
			"SendDiamonds: Problem decoding sender public key %s: %v",
			requestData.SenderPublicKeyBase58Check, err))
		return
	}

	// Decode the receiver public key
	receiverPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.ReceiverPublicKeyBase58Check)
	if err != nil || len(receiverPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		_AddBadRequestError(ww, fmt.Sprintf(
			"SendDiamonds: Problem decoding receiver public key %s: %v",
			requestData.ReceiverPublicKeyBase58Check, err))
		return
	}

	// Decode the diamond post hash.
	diamondPostHashBytes, err := hex.DecodeString(requestData.DiamondPostHashHex)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"SendDiamonds: Problem decoding DiamondPostHashHex %v: %v",
			requestData.DiamondPostHashHex, err))
		return
	}
	if len(diamondPostHashBytes) != lib.HashSizeBytes {
		_AddBadRequestError(ww, fmt.Sprintf(
			"SendDiamonds: Invalid length for DiamondPostHashHex %v",
			requestData.DiamondPostHashHex))
		return
	}

	// Now that we know we have a real post hash, we can turn it into a BlockHash.
	diamondPostHash := &lib.BlockHash{}
	copy(diamondPostHash[:], diamondPostHashBytes[:])

	if reflect.DeepEqual(senderPublicKeyBytes, receiverPublicKeyBytes) {
		_AddBadRequestError(ww, fmt.Sprintf("SendDiamonds: Sender and receiver cannot be the same."))
		return
	}

	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendDiamonds: Problem encoding extra data: %v", err))
		return
	}

	// Try and create the transfer with diamonds for the user.
	// We give diamonds in DESO if we're past the corresponding block height.
	blockHeight := fes.blockchain.BlockTip().Height + 1
	var txn *lib.MsgDeSoTxn
	var totalInput uint64
	var changeAmount uint64
	var fees uint64
	var additionalOutputs []*lib.DeSoOutput
	if blockHeight > fes.Params.ForkHeights.DeSoDiamondsBlockHeight {
		// Compute the additional transaction fees as specified by the request body and the node-level fees.
		additionalOutputs, err = fes.getTransactionFee(lib.TxnTypeBasicTransfer, senderPublicKeyBytes, requestData.TransactionFees)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SendDiamonds: TransactionFees specified in Request body are invalid: %v", err))
			return
		}
		txn, totalInput, _, changeAmount, fees, err = fes.blockchain.CreateBasicTransferTxnWithDiamonds(
			senderPublicKeyBytes,
			diamondPostHash,
			requestData.DiamondLevel,
			extraData,
			// Standard transaction fields
			requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool(), additionalOutputs)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SendDiamonds: Problem creating transaction: %v", err))
			return
		}

	} else {
		// Compute the additional transaction fees as specified by the request body and the node-level fees.
		additionalOutputs, err = fes.getTransactionFee(lib.TxnTypeCreatorCoinTransfer, senderPublicKeyBytes, requestData.TransactionFees)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SendDiamonds: TransactionFees specified in Request body are invalid: %v", err))
			return
		}
		txn, totalInput, changeAmount, fees, err = fes.blockchain.CreateCreatorCoinTransferTxnWithDiamonds(
			senderPublicKeyBytes,
			receiverPublicKeyBytes,
			diamondPostHash,
			requestData.DiamondLevel,
			// Standard transaction fields
			requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool(), additionalOutputs)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SendDiamonds: Problem creating transaction: %v", err))
			return
		}
	}

	// Add node source to txn metadata
	fes.AddNodeSourceToTxnMetadata(txn)

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendDiamonds: Problem serializing transaction: %v", err))
		return
	}

	if requestData.InTutorial {
		var userMetadata *UserMetadata
		userMetadata, err = fes.getUserMetadataFromGlobalStateByPublicKeyBytes(senderPublicKeyBytes)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SendDiamonds: Problem getting user metadata from global state: %v", err))
			return
		}
		if userMetadata.TutorialStatus != INVEST_SELF {
			_AddBadRequestError(ww, fmt.Sprintf("SendDiamonds: User should not be sending diamonds at this point in the tutorial"))
			return
		}
		userMetadata.TutorialStatus = DIAMOND
		if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SendDiamonds: Problem putting user metadata in global state: %v", err))
			return
		}
	}

	// Return all the data associated with the transaction in the response
	res := SendDiamondsResponse{
		SpendAmountNanos:  totalInput - changeAmount - fees,
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
		TxnHashHex:        txn.Hash().String(),
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendDiamonds: Problem encoding response as JSON: %v", err))
		return
	}
}

type DAOCoinOperationTypeString string

const (
	DAOCoinOperationStringMint                            DAOCoinOperationTypeString = "mint"
	DAOCoinOperationStringBurn                            DAOCoinOperationTypeString = "burn"
	DAOCoinOperationStringUpdateTransferRestrictionStatus DAOCoinOperationTypeString = "update_transfer_restriction_status"
	DAOCoinOperationStringDisableMinting                  DAOCoinOperationTypeString = "disable_minting"
)

type TransferRestrictionStatusString string

const (
	TransferRestrictionStatusStringUnrestricted            TransferRestrictionStatusString = "unrestricted"
	TransferRestrictionStatusStringProfileOwnerOnly        TransferRestrictionStatusString = "profile_owner_only"
	TransferRestrictionStatusStringDAOMembersOnly          TransferRestrictionStatusString = "dao_members_only"
	TransferRestrictionStatusStringPermanentlyUnrestricted TransferRestrictionStatusString = "permanently_unrestricted"
)

// DAOCoinRequest ...
type DAOCoinRequest struct {
	// The public key of the user who is performing the DAOCoin Txn
	UpdaterPublicKeyBase58Check string `safeForLogging:"true"`

	// The public key or username of the profile whose DAO coin the transactor is trying to transact with.
	ProfilePublicKeyBase58CheckOrUsername string `safeForLogging:"true"`

	// Whether this is a "mint", "burn" or "disable_minting" transaction
	OperationType DAOCoinOperationTypeString `safeForLogging:"true"`

	// Coins
	CoinsToMintNanos uint256.Int `safeForLogging:"true"`

	CoinsToBurnNanos uint256.Int `safeForLogging:"true"`

	// Transfer Restriction Status
	TransferRestrictionStatus TransferRestrictionStatusString `safeForLogging:"true"`

	MinFeeRateNanosPerKB uint64 `safeForLogging:"true"`

	// No need to specify ProfileEntryResponse in each TransactionFee
	TransactionFees []TransactionFee `safeForLogging:"true"`

	OptionalPrecedingTransactions []*lib.MsgDeSoTxn `safeForLogging:"true"`
}

// DAOCoinResponse ...
type DAOCoinResponse struct {
	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgDeSoTxn
	TransactionHex    string
	TxnHashHex        string
}

// DAOCoin ...
func (fes *APIServer) DAOCoin(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := DAOCoinRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("DAOCoin: Problem parsing request body: %v", err))
		return
	}

	// Convert OperationTypeString to DAOCoinOperationType
	var operationType lib.DAOCoinOperationType
	switch requestData.OperationType {
	case DAOCoinOperationStringMint:
		operationType = lib.DAOCoinOperationTypeMint
	case DAOCoinOperationStringBurn:
		operationType = lib.DAOCoinOperationTypeBurn
	case DAOCoinOperationStringUpdateTransferRestrictionStatus:
		operationType = lib.DAOCoinOperationTypeUpdateTransferRestrictionStatus
	case DAOCoinOperationStringDisableMinting:
		operationType = lib.DAOCoinOperationTypeDisableMinting
	default:
		_AddBadRequestError(ww, fmt.Sprintf("DAOCoin: OperationType \"%v\" not supported",
			requestData.OperationType))
		return
	}

	utxoView, err := lib.GetAugmentedUniversalViewWithAdditionalTransactions(
		fes.backendServer.GetMempool(),
		requestData.OptionalPrecedingTransactions,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("DAOCoin: Problem computing view: %v", err))
		return
	}
	// Decode the updater public key
	updaterPublicKeyBytes, err := GetPubKeyBytesFromBase58Check(requestData.UpdaterPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("DAOCoin: Problem decoding updater public key/username %s: %v",
			requestData.UpdaterPublicKeyBase58Check, err))
		return
	}

	// Compute the additional transaction fees as specified by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(lib.TxnTypeDAOCoin, updaterPublicKeyBytes, requestData.TransactionFees)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("DAOCoin: TransactionFees specified in Request body are invalid: %v", err))
		return
	}

	// Get the creator public key and make sure the profile exists
	creatorPublicKeyBytes, profileEntry, err := fes.GetPubKeyAndProfileEntryForUsernameOrPublicKeyBase58Check(
		requestData.ProfilePublicKeyBase58CheckOrUsername, utxoView)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("DAOCoin: error getting profile or decoding public key for "+
			"ProfilePublicKeyBase58CheckOrUsername %s: %v", requestData.ProfilePublicKeyBase58CheckOrUsername, err))
		return
	}

	if profileEntry == nil || profileEntry.IsDeleted() {
		_AddBadRequestError(ww, fmt.Sprintf("DAOCoin: no profile found for profile public key %v",
			requestData.ProfilePublicKeyBase58CheckOrUsername))
		return
	}

	// Perform some basic sanity checks
	if (operationType == lib.DAOCoinOperationTypeMint || operationType == lib.DAOCoinOperationTypeDisableMinting ||
		operationType == lib.DAOCoinOperationTypeUpdateTransferRestrictionStatus) &&
		!reflect.DeepEqual(updaterPublicKeyBytes, creatorPublicKeyBytes) {
		_AddBadRequestError(ww, fmt.Sprintf(
			"DAOCoin: Must be profile owner in order to perform %v operation", requestData.OperationType))
		return
	}
	if operationType == lib.DAOCoinOperationTypeMint && requestData.CoinsToMintNanos.IsZero() {
		_AddBadRequestError(ww, fmt.Sprint("DAOCoin: Cannot mint 0 coins"))
		return
	}

	if operationType == lib.DAOCoinOperationTypeBurn && requestData.CoinsToBurnNanos.IsZero() {
		_AddBadRequestError(ww, fmt.Sprint("DAOCoin: Cannot burn 0 coins"))
		return
	}

	var transferRestrictionStatus lib.TransferRestrictionStatus
	if operationType == lib.DAOCoinOperationTypeUpdateTransferRestrictionStatus {
		if profileEntry.DAOCoinEntry.TransferRestrictionStatus == lib.TransferRestrictionStatusPermanentlyUnrestricted {
			_AddBadRequestError(ww, fmt.Sprintf("DAOCoin: Cannot update TransferRestrictionStatus if current "+
				"status is Permanently Unrestricted"))
			return
		}
		switch requestData.TransferRestrictionStatus {
		case TransferRestrictionStatusStringUnrestricted:
			transferRestrictionStatus = lib.TransferRestrictionStatusUnrestricted
		case TransferRestrictionStatusStringProfileOwnerOnly:
			transferRestrictionStatus = lib.TransferRestrictionStatusProfileOwnerOnly
		case TransferRestrictionStatusStringDAOMembersOnly:
			transferRestrictionStatus = lib.TransferRestrictionStatusDAOMembersOnly
		case TransferRestrictionStatusStringPermanentlyUnrestricted:
			transferRestrictionStatus = lib.TransferRestrictionStatusPermanentlyUnrestricted
		default:
			_AddBadRequestError(ww, fmt.Sprintf("DAOCoin: TransferRestrictionStatus \"%v\" not supported",
				requestData.TransferRestrictionStatus))
			return
		}
		if profileEntry.DAOCoinEntry.TransferRestrictionStatus == transferRestrictionStatus {
			_AddBadRequestError(ww, fmt.Sprintf("DAOCoin: Cannot update transfer restriction status to be the "+
				"same as the current status"))
			return
		}
	}

	// Try and create the DAOCoin transaction for the user.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateDAOCoinTxn(
		updaterPublicKeyBytes,
		&lib.DAOCoinMetadata{
			OperationType:             operationType,
			ProfilePublicKey:          creatorPublicKeyBytes,
			CoinsToMintNanos:          requestData.CoinsToMintNanos,
			CoinsToBurnNanos:          requestData.CoinsToBurnNanos,
			TransferRestrictionStatus: transferRestrictionStatus,
		},
		// Standard transaction fields
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool(), additionalOutputs)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("DAOCoin: Problem adding inputs and change transaction: %v", err))
		return
	}

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("DAOCoin: Problem serializing transaction: %v", err))
		return
	}

	// Return all the data associated with the transaction in the response
	res := DAOCoinResponse{
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
		TxnHashHex:        txn.Hash().String(),
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("DAOCoin: Problem encoding response as JSON: %v", err))
		return
	}
}

// TransferDAOCoinRequest ...
type TransferDAOCoinRequest struct {
	// The public key of the user who is making the transfer.
	SenderPublicKeyBase58Check string `safeForLogging:"true"`

	// The public key/Username of the profile for the DAO coin that the user is transferring.
	ProfilePublicKeyBase58CheckOrUsername string `safeForLogging:"true"`

	// The public key/username of the user receiving the transferred creator coin.
	ReceiverPublicKeyBase58CheckOrUsername string `safeForLogging:"true"`

	// The amount of creator coins to transfer in nanos.
	DAOCoinToTransferNanos uint256.Int `safeForLogging:"true"`

	MinFeeRateNanosPerKB uint64 `safeForLogging:"true"`

	// No need to specify ProfileEntryResponse in each TransactionFee
	TransactionFees []TransactionFee `safeForLogging:"true"`

	OptionalPrecedingTransactions []*lib.MsgDeSoTxn `safeForLogging:"true"`
}

// TransferDAOCoinResponse ...
type TransferDAOCoinResponse struct {
	SpendAmountNanos  uint64
	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgDeSoTxn
	TransactionHex    string
	TxnHashHex        string
}

// TransferDAOCoin ...
func (fes *APIServer) TransferDAOCoin(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := TransferDAOCoinRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("TransferDAOCoin: Problem parsing request body: %v", err))
		return
	}

	if requestData.SenderPublicKeyBase58Check == "" ||
		requestData.ProfilePublicKeyBase58CheckOrUsername == "" ||
		requestData.ReceiverPublicKeyBase58CheckOrUsername == "" {
		_AddBadRequestError(ww, fmt.Sprintf("TransferDAOCoin: Must provide a sender, a creator, and a receiver."))
		return
	}

	utxoView, err := lib.GetAugmentedUniversalViewWithAdditionalTransactions(
		fes.backendServer.GetMempool(),
		requestData.OptionalPrecedingTransactions,
	)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("TransferDAOCoin: Problem fetching utxoView: %v", err))
		return
	}

	// Decode the updater public key
	senderPublicKeyBytes, _, err := fes.GetPubKeyAndProfileEntryForUsernameOrPublicKeyBase58Check(
		requestData.SenderPublicKeyBase58Check, utxoView)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("TransferDAOCoin: Problem decoding sender public key %s: %v",
			requestData.SenderPublicKeyBase58Check, err))
		return
	}

	// Compute the additional transaction fees as specified by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(lib.TxnTypeDAOCoinTransfer, senderPublicKeyBytes, requestData.TransactionFees)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("TransferDAOCoin: TransactionFees specified in Request body are invalid: %v", err))
		return
	}

	// Decode the creator public key
	creatorPublicKeyBytes, creatorProfileEntry, err := fes.GetPubKeyAndProfileEntryForUsernameOrPublicKeyBase58Check(
		requestData.ProfilePublicKeyBase58CheckOrUsername, utxoView)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("TransferDAOCoin: Problem decoding creator public key %s: %v",
			requestData.ProfilePublicKeyBase58CheckOrUsername, err))
		return
	}

	if creatorProfileEntry == nil || creatorProfileEntry.IsDeleted() {
		_AddBadRequestError(ww, fmt.Sprintf("TransferDAOCoin: No profile entry found for creator public key %s",
			requestData.ProfilePublicKeyBase58CheckOrUsername))
		return
	}

	// Get the public key for the receiver.
	receiverPublicKeyBytes, _, err := fes.GetPubKeyAndProfileEntryForUsernameOrPublicKeyBase58Check(
		requestData.ReceiverPublicKeyBase58CheckOrUsername, utxoView)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("TransferDAOCoin: Problem decoding reeceiver public key %s: %v",
			requestData.ReceiverPublicKeyBase58CheckOrUsername, err))
		return
	}

	if err = utxoView.IsValidDAOCoinTransfer(
		creatorProfileEntry, senderPublicKeyBytes, receiverPublicKeyBytes); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("TransferDAOCoin: Invalid DAOCoinTransfer: %v", err))
		return
	}

	// Try and create the TransferCreatorCoin transaction for the user.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateDAOCoinTransferTxn(
		senderPublicKeyBytes,
		&lib.DAOCoinTransferMetadata{
			ProfilePublicKey:       creatorPublicKeyBytes,
			ReceiverPublicKey:      receiverPublicKeyBytes,
			DAOCoinToTransferNanos: requestData.DAOCoinToTransferNanos,
		},
		// Standard transaction fields
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool(), additionalOutputs)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("TransferDAOCoin: Problem creating transaction: %v", err))
		return
	}

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("TransferDAOCoin: Problem serializing transaction: %v", err))
		return
	}

	// Return all the data associated with the transaction in the response
	res := TransferDAOCoinResponse{
		SpendAmountNanos:  totalInput - changeAmount - fees,
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
		TxnHashHex:        txn.Hash().String(),
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("TransferDAOCoin: Problem encoding response as JSON: %v", err))
		return
	}
}

type DAOCoinLimitOrderSimulatedExecutionResult struct {
	BuyingCoinQuantityFilled  string
	SellingCoinQuantityFilled string
}

// DAOCoinLimitOrderResponse ...
type DAOCoinLimitOrderResponse struct {
	SpendAmountNanos  uint64
	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgDeSoTxn
	TransactionHex    string
	TxnHashHex        string

	SimulatedExecutionResult *DAOCoinLimitOrderSimulatedExecutionResult
}

// DAOCoinLimitOrderWithExchangeRateAndQuantityRequest alias type for backwards compatibility
type DAOCoinLimitOrderWithExchangeRateAndQuantityRequest DAOCoinLimitOrderCreationRequest

type DAOCoinLimitOrderCreationRequest struct {
	// The public key of the user who is creating the order
	TransactorPublicKeyBase58Check string `safeForLogging:"true"`

	// The public key of the DAO coin being bought
	BuyingDAOCoinCreatorPublicKeyBase58Check string `safeForLogging:"true"`

	// The public key of the DAO coin being sold
	SellingDAOCoinCreatorPublicKeyBase58Check string `safeForLogging:"true"`

	// A decimal string (ex: 1.23) that represents the exchange rate between the two coins. If operation type is BID
	// then the denominator represents the coin being bought. If the operation type is ASK, then the denominator
	// represents the coin being sold
	Price string `safeForLogging:"true"`

	// A decimal string (ex: 1.23) that represents the quantity of coins being bought or sold. If operation type is BID,
	// then this quantity refers to the coin being bought. If operation type is ASK, then it refers to the coin being sold
	Quantity string `safeForLogging:"true"`

	OperationType DAOCoinLimitOrderOperationTypeString `safeForLogging:"true"`
	FillType      DAOCoinLimitOrderFillTypeString      `safeForLogging:"true"`

	// The two fields ExchangeRateCoinsToSellPerCoinToBuy and QuantityToFill will be deprecated once the above Price
	// and Quantity fields are deployed, and users have migrated to start using them. Until then, the API will continue
	// to accept ExchangeRateCoinsToSellPerCoinToBuy and QuantityToFill in requests to this endpoint
	ExchangeRateCoinsToSellPerCoinToBuy float64 `safeForLogging:"true"` // Deprecated
	QuantityToFill                      float64 `safeForLogging:"true"` // Deprecated

	MinFeeRateNanosPerKB uint64           `safeForLogging:"true"`
	TransactionFees      []TransactionFee `safeForLogging:"true"`

	OptionalPrecedingTransactions []*lib.MsgDeSoTxn `safeForLogging:"true"`
}

func (fes *APIServer) createDaoCoinLimitOrderHelper(
	requestData *DAOCoinLimitOrderCreationRequest,
) (
	_res *DAOCoinLimitOrderResponse,
	_err error,
) {
	// Basic validation that we have a transactor
	if requestData.TransactorPublicKeyBase58Check == "" {
		return nil, errors.New("CreateDAOCoinLimitOrder: must provide a TransactorPublicKeyBase58Check")
	}

	// Validate operation type
	operationType, err := orderOperationTypeToUint64(requestData.OperationType)
	if err != nil {
		return nil, errors.Errorf("CreateDAOCoinLimitOrder: %v", err)
	}

	// Parse and validate fill type; for backwards compatibility, default the empty string to GoodTillCancelled
	fillType := lib.DAOCoinLimitOrderFillTypeGoodTillCancelled
	if requestData.FillType != "" {
		fillType, err = orderFillTypeToUint64(requestData.FillType)
		if err != nil {
			return nil, errors.Errorf("CreateDAOCoinLimitOrder: %v", err)
		}
	}

	// Validated and parse price to a scaled exchange rate
	scaledExchangeRateCoinsToSellPerCoinToBuy := uint256.NewInt(0)
	if requestData.Price == "" && requestData.ExchangeRateCoinsToSellPerCoinToBuy == 0 {
		err = errors.Errorf("Price must be provided as a valid decimal string (ex: 1.23)")
	} else if requestData.Price != "" {
		scaledExchangeRateCoinsToSellPerCoinToBuy, err = CalculateScaledExchangeRateFromPriceString(
			requestData.BuyingDAOCoinCreatorPublicKeyBase58Check,
			requestData.SellingDAOCoinCreatorPublicKeyBase58Check,
			requestData.Price,
			operationType,
		)
	} else if requestData.ExchangeRateCoinsToSellPerCoinToBuy <= 0 {
		err = errors.Errorf("CreateDAOCoinLimitOrder: ExchangeRateCoinsToSellPerCoinToBuy must be greater than 0")
	} else {
		// ExchangeRateCoinsToSellPerCoinToBuy > 0
		scaledExchangeRateCoinsToSellPerCoinToBuy, err = CalculateScaledExchangeRateFromFloat(
			requestData.BuyingDAOCoinCreatorPublicKeyBase58Check,
			requestData.SellingDAOCoinCreatorPublicKeyBase58Check,
			requestData.ExchangeRateCoinsToSellPerCoinToBuy,
		)
	}
	if err != nil {
		return nil, errors.Errorf("CreateDAOCoinLimitOrder: %v", err)
	}

	// Parse and validated quantity
	quantityToFillInBaseUnits := uint256.NewInt(0)
	if requestData.Quantity == "" && requestData.QuantityToFill == 0 {
		err = errors.Errorf("Quantity must be provided as a valid decimal string (ex: 1.23)")
	} else if requestData.Quantity != "" {
		quantityToFillInBaseUnits, err = CalculateQuantityToFillAsBaseUnits(
			requestData.BuyingDAOCoinCreatorPublicKeyBase58Check,
			requestData.SellingDAOCoinCreatorPublicKeyBase58Check,
			requestData.OperationType,
			requestData.Quantity,
		)
	} else if requestData.QuantityToFill <= 0 {
		err = errors.Errorf("CreateDAOCoinLimitOrder: Quantity must be greater than 0")
	} else {
		quantityToFillInBaseUnits, err = CalculateQuantityToFillAsBaseUnits(
			requestData.BuyingDAOCoinCreatorPublicKeyBase58Check,
			requestData.SellingDAOCoinCreatorPublicKeyBase58Check,
			requestData.OperationType,
			formatFloatAsString(requestData.QuantityToFill),
		)
	}
	if err != nil {
		return nil, errors.Errorf("CreateDAOCoinLimitOrder: %v", err)
	}

	utxoView, err := lib.GetAugmentedUniversalViewWithAdditionalTransactions(
		fes.backendServer.GetMempool(),
		requestData.OptionalPrecedingTransactions,
	)
	if err != nil {
		return nil, errors.Errorf("CreateDAOCoinMarketOrder: problem fetching utxoView: %v", err)
	}

	// Decode and validate the buying / selling coin public keys
	buyingCoinPublicKey, sellingCoinPublicKey, err := fes.getBuyingAndSellingDAOCoinPublicKeys(
		requestData.BuyingDAOCoinCreatorPublicKeyBase58Check,
		requestData.SellingDAOCoinCreatorPublicKeyBase58Check,
	)
	if err != nil {
		return nil, errors.Errorf("CreateDAOCoinLimitOrder: %v", err)
	}

	// Validate transactor has sufficient selling coins.
	err = fes.validateTransactorSellingCoinBalance(
		requestData.TransactorPublicKeyBase58Check,
		requestData.BuyingDAOCoinCreatorPublicKeyBase58Check,
		requestData.SellingDAOCoinCreatorPublicKeyBase58Check,
		requestData.OperationType,
		scaledExchangeRateCoinsToSellPerCoinToBuy,
		quantityToFillInBaseUnits,
	)
	if err != nil {
		return nil, errors.Errorf("CreateDAOCoinLimitOrder: %v", err)
	}

	// Validate any transfer restrictions on buying the DAO coin.
	err = fes.validateDAOCoinOrderTransferRestriction(
		requestData.TransactorPublicKeyBase58Check,
		requestData.BuyingDAOCoinCreatorPublicKeyBase58Check)
	if err != nil {
		return nil, errors.Errorf("CreateDAOCoinLimitOrder: %v", err)
	}

	// Create order.
	res, err := fes.createDAOCoinLimitOrderResponse(
		utxoView,
		requestData.TransactorPublicKeyBase58Check,
		buyingCoinPublicKey,
		sellingCoinPublicKey,
		scaledExchangeRateCoinsToSellPerCoinToBuy,
		quantityToFillInBaseUnits,
		operationType,
		fillType,
		nil,
		requestData.MinFeeRateNanosPerKB,
		requestData.TransactionFees,
	)
	if err != nil {
		return nil, errors.Errorf("CreateDAOCoinLimitOrder: %v", err)
	}

	res.SimulatedExecutionResult, err = fes.getDAOCoinLimitOrderSimulatedExecutionResult(
		utxoView,
		requestData.TransactorPublicKeyBase58Check,
		requestData.BuyingDAOCoinCreatorPublicKeyBase58Check,
		requestData.SellingDAOCoinCreatorPublicKeyBase58Check,
		res.Transaction,
	)
	if err != nil {
		return nil, errors.Errorf("CreateDAOCoinLimitOrder: %v", err)
	}

	return res, nil
}

// CreateDAOCoinLimitOrder Constructs a transaction that creates a DAO coin limit order for the specified
// DAO coin pair, price, quantity, operation type, and fill type
func (fes *APIServer) CreateDAOCoinLimitOrder(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := DAOCoinLimitOrderCreationRequest{}

	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateDAOCoinLimitOrder: Problem parsing request body: %v", err))
		return
	}

	res, err := fes.createDaoCoinLimitOrderHelper(&requestData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateDAOCoinLimitOrder: %v", err))
		return
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("CreateDAOCoinLimitOrder: Problem encoding response as JSON: %v", err))
		return
	}
}

// DAOCoinMarketOrderWithQuantityRequest alias type for backwards compatibility
type DAOCoinMarketOrderWithQuantityRequest DAOCoinMarketOrderCreationRequest

type DAOCoinMarketOrderCreationRequest struct {
	// The public key of the user who is sending the order
	TransactorPublicKeyBase58Check string `safeForLogging:"true"`

	// The public key of the DAO coin being bought
	BuyingDAOCoinCreatorPublicKeyBase58Check string `safeForLogging:"true"`

	// The public key of the DAO coin being sold
	SellingDAOCoinCreatorPublicKeyBase58Check string `safeForLogging:"true"`

	// A decimal string (ex: 1.23) that represents the quantity of coins being bought or sold. If operation type is BID,
	// then this quantity refers to the coin being bought. If operation type is ASK, then it refers to the coin being sold
	Quantity string `safeForLogging:"true"`

	OperationType DAOCoinLimitOrderOperationTypeString `safeForLogging:"true"`
	FillType      DAOCoinLimitOrderFillTypeString      `safeForLogging:"true"`

	// The QuantityToFill field will be deprecated once the above Quantity field is deployed, and users have migrated to
	// start using it. Until then, the API will continue to accept QuantityToFill as an optional parameter in lieu of Quantity
	QuantityToFill float64 `safeForLogging:"true"` // Deprecated

	MinFeeRateNanosPerKB uint64           `safeForLogging:"true"`
	TransactionFees      []TransactionFee `safeForLogging:"true"`

	OptionalPrecedingTransactions []*lib.MsgDeSoTxn `safeForLogging:"true"`
}

func (fes *APIServer) createDaoCoinMarketOrderHelper(
	requestData *DAOCoinMarketOrderCreationRequest,
) (
	_res *DAOCoinLimitOrderResponse,
	_err error,
) {
	// Basic validation that we have a transactor
	if requestData.TransactorPublicKeyBase58Check == "" {
		return nil, errors.New("CreateDAOCoinMarketOrder: must provide a TransactorPublicKeyBase58Check")
	}

	// Validate operation type
	operationType, err := orderOperationTypeToUint64(requestData.OperationType)
	if err != nil {
		return nil, errors.Errorf("CreateDAOCoinMarketOrder: %v", err)
	}

	// Validate and convert quantity to base units

	// Parse and validated quantity
	quantityToFillInBaseUnits := uint256.NewInt(0)
	if requestData.Quantity == "" && requestData.QuantityToFill == 0 {
		err = errors.Errorf("CreateDAOCoinMarketOrder: Quantity must be provided as a valid decimal string (ex: 1.23)")
	} else if requestData.Quantity != "" {
		quantityToFillInBaseUnits, err = CalculateQuantityToFillAsBaseUnits(
			requestData.BuyingDAOCoinCreatorPublicKeyBase58Check,
			requestData.SellingDAOCoinCreatorPublicKeyBase58Check,
			requestData.OperationType,
			requestData.Quantity,
		)
	} else if requestData.QuantityToFill <= 0 {
		err = errors.Errorf("CreateDAOCoinMarketOrder: Quantity must be greater than 0")
	} else {
		quantityToFillInBaseUnits, err = CalculateQuantityToFillAsBaseUnits(
			requestData.BuyingDAOCoinCreatorPublicKeyBase58Check,
			requestData.SellingDAOCoinCreatorPublicKeyBase58Check,
			requestData.OperationType,
			formatFloatAsString(requestData.QuantityToFill),
		)
	}

	if err != nil {
		return nil, errors.Errorf("CreateDAOCoinMarketOrder: %v", err)
	}

	// Validate fill type
	fillType, err := orderFillTypeToUint64(requestData.FillType)
	if err != nil {
		return nil, errors.Errorf("CreateDAOCoinMarketOrder: %v", err)
	}
	if fillType == lib.DAOCoinLimitOrderFillTypeGoodTillCancelled {
		return nil, errors.New("CreateDAOCoinMarketOrder: GoodTillCancelled fill type not supported for market orders")
	}

	// Validate any transfer restrictions on buying the DAO coin.
	err = fes.validateDAOCoinOrderTransferRestriction(
		requestData.TransactorPublicKeyBase58Check,
		requestData.BuyingDAOCoinCreatorPublicKeyBase58Check)
	if err != nil {
		return nil, errors.Errorf("CreateDAOCoinMarketOrder: %v", err)
	}

	utxoView, err := lib.GetAugmentedUniversalViewWithAdditionalTransactions(
		fes.backendServer.GetMempool(),
		requestData.OptionalPrecedingTransactions,
	)
	if err != nil {
		return nil, errors.Errorf("CreateDAOCoinMarketOrder: problem fetching utxoView: %v", err)
	}

	// Decode and validate the buying / selling coin public keys
	buyingCoinPublicKey, sellingCoinPublicKey, err := fes.getBuyingAndSellingDAOCoinPublicKeys(
		requestData.BuyingDAOCoinCreatorPublicKeyBase58Check,
		requestData.SellingDAOCoinCreatorPublicKeyBase58Check,
	)
	if err != nil {
		return nil, errors.Errorf("CreateDAOCoinMarketOrder: %v", err)
	}

	// override the initial value and explicitly set to 0 for clarity
	zeroUint256 := uint256.NewInt(0)

	res, err := fes.createDAOCoinLimitOrderResponse(
		utxoView,
		requestData.TransactorPublicKeyBase58Check,
		buyingCoinPublicKey,
		sellingCoinPublicKey,
		zeroUint256,
		quantityToFillInBaseUnits,
		operationType,
		fillType,
		nil,
		requestData.MinFeeRateNanosPerKB,
		requestData.TransactionFees,
	)
	if err != nil {
		return nil, errors.Errorf("CreateDAOCoinMarketOrder: %v", err)
	}

	res.SimulatedExecutionResult, err = fes.getDAOCoinLimitOrderSimulatedExecutionResult(
		utxoView,
		requestData.TransactorPublicKeyBase58Check,
		requestData.BuyingDAOCoinCreatorPublicKeyBase58Check,
		requestData.SellingDAOCoinCreatorPublicKeyBase58Check,
		res.Transaction,
	)
	if err != nil {
		return nil, errors.Errorf("CreateDAOCoinMarketOrder: %v", err)
	}
	return res, nil
}

func (fes *APIServer) CreateDAOCoinMarketOrder(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := DAOCoinMarketOrderCreationRequest{}

	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateDAOCoinMarketOrder: Problem parsing request body: %v", err))
		return
	}

	res, err := fes.createDaoCoinMarketOrderHelper(&requestData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateDAOCoinMarketOrder: %v", err))
		return
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("CreateDAOCoinMarketOrder: Problem encoding response as JSON: %v", err))
		return
	}
}

// getBuyingAndSellingDAOCoinPublicKeys
// The string 'DESO' for the buying or selling coin represents $DESO. This enables $DESO <> DAO coin trades, and
// DAO coin <> DAO coin trades. At most one of the buying or selling coin can specify $DESO as we don't enable
// $DESO <> $DESO trades
func (fes *APIServer) getBuyingAndSellingDAOCoinPublicKeys(
	buyingDAOCoinCreatorPublicKeyBase58Check string,
	sellingDAOCoinCreatorPublicKeyBase58Check string,
) ([]byte, []byte, error) {
	if IsDesoPkid(sellingDAOCoinCreatorPublicKeyBase58Check) &&
		IsDesoPkid(buyingDAOCoinCreatorPublicKeyBase58Check) {
		return nil, nil, errors.Errorf("'DESO' specified for both the " +
			"coin to buy and the coin to sell. At least one must specify a valid DAO public key whose coin " +
			"will be bought or sold")
	}

	buyingCoinPublicKey := lib.ZeroPublicKey.ToBytes()
	sellingCoinPublicKey := lib.ZeroPublicKey.ToBytes()

	var err error

	if !IsDesoPkid(buyingDAOCoinCreatorPublicKeyBase58Check) {
		buyingCoinPublicKey, err = GetPubKeyBytesFromBase58Check(buyingDAOCoinCreatorPublicKeyBase58Check)
		if err != nil {
			return nil, nil, err
		}
	}

	if !IsDesoPkid(sellingDAOCoinCreatorPublicKeyBase58Check) {
		sellingCoinPublicKey, err = GetPubKeyBytesFromBase58Check(sellingDAOCoinCreatorPublicKeyBase58Check)
		if err != nil {
			return nil, nil, err
		}
	}

	return buyingCoinPublicKey, sellingCoinPublicKey, nil
}

type DAOCoinLimitOrderWithCancelOrderIDRequest struct {
	// The public key of the user who is cancelling the order
	TransactorPublicKeyBase58Check string `safeForLogging:"true"`

	CancelOrderID string `safeForLogging:"true"`

	MinFeeRateNanosPerKB uint64           `safeForLogging:"true"`
	TransactionFees      []TransactionFee `safeForLogging:"true"`

	OptionalPrecedingTransactions []*lib.MsgDeSoTxn `safeForLogging:"true"`
}

// CancelDAOCoinLimitOrder Constructs a transaction that cancels an existing DAO coin limit order with the specified
// order id
func (fes *APIServer) CancelDAOCoinLimitOrder(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := DAOCoinLimitOrderWithCancelOrderIDRequest{}

	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(
			ww,
			fmt.Sprintf("CancelDAOCoinLimitOrder: Problem parsing request body: %v", err),
		)
		return
	}

	if requestData.TransactorPublicKeyBase58Check == "" {
		_AddBadRequestError(
			ww,
			"CancelDAOCoinLimitOrder: must provide a TransactorPublicKeyBase58Check",
		)
		return
	}

	utxoView, err := lib.GetAugmentedUniversalViewWithAdditionalTransactions(
		fes.backendServer.GetMempool(),
		requestData.OptionalPrecedingTransactions,
	)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("CancelDAOCoinLimitOrder: problem fetching utxoView: %v", err))
		return
	}

	cancelOrderID, err := decodeBlockHashFromHex(requestData.CancelOrderID)
	if err != nil {
		_AddBadRequestError(
			ww,
			fmt.Sprintf("CancelDAOCoinLimitOrder: CancelOrderID param is not a valid order id: %v", err),
		)
		return
	}

	res, err := fes.createDAOCoinLimitOrderResponse(
		utxoView,
		requestData.TransactorPublicKeyBase58Check,
		nil,
		nil,
		nil,
		nil,
		0,
		0,
		cancelOrderID,
		requestData.MinFeeRateNanosPerKB,
		requestData.TransactionFees,
	)

	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("CancelDAOCoinLimitOrder: %v", err))
		return
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("CancelDAOCoinLimitOrder: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) createDAOCoinLimitOrderResponse(
	utxoView *lib.UtxoView,
	transactorPublicKeyBase58Check string,
	buyingCoinPublicKeyBytes []byte,
	sellingCoinPublicKeyBytes []byte,
	scaledExchangeRateCoinsToSellPerCoinToBuy *uint256.Int,
	quantityToFillInBaseUnits *uint256.Int,
	operationType lib.DAOCoinLimitOrderOperationType,
	fillType lib.DAOCoinLimitOrderFillType,
	cancelOrderId *lib.BlockHash,
	minFeeRateNanosPerKB uint64,
	transactionFees []TransactionFee,
) (*DAOCoinLimitOrderResponse, error) {

	transactorPublicKeyBytes, _, err := fes.GetPubKeyAndProfileEntryForUsernameOrPublicKeyBase58Check(
		transactorPublicKeyBase58Check,
		utxoView,
	)
	if err != nil {
		return nil, errors.Errorf("Error getting public key for the transactor: %v", err)
	}

	// Compute the additional transaction fees as specified by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(
		lib.TxnTypeDAOCoinLimitOrder,
		transactorPublicKeyBytes,
		transactionFees,
	)
	if err != nil {
		return nil, fmt.Errorf("specified transactionFees are invalid: %v", err)
	}

	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateDAOCoinLimitOrderTxn(
		transactorPublicKeyBytes,
		&lib.DAOCoinLimitOrderMetadata{
			BuyingDAOCoinCreatorPublicKey:             lib.NewPublicKey(buyingCoinPublicKeyBytes),
			SellingDAOCoinCreatorPublicKey:            lib.NewPublicKey(sellingCoinPublicKeyBytes),
			ScaledExchangeRateCoinsToSellPerCoinToBuy: scaledExchangeRateCoinsToSellPerCoinToBuy,
			QuantityToFillInBaseUnits:                 quantityToFillInBaseUnits,
			OperationType:                             operationType,
			FillType:                                  fillType,
			CancelOrderID:                             cancelOrderId,
		},
		minFeeRateNanosPerKB,
		fes.backendServer.GetMempool(),
		additionalOutputs,
	)

	if err != nil {
		return nil, err
	}

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		return nil, err
	}

	// Return all the data associated with the transaction in the response
	res := DAOCoinLimitOrderResponse{
		SpendAmountNanos:  totalInput - changeAmount - fees,
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
		TxnHashHex:        txn.Hash().String(),
	}

	return &res, nil
}

// getTransactionFee transforms transactionFees specified in an API request body to DeSoOutput and combines that with node-level transaction fees for this transaction type.
func (fes *APIServer) getTransactionFee(txnType lib.TxnType, transactorPublicKey []byte, transactionFees []TransactionFee) (_outputs []*lib.DeSoOutput, _err error) {
	// Transform transaction fees specified by the API request body.
	extraOutputs, err := TransformTransactionFeesToOutputs(transactionFees)
	if err != nil {
		return nil, err
	}
	// Look up node-level fees for this transaction type.
	fees := fes.TransactionFeeMap[txnType]
	// If there are no node fees for this transaction type, don't even bother checking exempt public keys, just return the DeSoOutputs specified by the API request body.
	if len(fees) == 0 {
		return extraOutputs, nil
	}
	// If this node has designated this public key as one exempt from node-level fees, only return the DeSoOutputs requested by the API request body.
	if _, exists := fes.ExemptPublicKeyMap[lib.PkToString(transactorPublicKey, fes.Params)]; exists {
		return extraOutputs, nil
	}
	// Append the fees to the extraOutputs and return.
	newOutputs := append(extraOutputs, fees...)
	return newOutputs, nil
}

type AssociationLimitMapItem struct {
	AssociationClass        lib.AssociationClassString
	AssociationType         string
	AppScopeType            lib.AssociationAppScopeTypeString
	AppPublicKeyBase58Check string
	AssociationOperation    lib.AssociationOperationString
	OpCount                 uint64
}

type AccessGroupLimitMapItem struct {
	AccessGroupOwnerPublicKeyBase58Check string
	ScopeType                            lib.AccessGroupScopeString
	AccessGroupKeyName                   string
	OperationType                        lib.AccessGroupOperationString
	OpCount                              uint64
}

type AccessGroupMemberLimitMapItem struct {
	AccessGroupOwnerPublicKeyBase58Check string
	ScopeType                            lib.AccessGroupScopeString
	AccessGroupKeyName                   string
	OperationType                        lib.AccessGroupMemberOperationString
	OpCount                              uint64
}

type StakeLimitMapItem struct {
	ValidatorPublicKeyBase58Check string
	StakeLimit                    *uint256.Int
}

type UnstakeLimitMapItem struct {
	ValidatorPublicKeyBase58Check string
	UnstakeLimit                  *uint256.Int
}

type UnlockStakeLimitMapItem struct {
	ValidatorPublicKeyBase58Check string
	OpCount                       uint64
}

type LockupLimitMapItem struct {
	ProfilePublicKeyBase58Check string
	ScopeType                   lib.LockupLimitScopeTypeString
	Operation                   lib.LockupLimitOperationString
	OpCount                     uint64
}

// TransactionSpendingLimitResponse is a backend struct used to describe the TransactionSpendingLimit for a Derived key
// in a way that can be JSON encoded/decoded.
type TransactionSpendingLimitResponse struct {
	// GlobalDESOLimit is the total amount of DESO (in nanos) that the DerivedKey can spend
	GlobalDESOLimit uint64
	// TransactionCountLimitMap is a map from transaction type (as a string) to the number of transactions
	// the derived key is authorized to perform.
	TransactionCountLimitMap map[lib.TxnString]uint64
	// CreatorCoinOperationLimitMap is a map with public key base58 check as keys mapped to a map of
	// CreatorCoinLimitOperationString (buy, sell, transfer, any) keys to the number of these operations that the
	// derived key is authorized to perform.
	CreatorCoinOperationLimitMap map[string]map[lib.CreatorCoinLimitOperationString]uint64
	// DAOCoinOperationLimitMap is a map with public key base58 check as keys mapped to a map of
	// DAOCoinLimitOperationString (mint, burn, transfer, disable_minting, update_transfer_restriction status, any)
	// keys to the number of these operations that the derived key is authorized to perform.
	DAOCoinOperationLimitMap map[string]map[lib.DAOCoinLimitOperationString]uint64
	// NFTOperationLimitMap is a map with post hash hex as keys mapped to a map with serial number keys mapped to a map
	// with NFTLimitOperationString (update, nft_bid, accept_nft_bid, transfer, burn, accept_nft_transfer, any) keys to
	// the number of these operations that the derived key is authorized to perform.
	NFTOperationLimitMap map[string]map[uint64]map[lib.NFTLimitOperationString]uint64
	// DAOCoinLimitOrderLimitMap is a map with BuyingCoinPublicKey as keys mapped to a map
	// of SellingCoinPublicKey mapped to the number of DAO Coin Limit Order transactions with
	// this Buying and Selling coin pair that the derived key is authorized to perform.
	DAOCoinLimitOrderLimitMap map[string]map[string]uint64
	// AssociationLimitMap is a slice of AssociationLimitMapItems. Because there are so many attributes to define
	// the key for AssociationLimits, we represent it as a slice instead of a deeply nested map.
	AssociationLimitMap []AssociationLimitMapItem
	// AccessGroupLimitMap is a slice of AccessGroupLimitMapItems.
	AccessGroupLimitMap []AccessGroupLimitMapItem
	// AccessGroupMemberLimitMap is a slice of AccessGroupMemberLimitMapItems.
	AccessGroupMemberLimitMap []AccessGroupMemberLimitMapItem
	// StakeLimitMap is a slice of StakeLimitMapItems
	StakeLimitMap []StakeLimitMapItem
	// UnstakeLimitMap is a slice of UnstakeLimitMapItems
	UnstakeLimitMap []UnstakeLimitMapItem
	// UnlockStakeLimitMap is a slice of UnlockStakeLimitMapItems
	UnlockStakeLimitMap []UnlockStakeLimitMapItem
	// LockupLimitMap is a slice of LockupLimitMapItems
	LockupLimitMap []LockupLimitMapItem

	// ===== ENCODER MIGRATION lib.UnlimitedDerivedKeysMigration =====
	// IsUnlimited determines whether this derived key is unlimited. An unlimited derived key can perform all transactions
	// that the owner can.
	IsUnlimited bool
}

// AuthorizeDerivedKeyRequest ...
type AuthorizeDerivedKeyRequest struct {
	// The original public key of the derived key owner.
	OwnerPublicKeyBase58Check string `safeForLogging:"true"`

	// The derived public key
	DerivedPublicKeyBase58Check string `safeForLogging:"true"`

	// The expiration block of the derived key pair.
	ExpirationBlock uint64 `safeForLogging:"true"`

	// The signature of hash(derived key + expiration block) made by the owner.
	AccessSignature string `safeForLogging:"true"`

	// The intended operation on the derived key.
	DeleteKey bool `safeForLogging:"true"`

	// If we intend to sign this transaction with a derived key.
	DerivedKeySignature bool `safeForLogging:"true"`

	// ExtraData is arbitrary key value map
	ExtraData map[string]string `safeForLogging:"true"`

	// TransactionSpendingLimitHex represents a struct that will be merged with
	// the TransactionSpendingLimitTracker for this Derived key. We require that
	// this be sent as hex in order to guarantee that the AccessHash computed from
	// this value is consistent with what the user is requesting.
	TransactionSpendingLimitHex string `safeForLogging:"true"`

	// Memo is a simple string that can be used to describe a derived key
	Memo string `safeForLogging:"true"`

	AppName string `safeForLogging:"true"`

	// No need to specify ProfileEntryResponse in each TransactionFee
	TransactionFees []TransactionFee `safeForLogging:"true"`

	MinFeeRateNanosPerKB uint64 `safeForLogging:"true"`
}

// AuthorizeDerivedKeyResponse ...
type AuthorizeDerivedKeyResponse struct {
	SpendAmountNanos  uint64
	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgDeSoTxn
	TransactionHex    string
	TxnHashHex        string
}

// AuthorizeDerivedKey ...
func (fes *APIServer) AuthorizeDerivedKey(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AuthorizeDerivedKeyRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AuthorizeDerivedKey: Problem parsing request body: %v", err))
		return
	}

	if requestData.OwnerPublicKeyBase58Check == "" ||
		requestData.DerivedPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprintf("AuthorizeDerivedKey: Must provide an owner and a derived key."))
		return
	}

	// Decode the owner public key
	ownerPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.OwnerPublicKeyBase58Check)
	if err != nil || len(ownerPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AuthorizeDerivedKey: Problem decoding owner public key %s: %v",
			requestData.OwnerPublicKeyBase58Check, err))
		return
	}

	// Decode the derived public key
	derivedPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.DerivedPublicKeyBase58Check)
	if err != nil || len(derivedPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AuthorizeDerivedKey: Problem decoding derived public key %s: %v",
			requestData.DerivedPublicKeyBase58Check, err))
		return
	}

	// Compute the additional transaction fees as specified by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(lib.TxnTypeAuthorizeDerivedKey, ownerPublicKeyBytes, requestData.TransactionFees)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AuthorizeDerivedKey: TransactionFees specified in Request body are invalid: %v", err))
		return
	}

	// Make sure owner and derived keys are different
	if reflect.DeepEqual(ownerPublicKeyBytes, derivedPublicKeyBytes) {
		_AddBadRequestError(ww, fmt.Sprintf("AuthorizeDerivedKey: Owner and derived public keys cannot be the same."))
		return
	}

	// Decode the access signature
	accessSignature, err := hex.DecodeString(requestData.AccessSignature)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AuthorizeDerivedKey: Couldn't decode access signature."))
		return
	}
	var memo []byte
	blockHeight := fes.blockchain.BlockTip().Height + 1
	// Only add the TransactionSpendingLimit and Memo if we're passed the block height.
	if blockHeight >= fes.Params.ForkHeights.DerivedKeySetSpendingLimitsBlockHeight {
		var memoStr string
		if len(requestData.Memo) != 0 {
			memoStr = requestData.Memo
		} else if len(requestData.AppName) != 0 {
			memoStr = requestData.AppName
		}
		if len(memoStr) != 0 {
			memo = make([]byte, hex.EncodedLen(len([]byte(memoStr))))
			hex.Encode(memo, []byte(memoStr))
		}
	}

	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AuthorizeDerivedKey: Problem decoding ExtraData: %v", err))
		return
	}

	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateAuthorizeDerivedKeyTxn(
		ownerPublicKeyBytes,
		derivedPublicKeyBytes,
		requestData.ExpirationBlock,
		accessSignature,
		requestData.DeleteKey,
		requestData.DerivedKeySignature,
		extraData,
		memo,
		requestData.TransactionSpendingLimitHex,
		// Standard transaction fields
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool(), additionalOutputs)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AuthorizeDerivedKey: Problem creating transaction: %v", err))
		return
	}

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AuthorizeDerivedKey: Problem serializing transaction: %v", err))
		return
	}

	// Return all the data associated with the transaction in the response
	res := AuthorizeDerivedKeyResponse{
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
		TxnHashHex:        txn.Hash().String(),
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AuthorizeDerivedKey: Problem encoding response as JSON: %v", err))
		return
	}
}

const DAOCoinLimitOrderDESOPublicKey = "DESO"

// TransactionSpendingLimitToResponse converts the core struct lib.TransactionSpendingLimit to a
// TransactionSpendingLimitResponse
func TransactionSpendingLimitToResponse(
	transactionSpendingLimit *lib.TransactionSpendingLimit, utxoView *lib.UtxoView, params *lib.DeSoParams,
) *TransactionSpendingLimitResponse {

	// If the transactionSpendingLimit is nil, return nil.
	if transactionSpendingLimit == nil {
		return nil
	}

	// Copy the GlobalDESOLimit and IsUnlimited fields.
	transactionSpendingLimitResponse := &TransactionSpendingLimitResponse{
		GlobalDESOLimit: transactionSpendingLimit.GlobalDESOLimit,
		IsUnlimited:     transactionSpendingLimit.IsUnlimited,
	}

	// Iterate over the TransactionCountLimit map - convert TxnType to TxnString and set as key with count as value
	if len(transactionSpendingLimit.TransactionCountLimitMap) > 0 {
		transactionSpendingLimitResponse.TransactionCountLimitMap = make(map[lib.TxnString]uint64)
		for txnType, txnCount := range transactionSpendingLimit.TransactionCountLimitMap {
			transactionSpendingLimitResponse.TransactionCountLimitMap[txnType.GetTxnString()] = txnCount
		}
	}

	// Iterate over the CreatorCoinOperationLimitMap - convert PKID from key into base58Check public key, convert
	// CreatorCoinLimitOperation to CreatorCoinLimitOperationString. Fill in the nested maps appropriately.
	if len(transactionSpendingLimit.CreatorCoinOperationLimitMap) > 0 {
		transactionSpendingLimitResponse.CreatorCoinOperationLimitMap = make(
			map[string]map[lib.CreatorCoinLimitOperationString]uint64)
		for ccLimitKey, opCount := range transactionSpendingLimit.CreatorCoinOperationLimitMap {
			var creatorPublicKeyBase58Check string
			if !ccLimitKey.CreatorPKID.IsZeroPKID() {
				creatorPublicKeyBase58Check = lib.PkToString(
					utxoView.GetPublicKeyForPKID(&ccLimitKey.CreatorPKID), params)
			}
			// If the key doesn't exist in the map yet, put key with empty map.
			if _, exists := transactionSpendingLimitResponse.CreatorCoinOperationLimitMap[creatorPublicKeyBase58Check]; !exists {
				transactionSpendingLimitResponse.CreatorCoinOperationLimitMap[creatorPublicKeyBase58Check] =
					make(map[lib.CreatorCoinLimitOperationString]uint64)
			}
			transactionSpendingLimitResponse.CreatorCoinOperationLimitMap[creatorPublicKeyBase58Check][ccLimitKey.Operation.ToCreatorCoinLimitOperationString()] = opCount
		}
	}

	// Iterate over the DAOCoinOperationLimitMap - convert PKID from key into base58Check public key, convert
	// DAOCoinLimitOperation to DAOCoinLimitOperationString. Fill in the nested maps appropriately.
	if len(transactionSpendingLimit.DAOCoinOperationLimitMap) > 0 {
		transactionSpendingLimitResponse.DAOCoinOperationLimitMap = make(
			map[string]map[lib.DAOCoinLimitOperationString]uint64)
		for daoLimitKey, opCount := range transactionSpendingLimit.DAOCoinOperationLimitMap {
			var creatorPublicKeyBase58Check string
			if !daoLimitKey.CreatorPKID.IsZeroPKID() {
				creatorPublicKeyBase58Check = lib.PkToString(
					utxoView.GetPublicKeyForPKID(&daoLimitKey.CreatorPKID), params)
			}
			// If the key doesn't exist in the map yet, put key with empty map.
			if _, exists := transactionSpendingLimitResponse.DAOCoinOperationLimitMap[creatorPublicKeyBase58Check]; !exists {
				transactionSpendingLimitResponse.DAOCoinOperationLimitMap[creatorPublicKeyBase58Check] =
					make(map[lib.DAOCoinLimitOperationString]uint64)
			}
			transactionSpendingLimitResponse.DAOCoinOperationLimitMap[creatorPublicKeyBase58Check][daoLimitKey.Operation.ToDAOCoinLimitOperationString()] = opCount
		}
	}

	// Iterate over the NFTOperationLimitMap - convert BlockHash from key into PostHashHex, convert
	// NFTLimitOperation to NFTLimitOperationString. Fill in the nested maps appropriately.
	if len(transactionSpendingLimit.NFTOperationLimitMap) > 0 {
		transactionSpendingLimitResponse.NFTOperationLimitMap = make(
			map[string]map[uint64]map[lib.NFTLimitOperationString]uint64)
		for nftLimitKey, opCount := range transactionSpendingLimit.NFTOperationLimitMap {
			var postHashHex string
			if !reflect.DeepEqual(nftLimitKey.BlockHash, lib.ZeroBlockHash) {
				postHashHex = hex.EncodeToString(nftLimitKey.BlockHash[:])
			}
			// If the key doesn't exist in the map yet, put key with empty map.
			if _, exists := transactionSpendingLimitResponse.NFTOperationLimitMap[postHashHex]; !exists {
				transactionSpendingLimitResponse.NFTOperationLimitMap[postHashHex] =
					make(map[uint64]map[lib.NFTLimitOperationString]uint64)
			}
			serialNum := nftLimitKey.SerialNumber
			// If serial number map doesn't exist in the map yet, put key with empty map.
			if _, exists := transactionSpendingLimitResponse.NFTOperationLimitMap[postHashHex][serialNum]; !exists {
				transactionSpendingLimitResponse.NFTOperationLimitMap[postHashHex][serialNum] =
					make(map[lib.NFTLimitOperationString]uint64)
			}

			transactionSpendingLimitResponse.NFTOperationLimitMap[postHashHex][serialNum][nftLimitKey.Operation.ToNFTLimitOperationString()] = opCount
		}
	}

	// Iterate over the DAOCoinLimitOrderLimitMap - convert PKID from key into base58Check public key.
	// Fill in the nested maps appropriately.
	if len(transactionSpendingLimit.DAOCoinLimitOrderLimitMap) > 0 {
		transactionSpendingLimitResponse.DAOCoinLimitOrderLimitMap = make(
			map[string]map[string]uint64)
		for daoCoinLimitOrderLimitKey, opCount := range transactionSpendingLimit.DAOCoinLimitOrderLimitMap {
			buyingPublicKey := DAOCoinLimitOrderDESOPublicKey
			if !daoCoinLimitOrderLimitKey.BuyingDAOCoinCreatorPKID.IsZeroPKID() {
				buyingPkBytes := utxoView.GetPublicKeyForPKID(&daoCoinLimitOrderLimitKey.BuyingDAOCoinCreatorPKID)
				buyingPublicKey = lib.PkToString(buyingPkBytes, params)
			}
			sellingPublicKey := DAOCoinLimitOrderDESOPublicKey
			if !daoCoinLimitOrderLimitKey.SellingDAOCoinCreatorPKID.IsZeroPKID() {
				sellingPkBytes := utxoView.GetPublicKeyForPKID(&daoCoinLimitOrderLimitKey.SellingDAOCoinCreatorPKID)
				sellingPublicKey = lib.PkToString(sellingPkBytes, params)
			}
			if _, exists := transactionSpendingLimitResponse.DAOCoinLimitOrderLimitMap[buyingPublicKey]; !exists {
				transactionSpendingLimitResponse.DAOCoinLimitOrderLimitMap[buyingPublicKey] = make(map[string]uint64)
			}
			transactionSpendingLimitResponse.DAOCoinLimitOrderLimitMap[buyingPublicKey][sellingPublicKey] = opCount
		}
	}

	// Iterate over the AssociationLimitMap - convert association limit key and op count to AssociationLimitMapItem
	// structs.
	if len(transactionSpendingLimit.AssociationLimitMap) > 0 {
		for associationLimitKey, opCount := range transactionSpendingLimit.AssociationLimitMap {
			associationClassString := associationLimitKey.AssociationClass.ToAssociationClassString()
			associationType := associationLimitKey.AssociationType
			associationAppScopeTypeString := associationLimitKey.AppScopeType.ToAssociationAppScopeTypeString()
			associationOperationString := associationLimitKey.Operation.ToAssociationOperationString()
			var appPublicKey string
			if !associationLimitKey.AppPKID.IsZeroPKID() {
				appPkBytes := utxoView.GetPublicKeyForPKID(&associationLimitKey.AppPKID)
				appPublicKey = lib.PkToString(appPkBytes, params)
			}
			transactionSpendingLimitResponse.AssociationLimitMap = append(transactionSpendingLimitResponse.AssociationLimitMap,
				AssociationLimitMapItem{
					AssociationClass:        associationClassString,
					AssociationType:         associationType,
					AppScopeType:            associationAppScopeTypeString,
					AppPublicKeyBase58Check: appPublicKey,
					AssociationOperation:    associationOperationString,
					OpCount:                 opCount,
				})
		}
	}

	// Iterate over the AccessGroupLimitMap.
	if len(transactionSpendingLimit.AccessGroupMap) > 0 {
		for accessGroupLimitKey, opCount := range transactionSpendingLimit.AccessGroupMap {
			accessGroupOwnerPublicKeyBase58Check := lib.Base58CheckEncode(
				accessGroupLimitKey.AccessGroupOwnerPublicKey.ToBytes(), false, params,
			)
			transactionSpendingLimitResponse.AccessGroupLimitMap = append(
				transactionSpendingLimitResponse.AccessGroupLimitMap,
				AccessGroupLimitMapItem{
					AccessGroupOwnerPublicKeyBase58Check: accessGroupOwnerPublicKeyBase58Check,
					ScopeType:                            accessGroupLimitKey.AccessGroupScopeType.ToAccessGroupScopeString(),
					AccessGroupKeyName:                   string(lib.AccessKeyNameDecode(&accessGroupLimitKey.AccessGroupKeyName)),
					OperationType:                        accessGroupLimitKey.OperationType.ToAccessGroupOperationString(),
					OpCount:                              opCount,
				},
			)
		}
	}

	// Iterate over the AccessGroupMemberLimitMap.
	if len(transactionSpendingLimit.AccessGroupMemberMap) > 0 {
		for accessGroupMemberLimitKey, opCount := range transactionSpendingLimit.AccessGroupMemberMap {
			accessGroupOwnerPublicKeyBase58Check := lib.Base58CheckEncode(
				accessGroupMemberLimitKey.AccessGroupOwnerPublicKey.ToBytes(), false, params,
			)
			transactionSpendingLimitResponse.AccessGroupMemberLimitMap = append(
				transactionSpendingLimitResponse.AccessGroupMemberLimitMap,
				AccessGroupMemberLimitMapItem{
					AccessGroupOwnerPublicKeyBase58Check: accessGroupOwnerPublicKeyBase58Check,
					ScopeType:                            accessGroupMemberLimitKey.AccessGroupScopeType.ToAccessGroupScopeString(),
					AccessGroupKeyName:                   string(lib.AccessKeyNameDecode(&accessGroupMemberLimitKey.AccessGroupKeyName)),
					OperationType:                        accessGroupMemberLimitKey.OperationType.ToAccessGroupMemberOperationString(),
					OpCount:                              opCount,
				},
			)
		}
	}

	if len(transactionSpendingLimit.StakeLimitMap) > 0 {
		for stakeLimitKey, stakeLimit := range transactionSpendingLimit.StakeLimitMap {
			var validatorPublicKeyBase58Check string
			if !stakeLimitKey.ValidatorPKID.IsZeroPKID() {
				validatorPublicKey := utxoView.GetPublicKeyForPKID(&stakeLimitKey.ValidatorPKID)
				validatorPublicKeyBase58Check = lib.Base58CheckEncode(
					validatorPublicKey, false, params,
				)
			}
			transactionSpendingLimitResponse.StakeLimitMap = append(
				transactionSpendingLimitResponse.StakeLimitMap,
				StakeLimitMapItem{
					ValidatorPublicKeyBase58Check: validatorPublicKeyBase58Check,
					StakeLimit:                    stakeLimit.Clone(),
				},
			)
		}
	}

	if len(transactionSpendingLimit.UnstakeLimitMap) > 0 {
		for unstakeLimitKey, unstakeLimit := range transactionSpendingLimit.UnstakeLimitMap {
			var validatorPublicKeyBase58Check string
			if !unstakeLimitKey.ValidatorPKID.IsZeroPKID() {
				validatorPublicKey := utxoView.GetPublicKeyForPKID(&unstakeLimitKey.ValidatorPKID)
				validatorPublicKeyBase58Check = lib.Base58CheckEncode(
					validatorPublicKey, false, params,
				)
			}
			transactionSpendingLimitResponse.UnstakeLimitMap = append(
				transactionSpendingLimitResponse.UnstakeLimitMap,
				UnstakeLimitMapItem{
					ValidatorPublicKeyBase58Check: validatorPublicKeyBase58Check,
					UnstakeLimit:                  unstakeLimit.Clone(),
				},
			)
		}
	}

	if len(transactionSpendingLimit.UnlockStakeLimitMap) > 0 {
		for unlockStakeLimitKey, opCount := range transactionSpendingLimit.UnlockStakeLimitMap {
			var validatorPublicKeyBase58Check string
			if !unlockStakeLimitKey.ValidatorPKID.IsZeroPKID() {
				validatorPublicKey := utxoView.GetPublicKeyForPKID(&unlockStakeLimitKey.ValidatorPKID)
				validatorPublicKeyBase58Check = lib.Base58CheckEncode(
					validatorPublicKey, false, params,
				)
			}
			transactionSpendingLimitResponse.UnlockStakeLimitMap = append(
				transactionSpendingLimitResponse.UnlockStakeLimitMap,
				UnlockStakeLimitMapItem{
					ValidatorPublicKeyBase58Check: validatorPublicKeyBase58Check,
					OpCount:                       opCount,
				},
			)
		}
	}

	if len(transactionSpendingLimit.LockupLimitMap) > 0 {
		for lockupLimitKey, opCount := range transactionSpendingLimit.LockupLimitMap {
			var publicKeyBase58Check string
			if !lockupLimitKey.ProfilePKID.IsZeroPKID() {
				publicKeyBytes := utxoView.GetPublicKeyForPKID(&lockupLimitKey.ProfilePKID)
				publicKeyBase58Check = lib.Base58CheckEncode(publicKeyBytes, false, params)
			}
			transactionSpendingLimitResponse.LockupLimitMap = append(
				transactionSpendingLimitResponse.LockupLimitMap,
				LockupLimitMapItem{
					ProfilePublicKeyBase58Check: publicKeyBase58Check,
					ScopeType:                   lockupLimitKey.ScopeType.ToScopeString(),
					Operation:                   lockupLimitKey.Operation.ToOperationString(),
					OpCount:                     opCount,
				})
		}
	}

	return transactionSpendingLimitResponse
}

func (fes *APIServer) TransactionSpendingLimitFromResponse(
	transactionSpendingLimitResponse TransactionSpendingLimitResponse) (*lib.TransactionSpendingLimit, error) {
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return nil, fmt.Errorf("TransactionSpendingLimitFromResponse: error getting utxoview: %v", err)
	}
	transactionSpendingLimit := &lib.TransactionSpendingLimit{
		GlobalDESOLimit: transactionSpendingLimitResponse.GlobalDESOLimit,
		IsUnlimited:     transactionSpendingLimitResponse.IsUnlimited,
	}

	if len(transactionSpendingLimitResponse.TransactionCountLimitMap) > 0 {
		transactionSpendingLimit.TransactionCountLimitMap = make(map[lib.TxnType]uint64)
		for txnType, value := range transactionSpendingLimitResponse.TransactionCountLimitMap {
			transactionSpendingLimit.TransactionCountLimitMap[lib.GetTxnTypeFromString(txnType)] = value
		}
	}

	getCreatorPKIDForBase58Check := func(pubKeyBase58Check string) (*lib.PKID, error) {
		creatorPKID := &lib.ZeroPKID
		if pubKeyBase58Check != "" {
			var pkBytes []byte
			pkBytes, _, err = lib.Base58CheckDecode(pubKeyBase58Check)
			if err != nil {
				return nil, err
			}
			pkid := utxoView.GetPKIDForPublicKey(pkBytes)
			if pkid == nil || pkid.PKID == nil {
				return nil, fmt.Errorf("No PKID found for public key %v", pubKeyBase58Check)
			}
			creatorPKID = pkid.PKID
		}
		return creatorPKID, nil
	}

	if len(transactionSpendingLimitResponse.CreatorCoinOperationLimitMap) > 0 {
		transactionSpendingLimit.CreatorCoinOperationLimitMap = make(map[lib.CreatorCoinOperationLimitKey]uint64)
		for pubKey, operationToCountMap := range transactionSpendingLimitResponse.CreatorCoinOperationLimitMap {
			creatorPKID, err := getCreatorPKIDForBase58Check(pubKey)
			if err != nil {
				return nil, fmt.Errorf("Error getting PKID for pub key %v", pubKey)
			}
			for operation, count := range operationToCountMap {
				transactionSpendingLimit.CreatorCoinOperationLimitMap[lib.MakeCreatorCoinOperationLimitKey(
					*creatorPKID, operation.ToCreatorCoinLimitOperation())] = count
			}
		}
	}

	if len(transactionSpendingLimitResponse.DAOCoinOperationLimitMap) > 0 {
		transactionSpendingLimit.DAOCoinOperationLimitMap = make(map[lib.DAOCoinOperationLimitKey]uint64)
		for pubKey, operationToCountMap := range transactionSpendingLimitResponse.DAOCoinOperationLimitMap {
			creatorPKID, err := getCreatorPKIDForBase58Check(pubKey)
			if err != nil {
				return nil, fmt.Errorf("Error getting PKID for pub key %v", pubKey)
			}
			for operation, count := range operationToCountMap {
				transactionSpendingLimit.DAOCoinOperationLimitMap[lib.MakeDAOCoinOperationLimitKey(
					*creatorPKID, operation.ToDAOCoinLimitOperation())] = count
			}
		}
	}

	if len(transactionSpendingLimitResponse.NFTOperationLimitMap) > 0 {
		transactionSpendingLimit.NFTOperationLimitMap = make(map[lib.NFTOperationLimitKey]uint64)
		for postHashHex, serialNumToOperationToCountMap := range transactionSpendingLimitResponse.NFTOperationLimitMap {
			postHash := &lib.ZeroBlockHash
			if postHashHex != "" {
				postHash, err = GetPostHashFromPostHashHex(postHashHex)
				if err != nil {
					return nil, err
				}
			}
			for serialNum, operationToCountMap := range serialNumToOperationToCountMap {
				for operation, count := range operationToCountMap {
					transactionSpendingLimit.NFTOperationLimitMap[lib.MakeNFTOperationLimitKey(
						*postHash, serialNum, operation.ToNFTLimitOperation())] = count
				}
			}
		}
	}

	if len(transactionSpendingLimitResponse.DAOCoinLimitOrderLimitMap) > 0 {
		transactionSpendingLimit.DAOCoinLimitOrderLimitMap = make(map[lib.DAOCoinLimitOrderLimitKey]uint64)
		for buyingPublicKey, sellingPublicKeyToCountMap := range transactionSpendingLimitResponse.DAOCoinLimitOrderLimitMap {
			buyingPKID := &lib.ZeroPKID
			if buyingPublicKey != DAOCoinLimitOrderDESOPublicKey {
				buyingPKID, err = getCreatorPKIDForBase58Check(buyingPublicKey)
				if err != nil {
					return nil, err
				}
			}
			for sellingPublicKey, count := range sellingPublicKeyToCountMap {
				sellingPKID := &lib.ZeroPKID
				if sellingPublicKey != DAOCoinLimitOrderDESOPublicKey {
					sellingPKID, err = getCreatorPKIDForBase58Check(sellingPublicKey)
					if err != nil {
						return nil, err
					}
				}
				transactionSpendingLimit.DAOCoinLimitOrderLimitMap[lib.MakeDAOCoinLimitOrderLimitKey(
					*buyingPKID, *sellingPKID)] = count
			}
		}
	}

	if len(transactionSpendingLimitResponse.AssociationLimitMap) > 0 {
		transactionSpendingLimit.AssociationLimitMap = make(map[lib.AssociationLimitKey]uint64)
		for _, associationLimitMapItem := range transactionSpendingLimitResponse.AssociationLimitMap {
			appPKID := &lib.ZeroPKID
			if associationLimitMapItem.AppPublicKeyBase58Check != "" {
				appPKID, err = getCreatorPKIDForBase58Check(associationLimitMapItem.AppPublicKeyBase58Check)
				if err != nil {
					return nil, err
				}
			}
			transactionSpendingLimit.AssociationLimitMap[lib.MakeAssociationLimitKey(
				associationLimitMapItem.AssociationClass.ToAssociationClass(),
				[]byte(associationLimitMapItem.AssociationType),
				*appPKID,
				associationLimitMapItem.AppScopeType.ToAssociationAppScopeType(),
				associationLimitMapItem.AssociationOperation.ToAssociationOperation(),
			)] = associationLimitMapItem.OpCount
		}
	}

	if len(transactionSpendingLimitResponse.AccessGroupLimitMap) > 0 {
		transactionSpendingLimit.AccessGroupMap = make(map[lib.AccessGroupLimitKey]uint64)
		for _, accessGroupLimitMapItem := range transactionSpendingLimitResponse.AccessGroupLimitMap {
			accessGroupOwnerPublicKey, _, err := lib.Base58CheckDecode(accessGroupLimitMapItem.AccessGroupOwnerPublicKeyBase58Check)
			if err != nil {
				return nil, err
			}
			accessGroupLimitKey := lib.MakeAccessGroupLimitKey(
				*lib.NewPublicKey(accessGroupOwnerPublicKey),
				accessGroupLimitMapItem.ScopeType.ToAccessGroupScopeType(),
				*lib.NewGroupKeyName([]byte(accessGroupLimitMapItem.AccessGroupKeyName)),
				accessGroupLimitMapItem.OperationType.ToAccessGroupOperationType(),
			)
			transactionSpendingLimit.AccessGroupMap[accessGroupLimitKey] = accessGroupLimitMapItem.OpCount
		}
	}

	if len(transactionSpendingLimitResponse.AccessGroupMemberLimitMap) > 0 {
		transactionSpendingLimit.AccessGroupMemberMap = make(map[lib.AccessGroupMemberLimitKey]uint64)
		for _, accessGroupMemberLimitMapItem := range transactionSpendingLimitResponse.AccessGroupMemberLimitMap {
			accessGroupOwnerPublicKey, _, err := lib.Base58CheckDecode(accessGroupMemberLimitMapItem.AccessGroupOwnerPublicKeyBase58Check)
			if err != nil {
				return nil, err
			}
			accessGroupMemberLimitKey := lib.MakeAccessGroupMemberLimitKey(
				*lib.NewPublicKey(accessGroupOwnerPublicKey),
				accessGroupMemberLimitMapItem.ScopeType.ToAccessGroupScopeType(),
				*lib.NewGroupKeyName([]byte(accessGroupMemberLimitMapItem.AccessGroupKeyName)),
				accessGroupMemberLimitMapItem.OperationType.ToAccessGroupMemberOperation(),
			)
			transactionSpendingLimit.AccessGroupMemberMap[accessGroupMemberLimitKey] = accessGroupMemberLimitMapItem.OpCount
		}
	}

	if len(transactionSpendingLimitResponse.StakeLimitMap) > 0 {
		transactionSpendingLimit.StakeLimitMap = make(map[lib.StakeLimitKey]*uint256.Int)
		for _, stakeLimitMapItem := range transactionSpendingLimitResponse.StakeLimitMap {
			validatorPKID := &lib.ZeroPKID
			if stakeLimitMapItem.ValidatorPublicKeyBase58Check != "" {
				validatorPKID, err = getCreatorPKIDForBase58Check(stakeLimitMapItem.ValidatorPublicKeyBase58Check)
				if err != nil {
					return nil, err
				}
			}
			stakeLimitKey := lib.MakeStakeLimitKey(validatorPKID)
			transactionSpendingLimit.StakeLimitMap[stakeLimitKey] = stakeLimitMapItem.StakeLimit.Clone()
		}
	}

	if len(transactionSpendingLimitResponse.UnstakeLimitMap) > 0 {
		transactionSpendingLimit.UnstakeLimitMap = make(map[lib.StakeLimitKey]*uint256.Int)
		for _, unstakeLimitMapItem := range transactionSpendingLimitResponse.UnstakeLimitMap {
			validatorPKID := &lib.ZeroPKID
			if unstakeLimitMapItem.ValidatorPublicKeyBase58Check != "" {
				validatorPKID, err = getCreatorPKIDForBase58Check(unstakeLimitMapItem.ValidatorPublicKeyBase58Check)
				if err != nil {
					return nil, err
				}
			}
			unstakeLimitKey := lib.MakeStakeLimitKey(validatorPKID)
			transactionSpendingLimit.UnstakeLimitMap[unstakeLimitKey] = unstakeLimitMapItem.UnstakeLimit.Clone()
		}
	}

	if len(transactionSpendingLimitResponse.UnlockStakeLimitMap) > 0 {
		transactionSpendingLimit.UnlockStakeLimitMap = make(map[lib.StakeLimitKey]uint64)
		for _, unlockStakeLimitMapItem := range transactionSpendingLimitResponse.UnlockStakeLimitMap {
			validatorPKID := &lib.ZeroPKID
			if unlockStakeLimitMapItem.ValidatorPublicKeyBase58Check != "" {
				validatorPKID, err = getCreatorPKIDForBase58Check(unlockStakeLimitMapItem.ValidatorPublicKeyBase58Check)
				if err != nil {
					return nil, err
				}
			}
			unlockStakeLimitKey := lib.MakeStakeLimitKey(validatorPKID)
			transactionSpendingLimit.UnlockStakeLimitMap[unlockStakeLimitKey] = unlockStakeLimitMapItem.OpCount
		}
	}
	if len(transactionSpendingLimitResponse.LockupLimitMap) > 0 {
		transactionSpendingLimit.LockupLimitMap = make(map[lib.LockupLimitKey]uint64)
		for _, lockupLimitMapItem := range transactionSpendingLimitResponse.LockupLimitMap {
			profilePKID := &lib.ZeroPKID
			if lockupLimitMapItem.ProfilePublicKeyBase58Check != "" {
				profilePKID, err = getCreatorPKIDForBase58Check(lockupLimitMapItem.ProfilePublicKeyBase58Check)
				if err != nil {
					return nil, err
				}
			}
			transactionSpendingLimit.LockupLimitMap[lib.MakeLockupLimitKey(
				*profilePKID,
				lockupLimitMapItem.ScopeType.ToScopeType(),
				lockupLimitMapItem.Operation.ToOperationType(),
			)] = lockupLimitMapItem.OpCount
		}
	}

	return transactionSpendingLimit, nil
}

// AppendExtraDataRequest ...
type AppendExtraDataRequest struct {
	// Transaction hex.
	TransactionHex string `safeForLogging:"true"`

	// ExtraData object.
	ExtraData map[string]string `safeForLogging:"true"`
}

// AppendExtraDataResponse ...
type AppendExtraDataResponse struct {
	// Final Transaction hex.
	TransactionHex string `safeForLogging:"true"`
}

// AppendExtraData ...
// This endpoint allows setting custom ExtraData for a given transaction hex.
func (fes *APIServer) AppendExtraData(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AppendExtraDataRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AppendExtraData: Problem parsing request body: %v", err))
		return
	}

	// Get the transaction bytes from the request data.
	txnBytes, err := hex.DecodeString(requestData.TransactionHex)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AppendExtraData: Problem decoding transaction hex %v", err))
		return
	}

	// Deserialize transaction from transaction bytes.
	txn := &lib.MsgDeSoTxn{}
	err = txn.FromBytes(txnBytes)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AppendExtraData: Problem deserializing transaction from bytes: %v", err))
		return
	}

	if txn.ExtraData == nil {
		txn.ExtraData = make(map[string][]byte)
	}

	// Append ExtraData entries
	encodedExtraDataToAppend, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AppendExtraData: Problem encoding ExtraData: %v", err))
		return
	}
	for k, vBytes := range encodedExtraDataToAppend {
		txn.ExtraData[k] = vBytes
	}

	// Get the final transaction bytes.
	txnBytesFinal, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AppendExtraData: Problem serializing transaction: %v", err))
		return
	}

	// Return the final transaction bytes.
	res := AppendExtraDataResponse{
		TransactionHex: hex.EncodeToString(txnBytesFinal),
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AppendExtraData: Problem encoding response as JSON: %v", err))
		return
	}
}

// GetTransactionSpendingRequest ...
type GetTransactionSpendingRequest struct {
	// Transaction hex.
	TransactionHex string `safeForLogging:"true"`
}

// GetTransactionSpendingResponse ...
type GetTransactionSpendingResponse struct {
	// Total transaction spending in nanos.
	TotalSpendingNanos uint64 `safeForLogging:"true"`
}

// GetTransactionSpending ...
// This endpoint allows you to calculate transaction total spending
// by subtracting transaction output to sender from transaction inputs.
// Note, this endpoint doesn't check if transaction is valid.
func (fes *APIServer) GetTransactionSpending(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetTransactionSpendingRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetTransactionSpending: Problem parsing request body: %v", err))
		return
	}

	// Get the transaction bytes from the request data.
	txnBytes, err := hex.DecodeString(requestData.TransactionHex)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetTransactionSpending: Problem decoding transaction hex %v", err))
		return
	}

	// Deserialize transaction from transaction bytes.
	txn := &lib.MsgDeSoTxn{}
	err = txn.FromBytes(txnBytes)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetTransactionSpending: Problem deserializing transaction from bytes: %v", err))
		return
	}

	// Get augmented universal view from mempool.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetTransactionSpending: Problem getting AugmentedUniversalView: %v", err))
		return
	}

	if txn.TxnFeeNanos != 0 {
		var utxoOperations []*lib.UtxoOperation
		utxoOperations, _, _, _, err = fes.simulateSubmitTransaction(utxoView, txn)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetTransactionSpending: error simulating txn: %v", err))
			return
		}
		var spendBalanceAmount, addBalanceAmount uint64
		for _, utxoOperation := range utxoOperations {
			if utxoOperation.Type == lib.OperationTypeSpendBalance && bytes.Equal(utxoOperation.BalancePublicKey, txn.PublicKey) {
				spendBalanceAmount, err = lib.SafeUint64().Add(spendBalanceAmount, utxoOperation.BalanceAmountNanos)
				if err != nil {
					_AddBadRequestError(ww, fmt.Sprintf("GetTransactionSpending: error summing spend balance amount: %v", err))
				}
			}
			if utxoOperation.Type == lib.OperationTypeAddBalance && bytes.Equal(utxoOperation.BalancePublicKey, txn.PublicKey) {
				addBalanceAmount, err = lib.SafeUint64().Add(addBalanceAmount, utxoOperation.BalanceAmountNanos)
				if err != nil {
					_AddBadRequestError(ww, fmt.Sprintf("GetTransactionSpending: error summing add balance amount: %v", err))
				}
			}
		}
		var totalSpendingNanos uint64
		if spendBalanceAmount > addBalanceAmount {
			totalSpendingNanos = spendBalanceAmount - addBalanceAmount
		}

		// Return the final transaction spending.
		res := GetTransactionSpendingResponse{
			TotalSpendingNanos: totalSpendingNanos,
		}
		if err = json.NewEncoder(ww).Encode(res); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetTransactionSpending: Problem encoding response as JSON: %v", err))
		}
		return
	}

	// If transaction has no inputs we can return immediately.
	if len(txn.TxInputs) == 0 {
		// Return the final transaction spending.
		res := GetTransactionSpendingResponse{
			TotalSpendingNanos: 0,
		}
		if err = json.NewEncoder(ww).Encode(res); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetTransactionSpending: Problem encoding response as JSON: %v", err))
		}
		return
	}

	// Create an array of utxoEntries from transaction inputs' utxoKeys.
	totalInputNanos := uint64(0)
	for _, txInput := range txn.TxInputs {
		utxoEntry := utxoView.GetUtxoEntryForUtxoKey((*lib.UtxoKey)(txInput))
		if utxoEntry == nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetTransactionSpending: Already spent utxo or invalid txn input: %v", txInput))
			return
		}
		totalInputNanos += utxoEntry.AmountNanos
	}

	// Get nanos sent back to the sender from outputs.
	changeAmountNanos := uint64(0)
	for _, txOutput := range txn.TxOutputs {
		if reflect.DeepEqual(txOutput.PublicKey, txn.PublicKey) {
			changeAmountNanos += txOutput.AmountNanos
		}
	}

	// Sanity check if output doesn't exceed inputs.
	if changeAmountNanos > totalInputNanos {
		_AddBadRequestError(ww, fmt.Sprintf("GetTransactionSpending: Output to sender exceeds inputs: (%v, %v)", changeAmountNanos, totalInputNanos))
		return
	}

	// Return the final transaction spending.
	totalSpendingNanos := totalInputNanos - changeAmountNanos
	res := GetTransactionSpendingResponse{
		TotalSpendingNanos: totalSpendingNanos,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetTransactionSpending: Problem encoding response as JSON: %v", err))
	}
	return
}

func (fes *APIServer) simulateSubmitTransaction(utxoView *lib.UtxoView, txn *lib.MsgDeSoTxn) (_utxoOperations []*lib.UtxoOperation, _totalInput uint64, _totalOutput uint64, _fees uint64, _err error) {
	bestHeight := fes.blockchain.BlockTip().Height + 1
	return utxoView.ConnectTransaction(
		txn,
		txn.Hash(),
		bestHeight,
		time.Now().UnixNano(),
		false,
		false,
	)
}

type GetSignatureIndexRequest struct {
	TransactionHex string
}

type GetSignatureIndexResponse struct {
	SignatureIndex int
}

func (fes *APIServer) GetSignatureIndex(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetSignatureIndexRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetSignatureIndex: Problem parsing request body: %v", err))
		return
	}
	transactionHex := requestData.TransactionHex
	txnBytes, err := hex.DecodeString(transactionHex)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetSignatureIndex: unable to decode transaction hex %v: %v", transactionHex, err))
		return
	}

	rr := bytes.NewReader(txnBytes)
	txn := &lib.MsgDeSoTxn{}
	if err = lib.ReadTransactionV0Fields(rr, txn); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetSignatureIndex: unable to read v0 fields of transaction hex %v: %v", transactionHex, err))
		return
	}

	res := &GetSignatureIndexResponse{
		SignatureIndex: len(txnBytes) - rr.Len() - 1,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetSignatureIndex: Problem encoding response as JSON: %v", err))
	}
	return
}

type GetTxnConstructionParamsRequest struct {
	MinFeeRateNanosPerKB uint64
}

type GetTxnConstructionParamsResponse struct {
	FeeRateNanosPerKB uint64
	BlockHeight       uint64
}

func (fes *APIServer) GetTxnConstructionParams(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	requestData := GetTxnConstructionParamsRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, "GetTxnConstructionParams: Problem parsing request body: "+err.Error())
		return
	}

	// Get the fees from the mempool
	feeRate := fes.backendServer.GetMempool().EstimateFeeRate(requestData.MinFeeRateNanosPerKB)
	// Return the fees
	if err := json.NewEncoder(ww).Encode(GetTxnConstructionParamsResponse{
		FeeRateNanosPerKB: feeRate,
		BlockHeight:       uint64(fes.backendServer.GetBlockchain().BlockTip().Height),
	}); err != nil {
		_AddBadRequestError(ww, "GetTxnConstructionParams: Problem encoding response as JSON: "+err.Error())
		return
	}
}

func (fes *APIServer) GetCommittedTipBlockInfo(ww http.ResponseWriter, req *http.Request) {
	// Get the block tip from the blockchain.
	fes.backendServer.GetBlockchain().ChainLock.RLock()
	blockTip, exists := fes.backendServer.GetBlockchain().GetCommittedTip()
	fes.backendServer.GetBlockchain().ChainLock.RUnlock()
	if !exists {
		_AddBadRequestError(ww, "GetCommittedTipBlockInfo: Problem getting block tip")
		return
	}
	// Return the block tip.
	if err := json.NewEncoder(ww).Encode(&lib.CheckpointBlockInfo{
		Height:     blockTip.Header.Height,
		Hash:       blockTip.Hash,
		HashHex:    blockTip.Hash.String(),
		LatestView: fes.backendServer.GetLatestView(),
	}); err != nil {
		_AddBadRequestError(ww, "GetCommittedTipBlockInfo: Problem encoding response as JSON: "+err.Error())
		return
	}
}
