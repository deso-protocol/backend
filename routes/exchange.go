package routes

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"reflect"
	"sort"
	"time"

	"github.com/deso-protocol/core/lib"

	"github.com/pkg/errors"

	"github.com/btcsuite/btcd/btcec"
	"github.com/golang/glog"
	bip39 "github.com/tyler-smith/go-bip39"
)

// This file implements basic functions required to manipulate
// DeSo programmatically. It is mainly useful to exchanges that
// list DeSo.
//
// We recommend using our Rosetta implementation instead of this API.

var (
	IsGraylisted  = []byte{1}
	IsBlacklisted = []byte{1}
)

const (
	// RoutePathAPIBase ...
	RoutePathAPIBase = "/api/v1"
	// RoutePathAPIKeyPair ...
	RoutePathAPIKeyPair = "/api/v1/key-pair"
	// RoutePathAPIBalance ...
	RoutePathAPIBalance = "/api/v1/balance"
	// RoutePathAPITransferDeSo ...
	RoutePathAPITransferDeSo = "/api/v1/transfer-deso"
	// RoutePathAPITransactionInfo ...
	RoutePathAPITransactionInfo = "/api/v1/transaction-info"
	// RoutePathAPINodeInfo ...
	RoutePathAPINodeInfo = "/api/v1/node-info"
	// RoutePathAPIBlock ...
	RoutePathAPIBlock = "/api/v1/block"
)

// APIRoutes returns the routes for the public-facing API.
func (fes *APIServer) APIRoutes() []Route {
	var APIRoutes = []Route{
		{
			"APIBase",
			[]string{"GET"},
			RoutePathAPIBase,
			fes.APIBase,
			PublicAccess,
		},
		{
			"APIKeyPair",
			[]string{"POST", "OPTIONS"},
			RoutePathAPIKeyPair,
			fes.APIKeyPair,
			PublicAccess,
		},
		{
			"APIBalance",
			[]string{"POST", "OPTIONS"},
			RoutePathAPIBalance,
			fes.APIBalance,
			PublicAccess,
		},
		{
			"APITransferDeSo",
			[]string{"POST", "OPTIONS"},
			RoutePathAPITransferDeSo,
			fes.APITransferDeSo,
			PublicAccess,
		},
		{
			"APITransactionInfo",
			[]string{"POST", "OPTIONS"},
			RoutePathAPITransactionInfo,
			fes.APITransactionInfo,
			PublicAccess,
		},
		{
			"APINodeInfo",
			[]string{"POST", "OPTIONS"},
			RoutePathAPINodeInfo,
			fes.APINodeInfo,
			PublicAccess,
		},
		{
			"APIBlock",
			[]string{"POST", "OPTIONS"},
			RoutePathAPIBlock,
			fes.APIBlock,
			PublicAccess,
		},
	}

	return APIRoutes
}

// APIAddError sets an error response on the ResponseWriter passed in.
func APIAddError(ww http.ResponseWriter, errorString string) {
	//glog.Error(errorString)
	ww.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(ww).Encode(struct {
		Error string
	}{Error: errorString})
}

// APIBaseResponse ...
type APIBaseResponse struct {
	// Blank if successful. Otherwise, contains a description of the
	// error that occurred.
	Error string

	// The information contained in the block’s header.
	Header *HeaderResponse

	Transactions []*TransactionResponse
}

func _headerToResponse(header *lib.MsgDeSoHeader, hash string) *HeaderResponse {
	return &HeaderResponse{
		BlockHashHex:             hash,
		Version:                  header.Version,
		PrevBlockHashHex:         header.PrevBlockHash.String(),
		TransactionMerkleRootHex: header.TransactionMerkleRoot.String(),
		TstampSecs:               header.TstampSecs,
		Height:                   header.Height,
		Nonce:                    header.Nonce,
		ExtraNonce:               header.ExtraNonce,
	}
}

// APIBase is an endpoint that simply confirms that the API is up and running.
func (fes *APIServer) APIBase(ww http.ResponseWriter, rr *http.Request) {
	if fes.TXIndex == nil {
		APIAddError(ww, fmt.Sprintf("APIBase: Cannot be called when TXIndexChain "+
			"is nil. This error occurs when --txindex was not passed to the program on startup"))
		return
	}

	blockNode := fes.blockchain.BlockTip()

	// Take the hash computed from above and find the corresponding block.
	blockMsg, err := lib.GetBlock(blockNode.Hash, fes.blockchain.DB(), fes.blockchain.Snapshot())
	if err != nil {
		APIAddError(ww, fmt.Sprintf("APIBase: Problem fetching block: %v", err))
		return
	}
	if blockMsg == nil {
		APIAddError(ww, fmt.Sprintf("APIBase: Block with hash %v not found", blockNode.Hash))
		return
	}

	res := &APIBaseResponse{
		Header: _headerToResponse(blockMsg.Header, blockNode.Hash.String()),
	}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		APIAddError(ww, fmt.Sprintf("APIBase: Problem fetching utxoView: %v", err))
		return
	}

	for _, txn := range blockMsg.Txns {
		// Look up the metadata for each transaction.
		txnMeta := lib.DbGetTxindexTransactionRefByTxID(fes.TXIndex.TXIndexChain.DB(), nil, txn.Hash())

		res.Transactions = append(
			res.Transactions, APITransactionToResponse(
				txn, txnMeta, utxoView, fes.Params))
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		APIAddError(ww, fmt.Sprintf("APIBaseResponse: Problem encoding response "+
			"as JSON: %v", err))
		return
	}
}

// APIKeyPairRequest specifies the params for a call to the
// APIKeyPair endpoint.
type APIKeyPairRequest struct {
	// A BIP39 mnemonic and extra text. Mnemonic can be 12 words or
	// 24 words. ExtraText is optional.
	Mnemonic  string
	ExtraText string

	// The index of the public/private key pair to generate
	Index uint32
}

// APIKeyPairResponse specifies the response for a call to the
// APIKeyPair endpoint.
type APIKeyPairResponse struct {
	// Blank if successful. Otherwise, contains a description of the
	// error that occurred.
	Error string
	// The DeSo public key encoded using base58 check encoding with
	// prefix = [3]byte{0x9, 0x7f, 0x0}
	// This public key can be passed in subsequent API calls to check
	// balance, among other things. All encoded DeSo public keys start
	// with the characters “BC”
	PublicKeyBase58Check string
	// The DeSo public key encoded as a plain hex string. This should
	// match the public key with the corresponding index generated by this tool.
	// This should not be passed to subsequent API calls, it is only provided
	// as a reference, mainly as a sanity-check.
	PublicKeyHex string
	// The DeSo private key encoded using base58 check encoding with
	// prefix = [3]byte{0x50, 0xd5, 0x0}
	// This private key can be passed in subsequent API calls to spend DeSo,
	// among other things. All DeSo private keys start with
	// the characters “bc”
	PrivateKeyBase58Check string
	// The DeSo private key encoded as a plain hex string. Note that
	// this will not directly match what is produced by the tool because the
	// tool shows the private key encoded using Bitcoin’s WIF format rather
	// than as raw hex. To convert this raw hex into Bitcoin’s WIF format you can
	// use this simple Python script. This should not be passed to subsequent
	// API calls, it is only provided as a reference, mainly as a sanity-check.
	PrivateKeyHex string
}

// APIKeyPair allows one to generate an arbitrary number of public/private
// DeSo keypairs.
//
// Each public/private key pair corresponds to
// a particular index associated. This means that index “5”, for example,
// will always generate the same public/private
// key pair. An infinite number of public/private key pairs can thus be generated
// by iterating an index for a seed.
//
// Note that all public/private keys are inter-operable as Bitcoin
// public/private keys.  Meaning they represent a point on the secp256k1 curve
// (same as what is used by Bitcoin).
//
// Note also that, under the hood, DeSo takes the BIP39 mnemonic and
// generates the public/private key pairs using the BIP32 derivation path
// m/44’/0’/0’/0/i, where “i” is the “index” of the public/private key being
// generated. This means that the DeSo public/private key pair generated by
// the node will always line up with the public/private key pairs generated by
// this tool (https://iancoleman.io/bip39/). An engineer can therefore “sanity
// check” that things are working by generating a mnemonic using the tool,
// creating seed with that mnemonic, and then verifying that the
// public/private key pairs generated line up with what is shown by the tool.
func (fes *APIServer) APIKeyPair(ww http.ResponseWriter, rr *http.Request) {
	// Decode the request data.
	decoder := json.NewDecoder(io.LimitReader(rr.Body, MaxRequestBodySizeBytes))
	apiKeyPairRequest := APIKeyPairRequest{}
	if err := decoder.Decode(&apiKeyPairRequest); err != nil {
		APIAddError(ww, fmt.Sprintf("APIKeyPair: Problem parsing request body: %v", err))
		return
	}

	seedBytes, err := bip39.NewSeedWithErrorChecking(apiKeyPairRequest.Mnemonic, apiKeyPairRequest.ExtraText)
	if err != nil {
		APIAddError(ww, fmt.Sprintf("APIKeyPair: Error converting mnemonic and extra text to seed: %v", err))
		return
	}
	pubKey, privKey, _, err := lib.ComputeKeysFromSeed(
		seedBytes, apiKeyPairRequest.Index, fes.Params)
	if err != nil {
		APIAddError(ww, fmt.Sprintf("APIKeyPair: Problem generating key at "+
			"index %d: %v", apiKeyPairRequest.Index, err))
		return
	}

	res := APIKeyPairResponse{
		PublicKeyBase58Check:  lib.PkToString(pubKey.SerializeCompressed(), fes.Params),
		PublicKeyHex:          hex.EncodeToString(pubKey.SerializeCompressed()),
		PrivateKeyBase58Check: lib.PrivToString(privKey.Serialize(), fes.Params),
		PrivateKeyHex:         hex.EncodeToString(privKey.Serialize()),
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		APIAddError(ww, fmt.Sprintf("APIKeyPair: Problem encoding response as JSON: %v", err))
		return
	}
}

// APIBalanceRequest specifies the params for a call to the
// APIBalance endpoint.
type APIBalanceRequest struct {
	PublicKeyBase58Check string
	Confirmations        uint32
}

// UTXOEntryResponse ...
// TODO: There is a slightly different but redundant definition of
// this in frontend_utils.go
type UTXOEntryResponse struct {
	// A string that uniquely identifies a previous transaction. This is
	// a sha256 hash of the transaction’s information encoded using
	// base58 check encoding.
	TransactionIDBase58Check string
	// The index within this transaction that corresponds to an output
	// spendable by the passed-in public key.
	Index int64
	// The amount that is spendable by this UTXO in “nanos”.
	AmountNanos uint64
	// The pulic key entitled to spend the amount stored in this UTXO.
	PublicKeyBase58Check string
	// The number of confirmations this UTXO has. Set to zero if the
	// UTXO is unconfirmed.
	Confirmations int64
	// Whether or not this UTXO was a block reward.
	UtxoType string

	BlockHeight int64
}

// APIBalanceResponse specifies the response for a call to the
// APIBalance endpoint.
type APIBalanceResponse struct {
	// Blank if successful. Otherwise, contains a description of the
	// error that occurred.
	Error string
	// The balance of the public key queried in “nanos.” Note
	// there are 1e9 “nanos” per DeSo, so if the balance were “1 DeSo” then
	// this value would be set to 1e9.
	ConfirmedBalanceNanos int64
	// The unconfirmed balance of the public key queried in “nanos.” This field
	// is set to zero if Confirmations is set to a value greater than zero.
	UnconfirmedBalanceNanos int64
	// DeSo uses a UTXO model similar to Bitcoin. As such, querying
	// the balance returns all of the UTXOs for a particular public key for
	// convenience. Note that a UTXO is simply a reference to a particular
	// output index in a previous transaction
	UTXOs []*UTXOEntryResponse
}

// APIBalance allows one to check the balance of a particular public key by
// passing the public key.
//
// Note that spent transaction outputs are not returned by this endpoint. To
// perform operations on spent transaction outputs, one must use the
// APITransactionInfo endpoint instead.
func (fes *APIServer) APIBalance(ww http.ResponseWriter, rr *http.Request) {
	// Decode the request data.
	decoder := json.NewDecoder(io.LimitReader(rr.Body, MaxRequestBodySizeBytes))
	balanceRequest := APIBalanceRequest{}
	if err := decoder.Decode(&balanceRequest); err != nil {
		APIAddError(ww, fmt.Sprintf("APIBalanceRequest: Problem parsing request body: %v", err))
		return
	}

	// A public key is required.
	if balanceRequest.PublicKeyBase58Check == "" {
		APIAddError(ww, "APIBalanceRequest: Missing PublicKeyBase58Check")
		return
	}

	// Parse the public key into bytes.
	publicKeyBytes, _, err := lib.Base58CheckDecode(balanceRequest.PublicKeyBase58Check)
	if err != nil {
		APIAddError(ww, fmt.Sprintf("APIBalanceRequest: Problem parsing request body: %v", err))
		return
	}

	// Get all the UTXOs for the public key.
	utxoView, err := fes.mempool.GetAugmentedUtxoViewForPublicKey(publicKeyBytes, nil)
	if err != nil {
		APIAddError(ww, fmt.Sprintf("APIBalanceRequest: Problem getting UTXOs for public key: %v", err))
		return
	}

	// Get the height of the current block tip.
	blockTipHeight := fes.blockchain.BlockTip().Height
	balanceResponse := &APIBalanceResponse{}
	if blockTipHeight >= utxoView.Params.ForkHeights.BalanceModelBlockHeight {
		unconfirmedBalance, err := utxoView.GetDeSoBalanceNanosForPublicKey(publicKeyBytes)
		if err != nil {
			APIAddError(ww, fmt.Sprintf("APIBalanceRequest: Problem getting unconfirmed balance: %v", err))
			return
		}
		if unconfirmedBalance > uint64(math.MaxInt64) {
			APIAddError(ww, fmt.Sprintf("APIBalanceRequest: Unconfirmed balance %d is too large", unconfirmedBalance))
			return
		}
		balanceResponse.UnconfirmedBalanceNanos = int64(unconfirmedBalance)
		confirmedBalance, err := lib.DbGetDeSoBalanceNanosForPublicKey(
			fes.blockchain.DB(), fes.blockchain.Snapshot(), publicKeyBytes)
		if err != nil {
			APIAddError(ww, fmt.Sprintf("APIBalanceRequest: Problem getting confirmed balance: %v", err))
			return
		}
		if confirmedBalance > uint64(math.MaxInt64) {
			APIAddError(ww, fmt.Sprintf("APIBalanceRequest: Confirmed balance %d is too large", confirmedBalance))
			return
		}
		balanceResponse.ConfirmedBalanceNanos = int64(confirmedBalance)
	} else {

		utxoEntries, err := utxoView.GetUnspentUtxoEntrysForPublicKey(publicKeyBytes)
		if err != nil {
			APIAddError(ww, fmt.Sprintf("APIBalanceRequest: Problem getting UTXO entries for public key: %v", err))
			return
		}
		// Populate the response by looping over the UTXOs we found.
		balanceResponse.UTXOs = []*UTXOEntryResponse{}
		for _, utxoEntry := range utxoEntries {
			// The height of UTXOs in the mempool is tip+1 so confirmations will
			// be (tip - (tip+1) + 1) = 0 for these, and >0 for anything that's
			// confirmed.
			confirmations := int64(blockTipHeight) - int64(utxoEntry.BlockHeight) + 1

			// Ignore UTXOs that don't have enough confirmations on them.
			if confirmations < int64(balanceRequest.Confirmations) {
				continue
			}

			if confirmations > 0 {
				balanceResponse.ConfirmedBalanceNanos += int64(utxoEntry.AmountNanos)
			} else {
				balanceResponse.UnconfirmedBalanceNanos += int64(utxoEntry.AmountNanos)
			}

			balanceResponse.UTXOs = append(balanceResponse.UTXOs, &UTXOEntryResponse{
				TransactionIDBase58Check: lib.PkToString(utxoEntry.UtxoKey.TxID[:], fes.Params),
				Index:                    int64(utxoEntry.UtxoKey.Index),
				AmountNanos:              utxoEntry.AmountNanos,
				PublicKeyBase58Check:     lib.PkToString(utxoEntry.PublicKey, fes.Params),
				Confirmations:            confirmations,
				UtxoType:                 utxoEntry.UtxoType.String(),
				BlockHeight:              int64(utxoEntry.BlockHeight),
			})
		}
	}

	if err := json.NewEncoder(ww).Encode(balanceResponse); err != nil {
		APIAddError(ww, fmt.Sprintf("APIBalance: Problem encoding response as JSON: %v", err))
		return
	}
}

// InputResponse ...
type InputResponse struct {
	TransactionIDBase58Check string
	Index                    int64
}

// OutputResponse ...
type OutputResponse struct {
	PublicKeyBase58Check string
	AmountNanos          uint64
}

// TransactionResponse ...
// TODO: This is redundant with TransactionInfo in frontend_utils.
type TransactionResponse struct {
	// A string that uniquely identifies this transaction. This is a sha256 hash
	// of the transaction’s data encoded using base58 check encoding.
	TransactionIDBase58Check string
	// The raw hex of the transaction data. This can be fully-constructed from
	// the human-readable portions of this object.
	RawTransactionHex string `json:",omitempty"`
	// The inputs and outputs for this transaction.
	Inputs  []*InputResponse  `json:",omitempty"`
	Outputs []*OutputResponse `json:",omitempty"`
	// The signature of the transaction in hex format.
	SignatureHex string `json:",omitempty"`
	// Will always be “0” for basic transfers
	TransactionType string `json:",omitempty"`
	// TODO: Create a TransactionMeta portion for the response.

	// The hash of the block in which this transaction was mined. If the
	// transaction is unconfirmed, this field will be empty. To look up
	// how many confirmations a transaction has, simply plug this value
	// into the "block" endpoint.
	BlockHashHex string `json:",omitempty"`

	TransactionMetadata *lib.TransactionMetadata `json:",omitempty"`

	// The ExtraData added to this transaction
	ExtraData map[string]string `json:",omitempty"`

	// Balance Model Fields
	TxnNonce    *lib.DeSoNonce     `json:",omitempty"`
	TxnFeeNanos uint64             `json:",omitempty"`
	TxnVersion  lib.DeSoTxnVersion `json:",omitempty"`
}

// TransactionInfoResponse contains information about the transaction
// that is computed for convenience.
type TransactionInfoResponse struct {
	// The sum of the inputs
	TotalInputNanos uint64
	// The amount being sent to the “RecipientPublicKeyBase58Check”
	SpendAmountNanos uint64
	// The amount being returned to the “SenderPublicKeyBase58Check”
	ChangeAmountNanos uint64
	// The total fee and the fee rate (in nanos per KB) that was used for this
	// transaction.
	FeeNanos          uint64
	FeeRateNanosPerKB uint64
	// Will match the public keys passed as params. Note that
	// SenderPublicKeyBase58Check receives the change from this transaction.
	SenderPublicKeyBase58Check    string
	RecipientPublicKeyBase58Check string
}

// APITransferDeSoRequest specifies the params for a call to the
// APITransferDeSo endpoint.
type APITransferDeSoRequest struct {
	// An DeSo private key encoded using base58 check encoding (starts
	// with "bc").
	SenderPrivateKeyBase58Check string
	// An DeSo public key encoded using base58 check encoding (starts
	// with “BC”) that will receive the DeSo being sent. This field is required
	// whether sending using an explicit public/private key pair.
	RecipientPublicKeyBase58Check string
	// The amount of DeSo to send in “nanos.” Note that “1 DeSo” is equal to
	// 1e9 nanos, so to send 1 DeSo, this value would need to be set to 1e9.
	AmountNanos int64
	// The fee rate to use for this transaction. If left unset, a default fee rate
	// will be used. This can be checked using the “DryRun” parameter below.
	MinFeeRateNanosPerKB int64

	// No need to specify ProfileEntryResponse in each TransactionFee
	TransactionFees []TransactionFee `safeForLogging:"true"`

	// When set to true, the transaction is returned in the response but not
	// actually broadcast to the network. Useful for testing.
	DryRun bool
}

// APITransferDeSoResponse specifies the response for a call to the
// APITransferDeSo endpoint.
type APITransferDeSoResponse struct {
	// Blank if successful. Otherwise, contains a description of the
	// error that occurred.
	Error string

	// The transaction we assembled.
	Transaction *TransactionResponse

	// Information about the transaction that we compute for
	// convenience.
	TransactionInfo *TransactionInfoResponse
}

// APITransactionToResponse converts a raw DeSo transaction message to
// an object that can be easily JSON serialized.
func APITransactionToResponse(
	txnn *lib.MsgDeSoTxn,
	txnMeta *lib.TransactionMetadata,
	utxoView *lib.UtxoView,
	params *lib.DeSoParams) *TransactionResponse {

	signatureHex := ""

	if txnn.Signature.Sign != nil {
		signatureHex = hex.EncodeToString(txnn.Signature.Sign.Serialize())
	}

	// Remove UtxoOps from the response because it's massive and usually useless
	// We do some funky pointer stuff here so that we don't change the original object
	var txnMetaResponse lib.TransactionMetadata
	if txnMeta != nil {
		txnMetaResponse = *txnMeta
		basicMetadata := *txnMeta.BasicTransferTxindexMetadata
		basicMetadata.UtxoOps = nil
		txnMetaResponse.BasicTransferTxindexMetadata = &basicMetadata
	}

	txnBytes, _ := txnn.ToBytes(false /*preSignature*/)

	ret := &TransactionResponse{
		TransactionIDBase58Check: lib.PkToString(txnn.Hash()[:], params),
		RawTransactionHex:        hex.EncodeToString(txnBytes),
		SignatureHex:             signatureHex,
		TransactionType:          txnn.TxnMeta.GetTxnType().String(),
		TransactionMetadata:      &txnMetaResponse,
		TxnNonce:                 txnn.TxnNonce,
		TxnFeeNanos:              txnn.TxnFeeNanos,
		TxnVersion:               txnn.TxnVersion,
		// Inputs, Outputs, ExtraData, and some txnMeta fields set below.
	}
	for _, input := range txnn.TxInputs {
		ret.Inputs = append(ret.Inputs, &InputResponse{
			TransactionIDBase58Check: lib.PkToString(input.TxID[:], params),
			Index:                    int64(input.Index),
		})
	}
	for _, output := range txnn.TxOutputs {
		ret.Outputs = append(ret.Outputs, &OutputResponse{
			PublicKeyBase58Check: lib.Base58CheckEncode(output.PublicKey, false, params),
			AmountNanos:          output.AmountNanos,
		})
	}
	ret.ExtraData = DecodeExtraDataMap(params, utxoView, txnn.ExtraData)

	if txnMeta != nil {
		ret.BlockHashHex = txnMeta.BlockHashHex
	}

	return ret
}

// APITransferDeSo can be used to transfer DeSo from one public key to
// another programmatically. To transfer DeSo, one must provide a
// public/private key pair. DeSo uses a UTXO model like Bitcoin but
// DeSo transactions are generally simpler than Bitcoin transactions
// because DeSo always uses the “from public key”
// as the “change” public key (meaning that it does not “rotate” keys by
// default).
//
// For example, if a transaction sends 10 DeSo from PubA to PubB with 5 DeSo
// in “change” and 1 DeSo as a “miner fee,” then the transaction would look as
// follows:
//   - Input: 16 DeSo (10 DeSo to send, 5 DeSo in change, and 1 DeSo as a fee)
//   - PubB: 10 DeSo (the amount being sent from A to B)
//   - PubA: 5 DeSo (change returned to A)
//   - Implicit 1 DeSo is paid as a fee to the miner. The miner fee is implicitly
//     computed as (total input – total output) just like in Bitcoin.
//
// TODO: This function is redundant with the APITransferDeSo function in frontend_utils
func (fes *APIServer) APITransferDeSo(ww http.ResponseWriter, rr *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(rr.Body, MaxRequestBodySizeBytes))
	transferDeSoRequest := APITransferDeSoRequest{}
	if err := decoder.Decode(&transferDeSoRequest); err != nil {
		APIAddError(ww, fmt.Sprintf("APITransferDeSo: Problem parsing request body: %v", err))
		return
	}

	senderPrivKeyString := transferDeSoRequest.SenderPrivateKeyBase58Check
	if senderPrivKeyString == "" {
		APIAddError(ww, "APITransferDeSo: SenderPrivateKeyBase58Check is required")
		return
	}

	// Decode the sender public and private key
	senderPrivBytes, _, err := lib.Base58CheckDecode(senderPrivKeyString)
	if err != nil {
		APIAddError(ww, fmt.Sprintf("APITransferDeSo: Problem decoding sender "+
			"base58 private key: %v", err))
		return
	}
	senderPriv, senderPub := btcec.PrivKeyFromBytes(btcec.S256(), senderPrivBytes)
	if senderPriv == nil {
		APIAddError(ww, fmt.Sprintf("APITransferDeSo: Problem parsing sender "+
			"base58 private key"))
		return
	}

	// Decode the recipient's public key.
	recipientPubBytes, _, err := lib.Base58CheckDecode(
		transferDeSoRequest.RecipientPublicKeyBase58Check)
	if err != nil {
		APIAddError(ww, fmt.Sprintf("APITransferDeSo: Problem decoding recipient "+
			"base58 public key %s: %v", transferDeSoRequest.RecipientPublicKeyBase58Check, err))
		return
	}
	recipientPub, err := btcec.ParsePubKey(recipientPubBytes, btcec.S256())
	if err != nil {
		APIAddError(ww, fmt.Sprintf("APITransferDeSo: Problem encoding recipient "+
			"base58 public key %s: %v", transferDeSoRequest.RecipientPublicKeyBase58Check, err))
		return
	}

	// Compute the min fee.
	minFeeRateNanosPerKB := transferDeSoRequest.MinFeeRateNanosPerKB
	if minFeeRateNanosPerKB <= 0 {
		minFeeRateNanosPerKB = int64(fes.MinFeeRateNanosPerKB)
	}

	senderPublicKeyBytes := senderPub.SerializeCompressed()

	// Compute the additional transaction fees as specified by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(lib.TxnTypeBasicTransfer, senderPublicKeyBytes, transferDeSoRequest.TransactionFees)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("APITransferDeSo: TransactionFees specified in Request body are invalid: %v", err))
		return
	}

	// If DryRun is set to false, which is the default, then we broadcast
	// the transaction.
	shouldBroadcast := !transferDeSoRequest.DryRun

	// If the AmountNanos is less than zero then we have a special case where we create
	// a transaction with the maximum spend.
	var txnn *lib.MsgDeSoTxn
	var totalInputt uint64
	var spendAmountt uint64
	var changeAmountt uint64
	var feeNanoss uint64
	if transferDeSoRequest.AmountNanos < 0 {
		// Create a MAX transaction
		txnn, totalInputt, spendAmountt, feeNanoss, err = fes.blockchain.CreateMaxSpend(
			senderPublicKeyBytes, recipientPub.SerializeCompressed(),
			uint64(minFeeRateNanosPerKB),
			fes.backendServer.GetMempool(), additionalOutputs)
		if err != nil {
			APIAddError(ww, fmt.Sprintf("APITransferDeSo: Error processing MAX transaction: %v", err))
			return
		}

		// Sanity check that the input is equal to:
		//   (spend amount + change amount + fees)
		if totalInputt != (spendAmountt + changeAmountt + feeNanoss) {
			APIAddError(ww, fmt.Sprintf("APITransferDeSo: totalInput=%d is not equal "+
				"to the sum of the (spend amount=%d, change=%d, and fees=%d) which sums "+
				"to %d. This means there was likely a problem with CreateMaxSpend",
				totalInputt, spendAmountt, changeAmountt, feeNanoss, (spendAmountt+changeAmountt+feeNanoss)))
			return
		}

		// Process the transaction according to whether the user wants us to
		// sign/validate/broadcast it.
		err = fes._processTransactionWithKey(txnn, senderPriv, shouldBroadcast)
		if err != nil {
			APIAddError(ww, fmt.Sprintf("APITransferDeSo: Problem processing transaction: %v", err))
			return
		}

	} else {
		// In this case, we are spending what the user asked us to spend as opposed to
		// spending the maximum amount possible.

		// Create the transaction outputs and add the recipient's public key and the
		// amount we want to pay them
		txnOutputs := append(additionalOutputs, &lib.DeSoOutput{
			PublicKey: recipientPub.SerializeCompressed(),
			// If we get here we know the amount is non-negative.
			AmountNanos: uint64(transferDeSoRequest.AmountNanos),
		})

		// Assemble the transaction so that inputs can be found and fees can
		// be computed.
		txnn = &lib.MsgDeSoTxn{
			// The inputs will be set below.
			TxInputs:  []*lib.DeSoInput{},
			TxOutputs: txnOutputs,
			PublicKey: senderPublicKeyBytes,
			TxnMeta:   &lib.BasicTransferMetadata{},
			// We wait to compute the signature until we've added all the
			// inputs and change.
		}

		// Add inputs to the transaction and do signing, validation, and broadcast
		// depending on what the user requested.
		totalInputt, spendAmountt, changeAmountt, feeNanoss, err = fes._augmentAndProcessTransactionWithSubsidyWithKey(
			txnn, senderPriv,
			uint64(minFeeRateNanosPerKB),
			0, /*inputSubsidy*/
			shouldBroadcast)
		if err != nil {
			APIAddError(ww, fmt.Sprintf("APITransferDeSo: Error processing regular transaction: %v", err))
			return
		}
	}

	// Return the transaction in the response.
	res := APITransferDeSoResponse{}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		APIAddError(ww, fmt.Sprintf("APITransferDeSo: Problem fetching utxoView: %v", err))
		return
	}
	// The block hash param is empty because this transaction clearly hasn't been
	// mined yet.
	res.Transaction = APITransactionToResponse(txnn, nil, utxoView, fes.Params)
	txnBytes, _ := txnn.ToBytes(false /*preSignature*/)
	res.TransactionInfo = &TransactionInfoResponse{
		TotalInputNanos:               totalInputt,
		SpendAmountNanos:              spendAmountt,
		ChangeAmountNanos:             changeAmountt,
		FeeNanos:                      feeNanoss,
		FeeRateNanosPerKB:             feeNanoss * 1000 / uint64(len(txnBytes)),
		SenderPublicKeyBase58Check:    lib.PkToString(senderPub.SerializeCompressed(), fes.Params),
		RecipientPublicKeyBase58Check: lib.PkToString(recipientPubBytes, fes.Params),
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		APIAddError(ww, fmt.Sprintf("APITransferDeSo: Problem encoding response as JSON: %v", err))
		return
	}
}

// APITransactionInfoRequest specifies the params for a call to the
// APITransactionInfo endpoint.
type APITransactionInfoRequest struct {
	// When set to true, the response simply contains all transactions in the
	// mempool with no filtering.
	IsMempool bool

	// A string that uniquely identifies this transaction. E.g. from a previous
	// call to “transfer-deso”. Ignored when PublicKeyBase58Check is set.
	TransactionIDBase58Check string

	// An DeSo public key encoded using base58 check encoding (starts
	// with “BC”) to get transaction IDs for. When set,
	// TransactionIDBase58Check is ignored.
	PublicKeyBase58Check string

	// Only return transaction IDs
	IDsOnly bool

	// Offset from which a page should be fetched
	LastTransactionIDBase58Check string

	// The last index of a transaction for a public key seen. If less than 0, it means we are not looking at
	// transactions in the database yet.
	LastPublicKeyTransactionIndex int64

	// Number of transactions to be returned
	Limit uint64
}

// APITransactionInfoResponse specifies the response for a call to the
// APITransactionInfo endpoint.
type APITransactionInfoResponse struct {
	// Blank if successful. Otherwise, contains a description of the
	// error that occurred.
	Error string

	// The info for all transactions this public key is associated with from oldest
	// to newest.
	Transactions []*TransactionResponse

	// The hash of the last transaction
	LastTransactionIDBase58Check string

	// The last index of a transaction for a public key seen.
	LastPublicKeyTransactionIndex int64

	BalanceNanos uint64
}

// APITransactionInfo allows one to get information about a particular transaction
// given its transaction ID (in base58check encoding) OR using a public key.
//
// If one has a TransactionIDBase58Check, e.g. from calling the
// “transfer-deso” endpoint, one can get the corresponding human-readable
// “TransactionInfo” by passing this transaction ID to a node. Note that
// DeSo nodes do not maintain a transaction index by default, so this
// endpoint will error if either --txindex is not passed when starting the node
// OR if the index is not yet up-to-date.
//
// If one has a PublicKeyBase58Check (starts with “BC”), one can get all of the
// TransactionIDs associated with that public key sorted by oldest to newest
// (this will include transactions where the address is a sender and a
// receiver). One can optionally get the full TransactionInfos for all of the
// transactions in the same call. Note that DeSo nodes do not maintain a
// transaction index by default, so this endpoint will error if either
// --txindex is not passed when starting the node OR if the index is not yet
// up-to-date.
func (fes *APIServer) APITransactionInfo(ww http.ResponseWriter, rr *http.Request) {
	// If the --txindex flag hasn't been passed to the node, return an error outright.
	if fes.TXIndex == nil {
		APIAddError(ww, fmt.Sprintf("APITransactionInfo: This function cannot be "+
			"called without passing --txindex to the node on startup."))
		return
	}

	// Decode the request
	decoder := json.NewDecoder(io.LimitReader(rr.Body, MaxRequestBodySizeBytes))
	transactionInfoRequest := APITransactionInfoRequest{}
	if err := decoder.Decode(&transactionInfoRequest); err != nil {
		APIAddError(ww, fmt.Sprintf("APITransactionInfo: Problem parsing request body: %v", err))
		return
	}

	var lastTxHash *lib.BlockHash
	lastTxSeen := false
	lastTxID := transactionInfoRequest.LastTransactionIDBase58Check
	if lastTxID == "" {
		lastTxSeen = true
	} else {
		txIDBytes, _, err := lib.Base58CheckDecode(lastTxID)
		if err != nil {
			APIAddError(ww, fmt.Sprintf("APITransactionInfo: Error decoding last tx id (%v): %v", lastTxID, err))
			return
		}
		lastTxHash = &lib.BlockHash{}
		copy(lastTxHash[:], txIDBytes)
	}

	limit := transactionInfoRequest.Limit
	if limit <= 0 {
		// Legacy support for unpaginated requests
		limit = 1000
	}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		APIAddError(ww, fmt.Sprintf("APITransactionInfo: Problem fetching utxoView: %v", err))
		return
	}

	// IsMempool means we should just return all of the transactions that are currently in the mempool.
	if transactionInfoRequest.IsMempool {
		// Get all the txns from the mempool.
		poolTxns, _, err := fes.mempool.GetTransactionsOrderedByTimeAdded()
		if err != nil {
			APIAddError(ww, fmt.Sprintf("APITransactionInfo: Error getting txns from mempool: %v", err))
			return
		}

		res := &APITransactionInfoResponse{}
		res.Transactions = []*TransactionResponse{}
		for _, poolTx := range poolTxns {
			// If we haven't seen the last transaction of the previous page, skip ahead until we find it.
			if !lastTxSeen {
				if reflect.DeepEqual(poolTx.Hash, lastTxHash) {
					lastTxSeen = true
				}
				continue
			}

			if transactionInfoRequest.IDsOnly {
				res.Transactions = append(res.Transactions,
					&TransactionResponse{TransactionIDBase58Check: lib.PkToString(poolTx.Tx.Hash()[:], fes.Params)})
			} else {
				res.Transactions = append(res.Transactions, APITransactionToResponse(poolTx.Tx, poolTx.TxMeta, utxoView, fes.Params))
			}

			// If we've filled up the page, exit.
			if uint64(len(res.Transactions)) == limit {
				break
			}
		}

		// Set the last transaction seen.
		if len(res.Transactions) > 0 {
			res.LastTransactionIDBase58Check = res.Transactions[len(res.Transactions)-1].TransactionIDBase58Check
		}

		// At this point, all the transactions should have been added to the request.
		if err := json.NewEncoder(ww).Encode(res); err != nil {
			APIAddError(ww, fmt.Sprintf("APITransactionInfo: Problem encoding response as JSON: %v", err))
			return
		}

		return
	}

	// If no public key is set, we're doing a simple transaction lookup using
	// the passed-in TransactionIDBase58Check.
	//
	// Note: we do not apply pagination here as we are looking up a single value.
	if transactionInfoRequest.PublicKeyBase58Check == "" {
		// Parse the passed-in txID
		txIDBytes, _, err := lib.Base58CheckDecode(transactionInfoRequest.TransactionIDBase58Check)
		if err != nil {
			// If not base58 try hex decode
			txIDBytes, err = hex.DecodeString(transactionInfoRequest.TransactionIDBase58Check)
			if err != nil {
				APIAddError(ww, fmt.Sprintf("APITransactionInfo: Problem parsing TransactionID: %v", err))
				return
			}
		}
		if len(txIDBytes) != 32 {
			APIAddError(ww, fmt.Sprintf("APITransactionInfo: TransactionID byte length is %d but should be 32", len(txIDBytes)))
			return
		}
		txID := &lib.BlockHash{}
		copy(txID[:], txIDBytes)

		// Use the txID to lookup the requested transaction.
		txn, txnMeta := lib.DbGetTxindexFullTransactionByTxID(fes.TXIndex.TXIndexChain.DB(), nil, fes.blockchain.DB(), txID)

		if txn == nil {
			// Try to look the transaction up in the mempool before giving up.
			txnInPool := fes.mempool.GetTransaction(txID)
			if txnInPool == nil {
				APIAddError(ww, fmt.Sprintf("APITransactionInfo: Could not find transaction with TransactionIDBase58Check = %s",
					transactionInfoRequest.TransactionIDBase58Check))
				return
			}
			txn = txnInPool.Tx
			txnMeta = txnInPool.TxMeta
		}

		res := &APITransactionInfoResponse{}
		res.Transactions = []*TransactionResponse{
			APITransactionToResponse(txn, txnMeta, utxoView, fes.Params),
		}

		if err := json.NewEncoder(ww).Encode(res); err != nil {
			APIAddError(ww, fmt.Sprintf("APITransactionInfo: Problem encoding response as JSON: %v", err))
			return
		}

		return
	}

	// At this point, we know we're looking up all the transactions for a particular public key

	// Parse the public key
	publicKeyBytes, _, err := lib.Base58CheckDecode(transactionInfoRequest.PublicKeyBase58Check)
	if err != nil {
		APIAddError(ww, fmt.Sprintf("APITransactionInfo: Problem parsing PublicKeyBase58Check: %v", err))
		return
	}

	totalBalanceNanos, err := utxoView.GetDeSoBalanceNanosForPublicKey(publicKeyBytes)
	if err != nil {
		APIAddError(ww, fmt.Sprintf("APITransactionInfo: Problem getting utxos from view: %v", err))
		return
	}

	res := &APITransactionInfoResponse{
		BalanceNanos: totalBalanceNanos,
	}
	res.Transactions = []*TransactionResponse{}

	validForPrefix := lib.DbTxindexPublicKeyPrefix(publicKeyBytes)
	// If FetchStartIndex is specified then the startPrefix is the public key with FetchStartIndex appended.
	// Otherwise, we leave off the index so that the seek will start from the end of the transaction list.
	startPrefix := lib.DbTxindexPublicKeyPrefix(publicKeyBytes)
	if transactionInfoRequest.LastPublicKeyTransactionIndex > 0 {
		startPrefix = lib.DbTxindexPublicKeyIndexToTxnKey(publicKeyBytes, uint32(transactionInfoRequest.LastPublicKeyTransactionIndex))
	}
	// The maximum key length is the length of the DB key constructed from the public key plus the size of the uint64 appended to it.
	maxKeyLen := len(lib.DbTxindexPublicKeyIndexToTxnKey(publicKeyBytes, uint32(0)))

	keysFound, valsFound, err := lib.DBGetPaginatedKeysAndValuesForPrefix(
		fes.TXIndex.TXIndexChain.DB(), startPrefix, validForPrefix,
		maxKeyLen, int(limit), true, true)
	if err != nil {
		APIAddError(ww, fmt.Sprintf("APITransactionInfo: Error fetching paginated txns: %v", err))
		return
	}

	// Speed up calls to GetBlock with a local cache
	blockMap := make(map[*lib.BlockHash]*lib.MsgDeSoBlock)

	// The API response returns oldest -> newest so we need to iterate over the results backwards
	for ii := len(valsFound) - 1; ii >= 0; ii-- {
		txIDBytes := valsFound[ii]
		txID := &lib.BlockHash{}
		copy(txID[:], txIDBytes)

		if transactionInfoRequest.IDsOnly {
			res.Transactions = append(res.Transactions, &TransactionResponse{
				TransactionIDBase58Check: lib.PkToString(txIDBytes[:], fes.Params),
			})
		} else {
			// In this case we need to look up the full transaction and convert it into a proper transaction response.
			txnMeta := lib.DbGetTxindexTransactionRefByTxID(fes.TXIndex.TXIndexChain.DB(), nil, txID)
			blockHashBytes, err := hex.DecodeString(txnMeta.BlockHashHex)
			if err != nil {
				APIAddError(ww, fmt.Sprintf("APITransactionInfo: Error parsing block: %v %v", txnMeta.BlockHashHex, err))
				return
			}

			// Fetch the block
			blockHash := &lib.BlockHash{}
			copy(blockHash[:], blockHashBytes)
			block := blockMap[blockHash]
			if block == nil {
				block, err = lib.GetBlock(blockHash, fes.blockchain.DB(), fes.blockchain.Snapshot())
				if block == nil || err != nil {
					fmt.Errorf("DbGetTxindexFullTransactionByTxID: Block corresponding to txn not found")
					return
				}
				blockMap[blockHash] = block
			}

			// Fetch the transaction
			fullTxn := block.Txns[txnMeta.TxnIndexInBlock]

			res.Transactions = append(res.Transactions, APITransactionToResponse(fullTxn, txnMeta, utxoView, fes.Params))
		}
	}

	if len(keysFound) > 0 {
		lastKey := keysFound[len(keysFound)-1]
		// The index comes after the <_Prefix, PublicKey> bytes.
		lastKeyIndexBytes := lastKey[len(lib.DbTxindexPublicKeyPrefix(publicKeyBytes)):]
		res.LastPublicKeyTransactionIndex = int64(lib.DecodeUint32(lastKeyIndexBytes))
	}

	// Start with the mempool
	poolTxns, _, err := fes.mempool.GetTransactionsOrderedByTimeAdded()
	if err != nil {
		APIAddError(ww, fmt.Sprintf("APITransactionInfo: Error getting txns from mempool: %v", err))
		return
	}

	// Go from most recent to least recent
	// TODO: Support pagination for mempool transactions
	// Tack on mempool transactions if LastPublicKeyTransactionIndex is not specified
	if transactionInfoRequest.LastPublicKeyTransactionIndex <= 0 {
		for _, poolTx := range poolTxns {
			txnMeta := poolTx.TxMeta

			isRelevantTxn := false
			// Iterate over the affected public keys to see if any of them hit the one we're looking for.
			for _, affectedPks := range txnMeta.AffectedPublicKeys {
				if affectedPks.PublicKeyBase58Check == transactionInfoRequest.PublicKeyBase58Check {
					isRelevantTxn = true
					break
				}
			}

			// Skip irrelevant transactions
			if !isRelevantTxn {
				continue
			}

			// Finally, add the transaction to our list if it's relevant
			if transactionInfoRequest.IDsOnly {
				txRes := &TransactionResponse{TransactionIDBase58Check: lib.PkToString(poolTx.Tx.Hash()[:], fes.Params)}
				res.Transactions = append(res.Transactions, txRes)
			} else {
				res.Transactions = append(res.Transactions, APITransactionToResponse(poolTx.Tx, txnMeta, utxoView, fes.Params))
			}
		}
	}

	// At this point, all the transactions should have been added to the request.
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		APIAddError(ww, fmt.Sprintf("APITransactionInfo: Problem encoding response "+
			"as JSON: %v", err))
		return
	}
}

// APINodeInfoRequest specifies the params for a call to the
// APINodeInfo endpoint.
type APINodeInfoRequest struct {
}

// APINodeInfoResponse specifies the response for a call to the
// APINodeInfo endpoint.
type APINodeInfoResponse struct {
	// Blank if successful. Otherwise, contains a description of the
	// error that occurred.
	Error string
}

// APINodeInfo returns general information about the state of the node's
// blockchain.
//
// The blockchain does a “headers-first” sync, meaning it first downloads all
// DeSo headers and then downloads all blocks. This means that, when the
// node is first syncing, the tip of the best “header chain” may be ahead of
// the tip of its most recently downloaded block. In addition to syncing
// DeSo headers and DeSo blocks, an DeSo node will also sync all of
// the latest Bitcoin headers to power its built-in decentralized exchange. For
// this reason, the endpoint also returns information on the node's best
// Bitcoin header chain, which is distinct from its DeSo chain.
func (fes *APIServer) APINodeInfo(ww http.ResponseWriter, rr *http.Request) {
	// Construct a request to node-control
	// TODO: This currently won't work if ADMIN_PUBLIC_KEYS is set.
	reqBodyObj := &NodeControlRequest{
		OperationType: "get_info",
	}
	bb, err := json.Marshal(reqBodyObj)
	if err != nil {
		APIAddError(ww, fmt.Sprintf("APINodeInfo: Problem serializing request "+
			"to node-control endpoint: %v", err))
		return
	}
	request, err := http.NewRequest("POST", RoutePathNodeControl,
		bytes.NewBuffer(bb))

	if err != nil {
		APIAddError(ww, fmt.Sprintf("APINodeInfo: Problem creating request "+
			"to node-control endpoint: %v", err))
		return
	}

	request.Header.Set("Content-Type", "application/json")
	fes.router.ServeHTTP(ww, request)
}

// APIBlockRequest specifies the params for a call to the
// APIBlock endpoint.
type APIBlockRequest struct {
	// Block height. 0 corresponds to the genesis block. An error will be
	// returned if the height exceeds the tip. This field is ignored if HashHex is
	// set.
	Height int64
	// Hash of the block to return. Height is ignored if this is set.
	HashHex string
	// When set to false, only returns the header of the block requested
	// not the full block. Otherwise, returns the full block.
	FullBlock bool
}

// HeaderResponse ...
type HeaderResponse struct {
	// The hash of the block that was queried.
	BlockHashHex string
	// Generally set to zero
	Version uint32
	// Hash of the previous block in the chain.
	PrevBlockHashHex string
	// The merkle root of all the transactions contained within the block.
	TransactionMerkleRootHex string
	// The unix timestamp (in seconds) specifying when this block was
	// mined.
	TstampSecs uint64
	// The height of the block this header corresponds to.
	Height uint64

	// The Nonce and ExtraNonce combine to give miners 128 bits of entropy
	Nonce      uint64
	ExtraNonce uint64
}

// APIBlockResponse specifies the response for a call to the
// APIBlock endpoint.
type APIBlockResponse struct {
	// Blank if successful. Otherwise, contains a description of the
	// error that occurred.
	Error string

	// The information contained in the block’s header.
	Header *HeaderResponse

	Transactions []*TransactionResponse
}

// APIBlock can be used to query a block's information using either the block
// hash or height.
//
// To get all blocks in the chain, simply query this endpoint by enumerating
// the heights starting from zero and iterating up to the tip. The tip height
// and hash can be obtained using the /info endpoint.
func (fes *APIServer) APIBlock(ww http.ResponseWriter, rr *http.Request) {
	// Decode the request
	decoder := json.NewDecoder(io.LimitReader(rr.Body, MaxRequestBodySizeBytes))
	blockRequest := APIBlockRequest{}
	if err := decoder.Decode(&blockRequest); err != nil {
		APIAddError(ww, fmt.Sprintf("APIBlockRequest: Problem parsing request body: %v", err))
		return
	}

	// For this endpoint we need to lock the blockchain for reading.
	// If the HashHex is set, look the block up using that.
	numBlocks := len(fes.blockchain.BestChain())

	var blockHash *lib.BlockHash
	if blockRequest.HashHex != "" {
		hashBytes, err := hex.DecodeString(blockRequest.HashHex)
		if err != nil {
			APIAddError(ww, fmt.Sprintf("APIBlockRequest: Problem parsing block hash: %v", err))
			return
		}
		blockHash = &lib.BlockHash{}
		copy(blockHash[:], hashBytes[:])

	} else {
		// Find the block node with the corresponding height on the best chain.
		if blockRequest.Height >= int64(numBlocks) || blockRequest.Height < 0 {
			maxHeight := len(fes.blockchain.BestChain()) - 1

			APIAddError(ww, fmt.Sprintf("APIBlockRequest: Height requested "+
				"%d must be >= 0 and <= "+
				"height of best block chain tip %d", blockRequest.Height,
				maxHeight))
			return
		}
		blockHash = fes.blockchain.BestChain()[blockRequest.Height].Hash
	}

	// Take the hash computed from above and find the corresponding block.
	blockMsg, err := lib.GetBlock(blockHash, fes.blockchain.DB(), fes.blockchain.Snapshot())
	if err != nil {
		APIAddError(ww, fmt.Sprintf("APIBlockRequest: Problem fetching block: %v", err))
		return
	}
	if blockMsg == nil {
		APIAddError(ww, fmt.Sprintf("APIBlockRequest: Block with hash %v not found", blockHash))
		return
	}

	res := &APIBlockResponse{
		Header: _headerToResponse(blockMsg.Header, blockHash.String()),
	}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		APIAddError(ww, fmt.Sprintf("APIBlockRequest: Problem fetching utxoView: %v", err))
		return
	}

	if blockRequest.FullBlock {
		for _, txn := range blockMsg.Txns {
			// Look up the metadata for each transaction.
			txnMeta := lib.DbGetTxindexTransactionRefByTxID(fes.TXIndex.TXIndexChain.DB(), nil, txn.Hash())

			res.Transactions = append(
				res.Transactions, APITransactionToResponse(
					txn, txnMeta, utxoView, fes.Params))
		}
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		APIAddError(ww, fmt.Sprintf("APITransactionInfo: Problem encoding response "+
			"as JSON: %v", err))
		return
	}
}

// TODO: This is a somewhat redundant version of processTransaction It exists
// because the API needed to cut out the derivation of the public key from the
// user object, among other things.
func (fes *APIServer) _processTransactionWithKey(
	txn *lib.MsgDeSoTxn, _privKey *btcec.PrivateKey, wantsBroadcast bool) error {

	txnSignature, err := txn.Sign(_privKey)
	if err != nil {
		return fmt.Errorf("_processTransactionWithKey: Error computing "+
			"transaction signature: %v", err)
	}
	txn.Signature.SetSignature(txnSignature)

	// Grab the block tip and use it as the height for validation.
	blockHeight := fes.blockchain.BlockTip().Height
	err = fes.blockchain.ValidateTransaction(
		txn,
		// blockHeight is set to the next block since that's where this
		// transaction will be mined at the earliest.
		blockHeight+1,
		true,
		fes.mempool)
	if err != nil {
		return fmt.Errorf("_processTransactionWithKey: Problem validating txn: %v", err)
	}

	// Broadcast the transaction if the caller asked us to. Note that if we
	// get here and Broadcast is true then we've already validated the transaction
	// so all we need is to broadcast it.
	if wantsBroadcast {
		if _, err := fes.backendServer.BroadcastTransaction(txn); err != nil {
			return fmt.Errorf("_processTransactionWithKey: Problem broadcasting txn: %v", err)
		}
	}

	return nil
}

// TODO: This is a somewhat redundant version of
// _augmentAndProcessTransactionWithSubsidy. It exists because the API needed to
// cut out the derivation of the public key from the user object, among other
// things.
func (fes *APIServer) _augmentAndProcessTransactionWithSubsidyWithKey(
	txn *lib.MsgDeSoTxn, privBase58 *btcec.PrivateKey,
	minFeeRateNanosPerKB uint64, inputSubsidy uint64,
	wantsBroadcast bool) (
	_totalInput uint64, _spendAmount uint64, _changeAmount uint64,
	_fees uint64, _err error) {

	// Add inputs to the transaction to satisfy the amount the user wants to burn,
	// if any. If we don't have enough total input to satisfy the constraints,
	// return an error.
	totalInput, spendAmount, changeAmount, fees, err :=
		fes.blockchain.AddInputsAndChangeToTransactionWithSubsidy(txn, minFeeRateNanosPerKB,
			inputSubsidy, fes.mempool, 0)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("_augmentAndProcessTransactionWithKey: Problem adding inputs and "+
			"change to transaction %v: %v", txn, err)
	}

	// Sanity check that the input is equal to:
	//   (spend amount + change amount + fees)
	if totalInput != (spendAmount + changeAmount + fees) {
		return 0, 0, 0, 0, fmt.Errorf("_augmentAndProcessTransactionWithKey: totalInput=%d is not equal "+
			"to the sum of the (spend amount=%d, change=%d, and fees=%d) which sums "+
			"to %d. This means there was likely a problem with AddInputsAndChangeToTransaction",
			totalInput, spendAmount, changeAmount, fees, (spendAmount + changeAmount + fees))
	}

	// At this point we know the transaction has enough input to cover the output
	// we want to send to the recipient plus the fees required to meet the feerate
	// specified (even if the signature has its maximum size). It also gives excess
	// change back to the sender public key.

	err = fes._processTransactionWithKey(txn, privBase58, wantsBroadcast)
	if err != nil {
		return 0, 0, 0, 0, errors.Wrapf(
			err, "_augmentAndProcessTransactionWithKey: Problem processing transaction: ")
	}

	return totalInput, spendAmount, changeAmount, fees, nil
}

// Accepts a PkMapKey <> PubKey map and returns a map with a subset of those keys based on
// the moderationType specified.  Passing an empty string will only filter out profiles
// that are "RemovedEverywhere."
//
// NOTE: If a readerPK is passed, it will always be returned in the new map.
func (fes *APIServer) FilterOutRestrictedPubKeysFromMap(profilePubKeyMap map[lib.PkMapKey][]byte, readerPK []byte, moderationType string, utxoView *lib.UtxoView,
) (_filteredPubKeyMap map[lib.PkMapKey][]byte, _err error) {

	filteredPubKeyMap := make(map[lib.PkMapKey][]byte)
	for pkMapKey, publicKey := range profilePubKeyMap {
		pkid := utxoView.GetPKIDForPublicKey(publicKey).PKID

		usernameGraylistState := fes.GetUsernameGraylistStateForPkid(pkid, utxoView)
		usernameBlacklistState := fes.GetUsernameBlacklistStateForPkid(pkid, utxoView)

		// If the key is restricted based on the current moderation type and the pkMapKey does not equal that of the currentPoster,
		// we can filter out this public key.  We need to check the currentPoster's PK to support hiding comments from
		// greylisted users (moderationType = "leaderboard") but still support getting posts from greylisted users.
		if IsRestrictedPubKey(fes.GetGraylistStateForPkid(pkid), usernameGraylistState, fes.GetBlacklistStateForPkid(pkid), usernameBlacklistState, moderationType) {
			continue
		} else {
			// If a public key does isn't restricted, add it to the map.
			filteredPubKeyMap[pkMapKey] = profilePubKeyMap[pkMapKey]
		}
	}

	if readerPK != nil {
		filteredPubKeyMap[lib.MakePkMapKey(readerPK)] = readerPK
	}

	return filteredPubKeyMap, nil

}

// Accepts a list of profile public keys and returns a subset of those keys based on
// the moderationType specified.  Passing an empty string will only filter out profiles
// that are "RemovedEverywhere."
func (fes *APIServer) FilterOutRestrictedPubKeysFromList(profilePubKeys [][]byte, readerPK []byte, moderationType string, utxoView *lib.UtxoView) (_filteredPubKeys [][]byte, _err error) {

	filteredPubKeys := [][]byte{}
	for _, profilePubKey := range profilePubKeys {
		pkid := utxoView.GetPKIDForPublicKey(profilePubKey).PKID

		usernameGraylistState := fes.GetUsernameGraylistStateForPkid(pkid, utxoView)
		usernameBlacklistState := fes.GetUsernameBlacklistStateForPkid(pkid, utxoView)

		if IsRestrictedPubKey(fes.GetGraylistStateForPkid(pkid), usernameGraylistState, fes.GetBlacklistStateForPkid(pkid), usernameBlacklistState, moderationType) {
			// Always let the reader access their content.
			if reflect.DeepEqual(readerPK, profilePubKey) {
				filteredPubKeys = append(filteredPubKeys, profilePubKey)
			} else {
				continue
			}
		} else {
			// If a public key does not meet any of the above restictions, add it.
			filteredPubKeys = append(filteredPubKeys, profilePubKey)
		}
	}
	return filteredPubKeys, nil
}

func IsRestrictedPubKey(userGraylistStatePkid []byte, usernameGraylistState []byte, userBlacklistStatePkid []byte, usernameBlacklistState []byte, moderationType string) bool {
	if moderationType == "unrestricted" {
		return false
	} else if reflect.DeepEqual(userBlacklistStatePkid, IsBlacklisted) || reflect.DeepEqual(usernameBlacklistState, IsBlacklisted) {
		return true
	} else if moderationType == "leaderboard" && (reflect.DeepEqual(userGraylistStatePkid, IsGraylisted) || reflect.DeepEqual(usernameGraylistState, IsGraylisted)) {
		return true
	} else {
		return false
	}
}

// Get the map of public keys this user has blocked.  The _blockedPubKeyMap operates as a hashset to speed up look up time
// while value are empty structs to keep memory usage down.
func (fes *APIServer) GetBlockedPubKeysForUser(userPubKey []byte) (_blockedPubKeyMap map[string]struct{}, _err error) {
	/* Get public keys of users the reader has blocked */
	userMetadata, err := fes.getUserMetadataFromGlobalState(lib.PkToString(userPubKey, fes.Params))
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf("GetBlockedPubKeysForUser: Problem with getUserMetadataFromGlobalState: %v", err), "")
	}

	blockedPublicKeys := userMetadata.BlockedPublicKeys
	if blockedPublicKeys == nil {
		blockedPublicKeys = make(map[string]struct{})
	}
	return blockedPublicKeys, nil
}

// Fetches all the profiles from the db starting with a given profilePubKey, up to numToFetch.
// This is then joined with mempool and all profiles are returned.  Because the mempool may contain
// profile changes, the number of profiles returned in the map is not guaranteed to be numEntries.
func (fes *APIServer) GetProfilesByCoinValue(
	bav *lib.UtxoView,
	readerPK []byte,
	startProfilePubKey []byte,
	numToFetch int,
	getPosts bool,
	moderationType string,
) (
	_profiles map[lib.PkMapKey]*lib.ProfileEntry,
	_postsByProfilePublicKey map[lib.PkMapKey][]*lib.PostEntry,
	_postEntryReaderStates map[lib.BlockHash]*lib.PostEntryReaderState, _err error,
) {

	var startProfile *lib.ProfileEntry
	if startProfilePubKey != nil {
		startProfile = lib.DBGetProfileEntryForPKID(bav.Handle, fes.blockchain.Snapshot(), lib.DBGetPKIDEntryForPublicKey(bav.Handle, fes.blockchain.Snapshot(), startProfilePubKey).PKID)
	}

	var startDeSoLockedNanos uint64
	if startProfile != nil {
		startDeSoLockedNanos = startProfile.CreatorCoinEntry.DeSoLockedNanos
	}

	// As we fetch from the DB, we filter out moderated / deleted / hidden profiles.
	// We stop fetching when the len(validProfilePubKeys) stops increasing or it hits numToFetch.
	// Remember that we must also filter out profiles from the mempool.
	validProfilePubKeys := [][]byte{}
	prevCount := -1
	nextStartKey := startProfilePubKey
	for len(validProfilePubKeys) > prevCount && len(validProfilePubKeys) < numToFetch {
		prevCount = len(validProfilePubKeys)
		// Fetch some profile pub keys from the db.
		dbProfilePubKeys, _, err := lib.DBGetPaginatedProfilesByDeSoLocked(
			bav.Handle, fes.blockchain.Snapshot(), startDeSoLockedNanos, nextStartKey, numToFetch, false /*fetchEntries*/)
		if err != nil {
			return nil, nil, nil, errors.Wrapf(err, "GetAllProfiles: Problem fetching ProfilePubKeys from db: ")
		}

		// Filter based on moderation level.
		unrestrictedPubKeys, err := fes.FilterOutRestrictedPubKeysFromList(dbProfilePubKeys, readerPK, moderationType, bav)
		if err != nil {
			return nil, nil, nil, errors.Wrapf(err, "GetAllProfiles: Problem filtering dbProfilePubKeys: ")
		}

		// Filter based on isDeleted / IsHidden.
		visibleUnrestrictedPubKeys := [][]byte{}
		for _, dbPubKey := range unrestrictedPubKeys {
			profileEntry := bav.GetProfileEntryForPublicKey(dbPubKey)
			// A profileEntry can be nil if we just transferred the profile associated with
			// the public key to a *new* public key. In this case, the DB will be out of sync
			// with the view and we should wait until the discrepancy is resolved before
			// showing it.
			if profileEntry != nil && !profileEntry.IsDeleted() && !profileEntry.IsHidden {
				visibleUnrestrictedPubKeys = append(visibleUnrestrictedPubKeys, dbPubKey)
			}
		}

		// If we didn't find any keys, break from the loop.
		if len(visibleUnrestrictedPubKeys) == 0 {
			break
		}

		// Append visible and unrestricted pub keys to our valid pub keys list.
		if len(validProfilePubKeys) == 0 {
			validProfilePubKeys = append(validProfilePubKeys, visibleUnrestrictedPubKeys...)
		} else {
			// If this is the second time through the loop, make sure we don't duplicate the start key.
			validProfilePubKeys = append(validProfilePubKeys, visibleUnrestrictedPubKeys[1:]...)
		}
		nextStartKey = dbProfilePubKeys[len(dbProfilePubKeys)-1]
	}

	// At this point, all the profiles should be loaded into the view.
	postsByPublicKey := make(map[lib.PkMapKey][]*lib.PostEntry)
	postEntryReaderStates := make(map[lib.BlockHash]*lib.PostEntryReaderState)
	if getPosts {
		// Do one more pass to load all the posts associated with each profile into the view.
		for _, pubKey := range validProfilePubKeys {
			profileEntry := bav.GetProfileEntryForPublicKey(pubKey)

			// Ignore deleted or rolled-back profiles.
			if profileEntry.IsDeleted() || profileEntry.IsHidden {
				continue
			}

			// Load all the posts
			_, dbPostAndCommentHashes, _, err := lib.DBGetAllPostsAndCommentsForPublicKeyOrderedByTimestamp(
				bav.Handle, fes.blockchain.Snapshot(), profileEntry.PublicKey, false /*fetchEntries*/, 0 /*minTimestamp*/, 0, /*maxTimestamp*/
			)
			if err != nil {
				return nil, nil, nil, errors.Wrapf(
					err, "GetAllPosts: Problem fetching PostEntry's from db: ")
			}

			for _, dbPostOrCommentHash := range dbPostAndCommentHashes {
				bav.GetPostEntryForPostHash(dbPostOrCommentHash)
			}
		}

		// Iterate through all the posts loaded into the view and attach them
		// to the relevant profiles.  Also adds the reader state if a reader pubkey is provided.
		for _, postEntry := range bav.PostHashToPostEntry {
			// Ignore deleted or rolled-back posts and any comments.
			if postEntry.IsDeleted() || postEntry.IsHidden || len(postEntry.ParentStakeID) != 0 {
				continue
			}
			posterPublicKey := lib.MakePkMapKey(postEntry.PosterPublicKey)
			postsForProfile := postsByPublicKey[posterPublicKey]
			postsForProfile = append(postsForProfile, postEntry)
			postsByPublicKey[posterPublicKey] = postsForProfile

			// Create reader state map. Ie, whether the reader has liked the post, etc.
			// If nil is passed in as the readerPK, this is skipped.
			if readerPK != nil {
				postEntryReaderState := bav.GetPostEntryReaderState(readerPK, postEntry)
				postEntryReaderStates[*postEntry.PostHash] = postEntryReaderState
			}
		}
	}

	// Now that the view is a complete picture, let's filter the public keys.
	var viewPubKeys [][]byte
	for _, profileEntry := range bav.ProfilePKIDToProfileEntry {
		viewPubKeys = append(viewPubKeys, profileEntry.PublicKey)
	}
	filteredViewPubKeys, err := fes.FilterOutRestrictedPubKeysFromList(viewPubKeys, readerPK, moderationType, bav)
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "GetAllProfiles: Problem filtering restricted profiles: ")
	}

	// Now that the view mappings are a complete picture, iterate through them
	// and set them on the map we're returning.
	profilesByPublicKey := make(map[lib.PkMapKey]*lib.ProfileEntry)
	for _, pubKey := range filteredViewPubKeys {
		pkidEntry := bav.GetPKIDForPublicKey(pubKey)
		profileEntry := bav.ProfilePKIDToProfileEntry[*pkidEntry.PKID]
		// Ignore deleted or rolled-back profiles.
		if profileEntry.IsDeleted() || profileEntry.IsHidden {
			continue
		}
		profilesByPublicKey[lib.MakePkMapKey(profileEntry.PublicKey)] = profileEntry
	}

	return profilesByPublicKey, postsByPublicKey, postEntryReaderStates, nil
}

func (fes *APIServer) GetPostsForFollowFeedForPublicKey(bav *lib.UtxoView, startAfterPostHash *lib.BlockHash, publicKey []byte, numToFetch int, skipHidden bool, mediaRequired bool, onlyNFTs bool, onlyPosts bool) (
	_postEntries []*lib.PostEntry, _err error) {
	// Get the people who follow publicKey
	// Note: GetFollowEntriesForPublicKey also loads them into the view
	if onlyNFTs && onlyPosts {
		return nil, fmt.Errorf("GetPostsForFollowFeedForPublicKey: OnlyNFTS and OnlyPosts can not be enabled both")
	}

	followEntries, err := bav.GetFollowEntriesForPublicKey(publicKey, false /* getEntriesFollowingPublicKey */)

	if err != nil {
		return nil, errors.Wrapf(
			err, "GetPostsForFollowFeedForPublicKey: Problem fetching FollowEntries from augmented UtxoView: ")
	}

	// Extract the followed pub keys from the follow entries.
	followedPubKeysMap := make(map[lib.PkMapKey][]byte)
	for _, followEntry := range followEntries {
		// Each follow entry needs to be converted back to a public key to stay consistent with
		// the old logic.
		pubKeyForPKID := bav.GetPublicKeyForPKID(followEntry.FollowedPKID)
		if len(pubKeyForPKID) == 0 {
			glog.Errorf("GetPostsForFollowFeedForPublicKey found PKID %v that "+
				"does not have public key mapping; this should never happen",
				lib.PkToString(followEntry.FollowedPKID[:], bav.Params))
			continue
		}
		followedPubKeysMap[lib.MakePkMapKey(pubKeyForPKID)] = pubKeyForPKID
	}

	// Filter out any restricted pub keys.
	filteredPubKeysMap, err := fes.FilterOutRestrictedPubKeysFromMap(followedPubKeysMap, publicKey, "", bav)
	if err != nil {
		return nil, errors.Wrapf(err, "GetPostsForFollowFeedForPublicKey: Problem filtering out restricted public keys: ")
	}

	minTimestampNanos := uint64(time.Now().UTC().AddDate(0, 0, -2).UnixNano()) // two days ago
	// For each of these pub keys, get their posts, and load them into the view too
	for _, followedPubKey := range filteredPubKeysMap {

		_, dbPostAndCommentHashes, _, err := lib.DBGetAllPostsAndCommentsForPublicKeyOrderedByTimestamp(
			bav.Handle, fes.blockchain.Snapshot(), followedPubKey, false /*fetchEntries*/, minTimestampNanos, 0, /*maxTimestampNanos*/
		)
		if err != nil {
			return nil, errors.Wrapf(err, "GetPostsForFollowFeedForPublicKey: Problem fetching PostEntry's from db: ")
		}

		// Iterate through the entries found in the db and force the view to load them.
		// This fills in any gaps in the view so that, after this, the view should contain
		// the union of what it had before plus what was in the db.
		for _, dbPostOrCommentHash := range dbPostAndCommentHashes {
			bav.GetPostEntryForPostHash(dbPostOrCommentHash)
		}
	}

	// Iterate over the view. Put all posts authored by people you follow into an array
	var postEntriesForFollowFeed []*lib.PostEntry
	for _, postEntry := range bav.PostHashToPostEntry {
		// Ignore deleted or hidden posts and any comments.
		if postEntry.IsDeleted() || (postEntry.IsHidden && skipHidden) || len(postEntry.ParentStakeID) != 0 {
			continue
		}

		// mediaRequired set to determine if we only want posts that include media and ignore posts without
		if mediaRequired && !postEntry.HasMedia() {
			continue
		}

		if onlyNFTs && !postEntry.IsNFT {
			continue
		}
		if onlyPosts && postEntry.IsNFT {
			continue
		}

		if _, isFollowedByUser := followedPubKeysMap[lib.MakePkMapKey(postEntry.PosterPublicKey)]; isFollowedByUser {
			postEntriesForFollowFeed = append(postEntriesForFollowFeed, postEntry)
		}
	}

	// Sort the post entries by time (newest to oldest)
	sort.Slice(postEntriesForFollowFeed, func(ii, jj int) bool {
		return postEntriesForFollowFeed[ii].TimestampNanos > postEntriesForFollowFeed[jj].TimestampNanos
	})

	var startIndex = 0
	if startAfterPostHash != nil {
		var indexOfStartAfterPostHash int
		startPostHashFound := false
		// Find the index of the starting post so that we can paginate the result
		for index, postEntry := range postEntriesForFollowFeed {
			if *postEntry.PostHash == *startAfterPostHash {
				indexOfStartAfterPostHash = index
				startPostHashFound = true
				break
			}
		}
		if !startPostHashFound {
			return nil, fmt.Errorf("GetPostsForFollowFeedForPublicKey: start post hash not found in results")
		}
		// the first element of our new slice should be the element AFTER startAfterPostHash
		startIndex = indexOfStartAfterPostHash + 1
	}

	endIndex := lib.MinInt((startIndex + numToFetch), len(postEntriesForFollowFeed))

	return postEntriesForFollowFeed[startIndex:endIndex], nil
}

// Fetches all the posts from the db starting with a given postHash, up to numToFetch.
// This is then joined with mempool and all posts are returned.  Because the mempool may contain
// post changes, the number of posts returned in the map is not guaranteed to be numToFetch.
func (fes *APIServer) GetPostsByTime(bav *lib.UtxoView, startPostHash *lib.BlockHash, readerPK []byte,
	numToFetch int, skipHidden bool, skipVanillaRepost bool, mediaRequired bool, onlyNFTs bool, onlyPosts bool) (
	_corePosts []*lib.PostEntry, _commentsByPostHash map[lib.BlockHash][]*lib.PostEntry, _err error) {

	if onlyNFTs && onlyPosts {
		return nil, nil, fmt.Errorf("GetPostsByTime: OnlyNFTS and OnlyPosts can not be enabled both")
	}

	var startPost *lib.PostEntry
	if startPostHash != nil {
		startPost = bav.GetPostEntryForPostHash(startPostHash)
		if startPost == nil || startPost.IsDeleted() {
			return nil, nil, fmt.Errorf("GetPostsByTime: start post entry not found")
		}
	}

	var startTstampNanos uint64
	if startPost != nil {
		startTstampNanos = startPost.TimestampNanos
	}

	allCorePosts := []*lib.PostEntry{}
	addedPostHashes := make(map[lib.BlockHash]struct{})
	skipFirstPost := false
	for len(allCorePosts) < numToFetch {
		// Start by fetching the posts we have in the db.
		dbPostHashes, _, _, err := lib.DBGetPaginatedPostsOrderedByTime(
			bav.Handle, fes.blockchain.Snapshot(), startTstampNanos, startPostHash, numToFetch, false /*fetchEntries*/, true)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "GetAllProfiles: Problem fetching ProfileEntrys from db: ")
		}

		// If we have not found any new post hashes, we exist
		if len(dbPostHashes) == 0 || (len(dbPostHashes) == 1 && skipFirstPost) {
			break
		}
		skipFirstPost = true

		// Iterate through the entries found in the db and force the view to load them.
		// This fills in any gaps in the view so that, after this, the view should contain
		// the union of what it had before plus what was in the db.
		for _, dbPostHash := range dbPostHashes {
			bav.GetPostEntryForPostHash(dbPostHash)
		}
		startPostHash = dbPostHashes[len(dbPostHashes)-1]
		startTstampNanos = bav.GetPostEntryForPostHash(startPostHash).TimestampNanos

		// Cycle through all the posts and store a map of the PubKeys so we can filter out those
		// that are restricted later.
		postEntryPubKeyMap := make(map[lib.PkMapKey][]byte)
		for _, postEntry := range bav.PostHashToPostEntry {
			// Ignore deleted / rolled-back / hidden posts.
			if postEntry.IsDeleted() || (postEntry.IsHidden && skipHidden) {
				continue
			}

			// If media is required and this post does not have media, skip it.
			if mediaRequired && !postEntry.HasMedia() {
				continue
			}

			if onlyNFTs && !postEntry.IsNFT {
				continue
			}
			if onlyPosts && postEntry.IsNFT {
				continue
			}

			// We make sure that the post isn't a comment.
			if len(postEntry.ParentStakeID) == 0 {
				postEntryPubKeyMap[lib.MakePkMapKey(postEntry.PosterPublicKey)] = postEntry.PosterPublicKey
			}
		}

		// Filter restricted public keys out of the posts.
		filteredPostEntryPubKeyMap, err := fes.FilterOutRestrictedPubKeysFromMap(postEntryPubKeyMap, readerPK, "leaderboard", bav)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "GetAllProfiles: Problem filtering restricted profiles from map: ")
		}

		// At this point, all the posts should be loaded into the view.

		for _, postEntry := range bav.PostHashToPostEntry {

			// Ignore deleted or rolled-back posts. Skip vanilla repost posts if skipVanillaRepost is true.
			if postEntry.IsDeleted() || (postEntry.IsHidden && skipHidden) || (lib.IsVanillaRepost(postEntry) && skipVanillaRepost) {
				continue
			}

			// If media is required and this post does not have media, skip it.
			if mediaRequired && !postEntry.HasMedia() {
				continue
			}

			if onlyNFTs && !postEntry.IsNFT {
				continue
			}
			if onlyPosts && postEntry.IsNFT {
				continue
			}

			// If this post has already been added to the list of all core posts, we skip it.
			if _, postAdded := addedPostHashes[*postEntry.PostHash]; postAdded {
				continue
			}

			// Make sure this isn't a comment and then make sure the public key isn't restricted.
			if len(postEntry.ParentStakeID) == 0 {
				if filteredPostEntryPubKeyMap[lib.MakePkMapKey(postEntry.PosterPublicKey)] == nil {
					continue
				}
				allCorePosts = append(allCorePosts, postEntry)
				addedPostHashes[*postEntry.PostHash] = struct{}{}
			}
		}
	}
	// We no longer return comments with the posts.  Too inefficient.
	commentsByPostHash := make(map[lib.BlockHash][]*lib.PostEntry)

	return allCorePosts, commentsByPostHash, nil
}
