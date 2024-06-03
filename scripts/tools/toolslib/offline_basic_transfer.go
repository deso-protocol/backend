package toolslib

import (
	"github.com/btcsuite/btcd/btcec"
	"github.com/deso-protocol/core/lib"
	"github.com/pkg/errors"
)

// ACCOUNT GENERATION
func accountGeneration() (*btcec.PrivateKey, *btcec.PublicKey, error) {
	privKey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return nil, nil, errors.Wrap(err, "accountGeneration() failed to generate private key")
	}
	pubKey := privKey.PubKey()
	return privKey, pubKey, nil
}

// Build Offline Transaction
func _generateUnsignedSendDeSoOffline(
	senderPubKey *btcec.PublicKey,
	recipientPubKey *btcec.PublicKey,
	amountNanos int64,
	nonce *lib.DeSoNonce,
	feeRateNanosPerKB uint64,
) (*lib.MsgDeSoTxn, error) {
	txn := &lib.MsgDeSoTxn{
		TxnVersion: lib.DeSoTxnVersion1,
		PublicKey:  senderPubKey.SerializeCompressed(),
		TxnMeta:    &lib.BasicTransferMetadata{},
		TxOutputs: []*lib.DeSoOutput{
			{
				PublicKey:   recipientPubKey.SerializeCompressed(),
				AmountNanos: uint64(amountNanos),
			},
		},
		TxnNonce: nonce,
	}
	return _computeFee(txn, feeRateNanosPerKB)
}

// Build offline transaction, offline signature transactions, and submit to node
func SendDeSoOffline(senderPubKey *btcec.PublicKey,
	senderPrivKey *btcec.PrivateKey,
	recipientPubKey *btcec.PublicKey, amountNanos int64, nonce *lib.DeSoNonce, feeRateNanosPerKB uint64, node string) error {
	txn, err := _generateUnsignedSendDeSoOffline(senderPubKey, recipientPubKey, amountNanos, nonce, feeRateNanosPerKB)
	if err != nil {
		return errors.Wrap(err, "SendDeSoLocal() failed to call _generateUnsignedSendDeSoLocal()")
	}

	// Sign the transaction
	signature, err := txn.Sign(senderPrivKey)
	if err != nil {
		return errors.Wrap(err, "SendDeSoLocal() failed to sign transaction")
	}
	txn.Signature.SetSignature(signature)

	// Submit the transaction to the node
	err = SubmitTransactionToNode(txn, node)
	if err != nil {
		return errors.Wrap(err, "SendDeSoLocal() failed to submit transaction")
	}
	return nil
}

// Helper to compute the fee for a transaction
func _computeFee(txn *lib.MsgDeSoTxn, feeRateNanosPerKB uint64) (*lib.MsgDeSoTxn, error) {
	feeAmountNanos := 0
	prevFeeAmountNanos := 0
	for feeAmountNanos == 0 || feeAmountNanos > prevFeeAmountNanos {
		prevFeeAmountNanos = feeAmountNanos
		preSigBytes, err := txn.ToBytes(true)
		if err != nil {
			return nil, err
		}
		txnWithSigLen := len(preSigBytes) + 74 // 71 is the maximum length of a signature, but some places have 74. Using 74 to be safe.
		feeAmountNanos = int(feeRateNanosPerKB * uint64(txnWithSigLen) / 1000)
		if (uint64(txnWithSigLen)*feeRateNanosPerKB)%1000 != 0 {
			feeAmountNanos++
		}
		lib.UpdateTxnFee(txn, uint64(feeAmountNanos))
	}
	return txn, nil
}

// Transaction Hash
func transactionHash(txn *lib.MsgDeSoTxn) string {
	return txn.Hash().String()
}

// Transaction ID
func transactionID(txn *lib.MsgDeSoTxn, params *lib.DeSoParams) string {
	return lib.PkToString(txn.PublicKey, params)
}

// Serialize unsigned transaction
func serializeUnsignedTransaction(txn *lib.MsgDeSoTxn) ([]byte, error) {
	return txn.ToBytes(true)
}

// Serialize signed transaction
func serializeTransaction(txn *lib.MsgDeSoTxn) ([]byte, error) {
	return txn.ToBytes(false)
}

// Deserialize transaction
func deserializeTransaction(txnBytes []byte) (*lib.MsgDeSoTxn, error) {
	txn := &lib.MsgDeSoTxn{}
	err := txn.FromBytes(txnBytes)
	if err != nil {
		return nil, err
	}
	return txn, nil
}
