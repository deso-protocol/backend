package routes

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/lib"
	"io"
	"net/http"
)

type RegisterAsValidatorRequest struct {
	TransactorPublicKeyBase58Check string            `safeForLogging:"true"`
	Domains                        []string          `safeForLogging:"true"`
	DisableDelegatedStake          bool              `safeForLogging:"true"`
	VotingPublicKey                string            `safeForLogging:"true"`
	VotingPublicKeySignature       string            `safeForLogging:"true"`
	ExtraData                      map[string]string `safeForLogging:"true"`
	MinFeeRateNanosPerKB           uint64            `safeForLogging:"true"`
	TransactionFees                []TransactionFee  `safeForLogging:"true"`
}

type UnregisterAsValidatorRequest struct {
	TransactorPublicKeyBase58Check string            `safeForLogging:"true"`
	ExtraData                      map[string]string `safeForLogging:"true"`
	MinFeeRateNanosPerKB           uint64            `safeForLogging:"true"`
	TransactionFees                []TransactionFee  `safeForLogging:"true"`
}

type ValidatorTxnResponse struct {
	SpendAmountNanos  uint64
	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgDeSoTxn
	TransactionHex    string
	TxnHashHex        string
}

func (fes *APIServer) RegisterAsValidator(ww http.ResponseWriter, req *http.Request) {
	// Decode request body.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := RegisterAsValidatorRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, "RegisterAsValidator: problem parsing request body")
		return
	}

	// Convert TransactorPublicKeyBase58Check to TransactorPublicKeyBytes.
	if requestData.TransactorPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, "RegisterAsValidator: must provide a TransactorPublicKeyBase58Check")
		return
	}
	transactorPublicKeyBytes, err := GetPubKeyBytesFromBase58Check(requestData.TransactorPublicKeyBase58Check)
	if err != nil {
		_AddInternalServerError(ww, "RegisterAsValidator: problem getting public key for the transactor")
		return
	}

	// Convert Domains from []string to [][]byte.
	var domains [][]byte
	for _, domain := range requestData.Domains {
		domains = append(domains, []byte(domain))
	}

	// Convert VotingPublicKeyString to VotingPublicKey.
	votingPublicKey, err := (&bls.PublicKey{}).FromString(requestData.VotingPublicKey)
	if err != nil {
		_AddBadRequestError(ww, "RegisterAsValidator: problem parsing VotingPublicKey")
		return
	}

	// Convert VotingPublicKeySignatureString to VotingPublicKeySignature.
	votingPublicKeySignature, err := (&bls.Signature{}).FromString(requestData.VotingPublicKeySignature)
	if err != nil {
		_AddBadRequestError(ww, "RegisterAsValidator: problem parsing VotingPublicKeySignature")
		return
	}

	// Parse ExtraData.
	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, "RegisterAsValidator: invalid ExtraData provided")
		return
	}

	// Compute the additional transaction fees as specified
	// by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(
		lib.TxnTypeRegisterAsValidator,
		transactorPublicKeyBytes,
		requestData.TransactionFees,
	)
	if err != nil {
		_AddBadRequestError(ww, "RegisterAsValidator: specified TransactionFees are invalid")
		return
	}

	// Create transaction.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateRegisterAsValidatorTxn(
		transactorPublicKeyBytes,
		&lib.RegisterAsValidatorMetadata{
			Domains:                  domains,
			DisableDelegatedStake:    requestData.DisableDelegatedStake,
			VotingPublicKey:          votingPublicKey,
			VotingPublicKeySignature: votingPublicKeySignature,
		},
		extraData,
		requestData.MinFeeRateNanosPerKB,
		fes.backendServer.GetMempool(),
		additionalOutputs,
	)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("RegisterAsValidator: problem creating txn: %v", err))
		return
	}

	// Construct response.
	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddInternalServerError(ww, "RegisterAsValidator: problem encoding txn to bytes")
		return
	}
	res := ValidatorTxnResponse{
		SpendAmountNanos:  totalInput - changeAmount - fees,
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
		TxnHashHex:        txn.Hash().String(),
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, "RegisterAsValidator: problem encoding response as JSON")
		return
	}
}

func (fes *APIServer) UnregisterAsValidator(ww http.ResponseWriter, req *http.Request) {
	// Decode request body.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := UnregisterAsValidatorRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, "UnregisterAsValidator: problem parsing request body")
		return
	}

	// Convert TransactorPublicKeyBase58Check to TransactorPublicKeyBytes.
	if requestData.TransactorPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, "UnregisterAsValidator: must provide a TransactorPublicKeyBase58Check")
		return
	}
	transactorPublicKeyBytes, err := GetPubKeyBytesFromBase58Check(requestData.TransactorPublicKeyBase58Check)
	if err != nil {
		_AddInternalServerError(ww, "UnregisterAsValidator: problem getting public key for the transactor")
		return
	}

	// Parse ExtraData.
	extraData, err := EncodeExtraDataMap(requestData.ExtraData)
	if err != nil {
		_AddBadRequestError(ww, "UnregisterAsValidator: invalid ExtraData provided")
		return
	}

	// Compute the additional transaction fees as specified
	// by the request body and the node-level fees.
	additionalOutputs, err := fes.getTransactionFee(
		lib.TxnTypeRegisterAsValidator,
		transactorPublicKeyBytes,
		requestData.TransactionFees,
	)
	if err != nil {
		_AddBadRequestError(ww, "UnregisterAsValidator: specified TransactionFees are invalid")
		return
	}

	// Create transaction.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateUnregisterAsValidatorTxn(
		transactorPublicKeyBytes,
		&lib.UnregisterAsValidatorMetadata{},
		extraData,
		requestData.MinFeeRateNanosPerKB,
		fes.backendServer.GetMempool(),
		additionalOutputs,
	)
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("UnregisterAsValidator: problem creating txn: %v", err))
		return
	}

	// Construct response.
	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddInternalServerError(ww, "UnregisterAsValidator: problem encoding txn to bytes")
		return
	}
	res := ValidatorTxnResponse{
		SpendAmountNanos:  totalInput - changeAmount - fees,
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
		TxnHashHex:        txn.Hash().String(),
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, "UnregisterAsValidator: problem encoding response as JSON")
		return
	}
}
