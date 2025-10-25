package routes

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/deso-protocol/core/lib"
	"github.com/golang/glog"
)

type GetBlockTemplateRequest struct {
	PublicKeyBase58Check string

	// The number of headers the miner wants to receive. Each header will have a
	// random ExtraData associated with it, which gives it a unique MerkleRoot.
	// This ensures that different miners don't accidentally run through the same
	// search space.
	NumHeaders int64

	// Defaults to zero, which allows it to remain backwards-compatible with miners
	// that use an older version. Setting version=1 allows miners to hash using 128-bit
	// nonces, which may be advantageous.
	HeaderVersion uint32
}

type GetBlockTemplateResponse struct {
	Headers [][]byte

	// Each header returned has an ExtraData associated with it that was embedded
	// in the block reward and which must be returned when SubmitBlock is called.
	//
	// TODO: This field should really be renamed ExtraDatas in JSON, but doing so
	// would break miners that are still running with v0 headers, so we will wait
	// to change this until v0 headers are fully deprecated.
	ExtraDatas []uint64 `json:"ExtraNonces"`

	// An identifier that the node uses to map a call to SubmitBlock back to the
	// block that was used to generate the headers.
	BlockID string

	// The difficulty target expressed in hex
	DifficultyTargetHex string

	// These fields provide metadata for the admin tab.
	LatestBlockTemplateStats *lib.BlockTemplateStats

	// TODO: The pool should return a merkle root that proves that the caller's
	// public key was the one that was included in the BlockRewardMetadata. This
	// isn't hard to do, and it would make this whole thing trustless, which would
	// be amazing.
}

// GetBlockTemplate ...
func (fes *APIServer) GetBlockTemplate(ww http.ResponseWriter, req *http.Request) {

	if fes.blockProducer == nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetBlockTemplate: This node is not running a block producer. "+
			"Restart it with --max_block_templates_to_cache > 0"))
		return
	}

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetBlockTemplateRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetBlockTemplate: Problem parsing request body: %v", err))
		return
	}

	// Reject requests for v0 headers to phase them out.
	if requestData.HeaderVersion == lib.HeaderVersion0 {
		_AddBadRequestError(ww, fmt.Sprintf("GetBlockTemplate: Error: Header version v0 not supported. "+
			"Please upgrade your miner to request v1 headers, and to hash "+
			"with DeSoHashV1"))
		return
	}

	if requestData.NumHeaders > 1000000 {
		_AddBadRequestError(ww, fmt.Sprintf("GetBlockTemplate: Error: NumHeaders must be less than 1000000"))
		return
	}

	// Decode the public key
	pkBytes, _, err := lib.Base58CheckDecode(requestData.PublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetBlockTemplate: Problem parsing public key: %v", err))
		return
	}

	blockID, headers, extraDatas, diffTarget, err := fes.blockProducer.GetHeadersAndExtraDatas(
		pkBytes, requestData.NumHeaders, requestData.HeaderVersion)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetBlockTemplate: Problem generating headers: %v", err))
		return
	}

	difficultyTargetHex := ""
	if diffTarget != nil {
		difficultyTargetHex = hex.EncodeToString(diffTarget[:])
	}

	res := &GetBlockTemplateResponse{
		BlockID:                  blockID,
		Headers:                  headers,
		ExtraDatas:               extraDatas,
		DifficultyTargetHex:      difficultyTargetHex,
		LatestBlockTemplateStats: fes.blockProducer.GetLatestBlockTemplateStats(),
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetBlockTemplate: Problem encoding response as JSON: %v", err))
		return
	}
}

type SubmitBlockRequest struct {
	PublicKeyBase58Check string

	Header []byte

	// TODO: This field should be renamed ExtraData in JSON, but doing so would break
	// existing miners so we should make this update after we switch away from v0.
	ExtraData uint64 `json:"ExtraNonce"`

	BlockID string
}

// SubmitBlockResponse ...
type SubmitBlockResponse struct {
	IsMainChain bool
	IsOrphan    bool
}

func (fes *APIServer) SubmitBlock(ww http.ResponseWriter, req *http.Request) {

	if fes.blockProducer == nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitBlock: This node is not running a block producer. "+
			"Restart it with --max_block_templates_to_cache > 0"))
		return
	}

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := SubmitBlockRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitBlock: Problem parsing request body: %v", err))
		return
	}

	glog.Infof("Currently submitting block for block ID: %v", requestData.BlockID)

	// Log all of the contents of the request
	glog.Infof("SubmitBlock: PublicKeyBase58Check: %v, Header: %v, ExtraData: %v, BlockID: %v",
		requestData.PublicKeyBase58Check, hex.EncodeToString(requestData.Header), requestData.ExtraData, requestData.BlockID)

	// Decode the public key
	pkBytes, _, err := lib.Base58CheckDecode(requestData.PublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitBlock: Problem parsing public key: %v", err))
		return
	}

	// Look up the block for the corresponding BlockID
	blockFound, err := fes.blockProducer.GetCopyOfRecentBlock(requestData.BlockID)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitBlock: Problem parsing request body: %v", err))
		return
	}

	// Swap in the ExtraNonce and the public key from the request.
	blockFound.Txns[0].TxOutputs[0].PublicKey = pkBytes
	blockFound.Txns[0].TxnMeta.(*lib.BlockRewardMetadataa).ExtraData = lib.UintToBuf(requestData.ExtraData)

	blockFound, err = lib.RecomputeBlockRewardWithBlockRewardOutputPublicKey(blockFound, pkBytes, fes.Params)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitBlock: Problem recomputing block reward: %v", err))
		return
	}

	header := &lib.MsgDeSoHeader{}
	if err := header.FromBytes(requestData.Header); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitBlock: Problem parsing header: %v", err))
		return
	}
	blockFound.Header = header

	// This will sign the block with the BlockProducer's key, if a key was set
	if err := fes.blockProducer.SignBlock(blockFound); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("Error signing block: %v", err))
		return
	}

	// Process the block. If the block is connected and/or accepted, the Server
	// will be informed about it. This will cause it to be relayed appropriately.
	//
	// TODO: Signature checking slows things down because it acquires the ChainLock.
	// The optimal solution is to check signatures in a way that doesn't acquire the
	// ChainLock, which is what Bitcoin Core does.
	isMainChain, isOrphan, _, err := fes.blockchain.ProcessBlock(
		blockFound, nil, true /*verifySignatures*/)
	glog.V(1).Infof("Called ProcessBlock/ConnectBlock: isMainChain=(%v), isOrphan=(%v), err=(%v)",
		isMainChain, isOrphan, err)
	if err != nil {
		errorMsg := fmt.Sprintf("ERROR calling ProcessBlock/ConnectBlock: isMainChain=(%v), isOrphan=(%v), err=(%v)",
			isMainChain, isOrphan, err)
		glog.V(1).Infof(errorMsg)
		_AddBadRequestError(ww, errorMsg)
		return
	}
	glog.V(1).Infof("ConnectBlock SUCCESS")

	// If we connected a block on the main chain, force an update in the BlockProducer
	if isMainChain {
		err = fes.blockProducer.UpdateLatestBlockTemplate()
		if err != nil {
			// If we hit an error, log it and sleep for a second. This could happen due to us
			// being in the middle of processing a block or something.
			glog.Errorf("Error producing block template: %v", err)
		}
	}

	// TODO: It would probably be nice if we could return some new headers to the miner
	// in this call in the event that we actually processed their block.

	// Return all the data associated with the transaction in the response
	res := SubmitBlockResponse{
		IsMainChain: isMainChain,
		IsOrphan:    isOrphan,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitBlock: Problem encoding response as JSON: %v", err))
		return
	}
}
