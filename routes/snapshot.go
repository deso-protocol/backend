package routes

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
)

type GetSnapshotEpochMetadataResponse struct {
	SnapshotBlockHeight      uint64 `safeForLogging:"true"`
	CurrentEpochChecksumHex  string `safeForLogging:"true"`
	CurrentEpochBlockHashHex string `safeForLogging:"true"`
}

func (fes *APIServer) GetSnapshotEpochMetadata(ww http.ResponseWriter, req *http.Request) {
	if fes.blockchain.Snapshot() == nil || fes.blockchain.Snapshot().CurrentEpochSnapshotMetadata == nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetSnapshotEpochMetadata: Node doesn't compute snapshots"))
		return
	}
	response := GetSnapshotEpochMetadataResponse{
		SnapshotBlockHeight:      fes.blockchain.Snapshot().CurrentEpochSnapshotMetadata.FirstSnapshotBlockHeight,
		CurrentEpochChecksumHex:  hex.EncodeToString(fes.blockchain.Snapshot().CurrentEpochSnapshotMetadata.CurrentEpochChecksumBytes),
		CurrentEpochBlockHashHex: hex.EncodeToString(fes.blockchain.Snapshot().CurrentEpochSnapshotMetadata.CurrentEpochBlockHash.ToBytes()),
	}
	if err := json.NewEncoder(ww).Encode(response); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetSnapshotEpochMetadata: Problem encoding response as JSON: %v", err))
		return
	}
}

type GetStateChecksumResponse struct {
	StateChecksumHex string `safeForLogging:"true"`
}

func (fes *APIServer) GetStateChecksum(ww http.ResponseWriter, req *http.Request) {
	if fes.blockchain.Snapshot() == nil || fes.blockchain.Snapshot().CurrentEpochSnapshotMetadata == nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetStateChecksum: Node doesn't compute snapshots"))
		return
	}

	checksumBytes, err := fes.blockchain.Snapshot().Checksum.ToBytes()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetStateChecksum: Problem encoding checksum to bytes: %v", err))
		return
	}
	response := GetStateChecksumResponse{
		StateChecksumHex: hex.EncodeToString(checksumBytes),
	}
	if err := json.NewEncoder(ww).Encode(response); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetStateChecksum: Problem encoding response as JSON: %v", err))
		return
	}
}
