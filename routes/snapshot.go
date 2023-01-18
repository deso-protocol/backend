package routes

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
)

type GetSnapshotEpochMetadataResponse struct {
	SnapshotBlockHeight uint64 `safeForLogging:"true"`

	CurrentEpochChecksumHex string `safeForLogging:"true"`

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
