package routes

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"time"

	"github.com/bitclout/core/lib"
)

type NFTEntryResponse struct {
	OwnerPublicKeyBase58Check  string                `safeForLogging:"true"`
	ProfileEntryResponse       *ProfileEntryResponse `json:",omitempty"`
	PostEntryResponse          *PostEntryResponse    `json:",omitempty"`
	SerialNumber               uint64                `safeForLogging:"true"`
	IsForSale                  bool                  `safeForLogging:"true"`
	MinBidAmountNanos          uint64                `safeForLogging:"true"`
	LastAcceptedBidAmountNanos uint64                `safeForLogging:"true"`

	HighestBidAmountNanos uint64 `safeForLogging:"true"`
	LowestBidAmountNanos uint64 `safeForLogging:"true"`
	// These fields are only populated when the reader is the owner.
	LastOwnerPublicKeyBase58Check *string `json:",omitempty"`
	EncryptedUnlockableText       *string `json:",omitempty"`
}

type NFTCollectionResponse struct {
	ProfileEntryResponse   *ProfileEntryResponse `json:",omitempty"`
	PostEntryResponse      *PostEntryResponse    `json:",omitempty"`
	HighestBidAmountNanos  uint64                `safeForLogging:"true"`
	LowestBidAmountNanos   uint64                `safeForLogging:"true"`
	NumCopiesForSale       uint64                `safeForLogging:"true"`
	AvailableSerialNumbers []uint64              `safeForLogging:"true"`
}

type NFTBidEntryResponse struct {
	PublicKeyBase58Check string
	ProfileEntryResponse *ProfileEntryResponse `json:",omitempty"`
	PostHashHex          *string               `json:",omitempty"`
	// likely nil if included in a list of NFTBidEntryResponses for a single NFT
	PostEntryResponse *PostEntryResponse `json:",omitempty"`
	SerialNumber      uint64             `safeForLogging:"true"`
	BidAmountNanos    uint64             `safeForLogging:"true"`

	// What is the highest bid and the lowest bid on this serial number
	HighestBidAmountNanos *uint64 `json:",omitempty"`
	LowestBidAmountNanos *uint64 `json:",omitempty"`

	// Current balance of this bidder.
	BidderBalanceNanos uint64
}

type CreateNFTRequest struct {
	UpdaterPublicKeyBase58Check    string `safeForLogging:"true"`
	NFTPostHashHex                 string `safeForLogging:"true"`
	NumCopies                      int    `safeForLogging:"true"`
	NFTRoyaltyToCreatorBasisPoints int    `safeForLogging:"true"`
	NFTRoyaltyToCoinBasisPoints    int    `safeForLogging:"true"`
	HasUnlockable                  bool   `safeForLogging:"true"`
	IsForSale                      bool   `safeForLogging:"true"`
	MinBidAmountNanos              int    `safeForLogging:"true"`

	MinFeeRateNanosPerKB uint64 `safeForLogging:"true"`
}

type CreateNFTResponse struct {
	NFTPostHashHex string `safeForLogging:"true"`

	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgBitCloutTxn
	TransactionHex    string
}

func (fes *APIServer) CreateNFT(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := CreateNFTRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateNFT: Error parsing request body: %v", err))
		return
	}

	// Grab a view (needed for getting global params, etc).
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateNFT: Error getting utxoView: %v", err))
		return
	}

	// Validate the requestData.
	if requestData.NFTPostHashHex == "" {
		_AddBadRequestError(ww, fmt.Sprintf("CreateNFT: Must include NFTPostHashHex"))
		return

	} else if requestData.UpdaterPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprintf("CreateNFT: Must include UpdaterPublicKeyBase58Check"))
		return
	} else if utxoView.GlobalParamsEntry.MaxCopiesPerNFT == 0 {
		_AddBadRequestError(ww,
			"NFT minting has not been enabled yet. Check back soon :)")
		return

	} else if requestData.NumCopies <= 0 || requestData.NumCopies > int(utxoView.GlobalParamsEntry.MaxCopiesPerNFT) {
		_AddBadRequestError(ww, fmt.Sprintf(
			"CreateNFT: NumCopies must be between %d and %d, received: %d",
			1, utxoView.GlobalParamsEntry.MaxCopiesPerNFT, requestData.NumCopies))
		return

	} else if requestData.NFTRoyaltyToCreatorBasisPoints < 0 || requestData.NFTRoyaltyToCreatorBasisPoints > int(fes.Params.MaxNFTRoyaltyBasisPoints) {
		_AddBadRequestError(ww, fmt.Sprintf(
			"CreateNFT: NFTRoyaltyToCreatorBasisPoints must be between %d and %d, received: %d",
			0, fes.Params.MaxNFTRoyaltyBasisPoints, requestData.NFTRoyaltyToCreatorBasisPoints))
		return

	} else if requestData.MinBidAmountNanos < 0 {
		_AddBadRequestError(ww, fmt.Sprintf(
			"CreateNFT: MinBidAmountNanos must be >= 0, got: %d", requestData.MinBidAmountNanos))
		return

	} else if requestData.NFTRoyaltyToCoinBasisPoints < 0 || requestData.NFTRoyaltyToCoinBasisPoints > int(fes.Params.MaxNFTRoyaltyBasisPoints) {
		_AddBadRequestError(ww, fmt.Sprintf(
			"CreateNFT: NFTRoyaltyToCoinBasisPoints must be between %d and %d, received: %d",
			0, fes.Params.MaxNFTRoyaltyBasisPoints, requestData.NFTRoyaltyToCoinBasisPoints))
		return
	}

	// Get the PostHash for the NFT we are creating.
	nftPostHashBytes, err := hex.DecodeString(requestData.NFTPostHashHex)
	if err != nil || len(nftPostHashBytes) != lib.HashSizeBytes {
		_AddBadRequestError(ww, fmt.Sprintf(
			"CreateNFT: Error parsing post hash %v: %v",
			requestData.NFTPostHashHex, err))
		return
	}
	nftPostHash := &lib.BlockHash{}
	copy(nftPostHash[:], nftPostHashBytes)

	// Get the updater's public key.
	updaterPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.UpdaterPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateNFT: Problem decoding user public key: %v", err))
		return
	}

	nftFee := utxoView.GlobalParamsEntry.CreateNFTFeeNanos * uint64(requestData.NumCopies)

	// Try and create the create NFT txn for the user.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateCreateNFTTxn(
		updaterPublicKeyBytes,
		nftPostHash,
		uint64(requestData.NumCopies),
		requestData.HasUnlockable,
		requestData.IsForSale,
		uint64(requestData.MinBidAmountNanos),
		nftFee,
		uint64(requestData.NFTRoyaltyToCreatorBasisPoints),
		uint64(requestData.NFTRoyaltyToCoinBasisPoints),
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool())
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateNFT: Problem creating transaction: %v", err))
		return
	}

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateNFT: Problem serializing transaction: %v", err))
		return
	}

	// Return all the data associated with the transaction in the response
	res := CreateNFTResponse{
		NFTPostHashHex:    requestData.NFTPostHashHex,
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("CreateNFT: Problem serializing object to JSON: %v", err))
		return
	}
}

type UpdateNFTRequest struct {
	UpdaterPublicKeyBase58Check string `safeForLogging:"true"`
	NFTPostHashHex              string `safeForLogging:"true"`
	SerialNumber                int    `safeForLogging:"true"`
	IsForSale                   bool   `safeForLogging:"true"`
	MinBidAmountNanos           int    `safeForLogging:"true"`

	MinFeeRateNanosPerKB uint64 `safeForLogging:"true"`
}

type UpdateNFTResponse struct {
	NFTPostHashHex string `safeForLogging:"true"`
	SerialNumber   int    `safeForLogging:"true"`

	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgBitCloutTxn
	TransactionHex    string
}

func (fes *APIServer) UpdateNFT(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := UpdateNFTRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateNFT: Error parsing request body: %v", err))
		return
	}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateNFT: Error getting utxoView: %v", err))
		return
	}

	// Do a simple validation of the requestData.
	if requestData.NFTPostHashHex == "" {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateNFT: Must include NFTPostHashHex"))
		return

	} else if requestData.UpdaterPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateNFT: Must include UpdaterPublicKeyBase58Check"))
		return

	} else if requestData.SerialNumber <= 0 || requestData.SerialNumber > int(utxoView.GlobalParamsEntry.MaxCopiesPerNFT) {
		_AddBadRequestError(ww, fmt.Sprintf(
			"UpdateNFT: SerialNumbers must be between %d and %d, received: %d",
			1, utxoView.GlobalParamsEntry.MaxCopiesPerNFT, requestData.SerialNumber))
		return

	} else if requestData.MinBidAmountNanos < 0 {
		_AddBadRequestError(ww, fmt.Sprintf(
			"UpdateNFT: MinBidAmountNanos must be >= 0, got: %d", requestData.MinBidAmountNanos))
		return
	}

	// Get the PostHash for the NFT.
	nftPostHashBytes, err := hex.DecodeString(requestData.NFTPostHashHex)
	if err != nil || len(nftPostHashBytes) != lib.HashSizeBytes {
		_AddBadRequestError(ww, fmt.Sprintf(
			"UpdateNFT: Error parsing post hash %v: %v",
			requestData.NFTPostHashHex, err))
		return
	}
	nftPostHash := &lib.BlockHash{}
	copy(nftPostHash[:], nftPostHashBytes)

	// Get the updater's public key.
	updaterPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.UpdaterPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateNFT: Problem decoding user public key: %v", err))
		return
	}

	// Get the NFT in question so we can do a more hardcore validation of the request data.
	nftKey := lib.MakeNFTKey(nftPostHash, uint64(requestData.SerialNumber))
	nftEntry := utxoView.GetNFTEntryForNFTKey(&nftKey)
	if nftEntry == nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"UpdateNFT: Error could not find the NFT an NFT with postHash %v and serialNumber %d",
			requestData.NFTPostHashHex, requestData.SerialNumber))
		return

	} else if nftEntry.IsForSale == requestData.IsForSale {
		_AddBadRequestError(ww, fmt.Sprintf(
			"UpdateNFT: NFT already has IsForSale=%v", requestData.IsForSale))
		return

	}

	// Try and create the update NFT txn for the user.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateUpdateNFTTxn(
		updaterPublicKeyBytes,
		nftPostHash,
		uint64(requestData.SerialNumber),
		requestData.IsForSale,
		uint64(requestData.MinBidAmountNanos),
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool())
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateNFT: Problem creating transaction: %v", err))
		return
	}

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateNFT: Problem serializing transaction: %v", err))
		return
	}

	// Return all the data associated with the transaction in the response
	res := UpdateNFTResponse{
		NFTPostHashHex: requestData.NFTPostHashHex,
		SerialNumber:   requestData.SerialNumber,

		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("UpdateNFT: Problem serializing object to JSON: %v", err))
		return
	}
}

type CreateNFTBidRequest struct {
	UpdaterPublicKeyBase58Check string `safeForLogging:"true"`
	NFTPostHashHex              string `safeForLogging:"true"`
	SerialNumber                int    `safeForLogging:"true"`
	BidAmountNanos              int    `safeForLogging:"true"`

	MinFeeRateNanosPerKB uint64 `safeForLogging:"true"`
}

type CreateNFTBidResponse struct {
	UpdaterPublicKeyBase58Check string `safeForLogging:"true"`
	NFTPostHashHex              string `safeForLogging:"true"`
	SerialNumber                int    `safeForLogging:"true"`
	BidAmountNanos              int    `safeForLogging:"true"`

	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgBitCloutTxn
	TransactionHex    string
}

func (fes *APIServer) CreateNFTBid(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := CreateNFTBidRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateNFTBid: Error parsing request body: %v", err))
		return
	}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateNFTBid: Error getting utxoView: %v", err))
		return
	}

	// Do a simple validation of the requestData.
	if requestData.NFTPostHashHex == "" {
		_AddBadRequestError(ww, fmt.Sprintf("CreateNFTBid: Must include NFTPostHashHex"))
		return

	} else if requestData.UpdaterPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprintf("CreateNFTBid: Must include UpdaterPublicKeyBase58Check"))
		return

	} else if requestData.SerialNumber <= 0 || requestData.SerialNumber > int(utxoView.GlobalParamsEntry.MaxCopiesPerNFT) {
		_AddBadRequestError(ww, fmt.Sprintf(
			"CreateNFTBid: SerialNumbers must be between %d and %d, received: %d",
			1, utxoView.GlobalParamsEntry.MaxCopiesPerNFT, requestData.SerialNumber))
		return

	} else if requestData.BidAmountNanos < 0 {
		_AddBadRequestError(ww, fmt.Sprintf(
			"CreateNFTBid: BidAmountNanos must be non-negative, received: %d", requestData.BidAmountNanos))
		return
	}

	// Get the PostHash for the NFT.
	nftPostHashBytes, err := hex.DecodeString(requestData.NFTPostHashHex)
	if err != nil || len(nftPostHashBytes) != lib.HashSizeBytes {
		_AddBadRequestError(ww, fmt.Sprintf(
			"CreateNFTBid: Error parsing post hash %v: %v",
			requestData.NFTPostHashHex, err))
		return
	}
	nftPostHash := &lib.BlockHash{}
	copy(nftPostHash[:], nftPostHashBytes)

	// Get the updater's public key.
	updaterPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.UpdaterPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateNFTBid: Problem decoding user public key: %v", err))
		return
	}

	// Get the NFT in question so we can do a more hardcore validation of the request data.
	if requestData.SerialNumber != 0 {
		nftKey := lib.MakeNFTKey(nftPostHash, uint64(requestData.SerialNumber))
		nftEntry := utxoView.GetNFTEntryForNFTKey(&nftKey)
		if nftEntry == nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"CreateNFTBid: Error could not find the NFT an NFT with postHash %v and serialNumber %d",
				requestData.NFTPostHashHex, requestData.SerialNumber))
			return

		} else if !nftEntry.IsForSale {
			_AddBadRequestError(ww, fmt.Sprintf(
				"CreateNFTBid: NFT with postHash %v and serialNumber %d is not for sale.",
				requestData.NFTPostHashHex, requestData.SerialNumber))
			return
		}
	} else {
		// The user can bid on serial number zero as long as it is the post hash provided is an NFT.
		postEntry := utxoView.GetPostEntryForPostHash(nftPostHash)
		if postEntry == nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"CreateNFTBid: Error could not find a post with postHash %v", requestData.NFTPostHashHex))
			return

		} else if !postEntry.IsNFT {
			_AddBadRequestError(ww, fmt.Sprintf(
				"CreateNFTBid: Post with postHash %v is not an NFT.", requestData.NFTPostHashHex))
			return
		}
	}

	// RPH-FIXME: Make sure the user has sufficient funds to make this bid.

	// Try and create the NFT bid txn for the user.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateNFTBidTxn(
		updaterPublicKeyBytes,
		nftPostHash,
		uint64(requestData.SerialNumber),
		uint64(requestData.BidAmountNanos),
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool())
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateNFTBid: Problem creating transaction: %v", err))
		return
	}

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateNFTBid: Problem serializing transaction: %v", err))
		return
	}

	// Return all the data associated with the transaction in the response
	res := CreateNFTBidResponse{
		UpdaterPublicKeyBase58Check: requestData.UpdaterPublicKeyBase58Check,
		NFTPostHashHex:              requestData.NFTPostHashHex,
		SerialNumber:                requestData.SerialNumber,
		BidAmountNanos:              requestData.BidAmountNanos,

		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("CreateNFTBid: Problem serializing object to JSON: %v", err))
		return
	}
}

type AcceptNFTBidRequest struct {
	UpdaterPublicKeyBase58Check string `safeForLogging:"true"`
	NFTPostHashHex              string `safeForLogging:"true"`
	SerialNumber                int    `safeForLogging:"true"`
	BidderPublicKeyBase58Check  string `safeForLogging:"true"`
	BidAmountNanos              int    `safeForLogging:"true"`
	EncryptedUnlockableText     string `safeForLogging:"true"`

	MinFeeRateNanosPerKB uint64 `safeForLogging:"true"`
}

type AcceptNFTBidResponse struct {
	BidderPublicKeyBase58Check string `safeForLogging:"true"`
	NFTPostHashHex             string `safeForLogging:"true"`
	SerialNumber               int    `safeForLogging:"true"`
	BidAmountNanos             int    `safeForLogging:"true"`

	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgBitCloutTxn
	TransactionHex    string
}

func (fes *APIServer) AcceptNFTBid(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AcceptNFTBidRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AcceptNFTBid: Error parsing request body: %v", err))
		return
	}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AcceptNFTBid: Error getting utxoView: %v", err))
		return
	}

	// Do a simple validation of the requestData.
	if requestData.NFTPostHashHex == "" {
		_AddBadRequestError(ww, fmt.Sprintf("AcceptNFTBid: Must include NFTPostHashHex"))
		return

	} else if requestData.UpdaterPublicKeyBase58Check == "" || requestData.BidderPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AcceptNFTBid: Must include UpdaterPublicKeyBase58Check and BidderPublicKeyBase58Check"))
		return

	} else if requestData.SerialNumber <= 0 || requestData.SerialNumber > int(utxoView.GlobalParamsEntry.MaxCopiesPerNFT) {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AcceptNFTBid: SerialNumbers must be between %d and %d, received: %d",
			1, utxoView.GlobalParamsEntry.MaxCopiesPerNFT, requestData.SerialNumber))
		return

	} else if requestData.BidAmountNanos < 0 {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AcceptNFTBid: BidAmountNanos must be non-negative, received: %d", requestData.BidAmountNanos))
		return
	}

	// Get the PostHash for the NFT.
	nftPostHashBytes, err := hex.DecodeString(requestData.NFTPostHashHex)
	if err != nil || len(nftPostHashBytes) != lib.HashSizeBytes {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AcceptNFTBid: Error parsing post hash %v: %v",
			requestData.NFTPostHashHex, err))
		return
	}
	nftPostHash := &lib.BlockHash{}
	copy(nftPostHash[:], nftPostHashBytes)

	// Get the updater's public key.
	updaterPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.UpdaterPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AcceptNFTBid: Problem decoding user public key: %v", err))
		return
	}

	// Get the bidder's public key.
	bidderPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.BidderPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AcceptNFTBid: Problem decoding bidder public key: %v", err))
		return
	}

	// Get the NFT bid so we can do a more hardcore validation of the request data.
	bidderPKID := utxoView.GetPKIDForPublicKey(bidderPublicKeyBytes)
	if bidderPKID == nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AcceptNFTBid: Error could not find PKID for bidder pub key %v",
			requestData.BidderPublicKeyBase58Check))
		return
	}
	nftBidKey := lib.MakeNFTBidKey(bidderPKID.PKID, nftPostHash, uint64(requestData.SerialNumber))
	nftBidEntry := utxoView.GetNFTBidEntryForNFTBidKey(&nftBidKey)
	if nftBidEntry == nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AcceptNFTBid: Error could not find an NFT bid entry for bidder pub key %v, "+
				"postHash %v and serialNumber %d", requestData.BidderPublicKeyBase58Check,
			requestData.NFTPostHashHex, requestData.SerialNumber))
		return
	}

	// RPH-FIXME: Make sure the bidder has sufficient funds to fill this bid.

	var encryptedUnlockableTextBytes []byte
	if requestData.EncryptedUnlockableText != "" {
		encryptedUnlockableTextBytes = []byte(requestData.EncryptedUnlockableText)
	}

	// Try and create the accept NFT bid txn for the user.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateAcceptNFTBidTxn(
		updaterPublicKeyBytes,
		nftPostHash,
		uint64(requestData.SerialNumber),
		bidderPKID.PKID,
		uint64(requestData.BidAmountNanos),
		encryptedUnlockableTextBytes,
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool())
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AcceptNFTBid: Problem creating transaction: %v", err))
		return
	}

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AcceptNFTBid: Problem serializing transaction: %v", err))
		return
	}

	// Return all the data associated with the transaction in the response
	res := AcceptNFTBidResponse{
		BidderPublicKeyBase58Check: requestData.BidderPublicKeyBase58Check,
		NFTPostHashHex:             requestData.NFTPostHashHex,
		SerialNumber:               requestData.SerialNumber,
		BidAmountNanos:             requestData.BidAmountNanos,

		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("AcceptNFTBid: Problem serializing object to JSON: %v", err))
		return
	}
}

type GetNFTShowcaseRequest struct {
	ReaderPublicKeyBase58Check string `safeForLogging:"true"`
}

type GetNFTShowcaseResponse struct {
	NFTCollections []*NFTCollectionResponse
}

func (fes *APIServer) GetNFTShowcase(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetNFTShowcaseRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetNFTShowcase: Error parsing request body: %v", err))
		return
	}

	var readerPublicKeyBytes []byte
	var err error
	if requestData.ReaderPublicKeyBase58Check != "" {
		readerPublicKeyBytes, _, err = lib.Base58CheckDecode(requestData.ReaderPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetNFTShowcase: Problem decoding reader public key: %v", err))
			return
		}
	}

	dropEntry, err := fes.GetLatestNFTDropEntry()
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetNFTShowcase: Problem getting latest drop: %v", err))
		return
	}

	currentTime := uint64(time.Now().UnixNano())
	if dropEntry.DropTstampNanos > currentTime {
		// In this case, we have found a pending drop. We must go back one drop in order to
		// get the current active drop.
		if dropEntry.DropNumber == 1 {
			// If the pending drop is drop #1, we need to return a blank dropEntry.
			dropEntry = &NFTDropEntry{}
		}

		if dropEntry.DropNumber > 1 {
			dropNumToFetch := dropEntry.DropNumber - 1
			dropEntry, err = fes.GetNFTDropEntry(dropNumToFetch)
			if err != nil {
				_AddInternalServerError(ww, fmt.Sprintf(
					"GetNFTShowcase: Problem getting drop #%d: %v", dropNumToFetch, err))
				return
			}
		}
	}

	// Now that we have the drop entry, fetch the NFTs.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetNFTShowcase: Error getting utxoView: %v", err))
		return
	}

	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetNFTBidsForNFTPost: Error getting verified user map: %v", err))
		return
	}

	var readerPKID *lib.PKID
	if requestData.ReaderPublicKeyBase58Check != "" {
		readerPKID = utxoView.GetPKIDForPublicKey(readerPublicKeyBytes).PKID
	}
	var nftCollectionResponses []*NFTCollectionResponse
	for _, nftHash := range dropEntry.NFTHashes {
		postEntry := utxoView.GetPostEntryForPostHash(nftHash)
		if postEntry == nil {
			_AddInternalServerError(ww, fmt.Sprint("GetNFTShowcase: Found nil post entry for NFT hash."))
			return
		}

		nftKey := lib.MakeNFTKey(nftHash, 1)
		nftEntry := utxoView.GetNFTEntryForNFTKey(&nftKey)

		postEntryResponse, err := fes._postEntryToResponse(
			postEntry, false, fes.Params, utxoView, readerPublicKeyBytes, verifiedMap, 2)
		if err != nil {
			_AddInternalServerError(ww, fmt.Sprint("GetNFTShowcase: Found invalid post entry for NFT hash."))
			return
		}
		postEntryResponse.PostEntryReaderState = utxoView.GetPostEntryReaderState(readerPublicKeyBytes, postEntry)
		nftCollectionResponse := fes._nftEntryToNFTCollectionResponse(nftEntry, postEntry.PosterPublicKey, postEntryResponse, utxoView, verifiedMap, readerPKID)
		nftCollectionResponses = append(nftCollectionResponses, nftCollectionResponse)
	}

	// Return all the data associated with the transaction in the response
	res := GetNFTShowcaseResponse{
		NFTCollections: nftCollectionResponses,
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetNFTShowcase: Problem serializing object to JSON: %v", err))
		return
	}
}

type GetNextNFTShowcaseRequest struct{}

type GetNextNFTShowcaseResponse struct {
	NextNFTShowcaseTstamp uint64
}

func (fes *APIServer) GetNextNFTShowcase(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetNextNFTShowcaseRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetNextNFTShowcase: Error parsing request body: %v", err))
		return
	}

	dropEntry, err := fes.GetLatestNFTDropEntry()
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetNextNFTShowcase: Problem getting latest drop: %v", err))
		return
	}

	var nextNFTShowcaseTstamp uint64

	currentTime := uint64(time.Now().UnixNano())
	if dropEntry.DropTstampNanos > currentTime && dropEntry.IsActive {
		// If there is a pending+active drop, return its timestamp.
		nextNFTShowcaseTstamp = dropEntry.DropTstampNanos
	}

	// Return all the data associated with the transaction in the response
	res := GetNextNFTShowcaseResponse{
		NextNFTShowcaseTstamp: nextNFTShowcaseTstamp,
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetNextNFTShowcase: Problem serializing object to JSON: %v", err))
		return
	}
}

type GetNFTsForUserRequest struct {
	UserPublicKeyBase58Check   string `safeForLogging:"true"`
	ReaderPublicKeyBase58Check string `safeForLogging:"true"`
	IsForSale                  *bool  `safeForLogging:"true"`
}

type NFTEntryAndPostEntryResponse struct {
	PostEntryResponse *PostEntryResponse
	NFTEntryResponses []*NFTEntryResponse
}

type GetNFTsForUserResponse struct {
	NFTsMap map[string]*NFTEntryAndPostEntryResponse
}

func (fes *APIServer) GetNFTsForUser(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetNFTsForUserRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetNFTsForUser: Error parsing request body: %v", err))
		return
	}

	if requestData.UserPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprintf("GetNFTsForUser: must provide UserPublicKeyBase58Check"))
		return
	}
	userPublicKey, _, err := lib.Base58CheckDecode(requestData.UserPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetNFTsForUser: Problem decoding reader public key: %v", err))
		return
	}

	var readerPublicKeyBytes []byte
	if requestData.ReaderPublicKeyBase58Check != "" {
		readerPublicKeyBytes, _, err = lib.Base58CheckDecode(requestData.ReaderPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetNFTsForUser: Problem decoding reader public key: %v", err))
			return
		}
	}

	// Get the NFT bid so we can do a more hardcore validation of the request data.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetNFTsForUser: Error getting utxoView: %v", err))
		return
	}

	verifiedUsernameMap, err := fes.GetVerifiedUsernameToPKIDMap()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetNFTsForUser: Error getting verified user map: %v", err))
		return
	}

	// Return all the data associated with the transaction in the response
	res := GetNFTsForUserResponse{
		NFTsMap: make(map[string]*NFTEntryAndPostEntryResponse),
	}
	pkid := utxoView.GetPKIDForPublicKey(userPublicKey)
	readerPKIDEntry := utxoView.GetPKIDForPublicKey(readerPublicKeyBytes)
	var readerPKID *lib.PKID
	if readerPKIDEntry != nil {
		readerPKID = readerPKIDEntry.PKID
	}

	nftEntries := utxoView.GetNFTEntriesForPKID(pkid.PKID)

	filteredNFTEntries := []*lib.NFTEntry{}
	if requestData.IsForSale != nil {
		checkForSale := *requestData.IsForSale
		for _, nftEntry := range nftEntries {
			if checkForSale == nftEntry.IsForSale {
				filteredNFTEntries = append(filteredNFTEntries, nftEntry)
			}
		}
	} else {
		filteredNFTEntries = nftEntries
	}

	postHashToEntryResponseMap := make(map[*lib.BlockHash]*PostEntryResponse)
	publicKeyToProfileEntryResponse := make(map[string]*ProfileEntryResponse)
	for _, nftEntry := range filteredNFTEntries {
		postEntryResponse := postHashToEntryResponseMap[nftEntry.NFTPostHash]
		if postEntryResponse == nil {
			postEntry := utxoView.GetPostEntryForPostHash(nftEntry.NFTPostHash)
			postEntryResponse, err = fes._postEntryToResponse(postEntry, true, fes.Params, utxoView, readerPublicKeyBytes, verifiedUsernameMap, 2)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("GetNFTsForUser: Problem converting post entry to response: %v", err))
				return
			}
			if peResponse, exists := publicKeyToProfileEntryResponse[postEntryResponse.PosterPublicKeyBase58Check]; !exists {
				profileEntry := utxoView.GetProfileEntryForPublicKey(postEntry.PosterPublicKey)
				profileEntryResponse := _profileEntryToResponse(profileEntry, fes.Params, verifiedUsernameMap, utxoView)
				postEntryResponse.ProfileEntryResponse = profileEntryResponse
				postEntryResponse.PostEntryReaderState = utxoView.GetPostEntryReaderState(readerPublicKeyBytes, postEntry)
				publicKeyToProfileEntryResponse[postEntryResponse.PosterPublicKeyBase58Check] = profileEntryResponse
			} else {
				postEntryResponse.ProfileEntryResponse = peResponse
			}
			postHashToEntryResponseMap[nftEntry.NFTPostHash] = postEntryResponse
		}
		if res.NFTsMap[postEntryResponse.PostHashHex] == nil {
			res.NFTsMap[postEntryResponse.PostHashHex] = &NFTEntryAndPostEntryResponse{
				PostEntryResponse: postEntryResponse,
				NFTEntryResponses: []*NFTEntryResponse{},
			}
		}
		res.NFTsMap[postEntryResponse.PostHashHex].NFTEntryResponses = append(
			res.NFTsMap[postEntryResponse.PostHashHex].NFTEntryResponses,
			fes._nftEntryToResponse(nftEntry, nil, utxoView, verifiedUsernameMap, true, readerPKID))
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetNFTsForUser: Problem serializing object to JSON: %v", err))
		return
	}
}

type GetNFTBidsForUserRequest struct {
	UserPublicKeyBase58Check   string `safeForLogging:"true"`
	ReaderPublicKeyBase58Check string `safeForLogging:"true"`
}

type GetNFTBidsForUserResponse struct {
	NFTBidEntries                              []*NFTBidEntryResponse
	PublicKeyBase58CheckToProfileEntryResponse map[string]*ProfileEntryResponse
	PostHashHexToPostEntryResponse             map[string]*PostEntryResponse
}

func (fes *APIServer) GetNFTBidsForUser(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetNFTBidsForUserRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetNFTBidsForUser: Error parsing request body: %v", err))
		return
	}

	var userPublicKeyBytes []byte
	var err error
	if requestData.UserPublicKeyBase58Check != "" {
		userPublicKeyBytes, _, err = lib.Base58CheckDecode(requestData.UserPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetNFTBidsForUser: Problem decoding reader public key: %v", err))
			return
		}
	} else {
		_AddBadRequestError(ww, fmt.Sprintf("GetNFTBidsForUser: Must supply UserPublicKeyBase58Check: %v", err))
		return
	}

	var readerPublicKeyBytes []byte
	if requestData.ReaderPublicKeyBase58Check != "" {
		readerPublicKeyBytes, _, err = lib.Base58CheckDecode(requestData.ReaderPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetNFTBidsForUser: Problem decoding reader public key: %v", err))
			return
		}
	}

	// Get the NFT bid so we can do a more hardcore validation of the request data.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetNFTBidsForUser: Error getting utxoView: %v", err))
		return
	}

	userPKID := utxoView.GetPKIDForPublicKey(userPublicKeyBytes)
	bidEntries := utxoView.GetNFTBidEntriesForPKID(userPKID.PKID)

	// Return all the data associated with the transaction in the response
	res := GetNFTBidsForUserResponse{
		NFTBidEntries: []*NFTBidEntryResponse{},
	}

	publicKeytoProfileEntryResponse := make(map[string]*ProfileEntryResponse)
	postHashToPostEntryResponse := make(map[string]*PostEntryResponse)

	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetNFTBidsForUser: Error getting verified user map: %v", err))
		return
	}

	for _, bidEntry := range bidEntries {
		postHashHex := hex.EncodeToString(bidEntry.NFTPostHash[:])
		if _, exists := postHashToPostEntryResponse[postHashHex]; !exists {
			postEntry := utxoView.GetPostEntryForPostHash(bidEntry.NFTPostHash)
			var newPostEntryResponse *PostEntryResponse
			newPostEntryResponse, err = fes._postEntryToResponse(postEntry, false, fes.Params, utxoView, readerPublicKeyBytes, verifiedMap, 2)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("GetNFTBidsForUser: Error getting PostEntryResponse: %v", err))
				return
			}
			newPostEntryResponse.PostEntryReaderState = utxoView.GetPostEntryReaderState(readerPublicKeyBytes, postEntry)
			if _, peExists := publicKeytoProfileEntryResponse[newPostEntryResponse.PosterPublicKeyBase58Check]; !peExists {
				profileEntry := utxoView.GetProfileEntryForPublicKey(postEntry.PosterPublicKey)
				peResponse := _profileEntryToResponse(profileEntry, fes.Params, verifiedMap, utxoView)
				publicKeytoProfileEntryResponse[newPostEntryResponse.PosterPublicKeyBase58Check] = peResponse
			}
			postHashToPostEntryResponse[postHashHex] = newPostEntryResponse
		}
		res.NFTBidEntries = append(res.NFTBidEntries, fes._bidEntryToResponse(bidEntry, nil, verifiedMap, utxoView, true, true))
	}

	res.PublicKeyBase58CheckToProfileEntryResponse = publicKeytoProfileEntryResponse
	res.PostHashHexToPostEntryResponse = postHashToPostEntryResponse

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetNFTBidsForUser: Problem serializing object to JSON: %v", err))
		return
	}
}

type GetNFTBidsForNFTPostRequest struct {
	ReaderPublicKeyBase58Check string
	PostHashHex                string
}

type GetNFTBidsForNFTPostResponse struct {
	PostEntryResponse *PostEntryResponse
	NFTEntryResponses []*NFTEntryResponse
	BidEntryResponses []*NFTBidEntryResponse
}

func (fes *APIServer) GetNFTBidsForNFTPost(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetNFTBidsForNFTPostRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetNFTBidsForNFTPost: Error parsing request body: %v", err))
		return
	}

	var readerPublicKeyBytes []byte
	var err error
	if requestData.ReaderPublicKeyBase58Check != "" {
		readerPublicKeyBytes, _, err = lib.Base58CheckDecode(requestData.ReaderPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetNFTBidsForNFTPost: Problem decoding reader public key: %v", err))
			return
		}
	}

	// Decode the postHash.
	postHash := &lib.BlockHash{}
	if requestData.PostHashHex != "" {
		var postHashBytes []byte
		postHashBytes, err = hex.DecodeString(requestData.PostHashHex)
		if err != nil || len(postHashBytes) != lib.HashSizeBytes {
			_AddBadRequestError(ww, fmt.Sprintf("GetNFTBidsForNFTPost: Error parsing post hash %v: %v",
				requestData.PostHashHex, err))
			return
		}
		copy(postHash[:], postHashBytes)
	} else {
		_AddBadRequestError(ww, fmt.Sprintf("GetNFTBidsForNFTPost: Request missing PostHashHex"))
		return
	}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetNFTBidsForNFTPost: Error getting utxoView: %v", err))
		return
	}
	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetNFTBidsForNFTPost: Error getting verified user map: %v", err))
		return
	}
	readerPKIDEntry := utxoView.GetPKIDForPublicKey(readerPublicKeyBytes)
	var readerPKID *lib.PKID
	if readerPKIDEntry != nil {
		readerPKID = readerPKIDEntry.PKID
	}
	postEntry := utxoView.GetPostEntryForPostHash(postHash)
	postEntryResponse, err := fes._postEntryToResponse(postEntry, true, fes.Params, utxoView, readerPublicKeyBytes, verifiedMap, 2)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetNFTBidsForNFTPost: Error converting post entry to response: %v", err))
		return
	}
	postEntryResponse.PostEntryReaderState = utxoView.GetPostEntryReaderState(readerPublicKeyBytes, postEntry)

	res := GetNFTBidsForNFTPostResponse{
		PostEntryResponse: postEntryResponse,
	}
	// Do I need to add something to get bid entries for serial # 0?
	nftEntries := utxoView.GetNFTEntriesForPostHash(postHash)
	for _, nftEntry := range nftEntries {
		res.NFTEntryResponses = append(res.NFTEntryResponses, fes._nftEntryToResponse(nftEntry, nil, utxoView, verifiedMap, false, readerPKID))
		bidEntries := utxoView.GetAllNFTBidEntries(postHash, nftEntry.SerialNumber)
		for _, bidEntry := range bidEntries {
			// We don't need to send the PostHash in the response since we know all these bids belong to the same PostHashHex
			bidEntry.NFTPostHash = nil
			res.BidEntryResponses = append(res.BidEntryResponses, fes._bidEntryToResponse(bidEntry, nil, verifiedMap, utxoView, false, false))
		}
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetNFTBidsForNFTPost: Problem serializing object to JSON: %v", err))
		return
	}
}

type GetNFTCollectionSummaryRequest struct {
	PostHashHex                string
	ReaderPublicKeyBase58Check string
}

type GetNFTCollectionSummaryResponse struct {
	NFTCollectionResponse          *NFTCollectionResponse
	SerialNumberToNFTEntryResponse map[uint64]*NFTEntryResponse
}

func (fes *APIServer) GetNFTCollectionSummary(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetNFTCollectionSummaryRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetNFTCollectionSummary: Error parsing request body: %v", err))
		return
	}

	// Decode the postHash.
	postHash := &lib.BlockHash{}
	if requestData.PostHashHex != "" {
		var postHashBytes []byte
		postHashBytes, err := hex.DecodeString(requestData.PostHashHex)
		if err != nil || len(postHashBytes) != lib.HashSizeBytes {
			_AddBadRequestError(ww, fmt.Sprintf("GetNFTCollectionSummary: Error parsing post hash %v: %v",
				requestData.PostHashHex, err))
			return
		}
		copy(postHash[:], postHashBytes)
	} else {
		_AddBadRequestError(ww, fmt.Sprintf("GetNFTCollectionSummary: Request missing PostHashHex"))
		return
	}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetNFTCollectionSummary: Error getting utxoView: %v", err))
		return
	}
	postEntry := utxoView.GetPostEntryForPostHash(postHash)
	if !postEntry.IsNFT {
		_AddBadRequestError(ww, fmt.Sprintf("GetNFTCollectionSummary: cannot get nft collection summary for post that is not an NFT"))
		return
	}
	var readerPublicKeyBytes []byte
	var readerPKID *lib.PKID
	if requestData.ReaderPublicKeyBase58Check != "" {
		readerPublicKeyBytes, _, err = lib.Base58CheckDecode(requestData.ReaderPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetNFTCollectionSummary: Problem decoding reader public key: %v", err))
			return
		}
		readerPKID = utxoView.GetPKIDForPublicKey(readerPublicKeyBytes).PKID
	}
	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetNFTCollectionSummary: Error getting verified user map: %v", err))
		return
	}

	postEntryResponse, err := fes._postEntryToResponse(postEntry, true, fes.Params, utxoView, readerPublicKeyBytes, verifiedMap, 2)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetNFTCollectionSummary: Error converting post entry to response: %v", err))
		return
	}

	postEntryResponse.PostEntryReaderState = utxoView.GetPostEntryReaderState(readerPublicKeyBytes, postEntry)

	nftKey := lib.MakeNFTKey(postEntry.PostHash, 1)
	nftEntry := utxoView.GetNFTEntryForNFTKey(&nftKey)

	res := &GetNFTCollectionSummaryResponse{
		NFTCollectionResponse:          fes._nftEntryToNFTCollectionResponse(nftEntry, postEntry.PosterPublicKey, postEntryResponse, utxoView, verifiedMap, readerPKID),
		SerialNumberToNFTEntryResponse: make(map[uint64]*NFTEntryResponse),
	}

	for _, serialNumber := range res.NFTCollectionResponse.AvailableSerialNumbers {
		serialNumberKey := lib.MakeNFTKey(postEntry.PostHash, serialNumber)
		serialNumberNFTEntry := utxoView.GetNFTEntryForNFTKey(&serialNumberKey)
		res.SerialNumberToNFTEntryResponse[serialNumber] = fes._nftEntryToResponse(serialNumberNFTEntry, nil, utxoView, verifiedMap, true, readerPKID)
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetNFTCollectionSummary: Problem serializing object to JSON: %v", err))
		return
	}
}

type GetNFTEntriesForPostHashRequest struct {
	PostHashHex                string
	ReaderPublicKeyBase58Check string
}

type GetNFTEntriesForPostHashResponse struct {
	NFTEntryResponses []*NFTEntryResponse
}

func (fes *APIServer) GetNFTEntriesForPostHash(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetNFTEntriesForPostHashRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetNFTEntriesForPostHash: Error parsing request body: %v", err))
		return
	}

	// Decode the postHash.
	postHash := &lib.BlockHash{}
	if requestData.PostHashHex != "" {
		var postHashBytes []byte
		postHashBytes, err := hex.DecodeString(requestData.PostHashHex)
		if err != nil || len(postHashBytes) != lib.HashSizeBytes {
			_AddBadRequestError(ww, fmt.Sprintf("GetNFTEntriesForPostHash: Error parsing post hash %v: %v",
				requestData.PostHashHex, err))
			return
		}
		copy(postHash[:], postHashBytes)
	} else {
		_AddBadRequestError(ww, fmt.Sprintf("GetNFTEntriesForPostHash: Request missing PostHashHex"))
		return
	}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetNFTEntriesForPostHash: Error getting utxoView: %v", err))
		return
	}
	postEntry := utxoView.GetPostEntryForPostHash(postHash)
	if !postEntry.IsNFT {
		_AddBadRequestError(ww, fmt.Sprintf("GetNFTEntriesForPostHash: cannot get nft collection summary for post that is not an NFT"))
		return
	}

	var readerPublicKeyBytes []byte
	var readerPKID *lib.PKID
	if requestData.ReaderPublicKeyBase58Check != "" {
		readerPublicKeyBytes, _, err = lib.Base58CheckDecode(requestData.ReaderPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetNFTEntriesForPostHash: Problem decoding reader public key: %v", err))
			return
		}
		readerPKID = utxoView.GetPKIDForPublicKey(readerPublicKeyBytes).PKID
	}

	res := &GetNFTEntriesForPostHashResponse{
		NFTEntryResponses: []*NFTEntryResponse{},
	}

	nftEntries := utxoView.GetNFTEntriesForPostHash(postHash)
	for _, nftEntry := range nftEntries {
		res.NFTEntryResponses = append(res.NFTEntryResponses, fes._nftEntryToResponse(nftEntry, nil, utxoView, nil, true, readerPKID))
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetNFTEntriesForPostHash: Problem serializing object to JSON: %v", err))
		return
	}
}

func (fes *APIServer) _nftEntryToResponse(nftEntry *lib.NFTEntry, postEntryResponse *PostEntryResponse, utxoView *lib.UtxoView, verifiedUsernameMap map[string]*lib.PKID, skipProfileEntryResponse bool, readerPKID *lib.PKID) *NFTEntryResponse {
	profileEntry := utxoView.GetProfileEntryForPKID(nftEntry.OwnerPKID)
	var profileEntryResponse *ProfileEntryResponse
	var publicKeyBase58Check string
	if profileEntry != nil && !skipProfileEntryResponse {
		profileEntryResponse = _profileEntryToResponse(profileEntry, fes.Params, verifiedUsernameMap, utxoView)
		publicKeyBase58Check = profileEntryResponse.PublicKeyBase58Check
	} else {
		publicKey := utxoView.GetPublicKeyForPKID(nftEntry.OwnerPKID)
		publicKeyBase58Check = lib.PkToString(publicKey, fes.Params)
	}

	// We only care about these values in the case where the reader is the current owner.
	var lastOwnerPublicKeyBase58Check *string
	var encryptedUnlockableText *string
	if len(nftEntry.UnlockableText) > 0 && reflect.DeepEqual(nftEntry.OwnerPKID, readerPKID) {
		encryptedUnlockableTextValue := string(nftEntry.UnlockableText)
		encryptedUnlockableText = &encryptedUnlockableTextValue
		if nftEntry.LastOwnerPKID != nil {
			publicKey := utxoView.GetPublicKeyForPKID(nftEntry.LastOwnerPKID)
			lastOwnerPublicKeyBase58CheckVal := lib.PkToString(publicKey, fes.Params)
			lastOwnerPublicKeyBase58Check = &lastOwnerPublicKeyBase58CheckVal
		}
	}
	var highBid uint64
	var lowBid uint64
	if nftEntry.IsForSale {
		highBid, lowBid = utxoView.GetHighAndLowBidsForNFTSerialNumber(nftEntry.NFTPostHash, nftEntry.SerialNumber)
	}
	return &NFTEntryResponse{
		OwnerPublicKeyBase58Check: publicKeyBase58Check,
		ProfileEntryResponse:      profileEntryResponse,
		PostEntryResponse:         postEntryResponse,
		SerialNumber:              nftEntry.SerialNumber,
		IsForSale:                 nftEntry.IsForSale,
		MinBidAmountNanos:         nftEntry.MinBidAmountNanos,

		HighestBidAmountNanos: highBid,
		LowestBidAmountNanos: lowBid,

		EncryptedUnlockableText:       encryptedUnlockableText,
		LastOwnerPublicKeyBase58Check: lastOwnerPublicKeyBase58Check,
		LastAcceptedBidAmountNanos:    nftEntry.LastAcceptedBidAmountNanos,
	}
}

func (fes *APIServer) _nftEntryToNFTCollectionResponse(
	nftEntry *lib.NFTEntry,
	posterPublicKey []byte,
	postEntryResponse *PostEntryResponse,
	utxoView *lib.UtxoView,
	verifiedUsernameMap map[string]*lib.PKID,
	readerPKID *lib.PKID,
) *NFTCollectionResponse {

	profileEntry := utxoView.GetProfileEntryForPublicKey(posterPublicKey)
	var profileEntryResponse *ProfileEntryResponse
	if profileEntry != nil {
		profileEntryResponse = _profileEntryToResponse(profileEntry, fes.Params, verifiedUsernameMap, utxoView)
	}

	postEntryResponse.ProfileEntryResponse = profileEntryResponse

	var numCopiesForSale uint64
	serialNumbersForSale := []uint64{}
	for ii := uint64(1); ii <= postEntryResponse.NumNFTCopies; ii++ {
		nftKey := lib.MakeNFTKey(nftEntry.NFTPostHash, ii)
		nftEntryii := utxoView.GetNFTEntryForNFTKey(&nftKey)
		if nftEntryii != nil && nftEntryii.IsForSale {
			if nftEntryii.OwnerPKID != readerPKID {
				serialNumbersForSale = append(serialNumbersForSale, ii)
			}
			numCopiesForSale++
		}
	}

	highestBidAmountNanos, lowestBidAmountNanos := utxoView.GetHighAndLowBidsForNFTCollection(
		nftEntry.NFTPostHash)

	return &NFTCollectionResponse{
		ProfileEntryResponse:   profileEntryResponse,
		PostEntryResponse:      postEntryResponse,
		HighestBidAmountNanos:  highestBidAmountNanos,
		LowestBidAmountNanos:   lowestBidAmountNanos,
		NumCopiesForSale:       numCopiesForSale,
		AvailableSerialNumbers: serialNumbersForSale,
	}
}

func (fes *APIServer) _bidEntryToResponse(bidEntry *lib.NFTBidEntry, postEntryResponse *PostEntryResponse, verifiedUsernameMap map[string]*lib.PKID, utxoView *lib.UtxoView, skipProfileEntryResponse bool, includeHighAndLowBids bool) *NFTBidEntryResponse {
	profileEntry := utxoView.GetProfileEntryForPKID(bidEntry.BidderPKID)
	var profileEntryResponse *ProfileEntryResponse
	var publicKeyBase58Check string
	var publicKey []byte
	if profileEntry != nil && !skipProfileEntryResponse {
		publicKey = profileEntry.PublicKey
		profileEntryResponse = _profileEntryToResponse(profileEntry, fes.Params, verifiedUsernameMap, utxoView)
		publicKeyBase58Check = profileEntryResponse.PublicKeyBase58Check
	} else {
		publicKey = utxoView.GetPublicKeyForPKID(bidEntry.BidderPKID)
		publicKeyBase58Check = lib.PkToString(publicKey, fes.Params)
	}
	var postHashHex *string
	if bidEntry.NFTPostHash != nil {
		postHashHexString := hex.EncodeToString(bidEntry.NFTPostHash[:])
		postHashHex = &postHashHexString
	}
	var highBid *uint64
	var lowBid *uint64

	if includeHighAndLowBids {
		highBidVal, lowBidVal := utxoView.GetHighAndLowBidsForNFTSerialNumber(bidEntry.NFTPostHash, bidEntry.SerialNumber)
		highBid = &highBidVal
		lowBid = &lowBidVal
	}

	// We ignore the error in this case and assume the bidder's balance is 0.
	bidderBalanceNanos, _ := utxoView.GetBitcloutBalanceNanosForPublicKey(publicKey)

	return &NFTBidEntryResponse{
		PostHashHex:          postHashHex,
		PublicKeyBase58Check: publicKeyBase58Check,
		ProfileEntryResponse: profileEntryResponse,
		PostEntryResponse:    postEntryResponse,
		SerialNumber:         bidEntry.SerialNumber,
		BidAmountNanos:       bidEntry.BidAmountNanos,

		HighestBidAmountNanos: highBid,
		LowestBidAmountNanos: lowBid,
		BidderBalanceNanos: bidderBalanceNanos,
	}
}
