package routes

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/bitclout/core/lib"
)

type NFTEntryResponse struct {
	PostEntry                      *PostEntryResponse
	NumCopies                      int  `safeForLogging:"true"`
	NFTRoyaltyToCreatorBasisPoints int  `safeForLogging:"true"`
	NFTRoyaltyToCoinBasisPoints    int  `safeForLogging:"true"`
	HasUnlockable                  bool `safeForLogging:"true"`
}

type CreateNFTRequest struct {
	UpdaterPublicKeyBase58Check    string `safeForLogging:"true"`
	NFTPostHashHex                 string `safeForLogging:"true"`
	NumCopies                      int    `safeForLogging:"true"`
	NFTRoyaltyToCreatorBasisPoints int    `safeForLogging:"true"`
	NFTRoyaltyToCoinBasisPoints    int    `safeForLogging:"true"`
	HasUnlockable                  bool   `safeForLogging:"true"`

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

	// Validate the requestData.
	if requestData.NFTPostHashHex == "" {
		_AddBadRequestError(ww, fmt.Sprintf("CreateNFT: Must include NFTPostHashHex"))
		return

	} else if requestData.UpdaterPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprintf("CreateNFT: Must include UpdaterPublicKeyBase58Check"))
		return

	} else if requestData.NumCopies <= 0 || requestData.NumCopies > int(fes.Params.MaxCopiesPerNFT) {
		_AddBadRequestError(ww, fmt.Sprintf(
			"CreateNFT: NumCopies must be between %d and %d, received: %d",
			1, fes.Params.MaxCopiesPerNFT, requestData.NumCopies))
		return

	} else if requestData.NFTRoyaltyToCreatorBasisPoints < 0 || requestData.NFTRoyaltyToCreatorBasisPoints > int(fes.Params.MaxNFTRoyaltyBasisPoints) {
		_AddBadRequestError(ww, fmt.Sprintf(
			"CreateNFT: NFTRoyaltyToCreatorBasisPoints must be between %d and %d, received: %d",
			0, fes.Params.MaxNFTRoyaltyBasisPoints, requestData.NFTRoyaltyToCreatorBasisPoints))
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

	// Calculate the fee for creating the NFT.
	// RPH-FIXME: Calculate the correct NFT fee here.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateNFT: Error getting utxoView: %v", err))
		return
	}
	nftFee := utxoView.GlobalParamsEntry.CreateNFTFeeNanos

	// Try and create the create NFT txn for the user.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateCreateNFTTxn(
		updaterPublicKeyBytes,
		nftPostHash,
		uint64(requestData.NumCopies),
		requestData.HasUnlockable,
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

	// Do a simple validation of the requestData.
	if requestData.NFTPostHashHex == "" {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateNFT: Must include NFTPostHashHex"))
		return

	} else if requestData.UpdaterPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateNFT: Must include UpdaterPublicKeyBase58Check"))
		return

	} else if requestData.SerialNumber <= 0 || requestData.SerialNumber > int(fes.Params.MaxCopiesPerNFT) {
		_AddBadRequestError(ww, fmt.Sprintf(
			"UpdateNFT: SerialNumbers must be between %d and %d, received: %d",
			1, fes.Params.MaxCopiesPerNFT, requestData.SerialNumber))
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
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateNFT: Error getting utxoView: %v", err))
		return
	}
	nftKey := lib.MakeNFTKey(nftPostHash, uint64(requestData.SerialNumber))
	nftEntry := utxoView.GetNFTEntryForNFTKey(&nftKey)
	if nftEntry == nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"UpdateNFT: Error could not find the NFT an NFT with postHash %v and serialNumber %d",
			requestData.NFTPostHashHex, requestData.SerialNumber))
		return

	} else if nftEntry.IsForSale == requestData.IsForSale {
		_AddBadRequestError(ww, fmt.Sprintf(
			"UpdateNFT: NFT already has IsForFale=%b", requestData.IsForSale))
		return

	}

	// Try and create the update NFT txn for the user.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateUpdateNFTTxn(
		updaterPublicKeyBytes,
		nftPostHash,
		uint64(requestData.SerialNumber),
		requestData.IsForSale,
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

	// Do a simple validation of the requestData.
	if requestData.NFTPostHashHex == "" {
		_AddBadRequestError(ww, fmt.Sprintf("CreateNFTBid: Must include NFTPostHashHex"))
		return

	} else if requestData.UpdaterPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprintf("CreateNFTBid: Must include UpdaterPublicKeyBase58Check"))
		return

	} else if requestData.SerialNumber <= 0 || requestData.SerialNumber > int(fes.Params.MaxCopiesPerNFT) {
		_AddBadRequestError(ww, fmt.Sprintf(
			"CreateNFTBid: SerialNumbers must be between %d and %d, received: %d",
			1, fes.Params.MaxCopiesPerNFT, requestData.SerialNumber))
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
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateNFTBid: Error getting utxoView: %v", err))
		return
	}
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
	UnencryptedUnlockableText   string `safeForLogging:"true"`

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

	// Do a simple validation of the requestData.
	if requestData.NFTPostHashHex == "" {
		_AddBadRequestError(ww, fmt.Sprintf("AcceptNFTBid: Must include NFTPostHashHex"))
		return

	} else if requestData.UpdaterPublicKeyBase58Check == "" || requestData.BidderPublicKeyBase58Check == "" {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AcceptNFTBid: Must include UpdaterPublicKeyBase58Check and BidderPublicKeyBase58Check"))
		return

	} else if requestData.SerialNumber <= 0 || requestData.SerialNumber > int(fes.Params.MaxCopiesPerNFT) {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AcceptNFTBid: SerialNumbers must be between %d and %d, received: %d",
			1, fes.Params.MaxCopiesPerNFT, requestData.SerialNumber))
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
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AcceptNFTBid: Error getting utxoView: %v", err))
		return
	}
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

	// Try and create the accept NFT bid txn for the user.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateAcceptNFTBidTxn(
		updaterPublicKeyBytes,
		nftPostHash,
		uint64(requestData.SerialNumber),
		bidderPKID.PKID,
		uint64(requestData.BidAmountNanos),
		requestData.UnencryptedUnlockableText,
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
