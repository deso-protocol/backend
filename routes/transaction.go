package routes

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/bitclout/core/lib"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/golang/glog"
	"github.com/pkg/errors"
)

type GetTxnRequest struct {
	// TxnHash to fetch.
	TxnHashHex string `safeForLogging:"true"`
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

	txnFound := fes.mempool.IsTransactionInPool(txnHash)
	res := &GetTxnResponse{
		TxnFound: txnFound,
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetSinglePost: Problem encoding response as JSON: %v", err))
		return
	}
}

type SubmitTransactionRequest struct {
	TransactionHex string `safeForLogging:"true"`
}

type SubmitTransactionResponse struct {
	Transaction *lib.MsgBitCloutTxn
	TxnHashHex  string

	// include the PostEntryResponse if a post was submitted
	PostEntryResponse *PostEntryResponse
}

func (fes *APIServer) SubmitTransaction(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := SubmitTransactionRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitTransactionRequest: Problem parsing request body: %v", err))
		return
	}

	txnBytes, err := hex.DecodeString(requestData.TransactionHex)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitTransactionRequest: Problem deserializing transaction hex: %v", err))
		return
	}

	txn := &lib.MsgBitCloutTxn{}
	err = txn.FromBytes(txnBytes)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitTransactionRequest: Problem deserializing transaction from bytes: %v", err))
		return
	}

	// If this is a creator coin transaction, we update global state user metadata to say user has purchased CC.
	if txn.TxnMeta.GetTxnType() == lib.TxnTypeCreatorCoin && txn.TxnMeta.(*lib.CreatorCoinMetadataa).OperationType == lib.CreatorCoinOperationTypeBuy {
		var userMetadata *UserMetadata
		userMetadata, err = fes.getUserMetadataFromGlobalStateByPublicKeyBytes(txn.PublicKey)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SubmitTransactionRequest: Problem getting usermetadata from global state for basic transfer: %v", err))
			return
		}
		if !userMetadata.HasPurchasedCreatorCoin {
			userMetadata.HasPurchasedCreatorCoin = true
			if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("SubmitTransactionRequest: Problem updating HasPurchasedCreatorCoin in global state user metadata: %v", err))
				return
			}
		}
	}

	_, diamondPostHashKeyExists := txn.ExtraData[lib.DiamondPostHashKey]
	// If this is a basic transfer (but not a diamond action), we check if user has purchased CC (if this node is configured for Jumio or Twilio)
	if !diamondPostHashKeyExists && txn.TxnMeta.GetTxnType() == lib.TxnTypeBasicTransfer && (fes.IsConfiguredForJumio() || fes.Twilio != nil) {
		var userMetadata *UserMetadata
		userMetadata, err = fes.getUserMetadataFromGlobalStateByPublicKeyBytes(txn.PublicKey)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SubmitTransactionRequest: Problem getting usermetadata from global state for basic transfer: %v", err))
			return
		}
		if (userMetadata.JumioVerified || userMetadata.PhoneNumber != "" ) && !userMetadata.HasPurchasedCreatorCoin && userMetadata.MustPurchaseCreatorCoin {
			_AddBadRequestError(ww, fmt.Sprintf("SubmitTransactionRequest: You must purchase a creator coin before performing a transfer: %v", err))
			return
		}
	}

	err = fes.backendServer.VerifyAndBroadcastTransaction(txn)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitTransaction: Problem processing transaction: %v", err))
		return
	}

	res := &SubmitTransactionResponse{
		Transaction: txn,
		TxnHashHex:  txn.Hash().String(),
	}

	if txn.TxnMeta.GetTxnType() == lib.TxnTypeSubmitPost {
		err = fes._afterProcessSubmitPostTransaction(txn, res)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("_afterSubmitPostTransaction: %v", err))
		}
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitTransactionResponse: Problem encoding response as JSON: %v", err))
		return
	}
}

// After we submit a new post transaction we need to do run a few callbacks
// 1. Attach the PostEntry to the response so the client can render it
// 2. Attempt to auto-whitelist the post for the global feed
func (fes *APIServer) _afterProcessSubmitPostTransaction(txn *lib.MsgBitCloutTxn, response *SubmitTransactionResponse) error {
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

	// attach a ProfileEntry to the PostEntryResponse
	verifiedMap, err := fes.GetVerifiedUsernameToPKIDMap()
	if err != nil {
		return err
	}

	profileEntry := utxoView.GetProfileEntryForPublicKey(postEntry.PosterPublicKey)
	postEntryResponse.ProfileEntryResponse = _profileEntryToResponse(profileEntry, fes.Params, verifiedMap, utxoView)

	// attach everything to the response
	response.PostEntryResponse = postEntryResponse

	// Try to whitelist a post if it is not a comment and is not a vanilla reclout.
	if len(postHashToModify) == 0 && !lib.IsVanillaReclout(postEntry) {
		// If this is a new post, let's try and auto-whitelist it now that it has been broadcast.
		// First we need to figure out if the user is whitelisted.
		userMetadata, err := fes.getUserMetadataFromGlobalState(lib.PkToString(updaterPublicKeyBytes, fes.Params))
		if err != nil {
			return errors.Wrapf(err, "GlobalStateGet error: Problem getting "+
				"metadata from global state.")
		}

		// Only whitelist posts for users that are auto-whitelisted and the post is not a comment or a vanilla reclout.
		if userMetadata.WhitelistPosts && len(postEntry.ParentStakeID) == 0 && (postEntry.IsQuotedReclout || postEntry.RecloutedPostHash == nil) {
			minTimestampNanos := time.Now().UTC().AddDate(0, 0, -1).UnixNano() // last 24 hours
			_, dbPostAndCommentHashes, _, err := lib.DBGetAllPostsAndCommentsForPublicKeyOrderedByTimestamp(
				fes.blockchain.DB(), updaterPublicKeyBytes, false /*fetchEntries*/, uint64(minTimestampNanos), 0, /*maxTimestampNanos*/
			)
			if err != nil {
				return errors.Errorf("Problem fetching last 24 hours of user posts: %v", err)
			}

			// Collect all the posts the user made in the last 24 hours.
			maxAutoWhitelistPostsPerDay := 5
			postEntriesInLastDay := 0
			for _, dbPostOrCommentHash := range dbPostAndCommentHashes {
				if existingPostEntry := utxoView.GetPostEntryForPostHash(dbPostOrCommentHash); len(existingPostEntry.ParentStakeID) == 0 && !lib.IsVanillaReclout(existingPostEntry) {
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
				if err = fes.GlobalStatePut(dbKey, []byte{1}); err != nil {
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

	MinFeeRateNanosPerKB uint64 `safeForLogging:"true"`
}

// UpdateProfileResponse ...
type UpdateProfileResponse struct {
	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgBitCloutTxn
	TransactionHex    string
	TxnHashHex        string
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

	// Validate that the user can create a profile
	userMetadata, err := fes.getUserMetadataFromGlobalState(requestData.UpdaterPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateProfile: Problem with getUserMetadataFromGlobalState: %v", err))
		return
	}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
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
			"UpdateProfile: Not allowed to update profile. Please verify your phone number or buy BitClout."))
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

	if len(requestData.NewUsername) > 0 && (strings.Index(requestData.NewUsername, "BC") == 0 ||
		strings.Index(requestData.NewUsername, "tBC") == 0) {
		_AddBadRequestError(ww, fmt.Sprintf(
			"UpdateProfile: Username cannot start with BC or tBC"))
		return
	}

	if uint64(len([]byte(requestData.NewUsername))) > utxoView.Params.MaxUsernameLengthBytes {
		_AddBadRequestError(ww, lib.RuleErrorProfileUsernameTooLong.Error())
		return
	}

	if uint64(len([]byte(requestData.NewDescription))) > utxoView.Params.MaxUserDescriptionLengthBytes {
		_AddBadRequestError(ww, lib.RuleErrorProfileDescriptionTooLong.Error())
		return
	}

	// If an image is set on the request then resize it.
	// Convert image to base64 by stripping the data: prefix.
	if requestData.NewProfilePic != "" {
		var resizedImageBytes []byte
		resizedImageBytes, err = resizeAndConvertToWebp(requestData.NewProfilePic, uint(fes.Params.MaxProfilePicDimensions))
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("Problem resizing profile picture: %v", err))
			return
		}
		// Convert the image back into base64
		webpBase64 := base64.StdEncoding.EncodeToString(resizedImageBytes)
		requestData.NewProfilePic = "data:image/webp;base64," + webpBase64
		if uint64(len([]byte(requestData.NewProfilePic))) > utxoView.Params.MaxProfilePicLengthBytes {
			_AddBadRequestError(ww, lib.RuleErrorMaxProfilePicSize.Error())
			return
		}
	}

	// CreatorBasisPoints > 0 < max, uint64 can't be less than zero
	if requestData.NewCreatorBasisPoints > fes.Params.MaxCreatorBasisPoints {
		_AddBadRequestError(ww, fmt.Sprintf(
			"UpdateProfile: Creator percentage must be less than %v percent",
			fes.Params.MaxCreatorBasisPoints/100))
		return
	}

	// Verify that this username doesn't exist in the mempool.
	if len(requestData.NewUsername) > 0 {

		utxoView.GetProfileEntryForUsername([]byte(requestData.NewUsername))
		if existingProfile, usernameExists := utxoView.ProfileUsernameToProfileEntry[lib.MakeUsernameMapKey([]byte(requestData.NewUsername))]; usernameExists && !existingProfile.IsDeleted() {
			// Check that the existing profile does not belong to the profile public key
			if utxoView.GetPKIDForPublicKey(profilePublicKey) != utxoView.GetPKIDForPublicKey(existingProfile.PublicKey) {
				_AddBadRequestError(ww, fmt.Sprintf(
					"UpdateProfile: Username %v already exists", string(existingProfile.Username)))
				return
			}

		}
		if !lib.UsernameRegex.Match([]byte(requestData.NewUsername)) {
			_AddBadRequestError(ww, lib.RuleErrorInvalidUsername.Error())
			return
		}
	}

	additionalFees, err := fes.CompProfileCreation(profilePublicKey, userMetadata, utxoView)
	if err != nil {
		_AddBadRequestError(ww, err.Error())
		return
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
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool())
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateProfile: Problem creating transaction: %v", err))
		return
	}

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateProfile: Problem serializing transaction: %v", err))
		return
	}

	// Return all the data associated with the transaction in the response
	res := UpdateProfileResponse{
		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
		TransactionHex:    hex.EncodeToString(txnBytes),
		TxnHashHex:        txn.Hash().String(),
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendMessage: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) CompProfileCreation(profilePublicKey []byte, userMetadata *UserMetadata, utxoView *lib.UtxoView) (_additionalFee uint64, _err error) {
	// Determine if this is a profile creation request and if we need to comp the user for creating the profile.
	existingProfileEntry := utxoView.GetProfileEntryForPublicKey(profilePublicKey)
	// If we are updating an existing profile, there is no fee and we do not comp anything.
	if existingProfileEntry != nil {
		return 0, nil
	}
	// Additional fee is set to the create profile fee when we are creating a profile
	additionalFees := utxoView.GlobalParamsEntry.CreateProfileFeeNanos

	// Only comp create profile fee if frontend server has both twilio and starter bitclout seed configured and the user
	// has verified their profile.
	if !fes.Config.CompProfileCreation || fes.Config.StarterBitcloutSeed == "" || fes.Twilio == nil || (userMetadata.PhoneNumber == "" && !userMetadata.JumioVerified) {
		return additionalFees, nil
	}
	var currentBalanceNanos uint64
	currentBalanceNanos, err := GetBalanceForPublicKeyUsingUtxoView(profilePublicKey, utxoView)
	if err != nil {
		return 0, errors.Wrap(fmt.Errorf("UpdateProfile: error getting current balance: %v", err), "")
	}
	createProfileFeeNanos := utxoView.GlobalParamsEntry.CreateProfileFeeNanos

	// If a user is jumio verified, we just comp the profile even if their balance is greater than the create profile fee.
	// If a user has a phone number verified but is not jumio verified, we need to check that they haven't spent all their
	// starter bitclout already and that ShouldCompProfileCreation is true
	var phoneNumberMetadata *PhoneNumberMetadata
	if userMetadata.PhoneNumber != "" && !userMetadata.JumioVerified {
		phoneNumberMetadata, err = fes.getPhoneNumberMetadataFromGlobalState(userMetadata.PhoneNumber)
		if err != nil {
			return 0, errors.Wrap(fmt.Errorf("UpdateProfile: error getting phone number metadata for public key %v: %v", profilePublicKey, err), "")
		}
		if phoneNumberMetadata == nil {
			return 0, errors.Wrap(fmt.Errorf("UpdateProfile: no phone number metadata for phone number %v", userMetadata.PhoneNumber), "")
		}
		if !phoneNumberMetadata.ShouldCompProfileCreation || currentBalanceNanos > createProfileFeeNanos {
			return additionalFees, nil
		}
	} else {
		// User has been Jumio verified but should comp profile creation is false, just return
		if !userMetadata.JumioShouldCompProfileCreation {
			return additionalFees, nil
		}
	}

	// Find the minimum starter bit clout amount
	minStarterBitCloutNanos := fes.Config.StarterBitcloutNanos
	if len(fes.Config.StarterPrefixNanosMap) > 0 {
		for _, starterBitClout := range fes.Config.StarterPrefixNanosMap {
			if starterBitClout < minStarterBitCloutNanos {
				minStarterBitCloutNanos = starterBitClout
			}
		}
	}
	// We comp the create profile fee minus the minimum starter bitclout amount divided by 2.
	// This discourages botting while covering users who verify a phone number.
	compAmount := createProfileFeeNanos - (minStarterBitCloutNanos / 2)
	// If the user won't have enough bitclout to cover the fee, this is an error.
	if currentBalanceNanos+compAmount < createProfileFeeNanos {
		return 0, errors.Wrap(fmt.Errorf("Creating a profile requires BitClout.  Please purchase some to create a profile."), "")
	}
	// Set should comp to false so we don't continually comp a public key.  PhoneNumberMetadata is only non-nil if
	// a user verified their phone number but is not jumio verified.
	if phoneNumberMetadata != nil {
		phoneNumberMetadata.ShouldCompProfileCreation = false
		if err = fes.putPhoneNumberMetadataInGlobalState(phoneNumberMetadata); err != nil {
			return 0, errors.Wrap(fmt.Errorf("UpdateProfile: Error setting ShouldComp to false for phone number metadata: %v", err), "")
		}
	} else {
		// Set JumioShouldCompProfileCreation to false so we don't continue to comp profile creation.
		userMetadata.JumioShouldCompProfileCreation = false
		if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
			return 0, errors.Wrap(fmt.Errorf("UpdateProfile: Error setting ShouldComp to false for jumio user metadata: %v", err), "")
		}
	}

	// Send the comp amount to the public key
	_, err = fes.SendSeedBitClout(profilePublicKey, compAmount, false)
	if err != nil {
		return 0, errors.Wrap(fmt.Errorf("UpdateProfile: error comping create profile fee: %v", err), "")
	}
	return additionalFees, nil
}

func GetBalanceForPublicKeyUsingUtxoView(
	publicKeyBytes []byte, utxoView *lib.UtxoView) (_balance uint64, _err error) {

	// Get unspent utxos from the view.
	utxoEntriesFound, err := utxoView.GetUnspentUtxoEntrysForPublicKey(publicKeyBytes)
	if err != nil {
		return 0, fmt.Errorf("UpdateProfile: Problem getting spendable utxos from UtxoView: %v", err)
	}
	totalBalanceNanos := uint64(0)
	for _, utxoEntry := range utxoEntriesFound {
		totalBalanceNanos += utxoEntry.AmountNanos
	}
	return totalBalanceNanos, nil
}

// ExchangeBitcoinRequest ...
type ExchangeBitcoinRequest struct {
	// The public key of the user who we're creating the burn for.
	PublicKeyBase58Check string `safeForLogging:"true"`
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

	SerializedTxnHex   string
	TxnHashHex         string
	BitCloutTxnHashHex string

	UnsignedHashes []string
}

// ExchangeBitcoinStateless ...
func (fes *APIServer) ExchangeBitcoinStateless(ww http.ResponseWriter, req *http.Request) {
	if fes.Config.BuyBitCloutSeed == "" {
		_AddBadRequestError(ww, "ExchangeBitcoinStateless: This node is not configured to sell BitClout for Bitcoin")
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
		glog.Tracef("ExchangeBitcoinStateless: Getting ready to burn %d Satoshis", burnAmountSatoshis)
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
	utxoSource := func(spendAddr string, params *lib.BitCloutParams) ([]*lib.BitcoinUtxo, error) {
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
	pubKey := addressPubKey.PubKey()

	bitcoinTxn, totalInputSatoshis, fee, unsignedHashes, bitcoinSpendErr := lib.CreateBitcoinSpendTransaction(
		uint64(burnAmountSatoshis),
		uint64(requestData.FeeRateSatoshisPerKB),
		pubKey,
		fes.Config.BuyBitCloutBTCAddress,
		fes.Params,
		utxoSource)

	if bitcoinSpendErr != nil {
		_AddBadRequestError(ww, fmt.Sprintf("ExchangeBitcoinStateless: Problem creating Bitcoin spend "+
			"transaction given input: %v", bitcoinSpendErr))
		return
	}

	// Add all the signatures to the inputs
	pkData := pubKey.SerializeCompressed()
	for ii, signedHash := range requestData.SignedHashes {
		sig, err := hex.DecodeString(signedHash)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("ExchangeBitcoinStateless: Failed to decode hash: %v", err))
			return
		}
		parsedSig, err := btcec.ParseDERSignature(sig, btcec.S256())
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

	// Check that BitClout purchased they would get does not exceed current balance.
	var feeBasisPoints uint64
	feeBasisPoints, err = fes.GetBuyBitCloutFeeBasisPointsResponseFromGlobalState()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("WyreWalletOrderSubscription: error getting buy bitclout premium basis points from global state: %v", err))
		return
	}

	// Update the current exchange price.
	fes.UpdateUSDCentsToBitCloutExchangeRate()

	nanosPurchased, err := fes.GetNanosFromSats(uint64(burnAmountSatoshis), feeBasisPoints)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("ExchangeBitcoinStateless: Error computing nanos purchased: %v", err))
		return
	}
	balanceInsufficient, err := fes.ExceedsBitCloutBalance(nanosPurchased, fes.Config.BuyBitCloutSeed)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("ExchangeBitcoinStateless: Error checking if send bitclout balance is sufficient: %v", err))
		return
	}
	if balanceInsufficient {
		_AddBadRequestError(ww, fmt.Sprintf("ExchangeBitcoinStateless: SendBitClout wallet balance is below nanos purchased"))
		return
	}

	var bitcloutTxnHash *lib.BlockHash
	if requestData.Broadcast {
		glog.Infof("ExchangeBitcoinStateless: Broadcasting Bitcoin txn: %v", bitcoinTxn)

		// Check whether the deposits being used to construct this transaction have RBF enabled.
		// If they do then we force the user to wait until those deposits have been mined into a
		// block before allowing this transaction to go through. This prevents double-spend
		// attacks where someone replaces a dependent transaction with a higher fee.
		//
		// TODO: We use a pretty janky API to check for this, and if it goes down then
		// BitcoinExchange txns break. But without it we're vulnerable to double-spends
		// so we keep it for now.
		if fes.Params.NetworkType == lib.NetworkType_MAINNET {
			// Go through the transaction's inputs. If any of them have RBF set then we
			// must assume that this transaction has RBF as well.
			for _, txIn := range bitcoinTxn.TxIn {
				isRBF, err := lib.BlockonomicsCheckRBF(txIn.PreviousOutPoint.Hash.String())
				if err != nil {
					glog.Errorf("ExchangeBitcoinStateless: ERROR: Blockonomics request to check RBF for txn "+
						"hash %v failed. This is bad because it means users are not able to "+
						"complete Bitcoin burns: %v", txIn.PreviousOutPoint.Hash.String(), err)
					_AddBadRequestError(ww, fmt.Sprintf(
						"The nodes are still processing your deposit. Please wait a few seconds "+
							"and try again."))
					return
				}
				// If we got a success response from Blockonomics then bail if the transaction has
				// RBF set.
				if isRBF {
					glog.Errorf("ExchangeBitcoinStateless: ERROR: Blockonomics found RBF txn: %v", bitcoinTxnHash.String())
					_AddBadRequestError(ww, fmt.Sprintf(
						"Your deposit has \"replace by fee\" set, "+
							"which means we must wait for one confirmation on the Bitcoin blockchain before "+
							"allowing you to buy. This usually takes about ten minutes.<br><br>"+
							"You can see how many confirmations your deposit has by "+
							"<a target=\"_blank\" href=\"https://www.blockchain.com/btc/tx/%v\">clicking here</a>.", txIn.PreviousOutPoint.Hash.String()))
					return
				}
			}
		}

		// If a BlockCypher API key is set then use BlockCypher to do the checks. Otherwise
		// use Bitcoin nodes to do it. Note that BLockCypher tends to be the more reliable path.
		if fes.BlockCypherAPIKey != "" {
			// Push the transaction to BlockCypher and ensure no error occurs.
			if err = lib.BlockCypherPushAndWaitForTxn(
				hex.EncodeToString(bitcoinTxnBytes), &bitcoinTxnHash,
				fes.BlockCypherAPIKey, fes.Params.BitcoinDoubleSpendWaitSeconds,
				fes.Params); err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("ExchangeBitcoinStateless: Error broadcasting transaction: %v", err))
				return
			}

		} else {
			_AddBadRequestError(ww, fmt.Sprintf("ExchangeBitcoinStateless: BlockCypher API is required for bitcoin transactions"))
			return
		}

		bitcloutTxnHash, err = fes.SendSeedBitClout(pkBytes, nanosPurchased, true)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("ExchangeBitcoinStateless: Error sending BitClout: %v", err))
			return
		}
	}

	bitcloutTxnHashString := ""
	if bitcloutTxnHash != nil {
		bitcloutTxnHashString = bitcloutTxnHash.String()
	}

	res := &ExchangeBitcoinResponse{
		TotalInputSatoshis:   totalInputSatoshis,
		BurnAmountSatoshis:   uint64(burnAmountSatoshis),
		FeeSatoshis:          fee,
		ChangeAmountSatoshis: totalInputSatoshis - uint64(burnAmountSatoshis) - fee,
		BitcoinTransaction:   bitcoinTxn,

		SerializedTxnHex:   hex.EncodeToString(bitcoinTxnBytes),
		TxnHashHex:         bitcoinTxn.TxHash().String(),
		BitCloutTxnHashHex: bitcloutTxnHashString,

		UnsignedHashes: unsignedHashes,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("BurnBitcoin: Problem encoding response as JSON: %v", err))
		return
	}
}

// GetNanosFromSats - convert Satoshis to BitClout nanos
func (fes *APIServer) GetNanosFromSats(satoshis uint64, feeBasisPoints uint64) (uint64, error) {
	usdCentsPerBitcoin := fes.UsdCentsPerBitCoinExchangeRate
	// If we don't have a valid value from monitoring at this time, use the price from the protocol
	if usdCentsPerBitcoin == 0 {
		readUtxoView, _ := fes.backendServer.GetMempool().GetAugmentedUniversalView()
		usdCentsPerBitcoin = float64(readUtxoView.GetCurrentUSDCentsPerBitcoin())
	}
	usdCents := (float64(satoshis) * usdCentsPerBitcoin) / lib.SatoshisPerBitcoin
	return fes.GetNanosFromUSDCents(usdCents, feeBasisPoints)
}

// GetNanosFromUSDCents - convert USD cents to BitClout nanos
func (fes *APIServer) GetNanosFromUSDCents(usdCents float64, feeBasisPoints uint64) (uint64, error) {
	// Get Exchange Price gets the max of price from blockchain.com and the reserve price.
	usdCentsPerBitClout := fes.GetExchangeBitCloutPrice()
	conversionRateAfterFee := float64(usdCentsPerBitClout) * (1 + (float64(feeBasisPoints) / (100.0 * 100.0)))
	nanosPurchased := uint64(usdCents * float64(lib.NanosPerUnit) / conversionRateAfterFee)
	return nanosPurchased, nil
}

// ExceedsSendBitCloutBalance - Check if nanosPurchased is greater than the balance of the BuyBitClout wallet.
func (fes *APIServer) ExceedsBitCloutBalance(nanosPurchased uint64, seed string) (bool, error) {
	buyBitCloutSeedBalance, err := fes.getBalanceForSeed(seed)
	if err != nil {
		return false, fmt.Errorf("Error getting buy bitclout balance: %v", err)
	}
	return nanosPurchased > buyBitCloutSeedBalance, nil
}



// SendBitCloutRequest ...
type SendBitCloutRequest struct {
	SenderPublicKeyBase58Check   string `safeForLogging:"true"`
	RecipientPublicKeyOrUsername string `safeForLogging:"true"`
	AmountNanos                  int64  `safeForLogging:"true"`
	MinFeeRateNanosPerKB         uint64 `safeForLogging:"true"`
}

// SendBitCloutResponse ...
type SendBitCloutResponse struct {
	TotalInputNanos          uint64
	SpendAmountNanos         uint64
	ChangeAmountNanos        uint64
	FeeNanos                 uint64
	TransactionIDBase58Check string
	Transaction              *lib.MsgBitCloutTxn
	TransactionHex           string
	TxnHashHex               string
}

// SendBitClout ...
func (fes *APIServer) SendBitClout(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := SendBitCloutRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendBitClout: Problem parsing request body: %v", err))
		return
	}

	if fes.IsConfiguredForJumio() {
		userMetadata, err := fes.getUserMetadataFromGlobalState(requestData.SenderPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SendBitClout: problem getting user metadata from global state: %v", err))
			return
		}
		if userMetadata.JumioVerified && !userMetadata.HasPurchasedCreatorCoin {
			_AddBadRequestError(ww, fmt.Sprintf("You must purchase a creator coin before you can send $CLOUT"))
			return
		}
	}

	// If the string starts with the public key characters than interpret it as
	// a public key. Otherwise we interpret it as a username and try to look up
	// the corresponding profile.
	var recipientPkBytes []byte
	if strings.Index(requestData.RecipientPublicKeyOrUsername, "BC") == 0 ||
		strings.Index(requestData.RecipientPublicKeyOrUsername, "tBC") == 0 {

		// Decode the recipient's public key.
		var err error
		recipientPkBytes, _, err = lib.Base58CheckDecode(requestData.RecipientPublicKeyOrUsername)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SendBitClout: Problem decoding recipient "+
				"base58 public key %s: %v", requestData.RecipientPublicKeyOrUsername, err))
			return
		}
	} else {
		// TODO(performance): This is inefficient because it loads all mempool
		// transactions.
		utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SendBitClout: Error generating "+
				"view to verify username: %v", err))
			return
		}
		profileEntry := utxoView.GetProfileEntryForUsername(
			[]byte(requestData.RecipientPublicKeyOrUsername))
		if profileEntry == nil {
			_AddBadRequestError(ww, fmt.Sprintf("SendBitClout: Profile with username "+
				"%v does not exist", requestData.RecipientPublicKeyOrUsername))
			return
		}
		recipientPkBytes = profileEntry.PublicKey
	}
	if len(recipientPkBytes) == 0 {
		_AddBadRequestError(ww, fmt.Sprintf("SendBitClout: Unknown error parsing public key."))
		return
	}

	// Decode the sender public key.
	senderPkBytes, _, err := lib.Base58CheckDecode(requestData.SenderPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendBitClout: Problem decoding sender base58 public key %s: %v", requestData.SenderPublicKeyBase58Check, err))
		return
	}

	// If the AmountNanos is less than zero then we have a special case where we create
	// a transaction with the maximum spend.
	var txnn *lib.MsgBitCloutTxn
	var totalInputt uint64
	var spendAmountt uint64
	var changeAmountt uint64
	var feeNanoss uint64
	if requestData.AmountNanos < 0 {
		// Create a MAX transaction
		txnn, totalInputt, spendAmountt, feeNanoss, err = fes.blockchain.CreateMaxSpend(
			senderPkBytes, recipientPkBytes, requestData.MinFeeRateNanosPerKB,
			fes.backendServer.GetMempool())
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SendBitClout: Error processing MAX transaction: %v", err))
			return
		}

	} else {
		// In this case, we are spending what the user asked us to spend as opposed to
		// spending the maximum amount posssible.

		// Create the transaction outputs and add the recipient's public key and the
		// amount we want to pay them
		txnOutputs := []*lib.BitCloutOutput{}
		txnOutputs = append(txnOutputs, &lib.BitCloutOutput{
			PublicKey: recipientPkBytes,
			// If we get here we know the amount is non-negative.
			AmountNanos: uint64(requestData.AmountNanos),
		})

		// Assemble the transaction so that inputs can be found and fees can
		// be computed.
		txnn = &lib.MsgBitCloutTxn{
			// The inputs will be set below.
			TxInputs:  []*lib.BitCloutInput{},
			TxOutputs: txnOutputs,
			PublicKey: senderPkBytes,
			TxnMeta:   &lib.BasicTransferMetadata{},
			// We wait to compute the signature until we've added all the
			// inputs and change.
		}

		// Add inputs to the transaction and do signing, validation, and broadcast
		// depending on what the user requested.
		totalInputt, spendAmountt, changeAmountt, feeNanoss, err =
			fes.blockchain.AddInputsAndChangeToTransaction(
				txnn, requestData.MinFeeRateNanosPerKB, fes.mempool)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SendBitClout: Error processing transaction: %v", err))
			return
		}
	}

	// Sanity check that the input is equal to:
	//   (spend amount + change amount + fees)
	if totalInputt != (spendAmountt + changeAmountt + feeNanoss) {
		_AddBadRequestError(ww, fmt.Sprintf("SendBitClout: totalInput=%d is not equal "+
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
		_AddBadRequestError(ww, fmt.Sprintf("SendBitClout: Problem serializing transaction: %v", err))
		return
	}

	// Return the transaction in the response along with some metadata. If we
	// get to this point and if the user requested that the transaction be
	// validated or broadcast, the user can assume that those operations
	// occurred successfully.
	res := SendBitCloutResponse{
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
		_AddBadRequestError(ww, fmt.Sprintf("SendBitClout: Problem encoding response as JSON: %v", err))
		return
	}
}

// CreateLikeStatelessRequest ...
type CreateLikeStatelessRequest struct {
	ReaderPublicKeyBase58Check string `safeForLogging:"true"`
	LikedPostHashHex           string `safeForLogging:"true"`
	IsUnlike                   bool   `safeForLogging:"true"`
	MinFeeRateNanosPerKB       uint64 `safeForLogging:"true"`
}

// CreateLikeStatelessResponse ...
type CreateLikeStatelessResponse struct {
	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgBitCloutTxn
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

	// We need to make the postHashBytes into a block hash in order to create the txn.
	postHash := lib.BlockHash{}
	copy(postHash[:], postHashBytes)

	// Try and create the message for the user.
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateLikeTxn(
		readerPkBytes, postHash, requestData.IsUnlike,
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool())
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateLikeStateless: Problem creating transaction: %v", err))
		return
	}

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
	BodyObj *lib.BitCloutBodySchema

	// The PostHashHex of the post being reclouted
	RecloutedPostHashHex string `safeForLogging:"true"`

	// ExtraData object to hold arbitrary attributes of a post.
	PostExtraData map[string]string `safeForLogging:"true"`

	// When set to true the post will be hidden.
	IsHidden bool `safeForLogging:"true"`

	MinFeeRateNanosPerKB uint64 `safeForLogging:"true"`
}

// SubmitPostResponse ...
type SubmitPostResponse struct {
	TstampNanos uint64 `safeForLogging:"true"`
	PostHashHex string `safeForLogging:"true"`

	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgBitCloutTxn
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
		} else if strings.Index(requestData.ParentStakeID, "BC") == 0 ||
			strings.Index(requestData.ParentStakeID, "tBC") == 0 {

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

	// If we're not modifying a post then do a bunch of checks.
	var bodyBytes []byte
	var recloutPostHashBytes []byte
	isQuotedReclout := false
	isReclout := false
	if len(postHashToModify) == 0 {
		// Verify that the body length is greater than the minimum.
		if requestData.BodyObj == nil {
			_AddBadRequestError(ww, fmt.Sprintf("SubmitPost: BodyObj is required"))
			return
		}

		// If a post is reclouting another post, we set a boolean value to indicates that this posts is a reclout and
		// convert the PostHashHex to bytes.
		if requestData.RecloutedPostHashHex != "" {
			isReclout = true
			// Convert the post hash hex of the reclouted post to bytes
			recloutPostHashBytes, err = hex.DecodeString(requestData.RecloutedPostHashHex)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("SubmitPost: Could not decode Reclout Post Hash Hex"))
			}
			// Check that the post being reclouted isn't a reclout without a comment.  A user should only be able to reclout
			// a reclout post if it is a quote reclout.
			if requestData.BodyObj.Body == "" && len(requestData.BodyObj.ImageURLs) == 0 {
				var utxoView *lib.UtxoView
				utxoView, err = fes.backendServer.GetMempool().GetAugmentedUniversalView()
				if err != nil {
					_AddBadRequestError(ww, fmt.Sprintf("SubmitPost: Error getting utxoView"))
					return
				}

				// Convert reclout post hash from bytes to block hash and look up postEntry by postHash.
				recloutPostHash := &lib.BlockHash{}
				copy(recloutPostHash[:], recloutPostHashBytes)
				recloutPostEntry := utxoView.GetPostEntryForPostHash(recloutPostHash)

				// If the body of the post that we are trying to reclout is empty, this is an error as
				// we do not want to allow a user to reclout
				if lib.IsVanillaReclout(recloutPostEntry) {
					_AddBadRequestError(ww, fmt.Sprintf("SubmitPost: Cannot reclout a post that is a reclout without a quote"))
					return
				}
			} else {
				isQuotedReclout = true
			}
		}
		bodyBytes, err = fes.cleanBody(requestData.BodyObj, isReclout)

		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"SubmitPost: Error validating body bytes: %v", err))
			return
		}
	} else {
		// In this case we're updating an existing post so just parse the body.
		// TODO: It's probably fine for the other fields to be updated.
		if requestData.RecloutedPostHashHex != "" {
			recloutPostHashBytes, err = hex.DecodeString(requestData.RecloutedPostHashHex)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("SubmitPost: Could not decode Reclout Post Hash Hex"))
			}
			isReclout = true
			if requestData.BodyObj.Body != "" || len(requestData.BodyObj.ImageURLs) > 0 {
				isQuotedReclout = true
			}
		}
		if requestData.BodyObj != nil {
			bodyBytes, err = fes.cleanBody(requestData.BodyObj, isReclout /*isReclout*/)
			if err != nil {
				_AddBadRequestError(ww, err.Error())
				return
			}
		}
	}

	postExtraData := preprocessExtraData(requestData.PostExtraData)

	// Try and create the SubmitPost for the user.
	tstamp := uint64(time.Now().UnixNano())
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateSubmitPostTxn(
		updaterPublicKeyBytes,
		postHashToModify,
		parentStakeID,
		bodyBytes,
		recloutPostHashBytes,
		isQuotedReclout,
		tstamp,
		postExtraData,
		requestData.IsHidden,
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool())
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitPost: Problem creating transaction: %v", err))
		return
	}

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitPost: Problem serializing transaction: %v", err))
		return
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

func (fes *APIServer) cleanBody(bodyObj *lib.BitCloutBodySchema, isReclout bool) ([]byte, error) {
	// Sanitize the Body field on the body object, which should exist.
	if bodyObj.Body == "" && len(bodyObj.ImageURLs) == 0 && !isReclout {
		return nil, fmt.Errorf("SubmitPost: Body or Image is required if not reclouting.")
	}

	bitcloutBodySchema := &lib.BitCloutBodySchema{
		Body:      bodyObj.Body,
		ImageURLs: bodyObj.ImageURLs,
	}
	// Serialize the body object to JSON.
	bodyBytes, err := json.Marshal(bitcloutBodySchema)
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
}

// CreateFollowTxnStatelessResponse ...
type CreateFollowTxnStatelessResponse struct {
	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgBitCloutTxn
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
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool())
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateFollowTxnStateless: Problem creating transaction: %v", err))
		return
	}

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
	// set. In a Buy transaction, BitCloutToSellNanos will be converted into
	// creator coin on behalf of the user. In a Sell transaction,
	// CreatorCoinToSellNanos will be converted into BitClout. In an AddBitClout
	// operation, BitCloutToAddNanos will be aded for the user. This allows us to
	// support multiple transaction types with same meta field.
	BitCloutToSellNanos    uint64 `safeForLogging:"true"`
	CreatorCoinToSellNanos uint64 `safeForLogging:"true"`
	BitCloutToAddNanos     uint64 `safeForLogging:"true"`

	// When a user converts BitClout into CreatorCoin, MinCreatorCoinExpectedNanos
	// specifies the minimum amount of creator coin that the user expects from their
	// transaction. And vice versa when a user is converting CreatorCoin for BitClout.
	// Specifying these fields prevents the front-running of users' buy/sell. Setting
	// them to zero turns off the check. Give it your best shot, Ivan.
	MinBitCloutExpectedNanos    uint64 `safeForLogging:"true"`
	MinCreatorCoinExpectedNanos uint64 `safeForLogging:"true"`

	MinFeeRateNanosPerKB uint64 `safeForLogging:"true"`
}

// BuyOrSellCreatorCoinResponse ...
type BuyOrSellCreatorCoinResponse struct {
	// The amount of BitClout
	ExpectedBitCloutReturnedNanos    uint64
	ExpectedCreatorCoinReturnedNanos uint64
	FounderRewardGeneratedNanos      uint64

	// Spend is defined as BitClout that's specified as input that winds up as "output not
	// belonging to you." In the case of a creator coin sell, your input is creator coin (not
	// BitClout), so this ends up being 0. In the case of a creator coin buy,
	// it should equal the amount of BitClout you put in to buy the creator coin
	SpendAmountNanos  uint64
	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgBitCloutTxn
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

	// Decode the creator public key
	creatorPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.CreatorPublicKeyBase58Check)
	if err != nil || len(creatorPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		_AddBadRequestError(ww, fmt.Sprintf(
			"BuyOrSellCreatorCoin: Problem decoding creator public key %s: %v",
			requestData.CreatorPublicKeyBase58Check, err))
		return
	}

	if requestData.BitCloutToSellNanos == 0 && requestData.CreatorCoinToSellNanos == 0 {
		_AddBadRequestError(ww, fmt.Sprintf(
			"BuyOrSellCreatorCoin: One of the following is required: "+
				"{BitCloutToSellNanos, CreatorCoinToSellNanos}"))
		return
	}
	if requestData.BitCloutToAddNanos != 0 {
		_AddBadRequestError(ww, fmt.Sprintf("BuyOrSellCreatorCoin: BitCloutToAddNanos not yet supported"))
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
		requestData.BitCloutToSellNanos,
		requestData.CreatorCoinToSellNanos,
		requestData.BitCloutToAddNanos,
		requestData.MinBitCloutExpectedNanos,
		requestData.MinCreatorCoinExpectedNanos,
		// Standard transaction fields
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool())
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("BuyOrSellCreatorCoin: Problem adding inputs and change transaction: %v", err))
		return
	}

	// Compute how much CreatorCoin or BitClout we expect to be returned
	// from applying this transaction. This helps the UI display an estimated
	// price.
	ExpectedBitCloutReturnedNanos := uint64(0)
	ExpectedCreatorCoinReturnedNanos := uint64(0)
	FounderRewardGeneratedNanos := uint64(0)
	{
		utxoView, err := fes.mempool.GetAugmentedUtxoViewForPublicKey(updaterPublicKeyBytes, txn)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("BuyOrSellCreatorCoin: Problem computing view for transaction: %v", err))
			return
		}
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
			_, _, bitCloutreturnedNanos, _, err :=
				utxoView.HelpConnectCreatorCoinSell(txn, txHash, blockHeight, false /*verifySignatures*/)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("BuyOrSellCreatorCoin: Problem connecting sell transaction: %v", err))
				return
			}
			ExpectedBitCloutReturnedNanos = bitCloutreturnedNanos

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

	// Return all the data associated with the transaction in the response
	res := BuyOrSellCreatorCoinResponse{
		ExpectedBitCloutReturnedNanos:    ExpectedBitCloutReturnedNanos,
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
		_AddBadRequestError(ww, fmt.Sprintf("SendMessage: Problem encoding response as JSON: %v", err))
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
}

// TransferCreatorCoinResponse ...
type TransferCreatorCoinResponse struct {
	SpendAmountNanos  uint64
	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgBitCloutTxn
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
		utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
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
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool())
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("TransferCreatorCoin: Problem creating transaction: %v", err))
		return
	}

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
}

// SendDiamondsResponse ...
type SendDiamondsResponse struct {
	SpendAmountNanos  uint64
	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *lib.MsgBitCloutTxn
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

	// Try and create the transfer with diamonds for the user.
	// We give diamonds in CLOUT if we're past the corresponding block height.
	blockHeight := fes.blockchain.BlockTip().Height + 1
	var txn *lib.MsgBitCloutTxn
	var totalInput uint64
	var changeAmount uint64
	var fees uint64
	if blockHeight > lib.BitCloutDiamondsBlockHeight {
		txn, totalInput, _, changeAmount, fees, err = fes.blockchain.CreateBasicTransferTxnWithDiamonds(
			senderPublicKeyBytes,
			diamondPostHash,
			requestData.DiamondLevel,
			// Standard transaction fields
			requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool())
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SendDiamonds: Problem creating transaction: %v", err))
			return
		}

	} else {
		txn, totalInput, changeAmount, fees, err = fes.blockchain.CreateCreatorCoinTransferTxnWithDiamonds(
			senderPublicKeyBytes,
			receiverPublicKeyBytes,
			diamondPostHash,
			requestData.DiamondLevel,
			// Standard transaction fields
			requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool())
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SendDiamonds: Problem creating transaction: %v", err))
			return
		}
	}

	txnBytes, err := txn.ToBytes(true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendDiamonds: Problem serializing transaction: %v", err))
		return
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
