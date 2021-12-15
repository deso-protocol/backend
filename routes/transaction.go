package routes

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/deso-protocol/core/lib"
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
	// Only check DB in testnet for now.
	if !txnFound && fes.Params.NetworkType == lib.NetworkType_TESTNET {
		txnFound = lib.DbCheckTxnExistence(fes.TXIndex.TXIndexChain.DB(), txnHash)
	}
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
	Transaction *lib.MsgDeSoTxn
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

	txn := &lib.MsgDeSoTxn{}
	err = txn.FromBytes(txnBytes)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitTransactionRequest: Problem deserializing transaction from bytes: %v", err))
		return
	}

	_, diamondPostHashKeyExists := txn.ExtraData[lib.DiamondPostHashKey]
	// If this is a basic transfer (but not a diamond action), we check if user has completed the tutorial (if this node is configured for Jumio)
	if !diamondPostHashKeyExists && txn.TxnMeta.GetTxnType() == lib.TxnTypeBasicTransfer && fes.IsConfiguredForJumio() {
		var userMetadata *UserMetadata
		userMetadata, err = fes.getUserMetadataFromGlobalStateByPublicKeyBytes(txn.PublicKey)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SubmitTransactionRequest: Problem getting usermetadata from global state for basic transfer: %v", err))
			return
		}
		if userMetadata.MustCompleteTutorial && userMetadata.TutorialStatus != COMPLETE && userMetadata.TutorialStatus != SKIPPED {
			_AddBadRequestError(ww, fmt.Sprintf("SubmitTransactionRequest: If you receive money from Jumio, you must complete the tutorial: %v", err))
			return
		}
	}

	if err = fes.backendServer.VerifyAndBroadcastTransaction(txn); err != nil {
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
func (fes *APIServer) _afterProcessSubmitPostTransaction(txn *lib.MsgDeSoTxn, response *SubmitTransactionResponse) error {
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
				fes.blockchain.DB(), updaterPublicKeyBytes, false /*fetchEntries*/, uint64(minTimestampNanos), 0, /*maxTimestampNanos*/
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

	MinFeeRateNanosPerKB uint64 `safeForLogging:"true"`

	// No need to specify ProfileEntryResponse in each TransactionFee
	TransactionFees []TransactionFee `safeForLogging:"true"`
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

	if len(requestData.NewUsername) > 0 && strings.Index(requestData.NewUsername, fes.PublicKeyBase58Prefix) == 0 {
		_AddBadRequestError(ww, fmt.Sprintf(
			"UpdateProfile: Username cannot start with %s", fes.PublicKeyBase58Prefix))
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
		existingProfile, usernameExists := utxoView.ProfileUsernameToProfileEntry[lib.MakeUsernameMapKey([]byte(requestData.NewUsername))]
		if usernameExists && existingProfile != nil && !existingProfile.IsDeleted() {
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
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool(), additionalOutputs)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateProfile: Problem creating transaction: %v", err))
		return
	}

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

func (fes *APIServer) CompProfileCreation(profilePublicKey []byte, userMetadata *UserMetadata, utxoView *lib.UtxoView) (_additionalFee uint64, _txnHash *lib.BlockHash, _err error) {
	// Determine if this is a profile creation request and if we need to comp the user for creating the profile.
	existingProfileEntry := utxoView.GetProfileEntryForPublicKey(profilePublicKey)
	// If we are updating an existing profile, there is no fee and we do not comp anything.
	if existingProfileEntry != nil {
		return 0, nil, nil
	}
	// Additional fee is set to the create profile fee when we are creating a profile
	additionalFees := utxoView.GlobalParamsEntry.CreateProfileFeeNanos

	// Only comp create profile fee if frontend server has both twilio and starter deso seed configured and the user
	// has verified their profile.
	if !fes.Config.CompProfileCreation || fes.Config.StarterDESOSeed == "" || fes.Twilio == nil || (userMetadata.PhoneNumber == "" && !userMetadata.JumioVerified) {
		return additionalFees, nil, nil
	}
	var currentBalanceNanos uint64
	currentBalanceNanos, err := GetBalanceForPublicKeyUsingUtxoView(profilePublicKey, utxoView)
	if err != nil {
		return 0, nil, errors.Wrap(fmt.Errorf("UpdateProfile: error getting current balance: %v", err), "")
	}
	createProfileFeeNanos := utxoView.GlobalParamsEntry.CreateProfileFeeNanos

	// If a user is jumio verified, we just comp the profile even if their balance is greater than the create profile fee.
	// If a user has a phone number verified but is not jumio verified, we need to check that they haven't spent all their
	// starter deso already and that ShouldCompProfileCreation is true
	var phoneNumberMetadata *PhoneNumberMetadata
	if userMetadata.PhoneNumber != "" && !userMetadata.JumioVerified {
		phoneNumberMetadata, err = fes.getPhoneNumberMetadataFromGlobalState(userMetadata.PhoneNumber)
		if err != nil {
			return 0, nil, errors.Wrap(fmt.Errorf("UpdateProfile: error getting phone number metadata for public key %v: %v", profilePublicKey, err), "")
		}
		if phoneNumberMetadata == nil {
			return 0, nil, errors.Wrap(fmt.Errorf("UpdateProfile: no phone number metadata for phone number %v", userMetadata.PhoneNumber), "")
		}
		if !phoneNumberMetadata.ShouldCompProfileCreation || currentBalanceNanos > createProfileFeeNanos {
			return additionalFees, nil, nil
		}
	} else {
		// User has been Jumio verified but should comp profile creation is false, just return
		if !userMetadata.JumioShouldCompProfileCreation {
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
	// We comp the create profile fee minus the minimum starter deso amount divided by 2.
	// This discourages botting while covering users who verify a phone number.
	compAmount := createProfileFeeNanos - (minStarterDESONanos / 2)
	// If the user won't have enough deso to cover the fee, this is an error.
	if currentBalanceNanos+compAmount < createProfileFeeNanos {
		return 0, nil, errors.Wrap(fmt.Errorf("Creating a profile requires DeSo.  Please purchase some to create a profile."), "")
	}
	// Set should comp to false so we don't continually comp a public key.  PhoneNumberMetadata is only non-nil if
	// a user verified their phone number but is not jumio verified.
	if phoneNumberMetadata != nil {
		phoneNumberMetadata.ShouldCompProfileCreation = false
		if err = fes.putPhoneNumberMetadataInGlobalState(phoneNumberMetadata); err != nil {
			return 0, nil, errors.Wrap(fmt.Errorf("UpdateProfile: Error setting ShouldComp to false for phone number metadata: %v", err), "")
		}
	} else {
		// Set JumioShouldCompProfileCreation to false so we don't continue to comp profile creation.
		userMetadata.JumioShouldCompProfileCreation = false
		if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
			return 0, nil, errors.Wrap(fmt.Errorf("UpdateProfile: Error setting ShouldComp to false for jumio user metadata: %v", err), "")
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

	// Check that DeSo purchased they would get does not exceed current balance.
	var feeBasisPoints uint64
	feeBasisPoints, err = fes.GetBuyDeSoFeeBasisPointsResponseFromGlobalState()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("WyreWalletOrderSubscription: error getting buy deso premium basis points from global state: %v", err))
		return
	}

	// Update the current exchange price.
	fes.UpdateUSDCentsToDeSoExchangeRate()

	nanosPurchased := fes.GetNanosFromSats(uint64(burnAmountSatoshis), feeBasisPoints)
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
	usdCentsPerDeSo := fes.GetExchangeDeSoPrice()
	conversionRateAfterFee := float64(usdCentsPerDeSo) * (1 + (float64(feeBasisPoints) / (100.0 * 100.0)))
	nanosPurchased := uint64(usdCents * float64(lib.NanosPerUnit) / conversionRateAfterFee)
	return nanosPurchased
}

func (fes *APIServer) GetUSDFromNanos(nanos uint64) float64 {
	usdCentsPerDeSo := float64(fes.UsdCentsPerDeSoExchangeRate)
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
	SenderPublicKeyBase58Check   string `safeForLogging:"true"`
	RecipientPublicKeyOrUsername string `safeForLogging:"true"`
	AmountNanos                  int64  `safeForLogging:"true"`
	MinFeeRateNanosPerKB         uint64 `safeForLogging:"true"`

	// No need to specify ProfileEntryResponse in each TransactionFee
	TransactionFees []TransactionFee `safeForLogging:"true"`
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

// SendDeSo ...
func (fes *APIServer) SendDeSo(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := SendDeSoRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendDeSo: Problem parsing request body: %v", err))
		return
	}

	if fes.IsConfiguredForJumio() {
		userMetadata, err := fes.getUserMetadataFromGlobalState(requestData.SenderPublicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SendDeSo: problem getting user metadata from global state: %v", err))
			return
		}
		if userMetadata.JumioVerified && userMetadata.MustCompleteTutorial && userMetadata.TutorialStatus != COMPLETE {
			_AddBadRequestError(ww, fmt.Sprintf("You must complete the tutorial before you can perform a basic transfer"))
			return
		}
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
		utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
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

	// If the AmountNanos is less than zero then we have a special case where we create
	// a transaction with the maximum spend.
	var txnn *lib.MsgDeSoTxn
	var totalInputt uint64
	var spendAmountt uint64
	var changeAmountt uint64
	var feeNanoss uint64
	if requestData.AmountNanos < 0 {
		// Create a MAX transaction
		txnn, totalInputt, spendAmountt, feeNanoss, err = fes.blockchain.CreateMaxSpend(
			senderPkBytes, recipientPkBytes, requestData.MinFeeRateNanosPerKB,
			fes.backendServer.GetMempool(), additionalOutputs)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SendDeSo: Error processing MAX transaction: %v", err))
			return
		}

	} else {
		// In this case, we are spending what the user asked us to spend as opposed to
		// spending the maximum amount possible.

		// Create the transaction outputs and add the recipient's public key and the
		// amount we want to pay them
		txnOutputs := append(additionalOutputs, &lib.DeSoOutput{
			PublicKey: recipientPkBytes,
			// If we get here we know the amount is non-negative.
			AmountNanos: uint64(requestData.AmountNanos),
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

		// Add inputs to the transaction and do signing, validation, and broadcast
		// depending on what the user requested.
		totalInputt, spendAmountt, changeAmountt, feeNanoss, err =
			fes.blockchain.AddInputsAndChangeToTransaction(
				txnn, requestData.MinFeeRateNanosPerKB, fes.mempool)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SendDeSo: Error processing transaction: %v", err))
			return
		}
	}

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

	var utxoView *lib.UtxoView
	utxoView, err = fes.backendServer.GetMempool().GetAugmentedUniversalView()
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

	postExtraData := preprocessExtraData(requestData.PostExtraData)

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

	utxoView, err := fes.mempool.GetAugmentedUtxoViewForPublicKey(updaterPublicKeyBytes, txn)
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

	// No need to specify ProfileEntryResponse in each TransactionFee
	TransactionFees []TransactionFee `safeForLogging:"true"`
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
		requestData.MinFeeRateNanosPerKB, fes.backendServer.GetMempool(), additionalOutputs)
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

	// Try and create the transfer with diamonds for the user.
	// We give diamonds in DESO if we're past the corresponding block height.
	blockHeight := fes.blockchain.BlockTip().Height + 1
	var txn *lib.MsgDeSoTxn
	var totalInput uint64
	var changeAmount uint64
	var fees uint64
	var additionalOutputs []*lib.DeSoOutput
	if blockHeight > lib.DeSoDiamondsBlockHeight {
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

	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreateAuthorizeDerivedKeyTxn(
		ownerPublicKeyBytes,
		derivedPublicKeyBytes,
		requestData.ExpirationBlock,
		accessSignature,
		requestData.DeleteKey,
		requestData.DerivedKeySignature,
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
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AuthorizeDerivedKey: Problem encoding response as JSON: %v", err))
		return
	}
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

	// Append ExtraData entries
	if txn.ExtraData == nil {
		txn.ExtraData = make(map[string][]byte)
	}

	for k, v := range requestData.ExtraData {
		vBytes, err := hex.DecodeString(v)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AppendExtraData: Problem decoding ExtraData: %v", err))
			return
		}
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

	// If transaction has no inputs we can return immediately.
	if len(txn.TxInputs) == 0 {
		// Return the final transaction spending.
		res := GetTransactionSpendingResponse{
			TotalSpendingNanos: 0,
		}
		if err := json.NewEncoder(ww).Encode(res); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetTransactionSpending: Problem encoding response as JSON: %v", err))
		}
		return
	}

	// Get augmented universal view from mempool.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetTransactionSpending: Problem getting AugmentedUniversalView: %v", err))
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
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetTransactionSpending: Problem encoding response as JSON: %v", err))
	}
	return
}
