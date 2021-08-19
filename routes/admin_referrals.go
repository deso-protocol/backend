package routes

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/bitclout/core/lib"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/base58"
	"github.com/pkg/errors"
)

type AdminCreateReferralHashRequest struct {
	// A username or public name can be provided. If both are provided, public key is used.
	UserPublicKeyBase58Check string `safeForLogging:"true"`
	Username                 string `safeForLogging:"true"`

	// ReferralInfo to add for the new referral hash.
	ReferrerAmountUSDCents uint64 `safeForLogging:"true"`
	RefereeAmountUSDCents  uint64 `safeForLogging:"true"`
	RequiresJumio          bool   `safeForLogging:"true"`

	AdminPublicKey string `safeForLogging:"true"`
}

type AdminCreateReferralHashResponse struct {
	ReferralHashBase58 string `safeForLogging:"true"`
}

func (fes *APIServer) putReferralHashWithInfo(
	referralHashBase58 string,
	referralInfo *ReferralInfo,
) (_err error) {
	referralHashBytes := base58.Decode(referralHashBase58)

	dbKey := GlobalStateKeyForReferralHashToReferralInfo(referralHashBytes)

	// Encode the updated entry and stick it in the database.
	referralInfoDataBuf := bytes.NewBuffer([]byte{})
	gob.NewEncoder(referralInfoDataBuf).Encode(referralInfo)
	err := fes.GlobalStatePut(dbKey, referralInfoDataBuf.Bytes())
	if err != nil {
		return errors.Wrap(fmt.Errorf(
			"putReferralHashWithInfo: Problem putting updated referralInfo: %v", err), "")
	}

	return nil
}

func (fes *APIServer) setReferralHashStatusForPublicKey(
	pkBytes []byte, referralHashBase58 string, isActive bool,
) (_err error) {
	referralHashBytes := base58.Decode(referralHashBase58)

	// Get the PKID for the pub key passed in.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return errors.Wrap(fmt.Errorf("putReferralHashWithInfo: Problem getting utxoView: %v", err), "")
	}
	referrerPKID := utxoView.GetPKIDForPublicKey(pkBytes)
	if referrerPKID == nil {
		return errors.Wrap(fmt.Errorf(
			"putReferralHashWithInfo: nil PKID for pubkey: %v", lib.PkToString(pkBytes, fes.Params)), "")
	}

	dbKey := GlobalStateKeyForPKIDReferralHashToIsActive(referrerPKID.PKID, referralHashBytes)

	// Encode the updated entry and stick it in the database.
	err = fes.GlobalStatePut(dbKey, []byte{lib.BoolToByte(isActive)})
	if err != nil {
		return errors.Wrap(fmt.Errorf(
			"putReferralHashWithInfo: Problem putting updated referralInfo: %v", err), "")
	}

	return nil
}

func (fes *APIServer) AdminCreateReferralHash(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminCreateReferralHashRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminCreateReferralHash: Problem parsing request body: %v", err))
		return
	}

	if requestData.UserPublicKeyBase58Check == "" && requestData.Username == "" {
		_AddBadRequestError(ww,
			fmt.Sprintf("AdminCreateReferralHashRequest: Must provide a valid username or public key."))
		return
	}

	referralLimitUSD := uint64(100000)
	if requestData.ReferrerAmountUSDCents > referralLimitUSD || requestData.RefereeAmountUSDCents > referralLimitUSD {
		_AddBadRequestError(ww,
			fmt.Sprintf("AdminCreateReferralHashRequest: Referrer and referee amounts should not exceed $1000 USD."))
		return
	}

	// Decode the user public key, if provided.
	var userPublicKeyBytes []byte
	var err error
	if requestData.UserPublicKeyBase58Check != "" {
		userPublicKeyBytes, _, err = lib.Base58CheckDecode(requestData.UserPublicKeyBase58Check)
		if err != nil || len(userPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
			_AddBadRequestError(ww, fmt.Sprintf("AdminCreateReferralHash: Problem decoding updater public key %s: %v",
				requestData.UserPublicKeyBase58Check, err))
			return
		}
	}

	// If we didn't get a public key, try and get one for the username.
	if userPublicKeyBytes == nil && requestData.Username != "" {
		utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminCreateReferralHash: Problem fetching utxoView: %v", err))
			return
		}

		profile := utxoView.GetProfileEntryForUsername([]byte(requestData.Username))
		if profile == nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminCreateReferralHash: Problem getting profile for username: %v : %s", err, requestData.Username))
			return
		}
		userPublicKeyBytes = profile.PublicKey
	}

	// Create a new referral hash. First we generate 16 random bytes of entropy (we should only need 8
	// but we double this to be safe), then we Base58 encode those bytes and take the first 8 characters.
	randBytes := make([]byte, 16)
	rand.Read(randBytes) // Since we are using crypto/rand there is no need to do rand.Seed()
	randBase58 := base58.Encode(randBytes)
	if len(randBase58) < 8 {
		_AddInternalServerError(ww, fmt.Sprintf(
			"AdminCreateReferralHash: randBase58 string is less than 8 characters (%d)", len(randBase58)))
		return
	}
	referralHashBase58 := randBase58[:8]

	// Create and fill a ReferralInfo struct for the new referral hash.
	referralInfo := &ReferralInfo{
		ReferrerAmountUSDCents: requestData.ReferrerAmountUSDCents,
		RefereeAmountUSDCents:  requestData.RefereeAmountUSDCents,
		RequiresJumio:          requestData.RequiresJumio,
		ReferralHashBase58:     referralHashBase58,
	}

	// Encode the updated entry and stick it in the database.
	err = fes.putReferralHashWithInfo(referralHashBase58, referralInfo)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminCreateReferralHash: Problem putting new referral hash and info: %v", err))
		return
	}

	// Set this as a new active referral hash for the user.
	err = fes.setReferralHashStatusForPublicKey(userPublicKeyBytes, referralHashBase58, true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminCreateReferralHash: Problem putting new referral hash and info: %v", err))
		return
	}

	// If we made it this far we were successful, return without error.
	res := AdminCreateReferralHashResponse{
		ReferralHashBase58: referralHashBase58,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminCreateReferralHash: Problem encoding response as JSON: %v", err))
		return
	}
}

type ReferralInfoResponse struct {
	IsActive bool
	Info     ReferralInfo
}

type AdminGetAllReferralInfoForUserRequest struct {
	// A username or public name can be provided. If both are provided, public key is used.
	UserPublicKeyBase58Check string `safeForLogging:"true"`
	Username                 string `safeForLogging:"true"`

	AdminPublicKey string `safeForLogging:"true"`
}

type AdminGetAllReferralInfoForUserResponse struct {
	ReferralInfoResponses []ReferralInfoResponse `safeForLogging:"true"`
}

func (fes *APIServer) getReferralInfoResponsesForPubKey(pkBytes []byte,
) (_referralInfoResponses []ReferralInfoResponse, _err error) {

	// Get the PKID for the pub key passed in.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		return nil, fmt.Errorf("putReferralHashWithInfo: Problem getting utxoView: %v", err)
	}
	referrerPKID := utxoView.GetPKIDForPublicKey(pkBytes)
	if referrerPKID == nil {
		return nil, fmt.Errorf(
			"putReferralHashWithInfo: nil PKID for pubkey: %v", lib.PkToString(pkBytes, fes.Params))
	}

	// Build a key to seek all of the referral hashes for this PKID.
	dbSeekKey := GlobalStateSeekKeyForPKIDReferralHashes(referrerPKID.PKID)
	keysFound, valsFound, err := fes.GlobalStateSeek(
		dbSeekKey, dbSeekKey, 0, 0, false /*reverse*/, true /*fetchValue*/)

	referralHashStartIndex := 1 + len(referrerPKID.PKID)
	var referralInfoResponses []ReferralInfoResponse
	for keyIndex, key := range keysFound {
		// Chop out all the referral hashes from the keys found.
		referralHashBytes := key[referralHashStartIndex:]
		referralHash := base58.Encode(referralHashBytes)

		// Grab the 'IsActive' status for this hash.
		isActiveBytes := valsFound[keyIndex]
		if len(isActiveBytes) == 0 {
			return nil, fmt.Errorf("fes.getReferralInfoResponsesForPubKey: got zero isActiveBytes: %s", referralHash)
		}
		isActive := lib.ReadBoolByte(bytes.NewReader(isActiveBytes))

		// Look up and decode the referral info for the hash.
		dbKey := GlobalStateKeyForReferralHashToReferralInfo(referralHashBytes)
		referralInfoBytes, err := fes.GlobalStateGet(dbKey)
		if err != nil {
			return nil, fmt.Errorf(
				"fes.getReferralInfoResponsesForPubKey: error getting referral info (%s): %v",
				referralHash, err)
		}
		referralInfo := ReferralInfo{}
		if referralInfoBytes != nil {
			err = gob.NewDecoder(bytes.NewReader(referralInfoBytes)).Decode(&referralInfo)
			if err != nil {
				return nil, fmt.Errorf(
					"getReferralInfoResponsesForPubKey: Failed decoding referral info (%s): %v",
					referralHash, err)
			}
		}

		// Construct the referral info response and append it to our list.
		referralInfoResponse := ReferralInfoResponse{
			IsActive: isActive,
			Info:     referralInfo,
		}
		referralInfoResponses = append(referralInfoResponses, referralInfoResponse)

	}

	return referralInfoResponses, nil
}

func (fes *APIServer) AdminGetAllReferralInfoForUser(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminGetAllReferralInfoForUserRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AdminGetAllReferralInfoForUser: Problem parsing request body: %v", err))
		return
	}

	if requestData.UserPublicKeyBase58Check == "" && requestData.Username == "" {
		_AddBadRequestError(ww,
			fmt.Sprintf("AdminGetAllReferralInfoForUser: Must provide a valid username or public key."))
		return
	}

	// Decode the user public key, if provided.
	var userPublicKeyBytes []byte
	var err error
	if requestData.UserPublicKeyBase58Check != "" {
		userPublicKeyBytes, _, err = lib.Base58CheckDecode(requestData.UserPublicKeyBase58Check)
		if err != nil || len(userPublicKeyBytes) != btcec.PubKeyBytesLenCompressed {
			_AddBadRequestError(ww, fmt.Sprintf("AdminGetAllReferralInfoForUser: Problem decoding updater public key %s: %v",
				requestData.UserPublicKeyBase58Check, err))
			return
		}
	}

	// If we didn't get a public key, try and get one for the username.
	if userPublicKeyBytes == nil && requestData.Username != "" {
		utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminGetAllReferralInfoForUser: Problem fetching utxoView: %v", err))
			return
		}

		profile := utxoView.GetProfileEntryForUsername([]byte(requestData.Username))
		if profile == nil {
			_AddBadRequestError(ww, fmt.Sprintf("AdminGetAllReferralInfoForUser: Problem getting profile for username: %v : %s", err, requestData.Username))
			return
		}
		userPublicKeyBytes = profile.PublicKey
	}

	// Get the referral link info structs.
	referralInfoResponses, err := fes.getReferralInfoResponsesForPubKey(userPublicKeyBytes)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetAllReferralInfoForUser: Problem putting new referral hash and info: %v", err))
		return
	}

	// If we made it this far we were successful, return without error.
	res := AdminGetAllReferralInfoForUserResponse{
		ReferralInfoResponses: referralInfoResponses,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminCreateReferralHash: Problem encoding response as JSON: %v", err))
		return
	}
}
