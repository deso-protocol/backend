package routes

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"time"

	"github.com/bitclout/core/lib"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/base58"
	"github.com/pkg/errors"
)

func (fes *APIServer) putReferralHashWithInfo(
	referralHashBase58 string,
	referralInfo *ReferralInfo,
) (_err error) {
	referralHashBytes := []byte(referralHashBase58)

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

func (fes *APIServer) getInfoForReferralHashBase58(
	referralHashBase58 string,
) (_referralInfo *ReferralInfo, _err error) {
	referralHashBytes := []byte(referralHashBase58)

	dbKey := GlobalStateKeyForReferralHashToReferralInfo(referralHashBytes)

	// Get the entry and decode the bytes.
	referralInfoBytes, err := fes.GlobalStateGet(dbKey)
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf(
			"getInfoForReferralHash: Problem putting updated referralInfo: %v", err), "")
	}
	referralInfo := ReferralInfo{}
	if referralInfoBytes != nil {
		err = gob.NewDecoder(bytes.NewReader(referralInfoBytes)).Decode(&referralInfo)
		if err != nil {
			return nil, fmt.Errorf(
				"getInfoForReferralHash: Failed decoding referral info (%s): %v",
				referralHashBase58, err)
		}
	} else {
		return nil, fmt.Errorf(
			"getInfoForReferralHashBase58: got nil bytes for hash (%s)", referralHashBase58)
	}

	return &referralInfo, nil
}

func (fes *APIServer) getReferralHashStatus(pkid *lib.PKID, referralHashBase58 string) bool {
	referralHashBytes := []byte(referralHashBase58)

	dbKey := GlobalStateKeyForPKIDReferralHashToIsActive(pkid, referralHashBytes)

	val, err := fes.GlobalStateGet(dbKey)
	if err != nil {
		return false
	}
	return reflect.DeepEqual(val, []byte{1})
}

func (fes *APIServer) setReferralHashStatusForPKID(
	pkid *lib.PKID, referralHashBase58 string, isActive bool,
) (_err error) {
	referralHashBytes := []byte(referralHashBase58)

	dbKey := GlobalStateKeyForPKIDReferralHashToIsActive(pkid, referralHashBytes)

	// Encode the updated entry and stick it in the database.
	err := fes.GlobalStatePut(dbKey, []byte{lib.BoolToByte(isActive)})
	if err != nil {
		return errors.Wrap(fmt.Errorf(
			"putReferralHashWithInfo: Problem putting updated referralInfo: %v", err), "")
	}

	return nil
}

func generateNewReferralHash() (_newHash string, _err error) {
	// Create a new referral hash. First we generate 16 random bytes of entropy (we should only need 8
	// but we double this to be safe), then we Base58 encode those bytes and take the first 8 characters.
	randBytes := make([]byte, 16)
	rand.Read(randBytes) // Since we are using crypto/rand there is no need to do rand.Seed()
	randBase58 := base58.Encode(randBytes)
	if len(randBase58) < 8 {
		return "", fmt.Errorf(
			"AdminCreateReferralHash: randBase58 string is less than 8 characters (%d)", len(randBase58))
	}
	return randBase58[:8], nil
}

type AdminCreateReferralHashRequest struct {
	// A username or public name can be provided. If both are provided, public key is used.
	UserPublicKeyBase58Check string `safeForLogging:"true"`
	Username                 string `safeForLogging:"true"`

	// ReferralInfo to add for the new referral hash.
	ReferrerAmountUSDCents uint64 `safeForLogging:"true"`
	RefereeAmountUSDCents  uint64 `safeForLogging:"true"`
	MaxReferrals           uint64 `safeForLogging:"true"`
	RequiresJumio          bool   `safeForLogging:"true"`

	AdminPublicKey string `safeForLogging:"true"`
}

type AdminCreateReferralHashResponse struct {
	ReferralInfoResponse ReferralInfoResponse `safeForLogging:"true"`
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

	// Get the PKID for the pub key.
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminCreateReferralHash: Problem getting utxoView: %v", err))
		return
	}
	referrerPKID := utxoView.GetPKIDForPublicKey(userPublicKeyBytes)
	if referrerPKID == nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AdminCreateReferralHash: nil PKID for pubkey: %v", lib.PkToString(userPublicKeyBytes, fes.Params)))
		return
	}

	// Generate a fresh referral hash for the new link.
	referralHashBase58, err := generateNewReferralHash()
	if err != nil {
		_AddInternalServerError(ww, fmt.Sprintf(
			"AdminCreateReferralHash: problem generating referral hash: %v", err))
		return
	}

	// Create and fill a ReferralInfo struct for the new referral hash.
	referralInfo := &ReferralInfo{
		ReferrerAmountUSDCents: requestData.ReferrerAmountUSDCents,
		RefereeAmountUSDCents:  requestData.RefereeAmountUSDCents,
		MaxReferrals:           requestData.MaxReferrals,
		RequiresJumio:          requestData.RequiresJumio,
		ReferralHashBase58:     referralHashBase58,
		ReferrerPKID:           referrerPKID.PKID,
		DateCreatedTStampNanos: uint64(time.Now().UnixNano()),
	}

	// Encode the updated entry and stick it in the database.
	err = fes.putReferralHashWithInfo(referralHashBase58, referralInfo)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AdminCreateReferralHash: Problem putting new referral hash and info: %v", err))
		return
	}

	// Set this as a new active referral hash for the user.
	err = fes.setReferralHashStatusForPKID(referrerPKID.PKID, referralHashBase58, true)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AdminCreateReferralHash: Problem setting referral hash status: %v", err))
		return
	}

	// If we made it this far we were successful, return without error.
	res := AdminCreateReferralHashResponse{
		ReferralInfoResponse: ReferralInfoResponse{
			IsActive: true,
			Info:     *referralInfo,
		},
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminCreateReferralHash: Problem encoding response as JSON: %v", err))
		return
	}
}

type AdminUpdateReferralHashRequest struct {
	// Referral hash to update.
	ReferralHashBase58 string `safeForLogging:"true"`

	// ReferralInfo to updatethe referral hash with.
	ReferrerAmountUSDCents uint64 `safeForLogging:"true"`
	RefereeAmountUSDCents  uint64 `safeForLogging:"true"`
	MaxReferrals           uint64 `safeForLogging:"true"`
	RequiresJumio          bool   `safeForLogging:"true"`
	IsActive               bool   `safeForLogging:"true"`

	AdminPublicKey string `safeForLogging:"true"`
}

type AdminUpdateReferralHashResponse struct {
	ReferralInfoResponse ReferralInfoResponse `safeForLogging:"true"`
}

func (fes *APIServer) AdminUpdateReferralHash(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminUpdateReferralHashRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateReferralHash: Problem parsing request body: %v", err))
		return
	}

	if requestData.ReferralHashBase58 == "" {
		_AddBadRequestError(ww,
			fmt.Sprintf("AdminUpdateReferralHashRequest: Must provide a referral hash to update."))
		return
	}

	referralInfo, err := fes.getInfoForReferralHashBase58(requestData.ReferralHashBase58)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AdminUpdateeReferralHash: Problem putting updated referral hash and info: %v", err))
		return
	}

	// Make a copy of the referral info. Note that the referrerPKID is a pointer but it should
	// be safe to leave them pointing to the same PKID in this endpoint.
	updatedReferralInfo := &ReferralInfo{}
	*updatedReferralInfo = *referralInfo

	// Update the referral info for this referral hash.
	updatedReferralInfo.ReferrerAmountUSDCents = requestData.ReferrerAmountUSDCents
	updatedReferralInfo.RefereeAmountUSDCents = requestData.RefereeAmountUSDCents
	updatedReferralInfo.MaxReferrals = requestData.MaxReferrals
	updatedReferralInfo.RequiresJumio = requestData.RequiresJumio

	// Encode the updated entry and stick it in the database.
	err = fes.putReferralHashWithInfo(requestData.ReferralHashBase58, updatedReferralInfo)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AdminUpdateReferralHash: Problem putting updated referral hash and info: %v", err))
		return
	}

	// Set the referral hash status.
	err = fes.setReferralHashStatusForPKID(
		referralInfo.ReferrerPKID, requestData.ReferralHashBase58, requestData.IsActive)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AdminUpdateReferralHash: Problem setting referral hash status: %v", err))
		return
	}

	// If we made it this far we were successful, return without error.
	res := AdminUpdateReferralHashResponse{
		ReferralInfoResponse: ReferralInfoResponse{
			IsActive: requestData.IsActive,
			Info:     *updatedReferralInfo,
		},
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AdminUpdateReferralHash: Problem encoding response as JSON: %v", err))
		return
	}
}

type ReferralInfoResponse struct {
	IsActive bool
	Info     ReferralInfo
}

type SimpleReferralInfoResponse struct {
	IsActive bool
	Info     SimpleReferralInfo
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
		referralHash := string(referralHashBytes)

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
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetAllReferralInfoForUser: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) getAllReferralInfos() (
	_referralInfos []ReferralInfo, _err error) {

	dbSeekKey := _GlobalStatePrefixReferralHashToReferralInfo
	_, valsFound, err := fes.GlobalStateSeek(
		dbSeekKey, dbSeekKey, 0, 0, false /*reverse*/, true /*fetchValue*/)

	var referralInfos []ReferralInfo
	for valIdx, valBytes := range valsFound {
		referralInfo := ReferralInfo{}
		if valBytes != nil {
			err = gob.NewDecoder(bytes.NewReader(valBytes)).Decode(&referralInfo)
			if err != nil {
				return nil, fmt.Errorf(
					"getReferralInfoResponsesForPubKey: Failed decoding referral info #%d: %v", valIdx, err)
			}
		}

		referralInfos = append(referralInfos, referralInfo)
	}

	return referralInfos, nil
}

func ReferralCSVHeaders() (_headers []string) {
	return []string{
		"ReferralHashBase58", "ReferrerPKIDBase58Check", "ReferrerAmountUSDCents", "RefereeAmountUSDCents",
		"MaxReferrals", "RequiresJumio", "NumJumioAttempts", "NumJumioSuccesses", "TotalReferrerBitCloutNanos",
		"TotalRefereeBitCloutNanos", "DateCreatedTStampNanos", "IsActive",
	}
}

type AdminDownloadReferralCSVRequest struct{}

type AdminDownloadReferralCSVResponse struct {
	CSVRows [][]string
}

func (fes *APIServer) AdminDownloadReferralCSV(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminDownloadReferralCSVRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AdminDownloadReferralCSV: Problem parsing request body: %v", err))
		return
	}

	// We create a list of rows that are constructed into a CSV on the frontend.
	csvRows := [][]string{ReferralCSVHeaders()}

	// We also track all the "status" keys so we can do a batch get at the end to figure out
	// whether or not each referral link is active.
	var activeStatusKeys [][]byte

	referralInfos, err := fes.getAllReferralInfos()
	if err != nil {
		_AddInternalServerError(
			ww, fmt.Sprintf("AdminDownloadReferralCSV: problem getting referralInfos: %v", err))
	}

	for _, referralInfo := range referralInfos {
		nextRow := []string{}
		nextRow = append(nextRow, referralInfo.ReferralHashBase58)
		nextRow = append(nextRow, lib.PkToString(lib.PKIDToPublicKey(referralInfo.ReferrerPKID), fes.Params))
		nextRow = append(nextRow, strconv.FormatUint(referralInfo.ReferrerAmountUSDCents, 10))
		nextRow = append(nextRow, strconv.FormatUint(referralInfo.RefereeAmountUSDCents, 10))
		nextRow = append(nextRow, strconv.FormatUint(referralInfo.MaxReferrals, 10))
		nextRow = append(nextRow, strconv.FormatBool(referralInfo.RequiresJumio))
		nextRow = append(nextRow, strconv.FormatUint(referralInfo.NumJumioAttempts, 10))
		nextRow = append(nextRow, strconv.FormatUint(referralInfo.NumJumioSuccesses, 10))
		nextRow = append(nextRow, strconv.FormatUint(referralInfo.TotalReferrerBitCloutNanos, 10))
		nextRow = append(nextRow, strconv.FormatUint(referralInfo.TotalRefereeBitCloutNanos, 10))
		nextRow = append(nextRow, strconv.FormatUint(referralInfo.DateCreatedTStampNanos, 10))
		csvRows = append(csvRows, nextRow)

		// Store this info to look up whether the link is active next.
		referralHashBytes := []byte(referralInfo.ReferralHashBase58)
		activeStatusKey := GlobalStateKeyForPKIDReferralHashToIsActive(referralInfo.ReferrerPKID, referralHashBytes)
		activeStatusKeys = append(activeStatusKeys, activeStatusKey)
	}

	statusVals, err := fes.GlobalStateBatchGet(activeStatusKeys)
	if err != nil {
		_AddInternalServerError(
			ww, fmt.Sprintf("AdminDownloadReferralCSV: problem getting referralInfo status: %v", err))
	}
	if len(statusVals) != len(csvRows)-1 {
		_AddInternalServerError(ww, fmt.Sprintf(
			"AdminDownloadReferralCSV: got incorrect number of statuses %d != %d",
			len(statusVals), len(csvRows)-1))
	}

	for statusValIdx, statusBytes := range statusVals {
		status := lib.ReadBoolByte(bytes.NewReader(statusBytes))
		// Note we have to add one to the idx here since csvRows has a header.
		csvRows[statusValIdx+1] = append(csvRows[statusValIdx+1], strconv.FormatBool(status))
	}

	// If we made it this far we were successful, return without error.
	res := AdminDownloadReferralCSVResponse{
		CSVRows: csvRows,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AdminDownloadReferralCSV: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) updateOrCreateReferralInfoFromCSVRow(row []string) (_err error) {
	// Sort out the referralHash.
	referralInfo := ReferralInfo{}
	if len(row[0]) == 0 {
		// Generate a fresh referral hash for the new link.
		referralHashBase58, err := generateNewReferralHash()
		if err != nil {
			return fmt.Errorf("updateOrCreateReferralInfoFromCSVRow: problem generating referral hash: %v", err)
		}
		referralInfo.ReferralHashBase58 = referralHashBase58
	} else {
		referralInfo.ReferralHashBase58 = row[0]

		// Since this is an existing referralInfo, we fetch it and copy it for the latest stats.
		existingReferralInfo, err := fes.getInfoForReferralHashBase58(referralInfo.ReferralHashBase58)
		if err != nil {
			return fmt.Errorf(
				"updateOrCreateReferralInfoFromCSVRow: error getting referral info (%s): %v",
				referralInfo.ReferralHashBase58, err)
		}
		referralInfo = *existingReferralInfo
	}

	// Decode and fill the PKID.
	var err error
	pkBytes, _, err := lib.Base58CheckDecode(row[1])
	if err != nil || len(pkBytes) != btcec.PubKeyBytesLenCompressed {
		return fmt.Errorf(
			"updateOrCreateReferralInfoFromCSVRow: Problem decoding pkid %s: %v", row[1], err)
	}
	referralInfo.ReferrerPKID = lib.PublicKeyToPKID(pkBytes)

	// Update the non-stats elements of the ReferralInfo.
	referralInfo.ReferrerAmountUSDCents, err = strconv.ParseUint(row[2], 10, 64)
	if err != nil {
		return fmt.Errorf(
			"updateOrCreateReferralInfoFromCSVRow: error parsing referrer amount (%s): %v", row[2], err)
	}
	referralInfo.RefereeAmountUSDCents, err = strconv.ParseUint(row[3], 10, 64)
	if err != nil {
		return fmt.Errorf(
			"updateOrCreateReferralInfoFromCSVRow: error parsing refereer amount (%s): %v", row[3], err)
	}
	referralInfo.MaxReferrals, err = strconv.ParseUint(row[4], 10, 64)
	if err != nil {
		return fmt.Errorf(
			"updateOrCreateReferralInfoFromCSVRow: error parsing max referrals (%s): %v", row[4], err)
	}
	referralInfo.RequiresJumio, err = strconv.ParseBool(row[5])
	if err != nil {
		return fmt.Errorf(
			"updateOrCreateReferralInfoFromCSVRow: error parsing requires jumio (%s): %v", row[4], err)
	}

	// Set the updated referral info.
	err = fes.putReferralHashWithInfo(referralInfo.ReferralHashBase58, &referralInfo)
	if err != nil {
		return fmt.Errorf(
			"updateOrCreateReferralInfoFromCSVRow: problem putting referral info (%s): %v",
			referralInfo.ReferralHashBase58, err)
	}

	// Figure out the links "IsActive" status and then set it.
	isActive := true
	if len(row[11]) > 0 {
		isActive, err = strconv.ParseBool(row[11])
		if err != nil {
			return fmt.Errorf(
				"updateOrCreateReferralInfoFromCSVRow: error parsing requires jumio (%s): %v", row[4], err)
		}
	}
	fes.setReferralHashStatusForPKID(referralInfo.ReferrerPKID, referralInfo.ReferralHashBase58, isActive)

	return nil
}

type AdminUploadReferralCSVRequest struct {
	CSVRows [][]string
}

type AdminUploadReferralCSVResponse struct {
	LinksCreated uint64
	LinksUpdated uint64
}

func (fes *APIServer) AdminUploadReferralCSV(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminUploadReferralCSVRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AdminUploadReferralCSV: Problem parsing request body: %v", err))
		return
	}

	numLinksCreated := uint64(0)
	numLinksUpdated := uint64(0)

	// Iterate over the rows and and collect updated+created referralInfos.
	for rowIdx, row := range requestData.CSVRows {
		// All of the rows should have the same length.
		if len(row) < 11 {
			_AddBadRequestError(ww, fmt.Sprintf(
				"AdminUploadReferralCSV: Unexpected number of columns (%d) at rowIdx %d", len(row), rowIdx))
			return
		}

		if rowIdx == 0 {
			expectedHeaders := ReferralCSVHeaders()
			if !reflect.DeepEqual(row, expectedHeaders) {
				_AddBadRequestError(ww, fmt.Sprintf(
					"AdminUploadReferralCSV: Unexpected column headers"))
				return
			}
		} else {
			// Make sure the referralHash is reasonable, if provided.
			if len(row[0]) != 8 && len(row[0]) != 0 {
				_AddBadRequestError(ww, fmt.Sprintf(
					"AdminUploadReferralCSV: Unexpected referralHash length (%d) at rowIdx %d", len(row[0]), rowIdx))
				return
			}

			err := fes.updateOrCreateReferralInfoFromCSVRow(row)
			if err != nil {
				_AddInternalServerError(ww, fmt.Sprintf(
					"AdminUploadReferralCSV: Problem updating idx %d: %v", rowIdx, err))
				return
			}

			if len(row[0]) == 0 {
				numLinksCreated++
			} else {
				numLinksUpdated++
			}
		}

	}

	// If we made it this far we were successful, return without error.
	res := AdminUploadReferralCSVResponse{
		LinksCreated: numLinksCreated,
		LinksUpdated: numLinksUpdated,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"AdminUploadReferralCSV: Problem encoding response as JSON: %v", err))
		return
	}
}
