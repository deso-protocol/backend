package routes

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/btcsuite/btcd/btcec"
	"github.com/deso-protocol/core/lib"
)

type GetReferralInfoForUserRequest struct {
	PublicKeyBase58Check string `safeForLogging:"true"`

	JWT string
}

type GetReferralInfoForUserResponse struct {
	ReferralInfoResponses []ReferralInfoResponse `safeForLogging:"true"`
}

func (fes *APIServer) GetReferralInfoForUser(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetReferralInfoForUserRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetReferralInfoForUser: Problem parsing request body: %v", err))
		return
	}

	// Validate the JWT is legit.
	isValid, err := fes.ValidateJWT(requestData.PublicKeyBase58Check, requestData.JWT)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetReferralInfoForUser: Error validating JWT: %v", err))
		return
	}
	if !isValid {
		_AddBadRequestError(ww, fmt.Sprintf("GetReferralInfoForUser: Invalid token: %v", err))
		return
	}

	// Decode the user public key, if provided.
	publicKeyBytes, _, err := lib.Base58CheckDecode(requestData.PublicKeyBase58Check)
	if err != nil || len(publicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetReferralInfoForUser: Problem decoding updater public key %s: %v",
			requestData.PublicKeyBase58Check, err))
		return
	}

	// Get the referral link info structs.
	referralInfoResponses, err := fes.getReferralInfoResponsesForPubKey(publicKeyBytes, false /*includeReferredUsers*/)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetReferralInfoForUser: Problem putting new referral hash and info: %v", err))
		return
	}

	// If we made it this far we were successful, return without error.
	res := GetReferralInfoForUserResponse{
		ReferralInfoResponses: referralInfoResponses,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetReferralInfoForUser: Problem encoding response as JSON: %v", err))
		return
	}
}

type GetReferralInfoForReferralHashRequest struct {
	ReferralHash string
}

type GetReferralInfoForReferralHashResponse struct {
	ReferralInfoResponse *SimpleReferralInfoResponse
	CountrySignUpBonus   CountryLevelSignUpBonus
}

func (fes *APIServer) GetReferralInfoForReferralHash(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetReferralInfoForReferralHashRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetReferralInfoForReferralHash: Problem parsing request body: %v", err))
		return
	}

	referralInfo, err := fes.getInfoForReferralHashBase58(requestData.ReferralHash)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetReferralInfoForReferralHash: Error getting referral info for referral hash: %v", err))
		return
	}

	simpleReferralInfo := SimpleReferralInfo{
		ReferralHashBase58:    referralInfo.ReferralHashBase58,
		RefereeAmountUSDCents: referralInfo.RefereeAmountUSDCents,
		MaxReferrals:          referralInfo.MaxReferrals,
		TotalReferrals:        referralInfo.TotalReferrals,
	}

	res := GetReferralInfoForReferralHashResponse{
		ReferralInfoResponse: &SimpleReferralInfoResponse{
			Info:     simpleReferralInfo,
			IsActive: fes.getReferralHashStatus(referralInfo.ReferrerPKID, referralInfo.ReferralHashBase58),
		},
		CountrySignUpBonus: fes.GetCountryLevelSignUpBonusFromHeader(req),
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetReferralInfoForUser: Problem encoding response as JSON: %v", err))
		return
	}
}
