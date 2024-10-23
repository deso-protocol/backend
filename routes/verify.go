package routes

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"github.com/deso-protocol/backend/countries"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"

	"github.com/deso-protocol/core/lib"
	"github.com/golang/glog"
	"github.com/nyaruka/phonenumbers"
)

type SendPhoneNumberVerificationTextRequest struct {
	PublicKeyBase58Check string `safeForLogging:"true"`
	PhoneNumber          string
	JWT                  string
}

type SendPhoneNumberVerificationTextResponse struct {
}

/*
************************************************************
How verification works:

1. User inputs phone number and hits submit

 2. Frontend hits SendPhoneNumberVerificationText. It uses Twilio to send a text to
    the user with a verification code. Before sending the text, it validates that the
    phone number isn't already in use by checking phoneNumberMetadata (explained below).

3. User inputs the code and hits submit

 4. Frontend hits SubmitPhoneNumberVerificationCode. This verifies the code and updates
    two mappings in global state.
    A. userMetadata is updated to include the user's phone number
    B. phoneNumberMetadata is created, which maps phone number => user's public key

************************************************************
*/
func (fes *APIServer) SendPhoneNumberVerificationText(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := SendPhoneNumberVerificationTextRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendPhoneNumberVerificationText: Problem parsing request body: %v", err))
		return
	}

	if fes.Twilio == nil {
		_AddBadRequestError(ww,
			"SendPhoneNumberVerificationText: Error: You must set Twilio API keys to use this functionality")
		return
	}

	// Validate their permissions
	isValid, err := fes.ValidateJWT(requestData.PublicKeyBase58Check, requestData.JWT)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendPhoneNumberVerificationText: Error validating JWT: %v", err))
	}

	if !isValid {
		_AddBadRequestError(ww, fmt.Sprintf("SendPhoneNumberVerificationText: Invalid token: %v", err))
		return
	}

	/**************************************************************/
	// Validations
	/**************************************************************/
	if err = fes.validatePhoneNumberNotAlreadyInUse(
		requestData.PhoneNumber, requestData.PublicKeyBase58Check); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"SendPhoneNumberVerificationText: Error with validatePhoneNumberNotAlreadyInUse: %v", err))
		return
	}

	/**************************************************************/
	// Ensure the phone number prefix is supported
	/**************************************************************/
	if fes.GetPhoneVerificationAmountToSendNanos(requestData.PhoneNumber) == 0 {
		_AddBadRequestError(ww, fmt.Sprintf("SendPhoneNumberVerificationText: phone number prefix not supported"))
		return
	}

	/**************************************************************/
	// Ensure the user-provided number is not a VOIP number
	/**************************************************************/
	phoneNumber := requestData.PhoneNumber
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	data := url.Values{}
	data.Add("Type", "carrier")
	lookup, err := fes.Twilio.Lookup.LookupPhoneNumbers.Get(ctx, phoneNumber, data)

	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendPhoneNumberVerificationText: Problem with Lookup: %v", err))
		return
	}
	if lookup.Carrier.Type == TwilioVoipCarrierType {
		_AddBadRequestError(ww, fmt.Sprintf("SendPhoneNumberVerificationText: VOIP number not allowed"))
		return
	}

	/**************************************************************/
	// Send the actual verification text
	/**************************************************************/
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	data = url.Values{}
	data.Add("To", phoneNumber)
	data.Add("Channel", "sms")
	_, err = fes.Twilio.Verify.Verifications.Create(ctx, fes.Config.TwilioVerifyServiceID, data)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendPhoneNumberVerificationText: Error with SendSMS: %v", err))
		return
	}
}

func (fes *APIServer) canUserCreateProfile(userMetadata *UserMetadata, utxoView *lib.UtxoView) (_canUserCreateProfile bool, _err error) {
	// If a user already has a profile, they can update their profile.
	profileEntry := utxoView.GetProfileEntryForPublicKey(userMetadata.PublicKey)
	if profileEntry != nil && len(profileEntry.Username) > 0 {
		return true, nil
	}

	totalBalanceNanos, err := utxoView.GetDeSoBalanceNanosForPublicKey(userMetadata.PublicKey)
	if err != nil {
		return false, err
	}
	// User can create a profile if they have a phone number or if they have enough DeSo to cover the create profile fee.
	// User can also create a profile if they've successfully filled out a captcha.
	// The PhoneNumber is only set if the user has passed phone number verification.
	if userMetadata.PhoneNumber != "" ||
		totalBalanceNanos >= utxoView.GetCurrentGlobalParamsEntry().CreateProfileFeeNanos ||
		userMetadata.LastHcaptchaBlockHeight > 0 {
		return true, nil
	}

	// Users who have verified with Jumio can create a profile
	if userMetadata.JumioVerified {
		return true, nil
	}

	metamaskAirdropMetadata, err := fes.GetMetamaskAirdropMetadata(userMetadata.PublicKey)
	if err != nil {
		return false, err
	}
	if metamaskAirdropMetadata != nil && metamaskAirdropMetadata.ShouldCompProfileCreation {
		return true, nil
	}
	// If we reached here, the user can't create a profile
	return false, nil
}

func (fes *APIServer) getMultiPhoneNumberMetadataFromGlobalState(phoneNumber string) (
	_phoneNumberMetadata []*PhoneNumberMetadata, _err error) {
	dbKey, err := GlobalStateKeyForPhoneNumberStringToMultiPhoneNumberMetadata(phoneNumber)
	if err != nil {
		return nil, fmt.Errorf(
			"getPhoneNumberMetadataFromGlobalState: Problem with GlobalStateKeyForPhoneNumberStringToPhoneNumberMetadata %v", err)
	}

	multiPhoneNumberMetadataBytes, err := fes.GlobalState.Get(dbKey)
	if err != nil {
		return nil, fmt.Errorf(
			"getPhoneNumberMetadataFromGlobalState: Problem with Get: %v", err)
	}

	multiPhoneNumberMetadata := []*PhoneNumberMetadata{}
	if multiPhoneNumberMetadataBytes != nil {
		if err = gob.NewDecoder(
			bytes.NewReader(multiPhoneNumberMetadataBytes)).Decode(&multiPhoneNumberMetadata); err != nil {
			return nil, fmt.Errorf(
				"getPhoneNumberMetadataFromGlobalState: Problem with NewDecoder: %v", err)
		}
	}
	return multiPhoneNumberMetadata, nil
}

func (fes *APIServer) getPhoneNumberMetadataFromGlobalState(phoneNumber string, publicKey []byte) (
	_phoneNumberMetadata *PhoneNumberMetadata, _err error) {

	multiPhoneNumberMetadata, err := fes.getMultiPhoneNumberMetadataFromGlobalState(phoneNumber)
	if err != nil {
		return nil, err
	}

	for _, phoneMetadata := range multiPhoneNumberMetadata {
		if phoneMetadata != nil && bytes.Equal(phoneMetadata.PublicKey, publicKey) {
			return phoneMetadata, nil
		}
	}

	return nil, fmt.Errorf("Specified publicKey not found for provided phone number")
}

func (fes *APIServer) putPhoneNumberMetadataInGlobalState(multiPhoneNumberMetadata []*PhoneNumberMetadata, phoneNumber string) (_err error) {
	dbKey, err := GlobalStateKeyForPhoneNumberStringToMultiPhoneNumberMetadata(phoneNumber)
	if err != nil {
		return fmt.Errorf(
			"putPhoneNumberMetadataInGlobalState: Problem with GlobalStateKeyForPhoneNumberStringToPhoneNumberMetadata %v", err)
	}

	metadataDataBuf := bytes.NewBuffer([]byte{})
	if err = gob.NewEncoder(metadataDataBuf).Encode(multiPhoneNumberMetadata); err != nil {
		return fmt.Errorf(
			"putPhoneNumberMetadataInGlobalState: Problem encoding slice of phone number metadata: %v", err)
	}

	if err = fes.GlobalState.Put(dbKey, metadataDataBuf.Bytes()); err != nil {
		return fmt.Errorf(
			"putPhoneNumberMetadataInGlobalState: Problem putting updated phone number metadata: %v", err)
	}
	return nil
}

func (fes *APIServer) validatePhoneNumberNotAlreadyInUse(phoneNumber string, userPublicKeyBase58Check string) (_err error) {
	userPublicKeyBytes, _, err := lib.Base58CheckDecode(userPublicKeyBase58Check)
	if err != nil {
		return fmt.Errorf("validatePhoneNumberNotAlreadyInUse: Error decoding user public key: %v", err)
	}
	multiPhoneNumberMetadata, err := fes.getMultiPhoneNumberMetadataFromGlobalState(phoneNumber)
	if err != nil {
		return fmt.Errorf(
			"validatePhoneNumberNotAlreadyInUse: Error with getPhoneNumberMetadataFromGlobalState: %v", err)
	}

	// TODO: this threshold should really be controlled by an admin on the node instead of via a flag.
	if uint64(len(multiPhoneNumberMetadata)) >= fes.Config.PhoneNumberUseThreshold {
		return fmt.Errorf(
			"validatePhoneNumberNotAlreadyInUse: Phone number has been used over %v times",
			fes.Config.PhoneNumberUseThreshold)
	}

	for _, phoneNumberMetadata := range multiPhoneNumberMetadata {
		if bytes.Equal(userPublicKeyBytes, phoneNumberMetadata.PublicKey) {
			return fmt.Errorf("validatePhoneNumberNotAlreadyInUse: Phone number already used by this public key")
		}
	}

	return nil
}

type SubmitCaptchaVerificationRequest struct {
	Token                string
	JWT                  string
	PublicKeyBase58Check string
}

type SubmitCaptchaVerificationResponse struct {
	Success    bool
	TxnHashHex string
}

func (fes *APIServer) HandleCaptchaVerificationRequest(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := SubmitCaptchaVerificationRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("HandleCaptchaVerificationRequest: Problem parsing request body: %v", err))
		return
	}

	// Validate their permissions
	isValid, err := fes.ValidateJWT(requestData.PublicKeyBase58Check, requestData.JWT)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("HandleCaptchaVerificationRequest: Error validating JWT: %v", err))
	}
	if !isValid {
		_AddBadRequestError(ww, fmt.Sprintf("HandleCaptchaVerificationRequest: Invalid token: %v", err))
		return
	}

	txnHashHex, err := fes.verifyHCaptchaTokenAndSendStarterDESO(requestData.Token, requestData.PublicKeyBase58Check)

	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("HandleCaptchaVerificationRequest: Error verifying captcha: %v", err))
		return
	}

	res := SubmitCaptchaVerificationResponse{
		Success:    true,
		TxnHashHex: txnHashHex,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("HandleCaptchaVerificationRequest: Problem encoding response: %v", err))
		return
	}
}

type AdminUpdateCaptchaRewardRequest struct {
	// Amount of nanos to reward for a successful captcha.
	RewardNanos uint64
}

type AdminUpdateCaptchaRewardResponse struct {
	// Amount of nanos to reward for a successful captcha.
	RewardNanos uint64
}

// HandleAdminUpdateCaptchaRewardRequest allows an admin to update the captcha reward amount.
func (fes *APIServer) AdminSetCaptchaRewardNanos(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminUpdateCaptchaRewardRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("HandleAdminUpdateCaptchaRewardRequest: Problem parsing request body: %v", err))
		return
	}

	// Ensure that the reward amount is not greater than the starter deso amount flag.
	if requestData.RewardNanos > fes.Config.StarterDESONanos {
		_AddBadRequestError(ww, fmt.Sprintf("HandleAdminUpdateCaptchaRewardRequest: Reward amount %v exceeds starter deso amount %v", requestData.RewardNanos, fes.Config.StarterDESONanos))
		return
	}

	if err := fes.putCaptchaRewardNanosInGlobalState(requestData.RewardNanos); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("HandleAdminUpdateCaptchaRewardRequest: Error putting captcha reward in global state: %v", err))
		return
	}

	res := AdminUpdateCaptchaRewardResponse{
		RewardNanos: requestData.RewardNanos,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("HandleAdminUpdateCaptchaRewardRequest: Problem encoding response: %v", err))
		return
	}
}

// getCaptchaRewardNanosFromGlobalState returns the amount of nanos to reward for a successful captcha from global state.
func (fes *APIServer) getCaptchaRewardNanosFromGlobalState() (uint64, error) {
	dbKey := GlobalStateKeyForCaptchaRewardAmountNanos()

	rewardNanosBytes, err := fes.GlobalState.Get(dbKey)
	if err != nil {
		return 0, fmt.Errorf(
			"getCaptchaRewardNanosFromGlobalState: Problem with Get: %v", err)
	}

	rewardNanos, err := lib.ReadUvarint(bytes.NewReader(rewardNanosBytes))

	return rewardNanos, nil
}

// putCaptchaRewardNanosInGlobalState puts the amount of nanos to reward for a successful captcha in global state.
func (fes *APIServer) putCaptchaRewardNanosInGlobalState(rewardNanos uint64) error {
	dbKey := GlobalStateKeyForCaptchaRewardAmountNanos()

	rewardNanosBytes := lib.UintToBuf(rewardNanos)

	if err := fes.GlobalState.Put(dbKey, rewardNanosBytes); err != nil {
		return fmt.Errorf(
			"putCaptchaRewardNanosInGlobalState: Problem with Put: %v", err)
	}

	return nil
}

// verifyHCaptchaTokenAndSendStarterDESO verifies the captcha token and sends the starter DESO to the user.
func (fes *APIServer) verifyHCaptchaTokenAndSendStarterDESO(token string, publicKeyBase58Check string) (txnHashHex string, err error) {
	if fes.Config.StarterDESOSeed == "" {
		return "", fmt.Errorf("HandleCaptchaVerificationRequest: Starter DESO seed not set")
	}

	// Retrieve the amount of nanos to reward for a successful captcha.
	amountToSendNanos, err := fes.getCaptchaRewardNanosFromGlobalState()
	if err != nil {
		return "", fmt.Errorf("HandleCaptchaVerificationRequest: Problem with getCaptchaRewardNanosFromGlobalState: %v", err)
	}

	// Decode the public key.
	publicKeyBytes, _, err := lib.Base58CheckDecode(publicKeyBase58Check)
	if err != nil {
		return "", fmt.Errorf("HandleCaptchaVerificationRequest: Problem decoding public key: %v", err)
	}

	// Ensure the user has not already received the starter DESO for submitting a successful captcha.
	userMetadata, err := fes.getUserMetadataFromGlobalState(publicKeyBase58Check)
	if err != nil {
		return "", fmt.Errorf("HandleCaptchaVerificationRequest: Problem with getUserMetadataFromGlobalState: %v", err)
	}

	if userMetadata.LastHcaptchaBlockHeight != 0 {
		return "", fmt.Errorf("HandleCaptchaVerificationRequest: LastHcaptchaBlockHeight is already set")
	}

	// Verify the token with hCaptcha.
	verificationSuccess, err := fes.verifyHCaptchaToken(token)

	if err != nil {
		return "", fmt.Errorf("HandleCaptchaVerificationRequest: Error verifying captcha: %v", err)
	}

	if !verificationSuccess {
		return "", fmt.Errorf("HandleCaptchaVerificationRequest: Captcha verification failed")
	}

	// Update the user's metadata to indicate that they have received the starter DESO.
	lastBlockheight := fes.blockchain.BlockTip().Height
	userMetadata.LastHcaptchaBlockHeight = lastBlockheight
	userMetadata.HcaptchaShouldCompProfileCreation = true

	if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
		return "", fmt.Errorf("HandleCaptchaVerificationRequest: Problem with putUserMetadataInGlobalState: %v", err)
	}

	// Send the starter DESO to the user.
	var txnHash *lib.BlockHash
	txnHash, err = fes.SendSeedDeSo(publicKeyBytes, amountToSendNanos, false)
	if err != nil {
		return "", fmt.Errorf("HandleCaptchaVerificationRequest: Error sending seed DeSo: %v", err)
	}

	// Log the transaction to datadog.
	if fes.backendServer.GetStatsdClient() != nil {
		fes.backendServer.GetStatsdClient().Incr("SEND_STARTER_DESO_CAPTCHA", nil, 1)
	}

	return txnHash.String(), nil
}

type VerificationResponse struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
}

const VERIFY_URL = "https://hcaptcha.com/siteverify"

// verifyHCaptchaToken verifies the captcha token via the hCaptcha API.
func (fes *APIServer) verifyHCaptchaToken(token string) (bool, error) {
	// Construct and send the request to hcaptcha.
	data := url.Values{}
	data.Set("secret", fes.Config.HCaptchaSecret)
	data.Set("response", token)

	resp, err := http.PostForm(VERIFY_URL, data)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// Parse the response and return the result.
	var verificationResponse VerificationResponse
	err = json.NewDecoder(resp.Body).Decode(&verificationResponse)
	if err != nil {
		return false, err
	}

	return verificationResponse.Success, nil
}

type SubmitPhoneNumberVerificationCodeRequest struct {
	JWT                  string
	PublicKeyBase58Check string
	PhoneNumber          string
	VerificationCode     string
}

type SubmitPhoneNumberVerificationCodeResponse struct {
	TxnHashHex string
}

func (fes *APIServer) SubmitPhoneNumberVerificationCode(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := SubmitPhoneNumberVerificationCodeRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitPhoneNumberVerificationCode: Problem parsing request body: %v", err))
		return
	}

	// Validate their permissions
	isValid, err := fes.ValidateJWT(requestData.PublicKeyBase58Check, requestData.JWT)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitPhoneNumberVerificaitonCodE: Error validating JWT: %v", err))
	}
	if !isValid {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitPhoneNumberVerificationCode: Invalid token: %v", err))
		return
	}

	/**************************************************************/
	// Validations
	/**************************************************************/
	if err = fes.validatePhoneNumberNotAlreadyInUse(
		requestData.PhoneNumber, requestData.PublicKeyBase58Check); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitPhoneNumberVerificationCode: Error with validatePhoneNumberNotAlreadyInUse: %v", err))
		return
	}

	/**************************************************************/
	// Ensure the phone number prefix is supported
	/**************************************************************/
	if fes.GetPhoneVerificationAmountToSendNanos(requestData.PhoneNumber) == 0 {
		_AddBadRequestError(ww, fmt.Sprintf("SendPhoneNumberVerificationText: phone number prefix not supported"))
		return
	}

	/**************************************************************/
	// Actual logic
	/**************************************************************/

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	data := url.Values{}
	data.Add("Code", requestData.VerificationCode)
	data.Add("To", requestData.PhoneNumber)
	checkPhoneNumberResponse, err := fes.Twilio.Verify.Verifications.Check(ctx, fes.Config.TwilioVerifyServiceID, data)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendPhoneNumberVerificationText: Error with SendSMS: %v", err))
		return
	}
	if checkPhoneNumberResponse.Status != TwilioCheckPhoneNumberApproved {
		// If the phone number has requested a code recently, and the code is well-formed (e.g. ~6 chars),
		// but the code is incorrect, we end up here
		_AddBadRequestError(ww, fmt.Sprintf("SendPhoneNumberVerificationText: Code is not valid"))
		return
	}

	/**************************************************************/
	// Save the phone number in global state
	/**************************************************************/
	// Update / save userMetadata in global state
	userMetadata, err := fes.getUserMetadataFromGlobalState(requestData.PublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitPhoneNumberVerificationCode: Problem with getUserMetadataFromGlobalState: %v", err))
		return
	}

	settingPhoneNumberForFirstTime := userMetadata.PhoneNumber == ""
	userMetadata.PhoneNumber = requestData.PhoneNumber
	// TODO: do we want to require users who got money from twilio to go through the tutorial?
	//userMetadata.MustPurchaseCreatorCoin = true
	err = fes.putUserMetadataInGlobalState(userMetadata)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitPhoneNumberVerificationCode: Error putting usermetadata in Global state: %v", err))
		return
	}

	// Update / save phoneNumberMetadata in global state
	multiPhoneNumberMetadata, err := fes.getMultiPhoneNumberMetadataFromGlobalState(requestData.PhoneNumber)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitPhoneNumberVerificationCode: Error with getPhoneNumberMetadataFromGlobalState: %v", err))
		return
	}

	phoneNumberMetadata := &PhoneNumberMetadata{
		PublicKey:                 userMetadata.PublicKey,
		PhoneNumber:               requestData.PhoneNumber,
		ShouldCompProfileCreation: true,
	}
	// Parse the raw phone number
	parsedNumber, err := phonenumbers.Parse(phoneNumberMetadata.PhoneNumber, "")
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GlobalStateKeyForPhoneNumberStringToPhoneNumberMetadata: Problem with phonenumbers.Parse: %v", err))
		return
	}
	if parsedNumber.CountryCode != nil {
		phoneNumberMetadata.PhoneNumberCountryCode =
			phonenumbers.GetRegionCodeForCountryCode(int(*parsedNumber.CountryCode))
	}
	// Append the new phone number to the metadata
	multiPhoneNumberMetadata = append(multiPhoneNumberMetadata, phoneNumberMetadata)
	if err = fes.putPhoneNumberMetadataInGlobalState(multiPhoneNumberMetadata, requestData.PhoneNumber); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitPhoneNumberVerificationCode: Problem with putPhoneNumberMetadataInGlobalState: %v", err))
		return
	}

	/**************************************************************/
	// Send the user starter DeSo, if we haven't already sent it
	/**************************************************************/
	if settingPhoneNumberForFirstTime && fes.Config.StarterDESOSeed != "" {
		amountToSendNanos := fes.Config.StarterDESONanos

		if len(requestData.PhoneNumber) == 0 || requestData.PhoneNumber[0] != '+' {
			_AddBadRequestError(ww, fmt.Sprintf("SubmitPhoneNumberVerificationCode: Phone number must start with a plus sign"))
			return
		}

		if requestData.PhoneNumber != "" {
			amountToSendNanos = fes.GetPhoneVerificationAmountToSendNanos(requestData.PhoneNumber)
		}

		var txnHash *lib.BlockHash
		txnHash, err = fes.SendSeedDeSo(userMetadata.PublicKey, amountToSendNanos, false)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SubmitPhoneNumberVerificationCode: Error sending seed DeSo: %v", err))
			return
		}
		res := SubmitPhoneNumberVerificationCodeResponse{
			TxnHashHex: txnHash.String(),
		}
		if err = json.NewEncoder(ww).Encode(res); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SubmitPhoneNumberVerificationCode: Problem encoding response: %v", err))
			return
		}
	}
}

func (fes *APIServer) GetPhoneVerificationAmountToSendNanos(phoneNumber string) uint64 {
	// We sort the country codes by size, with the longest prefix
	// first so that we match on the longest prefix when we iterate.
	sortedPrefixExceptionMap := []string{}
	for countryCodePrefix := range fes.Config.StarterPrefixNanosMap {
		sortedPrefixExceptionMap = append(sortedPrefixExceptionMap, countryCodePrefix)
	}
	sort.Slice(sortedPrefixExceptionMap, func(ii, jj int) bool {
		return len(sortedPrefixExceptionMap[ii]) > len(sortedPrefixExceptionMap[jj])
	})
	for _, countryPrefix := range sortedPrefixExceptionMap {
		amountForPrefix := fes.Config.StarterPrefixNanosMap[countryPrefix]
		if strings.Contains(phoneNumber, countryPrefix) {
			return amountForPrefix
		}
	}
	return fes.Config.StarterDESONanos
}

type ResendVerifyEmailRequest struct {
	PublicKey string
	JWT       string
}

func (fes *APIServer) ResendVerifyEmail(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := ResendVerifyEmailRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("ResendVerifyEmail: Problem parsing request body: %v", err))
		return
	}

	if !fes.IsConfiguredForSendgrid() {
		_AddBadRequestError(ww, "ResendVerifyEmail: Sendgrid not configured")
		return
	}

	isValid, err := fes.ValidateJWT(requestData.PublicKey, requestData.JWT)
	if !isValid {
		_AddBadRequestError(ww, fmt.Sprintf("ResendVerifyEmail: Invalid token: %v", err))
		return
	}

	userPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.PublicKey)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("ResendVerifyEmail: Invalid public key: %v", err))
		return
	}

	userMetadata, err := fes.getUserMetadataFromGlobalState(lib.PkToString(userPublicKeyBytes, fes.Params))
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("ResendVerifyEmail: Problem with getUserMetadataFromGlobalState: %v", err))
		return
	}

	if userMetadata.Email == "" {
		_AddBadRequestError(ww, "ResendVerifyEmail: Email missing")
		return
	}

	fes.sendVerificationEmail(userMetadata.Email, requestData.PublicKey)
}

type VerifyEmailRequest struct {
	PublicKey string
	EmailHash string
}

type SGContact struct {
	Email        string            `json:"email"`
	CustomFields map[string]string `json:"custom_fields"`
}

type SGRequestBody struct {
	Contacts []SGContact `json:"contacts"`
}

func (fes *APIServer) VerifyEmail(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := VerifyEmailRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("VerifyEmail: Problem parsing request body: %v", err))
		return
	}

	userPublicKeyBytes, _, err := lib.Base58CheckDecode(requestData.PublicKey)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("VerifyEmail: Invalid public key: %v", err))
		return
	}

	// Now that we have a public key, update the global state object.
	userMetadata, err := fes.getUserMetadataFromGlobalState(lib.PkToString(userPublicKeyBytes, fes.Params))
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("VerifyEmail: Problem with getUserMetadataFromGlobalState: %v", err))
		return
	}

	validHash := fes.verifyEmailHash(userMetadata.Email, requestData.PublicKey)
	if requestData.EmailHash != validHash {
		_AddBadRequestError(ww, fmt.Sprintf("VerifyEmail: Invalid hash: %s", requestData.EmailHash))
		return
	}

	userMetadata.EmailVerified = true

	err = fes.putUserMetadataInGlobalState(userMetadata)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("VerifyEmail: Failed to save user: %v", err))
		return
	}

	if !fes.IsConfiguredForSendgrid() {
		return
	}

	sgContact := SGContact{
		Email: userMetadata.Email,
		CustomFields: map[string]string{
			// Public key custom field.
			"e5_T": requestData.PublicKey,
		},
	}

	var utxoView *lib.UtxoView
	utxoView, err = fes.backendServer.GetMempool().GetAugmentedUniversalView()

	// If the utxoview errors, just create the contact as is.
	if err != nil {
		fes.createSendgridContact(&sgContact)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("VerifyEmail: Failed to create sendgrid contact: %v", err))
			return
		}
		return
	}

	profileEntry := utxoView.GetProfileEntryForPublicKey(userPublicKeyBytes)
	if profileEntry == nil || profileEntry.IsDeleted() {
		err = fes.createSendgridContact(&sgContact)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("VerifyEmail: Failed to create sendgrid contact: %v", err))
			return
		}
		return
	}

	// Username custom field.
	sgContact.CustomFields["e4_T"] = string(profileEntry.Username)
	err = fes.createSendgridContact(&sgContact)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("VerifyEmail: Failed to create sendgrid contact: %v", err))
		return
	}
}

func (fes *APIServer) createSendgridContact(contact *SGContact) error {
	if !fes.IsConfiguredForSendgrid() {
		return fmt.Errorf("Sendgrid not configured")
	}

	rb := SGRequestBody{
		Contacts: []SGContact{
			*contact,
		},
	}

	jsonData, err := json.Marshal(rb)
	if err != nil {
		return fmt.Errorf("Error constructing contact: %v", err)
	}

	request := sendgrid.GetRequest(fes.Config.SendgridApiKey, "/v3/marketing/contacts", "https://api.sendgrid.com")
	request.Method = "PUT"

	request.Body = jsonData

	_, err = sendgrid.API(request)
	if err != nil {
		return fmt.Errorf("Error creating contact: %v", err)
	}

	return nil
}

func (fes *APIServer) sendVerificationEmail(emailAddress string, publicKey string) {
	email := mail.NewV3Mail()
	email.SetTemplateID(fes.Config.SendgridConfirmEmailId)

	from := mail.NewEmail(fes.Config.SendgridFromName, fes.Config.SendgridFromEmail)
	email.SetFrom(from)

	p := mail.NewPersonalization()
	tos := []*mail.Email{
		mail.NewEmail("", emailAddress),
	}
	p.AddTos(tos...)

	hash := fes.verifyEmailHash(emailAddress, publicKey)
	confirmUrl := fmt.Sprintf("%s/verify-email/%s/%s", fes.Config.SendgridDomain, publicKey, hash)
	p.SetDynamicTemplateData("confirm_url", confirmUrl)
	email.AddPersonalizations(p)

	fes.sendEmail(email)
}

func (fes *APIServer) verifyEmailHash(emailAddress string, publicKey string) string {
	hashBytes := []byte(emailAddress)
	hashBytes = append(hashBytes, []byte(publicKey)...)
	hashBytes = append(hashBytes, []byte(fes.Config.SendgridSalt)...)
	return lib.Sha256DoubleHash(hashBytes).String()[:8]
}

func (fes *APIServer) sendEmail(email *mail.SGMailV3) {
	if !fes.IsConfiguredForSendgrid() {
		return
	}

	request := sendgrid.GetRequest(fes.Config.SendgridApiKey, "/v3/mail/send", "https://api.sendgrid.com")
	request.Method = "POST"
	request.Body = mail.GetRequestBody(email)
	response, err := sendgrid.API(request)
	if err != nil {
		glog.Errorf("%v: %v", err, response)
	}
}

func (fes *APIServer) IsConfiguredForSendgrid() bool {
	return fes.Config.SendgridApiKey != ""
}

//
// JUMIO
//

func (fes *APIServer) IsConfiguredForJumio() bool {
	return fes.Config.JumioToken != "" && fes.Config.JumioSecret != ""
}

type JumioInitRequest struct {
	CustomerInternalReference string `json:"customerInternalReference"`
	UserReference             string `json:"userReference"`
	SuccessURL                string `json:"successUrl"`
	ErrorURL                  string `json:"errorUrl"`
}

type JumioInitResponse struct {
	RedirectURL          string `json:"redirectUrl"`
	TransactionReference string `json:"transactionReference"`
}

type JumioBeginRequest struct {
	PublicKey          string
	ReferralHashBase58 string
	SuccessURL         string
	ErrorURL           string
	JWT                string
}

type JumioBeginResponse struct {
	URL string
}

func (fes *APIServer) JumioBegin(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := JumioBeginRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioBegin: Problem parsing request body: %v", err))
		return
	}

	isValid, err := fes.ValidateJWT(requestData.PublicKey, requestData.JWT)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioBegin: Error validating JWT: %v", err))
		return
	}
	if !isValid {
		_AddBadRequestError(ww, fmt.Sprintf("JumioBegin: Invalid token: %v", err))
		return
	}

	// Get UserMetadata from global state and check that user has not already been through Jumio Verification flow
	userMetadata, err := fes.getUserMetadataFromGlobalState(requestData.PublicKey)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioBegin: Problem getting user metadata from global state: %v", err))
		return
	}

	if userMetadata.JumioVerified {
		_AddBadRequestError(ww, fmt.Sprintf("JumioBegin: public key already went through jumio verification flow: %v", requestData.PublicKey))
		return
	}

	if userMetadata.JumioFinishedTime > 0 && !userMetadata.JumioReturned {
		_AddBadRequestError(ww, fmt.Sprintf("JumioBegin: please wait for Jumio to finish processing your existing verification attempt before retrying."))
		return
	}

	if requestData.ReferralHashBase58 != "" {
		var referralInfo *ReferralInfo
		referralInfo, err = fes.getInfoForReferralHashBase58(requestData.ReferralHashBase58)
		if err != nil {
			glog.Errorf("JumioBegin: Error getting referral info: %v", err)
		} else if referralInfo != nil {
			userMetadata.ReferralHashBase58Check = requestData.ReferralHashBase58
			referralInfo.NumJumioAttempts++
			if err = fes.putReferralHashWithInfo(referralInfo.ReferralHashBase58, referralInfo); err != nil {
				glog.Errorf("JumioBegin: Error updating referral info: %v", err)
			}
		}
	}

	tStampNanos := int(time.Now().UnixNano())

	jumioInternalReference := requestData.PublicKey + strconv.Itoa(tStampNanos)

	userMetadata.JumioInternalReference = jumioInternalReference
	userMetadata.JumioFinishedTime = 0
	userMetadata.JumioReturned = false
	if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioBegin: error putting jumio internal reference in global state: %v", err))
		return
	}

	eventDataMap := make(map[string]interface{})
	eventDataMap["referralCode"] = requestData.ReferralHashBase58
	if err = fes.logAmplitudeEvent(requestData.PublicKey, "jumio : begin", eventDataMap); err != nil {
		glog.Errorf("JumioBegin: Error logging Jumio Begin in amplitude: %v", err)
	}

	// CustomerInternalReference is Public Key + timestamp
	// UserReference is just PublicKey
	initData := &JumioInitRequest{
		CustomerInternalReference: jumioInternalReference,
		UserReference:             requestData.PublicKey,
		SuccessURL:                requestData.SuccessURL,
		ErrorURL:                  requestData.ErrorURL,
	}
	// Marshal the Jumio payload
	jsonData, err := json.Marshal(initData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioBegin: JSON invalid: %v", err))
		return
	}

	// Create the request
	req, err = http.NewRequest("POST", "https://netverify.com/api/v4/initiate", bytes.NewBuffer(jsonData))
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioBegin: Request creation failed: %v", err))
		return
	}

	// Set content-type and basic authentication (token, secret)
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(fes.Config.JumioToken, fes.Config.JumioSecret)

	// Make the request
	postRes, err := http.DefaultClient.Do(req)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioBegin: Request failed: %v", err))
		return
	}

	if postRes.StatusCode != 200 {
		defer postRes.Body.Close()

		// Decode the response into the appropriate struct.
		body, _ := ioutil.ReadAll(postRes.Body)
		_AddBadRequestError(ww, fmt.Sprintf("JumioBegin: Request returned non-200 status code: %v, %v", postRes.StatusCode, string(body)))
		return
	}

	// Decode the response
	jumioInit := JumioInitResponse{}
	if err = json.NewDecoder(postRes.Body).Decode(&jumioInit); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioBegin: Decode failed: %v", err))
		return
	}
	if err = postRes.Body.Close(); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioBegin: Closing post request body failed: %v", err))
		return
	}

	res := JumioBeginResponse{
		URL: jumioInit.RedirectURL,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioBegin: Encode failed: %v", err))
		return
	}
}

type JumioFlowFinishedRequest struct {
	PublicKey              string
	JumioInternalReference string
	JWT                    string
}

func (fes *APIServer) JumioFlowFinished(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := JumioFlowFinishedRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioFlowFinished: Problem parsing request body: %v", err))
		return
	}

	isValid, err := fes.ValidateJWT(requestData.PublicKey, requestData.JWT)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioFlowFinished: Error validating JWT: %v", err))
		return
	}
	if !isValid {
		_AddBadRequestError(ww, fmt.Sprintf("JumioFlowFinished: Invalid token: %v", err))
		return
	}

	// Get UserMetadata from global state and check internal reference matches and we haven't marked this user as finished already.
	userMetadata, err := fes.getUserMetadataFromGlobalState(requestData.PublicKey)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioFlowFinished: Problem getting user metadata from global state: %v", err))
		return
	}

	if userMetadata.JumioInternalReference != requestData.JumioInternalReference {
		_AddBadRequestError(ww, fmt.Sprintf("JumioFlowFinished: UserMetadata's jumio internal reference (%v) does not match value from payload (%v)", userMetadata.JumioInternalReference, requestData.JumioInternalReference))
		return
	}

	userMetadata.JumioFinishedTime = uint64(time.Now().UnixNano())

	if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioFlowFinished: Error putting jumio finish time in global state: %v", err))
		return
	}
}

type JumioIdentityVerification struct {
	Similarity string `json:"similarity"`
	Validity   bool   `json:"validity"`
	Reason     string `json:"reason"`
}

type JumioRejectReason struct {
	RejectReasonCode        string      `json:"rejectReasonCode"`
	RejectReasonDescription string      `json:"rejectReasonDescription"`
	RejectReasonDetails     interface{} `json:"rejectReasonDetails"`
}

// Jumio webhook - If Jumio verified user is a human that we haven't paid already, pay them some starter DESO.
// Make sure you only allow access to jumio IPs for this endpoint, otherwise anybody can take all the funds from
// the public key that sends DeSo. WHITELIST JUMIO IPs.
func (fes *APIServer) JumioCallback(ww http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: Problem parsing form: %v", err))
		return
	}

	// Convert the post form of the request into a map of string keys to string slice values
	payloadMap := make(map[string][]string)
	for k, v := range req.PostForm {
		payloadMap[k] = v
	}

	// PASSPORT, DRIVING_LICENSE, ID_CARD, VISA
	idType := req.PostFormValue("idType")
	// More specific type of ID
	idSubType := req.PostFormValue("idSubtype")

	// Country of ID
	idCountry := req.PostFormValue("idCountry")

	// Identifier on ID - e.g. Driver's license number for DRIVING_LICENSE, Passport number for PASSPORT
	idNumber := req.PostFormValue("idNumber")

	// customerId maps to the userReference passed when creating the Jumio session. userReference represents Public Key
	userReference := req.PostFormValue("customerId")

	// Jumio TransactionID
	jumioTransactionId := req.PostFormValue("jumioIdScanReference")

	// Verification status
	verificationStatus := req.FormValue("verificationStatus")

	// Get Public key bytes and PKID
	if userReference == "" {
		_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: Public key (customerId) is required"))
		return
	}
	publicKeyBytes, _, err := lib.Base58CheckDecode(userReference)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: Problem decoding user public key (customerId): %v", err))
		return
	}

	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: error getting utxoview: %v", err))
		return
	}

	pkid := utxoView.GetPKIDForPublicKey(publicKeyBytes)
	if pkid == nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: No PKID found for public key: %v", userReference))
		return
	}

	var userMetadata *UserMetadata
	userMetadata, err = fes.getUserMetadataFromGlobalState(userReference)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: Error getting user metadata from global state: %v", err))
		return
	}

	// If the user is already jumio verified, this is an error and we shouldn't pay them again.
	if userMetadata.JumioVerified {
		_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: User already verified: %v", err))
		return
	}

	// Always set JumioReturned so we know that Jumio callback has finished.
	userMetadata.JumioReturned = true

	// Map of data for amplitude
	eventDataMap := make(map[string]interface{})
	eventDataMap["referralCode"] = userMetadata.ReferralHashBase58Check
	eventDataMap["verificationStatus"] = verificationStatus

	// If verification status is DENIED_FRAUD or ERROR_NOT_READABLE_ID, parse the rejection reason
	// See description of rejectReason here:
	// https://github.com/Jumio/implementation-guides/blob/master/netverify/callback.md#parameters
	if verificationStatus == "DENIED_FRAUD" || verificationStatus == "ERROR_NOT_READABLE_ID" {
		rejectReason := req.FormValue("rejectReason")
		var jumioRejectReason JumioRejectReason
		if err = json.Unmarshal([]byte(rejectReason), &jumioRejectReason); err != nil {
			glog.Errorf("JumioCallback: error unmarshaling reject reason: %v", err)
		} else {
			eventDataMap["rejectReason"] = jumioRejectReason
		}
	}

	if req.FormValue("idScanStatus") != "SUCCESS" {
		glog.Infof("JumioCallback: idScanStatus was %s, not paying user with public key %s", req.FormValue("idScanStatus"), userReference)
		if err = fes.logAmplitudeEvent(userReference, "jumio : callback : scan : fail", eventDataMap); err != nil {
			glog.Errorf("JumioCallback: Error logging failed scan in amplitude: %v", err)
		}
		// This means the scan failed. We save that Jumio returned and bail.
		if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: Error putting user metdata in global state: %v", err))
		}
		return
	}

	if len(req.Form["livenessImages"]) == 0 {
		glog.Infof("JumioCallback: No liveness images, not paying user with public key %s", userReference)
		if err = fes.logAmplitudeEvent(userReference, "jumio : callback : liveness : fail", eventDataMap); err != nil {
			glog.Errorf("JumioCallback: Error logging failed scan in amplitude: %v", err)
		}
		// This means there wasn't a liveness check. We save that Jumio returned and bail.
		if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: Error putting user metdata in global state: %v", err))
		}
		return
	}

	identityVerification := req.FormValue("identityVerification")
	if identityVerification == "" {
		_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: identityVerification must be present"))
		return
	}
	var jumioIdentityVerification JumioIdentityVerification
	if err = json.Unmarshal([]byte(identityVerification), &jumioIdentityVerification); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: error unmarshal identity verification"))
		return
	}

	if jumioIdentityVerification.Validity != true || jumioIdentityVerification.Similarity != "MATCH" {
		glog.Infof("JumioCallback: Validity %t and Similarity %s for public key %s",
			jumioIdentityVerification.Validity, jumioIdentityVerification.Similarity, userReference)
		// Don't raise an exception, but do not pay this user.
		if err = fes.logAmplitudeEvent(userReference, "jumio : callback : verification : fail", eventDataMap); err != nil {
			glog.Errorf("JumioCallback: Error logging failed verification in amplitude: %v", err)
		}
		// This means the verification failed. We've logged the payload in global state above, so now we bail.
		if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: Error putting user metdata in global state: %v", err))
		}
		return
	}

	// Make sure this id hasn't been verified before.
	uniqueJumioKey := GlobalStateKeyForCountryIDDocumentTypeSubTypeDocumentNumber(idCountry, idType, idSubType, idNumber)
	// We expect badger to return a key not found error if this document has not been verified before.
	// If it does not return an error, this is a duplicate, so we skip ahead.
	if val, _ := fes.GlobalState.Get(uniqueJumioKey); val == nil || userMetadata.RedoJumio {
		if err = fes.logAmplitudeEvent(userReference, "jumio : callback : verified", eventDataMap); err != nil {
			glog.Errorf("JumioCallback: Error logging successful verification in amplitude: %v", err)
		}
		userMetadata, err = fes.JumioVerifiedHandler(userMetadata, jumioTransactionId, idCountry, publicKeyBytes, utxoView)
		if err != nil {
			glog.Errorf("JumioCallback: Error in JumioVerifiedHandler: %v", err)
		}
		if err = fes.GlobalState.Put(uniqueJumioKey, []byte{1}); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: Error putting unique jumio key in global state: %v", err))
			return
		}
	} else {
		glog.Infof("JumioCallback: Duplicate detected for public key %s", userReference)
		if err = fes.logAmplitudeEvent(userReference, "jumio : callback : verified : duplicate", eventDataMap); err != nil {
			glog.Errorf("JumioCallback: Error logging duplicate verification in amplitude: %v", err)
		}
	}
	if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: Error updating user metadata in global state: %v", err))
		return
	}
}

// GetDefaultJumioCountrySignUpBonus returns the default sign-up bonus configuration.
func (fes *APIServer) GetDefaultJumioCountrySignUpBonus() CountryLevelSignUpBonus {
	return CountryLevelSignUpBonus{
		AllowCustomKickbackAmount:      false,
		AllowCustomReferralAmount:      false,
		ReferralAmountOverrideUSDCents: fes.JumioUSDCents,
		KickbackAmountOverrideUSDCents: fes.JumioKickbackUSDCents,
	}
}

// GetJumioCountrySignUpBonus gets the country level sign up bonus configuration for the provided country code.  If
// there is an error or there is no sign up bonus configuration for a given country, return the default sign-up bonus
// configuration.
func (fes *APIServer) GetJumioCountrySignUpBonus(countryCode string) (_signUpBonus CountryLevelSignUpBonus, _err error) {
	key := GlobalStateKeyForCountryCodeToCountrySignUpBonus(countryCode)

	jumioCountrySignUpBonusMetadataBytes, err := fes.GlobalState.Get(key)
	if err != nil {
		return fes.GetDefaultJumioCountrySignUpBonus(), fmt.Errorf(
			"GetJumioCountrySignUpBonus: error getting sign up bonus metadata from global state for %s: %v",
			countryCode, err)
	}
	var signUpBonus CountryLevelSignUpBonus

	if jumioCountrySignUpBonusMetadataBytes != nil {
		if err = gob.NewDecoder(bytes.NewReader(jumioCountrySignUpBonusMetadataBytes)).Decode(
			&signUpBonus); err != nil {
			return fes.GetDefaultJumioCountrySignUpBonus(), fmt.Errorf(
				"GetJumioCountrySignUpBonus: Failed decoding signup bonus metadata (%s): %v",
				countryCode, err)
		}
		return signUpBonus, nil
	} else {
		// We were unable to find a country, return the default
		return fes.GetDefaultJumioCountrySignUpBonus(), nil
	}
}

func (fes *APIServer) GetCountryLevelSignUpBonusFromHeader(req *http.Request) (_signUpBonus CountryLevelSignUpBonus) {
	// Extract CF-IPCountry header
	countryCodeAlpha2 := req.Header.Get("CF-IPCountry")

	// If we have a valid country code alpha 2 value, look up the sign up bonus config for the alpha2 code
	// Note: XX is used for clients without country code data
	// Note: T1 is used for clients using the tor network
	if countryCodeAlpha2 != "" && countryCodeAlpha2 != "XX" && countryCodeAlpha2 != "T1" {
		return fes.GetCountryLevelSignUpBonusFromAlpha2(countryCodeAlpha2)
	}
	return fes.GetDefaultJumioCountrySignUpBonus()
}

func (fes *APIServer) GetCountryLevelSignUpBonusFromAlpha2(countryCodeAlpha2 string) (_signUpBonus CountryLevelSignUpBonus) {
	countrySignUpBonus := fes.GetDefaultJumioCountrySignUpBonus()

	if alpha3, exists := countries.Alpha2ToAlpha3[countryCodeAlpha2]; exists {
		countrySignUpBonus = fes.GetSingleCountrySignUpBonus(alpha3)
	}

	return countrySignUpBonus
}

// GetRefereeSignUpBonusAmount gets the amount the referee should get a sign-up bonus for verifying with Jumio based on
// the country of their ID.
func (fes *APIServer) GetRefereeSignUpBonusAmount(signUpBonus CountryLevelSignUpBonus, referralCodeUSDCents uint64) uint64 {
	amount := signUpBonus.ReferralAmountOverrideUSDCents
	if signUpBonus.AllowCustomReferralAmount && referralCodeUSDCents > amount {
		amount = referralCodeUSDCents
	}
	return fes.GetNanosFromUSDCents(float64(amount), 0)
}

// GetReferrerSignUpBonusAmount gets the amount the referrer should get as a kickback for referring the user based
// on the country from which the referee signed up.
func (fes *APIServer) GetReferrerSignUpBonusAmount(signUpBonus CountryLevelSignUpBonus, referralCodeUSDCents uint64) uint64 {
	amount := signUpBonus.KickbackAmountOverrideUSDCents
	if signUpBonus.AllowCustomKickbackAmount && referralCodeUSDCents > amount {
		amount = referralCodeUSDCents
	}
	return fes.GetNanosFromUSDCents(float64(amount), 0)
}

func (fes *APIServer) JumioVerifiedHandler(userMetadata *UserMetadata, jumioTransactionId string,
	jumioCountryCode string, publicKeyBytes []byte, utxoView *lib.UtxoView) (_userMetadata *UserMetadata, err error) {
	// Update the user metadata to show that user has been jumio verified and store jumio transaction id.
	userMetadata.JumioVerified = true
	userMetadata.JumioTransactionID = jumioTransactionId
	userMetadata.JumioShouldCompProfileCreation = true
	userMetadata.MustCompleteTutorial = true
	userMetadata.RedoJumio = false

	// We will always get a valid signUpBonusMetadataObject, so glog the error and proceed.
	signUpBonusMetadata := fes.GetSingleCountrySignUpBonus(jumioCountryCode)

	// Decide whether or not the user is going to get paid.
	if signUpBonusMetadata.ReferralAmountOverrideUSDCents > 0 || userMetadata.ReferralHashBase58Check != "" {
		payReferrer := false

		referralAmountUSDCents := uint64(0)
		// Decide whether the user should be paid the standard amount or a special referral amount.
		if userMetadata.ReferralHashBase58Check != "" {
			var referralInfo *ReferralInfo
			referralInfo, err = fes.getInfoForReferralHashBase58(userMetadata.ReferralHashBase58Check)
			if err != nil {
				glog.Errorf("JumioVerifiedHandler: Error getting referral info: %v", err)
			} else if referralInfo != nil && (referralInfo.TotalReferrals < referralInfo.MaxReferrals || referralInfo.MaxReferrals == 0) && fes.getReferralHashStatus(referralInfo.ReferrerPKID, referralInfo.ReferralHashBase58) {
				referralAmountUSDCents = referralInfo.RefereeAmountUSDCents
				payReferrer = true
			}
		}

		refereeSignUpBonusDeSoNanos := fes.GetRefereeSignUpBonusAmount(signUpBonusMetadata, referralAmountUSDCents)

		publicKeyString := lib.PkToString(publicKeyBytes, fes.Params)
		glog.Infof("JumioVerifiedHandler: Paying %d nanos to public key %s as referee sign-up bonus. "+
			"Country code: %s. Country Allow Custom Referral Amount: %t. "+
			"Country Referral amount override: %d. Referrer Amount from Referral Code: %d.",
			refereeSignUpBonusDeSoNanos, publicKeyString, jumioCountryCode,
			signUpBonusMetadata.AllowCustomReferralAmount, signUpBonusMetadata.ReferralAmountOverrideUSDCents,
			referralAmountUSDCents)

		// Pay the referee.
		if refereeSignUpBonusDeSoNanos > 0 {
			// Check the balance of the starter deso seed.
			var balanceInsufficient bool
			balanceInsufficient, err = fes.ExceedsDeSoBalance(refereeSignUpBonusDeSoNanos, fes.Config.StarterDESOSeed)
			if err != nil {
				return userMetadata, fmt.Errorf("JumioVerifiedHandler: Error checking if send deso balance is sufficient: %v", err)
			}
			if balanceInsufficient {
				return userMetadata, fmt.Errorf("JumioVerifiedHandler: SendDeSo wallet balance is below nanos purchased")
			}
			// Send JumioDeSoNanos to public key
			var txnHash *lib.BlockHash
			txnHash, err = fes.SendSeedDeSo(publicKeyBytes, refereeSignUpBonusDeSoNanos, false)
			if err != nil {
				return userMetadata, fmt.Errorf("JumioVerifiedHandler: Error sending starter DeSo: %v", err)
			}

			// Log payout to referee in amplitude
			eventDataMap := make(map[string]interface{})
			eventDataMap["amountNanos"] = refereeSignUpBonusDeSoNanos
			eventDataMap["txnHashHex"] = txnHash.String()
			eventDataMap["referralCode"] = userMetadata.ReferralHashBase58Check
			if err = fes.logAmplitudeEvent(lib.PkToString(publicKeyBytes, fes.Params), "referral : payout : referee", eventDataMap); err != nil {
				glog.Errorf("JumioVerifiedhandler: Error logging payout to referee in amplitude: %v", err)
			}

			// Save transaction hash hex in user metadata.
			userMetadata.JumioStarterDeSoTxnHashHex = txnHash.String()
		}

		// Pay the referrer.
		if userMetadata.ReferralHashBase58Check != "" && payReferrer {
			// We get the referral info again from global state. It is possible that another referral has been given out
			// and to make sure the stats are correct, we pull the latest referral info.
			var referralInfo *ReferralInfo
			referralInfo, err = fes.getInfoForReferralHashBase58(userMetadata.ReferralHashBase58Check)
			if err != nil {
				return userMetadata, fmt.Errorf("JumioVerifiedHandler: Error getting referral info: %v", err)
			}

			kickbackAmountDeSoNanos := fes.GetReferrerSignUpBonusAmount(signUpBonusMetadata,
				referralInfo.ReferrerAmountUSDCents)
			// Add an index for logging all the PKIDs referred by a single PKID+ReferralHash pair.
			refereePKID := utxoView.GetPKIDForPublicKey(publicKeyBytes)
			pkidReferralHashRefereePKIDKey := GlobalStateKeyForPKIDReferralHashRefereePKID(referralInfo.ReferrerPKID, []byte(referralInfo.ReferralHashBase58), refereePKID.PKID)
			if err = fes.GlobalState.Put(pkidReferralHashRefereePKIDKey, []byte{1}); err != nil {
				glog.Errorf("JumioVerifiedHandler: Error adding to the index of users who were referred by a given referral code")
			}
			// Same as the index above but sorted by timestamp.
			currTimestampNanos := uint64(time.Now().UTC().UnixNano()) // current tstamp
			tstampPKIDReferralHashRefereePKIDKey := GlobalStateKeyForTimestampPKIDReferralHashRefereePKID(
				currTimestampNanos, referralInfo.ReferrerPKID, []byte(referralInfo.ReferralHashBase58), refereePKID.PKID)
			if err = fes.GlobalState.Put(tstampPKIDReferralHashRefereePKIDKey, []byte{1}); err != nil {
				glog.Errorf("JumioVerifiedHandler: Error adding to the index of users who were referred by a given referral code")
			}

			referrerPKID := referralInfo.ReferrerPKID
			referrerPublicKeyBytes := utxoView.GetPublicKeyForPKID(referrerPKID)
			referrerPublicKeyString := lib.PkToString(referrerPublicKeyBytes, fes.Params)
			glog.Infof("JumioVerifiedHandler: Paying %d nanos to public key %s as referrer kickback. "+
				"Country code: %s. Country Allow Custom Kickback Amount: %t. "+
				"Country Kickback amount override: %d. Kickback Amount from Referral Code: %d.",
				kickbackAmountDeSoNanos, referrerPublicKeyString, jumioCountryCode,
				signUpBonusMetadata.AllowCustomKickbackAmount, signUpBonusMetadata.KickbackAmountOverrideUSDCents,
				referralInfo.ReferrerAmountUSDCents)
			if referralInfo.TotalReferrals >= referralInfo.MaxReferrals && referralInfo.MaxReferrals > 0 {
				glog.Info("JumioVerifiedHandler: Not paying for kickback. Max Referrals exceeded")
				return userMetadata, nil
			}
			// Check the balance of the starter deso seed compared to the referrer deso nanos.
			var balanceInsufficientForReferrer bool
			balanceInsufficientForReferrer, err = fes.ExceedsDeSoBalance(kickbackAmountDeSoNanos, fes.Config.StarterDESOSeed)
			if err != nil {
				return userMetadata, fmt.Errorf("JumioVerifiedHandler: Error checking if send deso balance is sufficient: %v", err)
			}
			if balanceInsufficientForReferrer {
				return userMetadata, fmt.Errorf("JumioVerifiedHandler: Balance insufficient to pay referrer")
			}

			// Increment JumioSuccesses, TotalReferrals and add to TotralRefereeDeSoNanos and TotalReferrerDeSoNanos
			referralInfo.NumJumioSuccesses++
			referralInfo.TotalReferrals++
			referralInfo.TotalRefereeDeSoNanos += refereeSignUpBonusDeSoNanos
			referralInfo.TotalReferrerDeSoNanos += kickbackAmountDeSoNanos

			// Update the referral info in global state.
			if err = fes.putReferralHashWithInfo(userMetadata.ReferralHashBase58Check, referralInfo); err != nil {
				return userMetadata, fmt.Errorf("JumioVerifiedHandler: Error updating referral info. Skipping paying referrer: %v", err)
			}
			// Check that we actually have to pay the referrer before proceeding
			if kickbackAmountDeSoNanos == 0 {
				return userMetadata, nil
			}
			// Send the referrer money
			var referrerTxnHash *lib.BlockHash
			referrerTxnHash, err = fes.SendSeedDeSo(referrerPublicKeyBytes, kickbackAmountDeSoNanos, false)
			if err != nil {
				return userMetadata, fmt.Errorf("JumioVerifiedHandler: Error sending DESO to referrer: %v", err)
			}
			// Log payout to referee in amplitude
			eventDataMap := make(map[string]interface{})
			eventDataMap["amountNanos"] = kickbackAmountDeSoNanos
			eventDataMap["txnHashHex"] = referrerTxnHash.String()
			eventDataMap["referralCode"] = userMetadata.ReferralHashBase58Check
			eventDataMap["refereePublicKey"] = lib.PkToString(publicKeyBytes, fes.Params)
			eventDataMap["totalReferrals"] = referralInfo.TotalReferrals
			eventDataMap["totalReferrerPayoutNanos"] = referralInfo.TotalReferrerDeSoNanos
			if err = fes.logAmplitudeEvent(lib.PkToString(referrerPublicKeyBytes, fes.Params), "referral : payout : referrer", eventDataMap); err != nil {
				glog.Errorf("JumioVerifiedhandler: Error logging payout to referrer in amplitude: %v", err)
			}
			// Set the referrer deso txn hash.
			userMetadata.ReferrerDeSoTxnHash = referrerTxnHash.String()
		}
	}
	return userMetadata, nil
}

// SetJumioUSDCents sets the cached value of the default amount a user receives for verifying with Jumio without a
// referral code.
func (fes *APIServer) SetJumioUSDCents() {
	val, err := fes.GlobalState.Get(GlobalStateKeyForJumioUSDCents())
	if err != nil {
		glog.V(2).Infof("SetJumioUSDCents: Error getting Jumio USD Cents from global state: %v", err)
		return
	}
	if len(val) == 0 {
		return
	}
	jumioUSDCents, bytesRead := lib.Uvarint(val)
	if bytesRead <= 0 {
		glog.V(2).Infof("SetJumioUSDCents: invalid bytes read: %v", bytesRead)
		return
	}
	fes.JumioUSDCents = jumioUSDCents
}

func (fes *APIServer) GetJumioDeSoNanos() uint64 {
	return fes.GetNanosFromUSDCents(float64(fes.JumioUSDCents), 0)
}

func (fes *APIServer) SetJumioKickbackUSDCents() {
	val, err := fes.GlobalState.Get(GlobalStateKeyForJumioKickbackUSDCents())
	if err != nil {
		glog.V(2).Infof("SetJumioKickbackUSDCents: Error getting Jumio Kickback USD Cents from global state: %v", err)
		return
	}
	if len(val) == 0 {
		return
	}
	jumioKickbackUSDCents, bytesRead := lib.Uvarint(val)
	if bytesRead <= 0 {
		glog.V(2).Infof("SetJumioKickbackUSDCents: invalid bytes read: %v", bytesRead)
		return
	}
	fes.JumioKickbackUSDCents = jumioKickbackUSDCents
}

type GetJumioStatusForPublicKeyRequest struct {
	JWT                  string
	PublicKeyBase58Check string
}

type GetJumioStatusForPublicKeyResponse struct {
	JumioFinishedTime uint64
	JumioReturned     bool
	JumioVerified     bool

	BalanceNanos *uint64
}

func (fes *APIServer) GetJumioStatusForPublicKey(ww http.ResponseWriter, rr *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(rr.Body, MaxRequestBodySizeBytes))
	requestData := GetJumioStatusForPublicKeyRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetJumioStatusForPublicKey: Error parsing request body: %v", err))
		return
	}

	isValid, err := fes.ValidateJWT(requestData.PublicKeyBase58Check, requestData.JWT)
	if !isValid {
		_AddBadRequestError(ww, fmt.Sprintf("GetJumioStatusForPublicKey: Invalid token: %v", err))
		return
	}

	userMetadata, err := fes.getUserMetadataFromGlobalState(requestData.PublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetJumioStatusForPublicKey: Error getting user metadata from global state: %v", err))
		return
	}

	res := &GetJumioStatusForPublicKeyResponse{
		JumioFinishedTime: userMetadata.JumioFinishedTime,
		JumioReturned:     userMetadata.JumioReturned,
		JumioVerified:     userMetadata.JumioVerified,
	}

	if userMetadata.JumioVerified {
		var utxoView *lib.UtxoView
		utxoView, err = fes.backendServer.GetMempool().GetAugmentedUniversalView()
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetJumioStatusForPublicKey: error getting utxoview: %v", err))
			return
		}
		var balanceNanos uint64
		balanceNanos, err = utxoView.GetDeSoBalanceNanosForPublicKey(userMetadata.PublicKey)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetJumioStatusForPublicKey: Error getting balance: %v", err))
			return
		}
		res.BalanceNanos = &balanceNanos
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetJumioStatusForPublicKey: Encode failed: %v", err))
		return
	}
}
