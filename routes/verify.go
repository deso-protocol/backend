package routes

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bitclout/core/lib"
	"github.com/golang/glog"
	"github.com/nyaruka/phonenumbers"
	"github.com/pkg/errors"
)

type SendPhoneNumberVerificationTextRequest struct {
	PublicKeyBase58Check string `safeForLogging:"true"`
	PhoneNumber          string
	JWT                  string
}

type SendPhoneNumberVerificationTextResponse struct {
}

/*************************************************************
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
*************************************************************/
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
	err = fes.validatePhoneNumberNotAlreadyInUse(requestData.PhoneNumber, requestData.PublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"SendPhoneNumberVerificationText: Error with validatePhoneNumberNotAlreadyInUse: %v", err))
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

	totalBalanceNanos, err := fes.GetBalanceForPublicKey(userMetadata.PublicKey)
	if err != nil {
		return false, err
	}
	// User can create a profile if they have a phone number or if they have enough BitClout to cover the create profile fee.
	// The PhoneNumber is only set if the user has passed phone number verification.
	if userMetadata.PhoneNumber != "" || totalBalanceNanos >= utxoView.GlobalParamsEntry.CreateProfileFeeNanos {
		return true, nil
	}

	// Users who have verified with Jumio can create a profile
	if userMetadata.JumioVerified {
		return true, nil
	}

	// If we reached here, the user can't create a profile
	return false, nil
}

func (fes *APIServer) getPhoneNumberMetadataFromGlobalState(phoneNumber string) (_phoneNumberMetadata *PhoneNumberMetadata, _err error) {
	dbKey, err := GlobalStateKeyForPhoneNumberStringToPhoneNumberMetadata(phoneNumber)
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf(
			"getPhoneNumberMetadataFromGlobalState: Problem with GlobalStateKeyForPhoneNumberStringToPhoneNumberMetadata %v", err), "")
	}

	phoneNumberMetadataBytes, err := fes.GlobalStateGet(dbKey)
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf(
			"getPhoneNumberMetadataFromGlobalState: Problem with GlobalStateGet: %v", err), "")
	}

	phoneNumberMetadata := PhoneNumberMetadata{}
	if phoneNumberMetadataBytes != nil {
		err = gob.NewDecoder(bytes.NewReader(phoneNumberMetadataBytes)).Decode(&phoneNumberMetadata)
		if err != nil {
			return nil, errors.Wrap(fmt.Errorf(
				"getPhoneNumberMetadataFromGlobalState: Problem with NewDecoder: %v", err), "")
		}
	}

	return &phoneNumberMetadata, nil
}

func (fes *APIServer) putPhoneNumberMetadataInGlobalState(phoneNumberMetadata *PhoneNumberMetadata) (_err error) {
	dbKey, err := GlobalStateKeyForPhoneNumberStringToPhoneNumberMetadata(phoneNumberMetadata.PhoneNumber)
	if err != nil {
		return errors.Wrap(fmt.Errorf(
			"putPhoneNumberMetadataInGlobalState: Problem with GlobalStateKeyForPhoneNumberStringToPhoneNumberMetadata %v", err), "")
	}

	metadataDataBuf := bytes.NewBuffer([]byte{})
	gob.NewEncoder(metadataDataBuf).Encode(phoneNumberMetadata)
	err = fes.GlobalStatePut(dbKey, metadataDataBuf.Bytes())
	if err != nil {
		return errors.Wrap(fmt.Errorf(
			"putPhoneNumberMetadataInGlobalState: Problem putting updated phone number metadata: %v", err), "")
	}

	return nil
}

func (fes *APIServer) validatePhoneNumberNotAlreadyInUse(phoneNumber string, userPublicKeyBase58Check string) (_err error) {
	phoneNumberMetadata, err := fes.getPhoneNumberMetadataFromGlobalState(phoneNumber)
	if err != nil {
		return errors.Wrap(fmt.Errorf(
			"validatePhoneNumberNotAlreadyInUse: Error with getPhoneNumberMetadataFromGlobalState: %v", err), "")
	}

	// Validate that the phone number is not already in use by a different account
	if phoneNumberMetadata.PublicKey != nil {
		publicKeyBase58Check := lib.PkToString(phoneNumberMetadata.PublicKey, fes.Params)
		if publicKeyBase58Check != userPublicKeyBase58Check {
			return errors.Wrap(fmt.Errorf("validatePhoneNumberNotAlreadyInUse: Phone number already in use"), "")
		}
	}

	return nil
}

type SubmitPhoneNumberVerificationCodeRequest struct {
	JWT string
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
	err = fes.validatePhoneNumberNotAlreadyInUse(requestData.PhoneNumber, requestData.PublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitPhoneNumberVerificationCode: Error with validatePhoneNumberNotAlreadyInUse: %v", err))
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
	phoneNumberMetadata, err := fes.getPhoneNumberMetadataFromGlobalState(requestData.PhoneNumber)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitPhoneNumberVerificationCode: Error with getPhoneNumberMetadataFromGlobalState: %v", err))
		return
	}

	phoneNumberMetadata.PublicKey = userMetadata.PublicKey
	phoneNumberMetadata.PhoneNumber = requestData.PhoneNumber
	phoneNumberMetadata.ShouldCompProfileCreation = true
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
	err = fes.putPhoneNumberMetadataInGlobalState(phoneNumberMetadata)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SubmitPhoneNumberVerificationCode: Problem with putPhoneNumberMetadataInGlobalState: %v", err))
		return
	}

	/**************************************************************/
	// Send the user starter BitClout, if we haven't already sent it
	/**************************************************************/
	if settingPhoneNumberForFirstTime && fes.Config.StarterBitcloutSeed != "" {
		amountToSendNanos := fes.Config.StarterBitcloutNanos

		if len(requestData.PhoneNumber) == 0 || requestData.PhoneNumber[0] != '+' {
			_AddBadRequestError(ww, fmt.Sprintf("SubmitPhoneNumberVerificationCode: Phone number must start with a plus sign"))
			return
		}

		if requestData.PhoneNumber != "" {
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
				if strings.Contains(requestData.PhoneNumber, countryPrefix) {
					amountToSendNanos = amountForPrefix
					break
				}
			}
		}

		var txnHash *lib.BlockHash
		txnHash, err = fes.SendSeedBitClout(userMetadata.PublicKey, amountToSendNanos, false)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SubmitPhoneNumberVerificationCode: Error sending seed BitClout: %v", err))
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
		glog.Error("%v: %v", err, response)
	}
}

func (fes *APIServer) IsConfiguredForSendgrid() bool {
	return fes.Config.SendgridApiKey != ""
}

//
// JUMIO
//

func (fes *APIServer) IsConfiguredForJumio() bool {
	return fes.Config.JumioToken != ""  && fes.Config.JumioSecret != ""
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
	PublicKey string
	SuccessURL string
	ErrorURL string
	JWT       string
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

	tStampNanos := int(time.Now().UnixNano())

	jumioInternalReference := requestData.PublicKey + strconv.Itoa(tStampNanos)

	userMetadata.JumioInternalReference = jumioInternalReference
	userMetadata.JumioFinishedTime = 0
	userMetadata.JumioReturned = false
	if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioBegin: error putting jumio internal reference in global state: %v", err))
		return
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
		_AddBadRequestError(ww, fmt.Sprintf("JumioBegin: Request returned non-200 status code: %v", postRes.StatusCode))
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
	PublicKey string
	JumioInternalReference string
	JWT string
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
	Similarity  string `json:"similarity"`
	Validity    bool `json:"validity"`
	Reason      string `json:"reason"`
}

// Jumio webhook - If Jumio verified user is a human that we haven't paid already, pay them some starter CLOUT.
// Make sure you only allow access to jumio IPs for this endpoint, otherwise anybody can take all the funds from
// the public key that sends BitClout. WHITELIST JUMIO IPs.
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

	if req.FormValue("idScanStatus") != "SUCCESS" {
		if err = fes.logAmplitudeEvent(userReference, "jumio : callback : scan : fail", nil); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: Error logging failed scan in amplitude: %v", err))
			return
		}
		// This means the scan failed. We save that Jumio returned and bail.
		if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: Error putting user metdata in global state: %v", err))
		}
		return
	}

	if len(req.Form["livenessImages"]) == 0 {
		if err = fes.logAmplitudeEvent(userReference, "jumio : callback : liveness : fail", nil); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: Error logging failed scan in amplitude: %v", err))
			return
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
		// Don't raise an exception, but do not pay this user.
		if err = fes.logAmplitudeEvent(userReference, "jumio : callback : verification : fail", nil); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: Error logging failed verification in amplitude: %v", err))
			return
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
	if val, _ := fes.GlobalStateGet(uniqueJumioKey); val == nil || userMetadata.RedoJumio {
		if err = fes.logAmplitudeEvent(userReference, "jumio : callback : verified", nil); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: Error logging successful verification in amplitude: %v", err))
			return
		}
		// Update the user metadata to show that user has been jumio verified and store jumio transaction id.
		userMetadata.JumioVerified = true
		userMetadata.JumioTransactionID = jumioTransactionId
		userMetadata.JumioShouldCompProfileCreation = true
		userMetadata.MustCompleteTutorial = true
		userMetadata.RedoJumio = false

		if bitcloutNanos := fes.GetJumioBitCloutNanos(); bitcloutNanos > 0 {
			// Check the balance of the starter bitclout seed.
			var balanceInsufficient bool
			balanceInsufficient, err = fes.ExceedsBitCloutBalance(bitcloutNanos, fes.Config.StarterBitcloutSeed)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: Error checking if send bitclout balance is sufficient: %v", err))
				return
			}
			if balanceInsufficient {
				_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: SendBitClout wallet balance is below nanos purchased"))
				return
			}
			// Send JumioBitCloutNanos to public key
			var txnHash *lib.BlockHash
			txnHash, err = fes.SendSeedBitClout(publicKeyBytes, bitcloutNanos, false)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: Error sending starter BitClout: %v", err))
				return
			}

			// Save transaction hash hex in user metadata.
			userMetadata.JumioStarterBitCloutTxnHashHex = txnHash.String()
		}
		if err = fes.GlobalStatePut(uniqueJumioKey, []byte{1}); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: Error putting unique jumio key in global state: %v", err))
			return
		}
	} else {
		if err = fes.logAmplitudeEvent(userReference, "jumio : callback : verified : duplicate", nil); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: Error logging duplicate verification in amplitude: %v", err))
			return
		}
	}
	if err = fes.putUserMetadataInGlobalState(userMetadata); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: Error updating user metadata in global state: %v", err))
		return
	}
}

func (fes *APIServer) GetJumioBitCloutNanos() uint64 {
	val, err := fes.GlobalStateGet(GlobalStateKeyForJumioBitCloutNanos())
	if err != nil {
		return 0
	}
	jumioBitCloutNanos, bytesRead := lib.Uvarint(val)
	if bytesRead <= 0 {
		return 0
	}
	return jumioBitCloutNanos
}

type GetJumioStatusForPublicKeyRequest struct {
	JWT string
	PublicKeyBase58Check string
}

type GetJumioStatusForPublicKeyResponse struct {
	JumioFinishedTime uint64
	JumioReturned     bool
	JumioVerified     bool

	BalanceNanos      *uint64
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
		balanceNanos, err = utxoView.GetBitcloutBalanceNanosForPublicKey(userMetadata.PublicKey)
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
