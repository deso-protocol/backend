package routes

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/bitclout/core/lib"
	"github.com/golang/glog"
	"github.com/nyaruka/phonenumbers"
	"github.com/pkg/errors"
)

type SendPhoneNumberVerificationTextRequest struct {
	PublicKeyBase58Check string `safeForLogging:"true"`
	PhoneNumber          string
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

	/**************************************************************/
	// Validations
	/**************************************************************/
	err := fes.validatePhoneNumberNotAlreadyInUse(requestData.PhoneNumber, requestData.PublicKeyBase58Check)
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

	/**************************************************************/
	// Validations
	/**************************************************************/
	err := fes.validatePhoneNumberNotAlreadyInUse(requestData.PhoneNumber, requestData.PublicKeyBase58Check)
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

type JumioInitRequest struct {
	CustomerInternalReference string `json:"customerInternalReference"`
	UserReference             string `json:"userReference"`
}

type JumioInitResponse struct {
	RedirectURL          string `json:"redirectUrl"`
	TransactionReference string `json:"transactionReference"`
}

type JumioBeginRequest struct {
	PublicKey string
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

	// TODO: if public key has already successfully completed Jumio flow, return error.
	initData := &JumioInitRequest{
		CustomerInternalReference: requestData.PublicKey + uuid.NewString(),
		UserReference:             requestData.PublicKey,
	}
	jsonData, err := json.Marshal(initData)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioBegin: JSON invalid: %v", err))
		return
	}

	req, err = http.NewRequest("POST", "https://netverify.com/api/v4/initiate", bytes.NewBuffer(jsonData))
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioBegin: Request creation failed: %v", err))
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(fes.Config.JumioToken, fes.Config.JumioSecret) // TODO: Move these to config values

	postRes, err := http.DefaultClient.Do(req)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioBegin: Request failed: %v", err))
		return
	}

	jumioInit := JumioInitResponse{}
	if err = json.NewDecoder(postRes.Body).Decode(&jumioInit); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioBegin: Decode failed: %v", err))
		return
	}
	postRes.Body.Close()

	res := JumioBeginResponse{
		URL: jumioInit.RedirectURL,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioBegin: Encode failed: %v", err))
		return
	}
}

func (fes *APIServer) JumioCallback(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	var requestData interface{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("JumioBegin: Problem parsing request body: %v", err))
		return
	}

	//var publicKeyBytes []byte
	//if requestData.PublicKey != "" {
	//	var err error
	//	publicKeyBytes, _, err = lib.Base58CheckDecode(requestData.PublicKey)
	//	if err != nil {
	//		_AddBadRequestError(ww, fmt.Sprintf("JumioBegin: Problem decoding user public key: %v", err))
	//		return
	//	}
	//} else {
	//	_AddBadRequestError(ww, fmt.Sprintf("JumioBegin: Public key is required"))
	//	return
	//}
	//
	//
	//utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	//if err != nil {
	//	_AddBadRequestError(ww, fmt.Sprintf("JumioBegin: error getting utxoview: %v", err))
	//	return
	//}
	//
	//pkid := utxoView.GetPKIDForPublicKey(publicKeyBytes)
	//if pkid == nil {
	//	_AddBadRequestError(ww, fmt.Sprintf("JumioBegin: No PKID found for public key: %v", requestData.PublicKey))
	//	return
	//}

	// TODO: log the request data somewhere and save in global state.
	requestDataMap := requestData.(map[string]interface{})
	if requestDataMap["idScanStatus"] != "SUCCESS" {
		// This means the verification failed. save the failed body somewhere and bail.
		return
	}
	var err error
	var payloadBytes []byte
	payloadBytes, err = json.Marshal(requestData)
	if err != nil {
		return
	}

	// PASSPORT, DRIVING_LICENSE, ID_CARD, VISA
	idType := requestDataMap["idType"].(string)
	// More specific type
	idSubType := requestDataMap["idSubtype"].(string)

	idCountry := requestDataMap["idCountry"].(string)

	idNumber := requestDataMap["idNumber"].(string)

	//GlobalStateKeyForPKIDToJumioTransaction()
	// Make sure this order hasn't been paid out, then mark it as paid out.
	uniqueJumioKey := GlobalStateKeyForCountryIDDocumentTypeSubTypeDocumentNumber(idCountry, idType, idSubType, idNumber)
	// We expect badger to return a key not found error if BitClout has been paid out for this order.
	// If it does not return an error, BitClout has already been paid out, so we skip ahead.
	if val, _ := fes.GlobalStateGet(uniqueJumioKey); val == nil {
		// Put the transaction in global state for the PKID key
		// Put the transaction in global state for the unique document key
		// Get user metadata from global state and set jumio attributes
		// Check the balance of merlin, pay out from merlin
		bitcloutNanos := fes.Config.JumioBitcloutNanos
		if bitcloutNanos != 0 {
			var balanceInsufficient bool
			balanceInsufficient, err = fes.ExceedsBitCloutBalance(bitcloutNanos, fes.Config.StarterBitcloutSeed)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("WyreWalletOrdersubscription: Error checking if send bitclout balance is sufficient: %v", err))
				return
			}
			if balanceInsufficient {
				// TODO: THIS SHOULD TRIGGER ALERT
				_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: SendBitClout wallet balance is below nanos purchased"))
				return
			}
			if err = fes.GlobalStatePut(uniqueJumioKey, payloadBytes); err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: Error putting unique jumio key in global state: %v", err))
				return
			}
			// TODO: Get public key correctly from payload
			var publicKeyBase58Check string
			var userMetadata *UserMetadata
			userMetadata, err = fes.getUserMetadataFromGlobalState(publicKeyBase58Check)
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: Error getting user metadata from global state: %v", err))
				return
			}
			userMetadata.JumioVerified = true
			userMetadata.JumioTransactionID = "somestring"
			//var publicKeyBytes []byte
			//fes.GlobalStateGet(GlobalStateKeyForPublicKeyToUserMetadata(publicKeyBytes))
			// TODO: which fields map to customerReferenceId and userReference
			//if err = fes.GlobalStatePut(GlobalStateKeyForPKIDReferenceIdToJumioTransaction(pkid, referenceId), payloadBytes); err != nil {
			//	_AddBadRequestError(ww, fmt.Sprintf("JumioCallback: Error putting unique jumio key in global state: %v", err))
			//	return
			//}
		}
		// Save the transaction hash of the payout somewhere.
	}
	// Mark this order as paid out
	//if err = fes.GlobalStatePut(wyreOrderIdKey, []byte{1}); err != nil
}
