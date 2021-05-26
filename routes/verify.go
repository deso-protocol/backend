package routes

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"fmt"
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
	_, err = fes.Twilio.Verify.Verifications.Create(ctx, fes.TwilioVerifyServiceId, data)
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
	checkPhoneNumberResponse, err := fes.Twilio.Verify.Verifications.Check(ctx, fes.TwilioVerifyServiceId, data)
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
	if settingPhoneNumberForFirstTime && fes.StarterBitCloutSeed != "" {
		amountToSendNanos := fes.StarterBitCloutAmountNanos

		if len(requestData.PhoneNumber) == 0 || requestData.PhoneNumber[0] != '+' {
			_AddBadRequestError(ww, fmt.Sprintf("SubmitPhoneNumberVerificationCode: Phone number must start with a plus sign"))
			return
		}

		if requestData.PhoneNumber != "" {
			// We sort the country codes by size, with the longest prefix
			// first so that we match on the longest prefix when we iterate.
			sortedPrefixExceptionMap := []string{}
			for countryCodePrefix := range fes.StarterBitCloutPrefixExceptionMap {
				sortedPrefixExceptionMap = append(sortedPrefixExceptionMap, countryCodePrefix)
			}
			sort.Slice(sortedPrefixExceptionMap, func(ii, jj int) bool {
				return len(sortedPrefixExceptionMap[ii]) > len(sortedPrefixExceptionMap[jj])
			})
			for _, countryPrefix := range sortedPrefixExceptionMap {
				amountForPrefix := fes.StarterBitCloutPrefixExceptionMap[countryPrefix]
				if strings.Contains(requestData.PhoneNumber, countryPrefix) {
					amountToSendNanos = amountForPrefix
					break
				}
			}
		}

		if _, err = fes.SendSeedBitClout(userMetadata.PublicKey, amountToSendNanos, false); err != nil {
			glog.Errorf("SubmitPhoneNumberVerificationCode: Error sending seed BitClout: %v", err)
		}
	}
}
