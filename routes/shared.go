package routes

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/bitclout/core/lib"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"github.com/tyler-smith/go-bip39"
)

func _AddBadRequestError(ww http.ResponseWriter, errorString string) {
	_AddHttpError(ww, errorString, http.StatusBadRequest)
}

func _AddNotFoundError(ww http.ResponseWriter, errorString string) {
	_AddHttpError(ww, errorString, http.StatusNotFound)
}

func _AddInternalServerError(ww http.ResponseWriter, errorString string) {
	_AddHttpError(ww, errorString, http.StatusInternalServerError)
}

func _AddHttpError(ww http.ResponseWriter, errorString string, statusCode int) {
	glog.Error(errorString)
	ww.WriteHeader(statusCode)
	json.NewEncoder(ww).Encode(struct {
		Error string `json:"error"`
	}{Error: errorString})
}

type TransactionInfo struct {
	TotalInputNanos          uint64
	SpendAmountNanos         uint64
	ChangeAmountNanos        uint64
	FeeNanos                 uint64
	TransactionIDBase58Check string

	// These are Base58Check encoded
	RecipientPublicKeys   []string
	RecipientAmountsNanos []uint64

	TransactionHex string

	// TODO: Not including the transaction because it causes encoding to
	// fail due to the presence of an interface for TxnMeta.
	//Transaction    *lib.MsgBitCloutTxn

	// Unix timestamp (seconds since epoch).
	TimeAdded int64
}

type MessageEntryResponse struct {
	SenderPublicKeyBase58Check    string
	RecipientPublicKeyBase58Check string

	EncryptedText string
	TstampNanos   uint64

	// Whether or not the user is the sender of the message.
	IsSender bool

	// Indicate if message was encrypted using shared secret
	V2 bool
}

type MessageContactResponse struct {
	PublicKeyBase58Check string
	Messages             []*MessageEntryResponse

	ProfileEntryResponse *ProfileEntryResponse

	// The number of messages this user has read from this contact. This is
	// used to show a notification badge for unread messages.
	NumMessagesRead int64
}

// User ...
type User struct {
	// The public key for the user is computed from the seed using the exact
	// parameters used to generate the BTC deposit address below. Because
	// of this, the BitClout private and public key pair is also the key
	// pair corresponding to the BTC address above. We store this same
	// key in base58 format above for convenience in communicating with
	// the FE.
	PublicKeyBase58Check string

	ProfileEntryResponse *ProfileEntryResponse

	Utxos               []*UTXOEntryResponse
	BalanceNanos        uint64
	UnminedBalanceNanos uint64

	PublicKeysBase58CheckFollowedByUser []string

	UsersYouHODL         []*BalanceEntryResponse
	UsersWhoHODLYouCount int

	// HasPhoneNumber is a computed boolean so we can avoid returning the phone number in the
	// API response, since phone numbers are sensitive PII.
	HasPhoneNumber   bool
	CanCreateProfile bool
	BlockedPubKeys   map[string]struct{}
	HasEmail         bool
	EmailVerified    bool

	// JumioStartTime = Time user requested to initiate Jumio flow
	JumioStartTime uint64
	// JumioFinishedTime = Time user completed flow in Jumio
	JumioFinishedTime uint64
	// JumioVerified = user was verified from Jumio flow
	JumioVerified    bool
	// JumioReturned = jumio webhook called
	JumioReturned    bool

	// Is this user an admin
	IsAdmin bool
	// Is th user a super admin
	IsSuperAdmin bool

	// Is this user blacklisted/graylisted
	IsBlacklisted bool
	IsGraylisted  bool

	// Where is the user in the tutorial flow
	TutorialStatus TutorialStatus

	// Username of creator purchased during onboarding flow - used in case a user changes devices in the middle of the flow.
	CreatorPurchasedInTutorialUsername *string `json:",omitempty"`

	// Amount of creator coins purchased in the tutorial
	CreatorCoinsPurchasedInTutorial uint64

	// Does this user need to complete the tutorial
	MustCompleteTutorial bool
}

type BalanceEntryResponse struct {
	// The public keys are provided for the frontend
	HODLerPublicKeyBase58Check string
	// The public keys are provided for the frontend
	CreatorPublicKeyBase58Check string

	// Has the hodler purchased this creator's coin
	HasPurchased bool

	// How much this HODLer owns of a particular creator coin.
	BalanceNanos uint64
	// The net effect of transactions in the mempool on a given BalanceEntry's BalanceNanos.
	// This is used by the frontend to convey info about mining.
	NetBalanceInMempool int64

	ProfileEntryResponse *ProfileEntryResponse `json:",omitempty"`
}

func (fes *APIServer) GetBalanceForPublicKey(publicKeyBytes []byte) (
	_balanceNanos uint64, _err error) {

	// Get the UtxoEntries from the augmented view
	utxoEntries, err := fes.blockchain.GetSpendableUtxosForPublicKey(publicKeyBytes, fes.backendServer.GetMempool(), nil)
	if err != nil {
		return 0, fmt.Errorf(
			"GetBalanceForPublicKey: Problem getting utxos from view: %v", err)
	}
	totalBalanceNanos := uint64(0)
	for _, utxoEntry := range utxoEntries {
		totalBalanceNanos += utxoEntry.AmountNanos
	}
	return totalBalanceNanos, nil
}

// GetVerifiedUsernameToPKIDMap
//
// Acts as a helper function for dealing with the verified usernames map.
// If the map does not already exist, this function will create one in global state.
// Returns nil it encounters an error. Returning nil is not dangerous, as
// _profileEntryToResponse() will ignore the map entirely in that case.
func (fes *APIServer) GetVerifiedUsernameToPKIDMap() (_verificationMap map[string]*lib.PKID, _err error) {
	return fes.VerifiedUsernameMap, nil
}

func (fes *APIServer) RefreshVerifiedUsernameToPKIDMap() {
	// Pull the verified map from global state.
	verifiedMapBytes, err := fes.GlobalStateGet(_GlobalStatePrefixForVerifiedMap)
	if err != nil {
		glog.Errorf("RefreshVerifiedUsernameToPKIDMap: Cannot Decode Verification Map: %v", err)
	}
	verifiedMapStruct := VerifiedUsernameToPKID{}

	// Check if a map exists right now
	if len(verifiedMapBytes) > 0 {
		err = gob.NewDecoder(bytes.NewReader(verifiedMapBytes)).Decode(&verifiedMapStruct)
		if err != nil {
			glog.Errorf("RefreshVerifiedUsernameToPKIDMap: Cannot Decode Verification Map: %v", err)
		}
	} else {
		// Create the inital map structure
		verifiedMapStruct.VerifiedUsernameToPKID = make(map[string]*lib.PKID)

		// Encode the map and stick it in the database.
		metadataDataBuf := bytes.NewBuffer([]byte{})
		gob.NewEncoder(metadataDataBuf).Encode(verifiedMapStruct)
		err = fes.GlobalStatePut(_GlobalStatePrefixForVerifiedMap, metadataDataBuf.Bytes())
		if err != nil {
			glog.Errorf("RefreshVerifiedUsernameToPKIDMap: Cannot Decode Verification Map: %v", err)
		}
	}
	fes.VerifiedUsernameMap = verifiedMapStruct.VerifiedUsernameToPKID
}

// TODO: We may want to move this into getUserMetadataFromGlobalState and change
// the other usage to use getUserMetadataFromGlobalState
func makeUserMetadata(userMetadataBytes []byte, userPublicKeyBytes []byte) (_userMetadata *UserMetadata, _err error) {
	userMetadata := UserMetadata{}
	if userMetadataBytes != nil {
		err := gob.NewDecoder(bytes.NewReader(userMetadataBytes)).Decode(&userMetadata)
		if err != nil {
			return nil, errors.Wrap(fmt.Errorf(
				"makeUserMetadata: Problem getting metadata from global state: %v", err), "")
		}
	} else {
		// If this is a brand new user metadata object we need to add its public key.
		userMetadata.PublicKey = userPublicKeyBytes
	}
	return &userMetadata, nil
}

func (fes *APIServer) getUserMetadataFromGlobalStateByPublicKeyBytes(userPublicKeyBytes []byte) (_userMetadata *UserMetadata, _err error) {
	dbKey := GlobalStateKeyForPublicKeyToUserMetadata(userPublicKeyBytes)
	userMetadataBytes, err := fes.GlobalStateGet(dbKey)
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf(
			"getUserMetadataFromGlobalStateByPublicKeyBytes: Problem with GlobalStateGet: %v", err), "")
	}

	userMetadata, err := makeUserMetadata(userMetadataBytes, userPublicKeyBytes)
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf(
			"getUserMetadataFromGlobalStateByPublicKeyBytes: Problem with makeUserMetadata: %v", err), "")
	}

	// Check if we need to add the public key to userMetadata
	if len(userMetadata.PublicKey) != 33 {
		userMetadata.PublicKey = userPublicKeyBytes
	}

	return userMetadata, nil
}

func (fes *APIServer) getUserMetadataFromGlobalState(
	publicKeyBase58Check string,
) (_userMetadata *UserMetadata, _err error) {
	userPublicKeyBytes, _, err := lib.Base58CheckDecode(publicKeyBase58Check)
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf(
			"getUserMetadataFromGlobalState: Problem with lib.Base58CheckDecode: %v", err), "")
	}

	return fes.getUserMetadataFromGlobalStateByPublicKeyBytes(userPublicKeyBytes)
}

func (fes *APIServer) putUserMetadataInGlobalState(
	userMetadata *UserMetadata,
) (_err error) {
	dbKey := GlobalStateKeyForPublicKeyToUserMetadata(userMetadata.PublicKey)

	// Encode the updated entry and stick it in the database.
	metadataDataBuf := bytes.NewBuffer([]byte{})
	gob.NewEncoder(metadataDataBuf).Encode(userMetadata)
	err := fes.GlobalStatePut(dbKey, metadataDataBuf.Bytes())
	if err != nil {
		return errors.Wrap(fmt.Errorf(
			"AdminUpdateUserGlobalMetadata: Problem putting updated user metadata: %v", err), "")
	}

	return nil
}

func (fes *APIServer) SendSeedBitClout(recipientPkBytes []byte, amountNanos uint64, useBuyBitCloutSeed bool) (txnHash *lib.BlockHash, _err error) {
	fes.mtxSeedBitClout.Lock()
	defer fes.mtxSeedBitClout.Unlock()

	senderSeed := fes.Config.StarterBitcloutSeed
	if useBuyBitCloutSeed {
		senderSeed = fes.Config.BuyBitCloutSeed
	}
	starterSeedBytes, err := bip39.NewSeedWithErrorChecking(senderSeed, "")
	if err != nil {
		glog.Errorf("SendSeedBitClout: error converting mnemonic: %v", err)
		return nil, fmt.Errorf("SendSeedBitClout: Error converting mnemonic: %+v", err)
	}

	starterPubKey, starterPrivKey, _, err := lib.ComputeKeysFromSeed(starterSeedBytes, 0, fes.Params)
	if err != nil {
		glog.Errorf("SendSeedBitClout: Error computing keys from seed: %v", err)
		return nil, fmt.Errorf("SendSeedBitClout: Error computing keys from seed: %+v", err)
	}

	sendBitClout := func() (txnHash *lib.BlockHash, _err error) {
		// Create the transaction outputs and add the recipient's public key and the
		// amount we want to pay them
		txnOutputs := []*lib.BitCloutOutput{}
		txnOutputs = append(txnOutputs, &lib.BitCloutOutput{
			PublicKey: recipientPkBytes,
			// If we get here we know the amount is non-negative.
			AmountNanos: amountNanos,
		})

		// Assemble the transaction so that inputs can be found and fees can
		// be computed.
		txn := &lib.MsgBitCloutTxn{
			// The inputs will be set below.
			TxInputs:  []*lib.BitCloutInput{},
			TxOutputs: txnOutputs,
			PublicKey: starterPubKey.SerializeCompressed(),
			TxnMeta:   &lib.BasicTransferMetadata{},
			// We wait to compute the signature until we've added all the
			// inputs and change.
		}

		// Add inputs to the transaction and do signing, validation, and broadcast
		// depending on what the user requested.
		utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
		if err != nil {
			return nil, err
		}
		minFee := fes.MinFeeRateNanosPerKB
		if utxoView.GlobalParamsEntry != nil && utxoView.GlobalParamsEntry.MinimumNetworkFeeNanosPerKB > 0 {
			minFee = utxoView.GlobalParamsEntry.MinimumNetworkFeeNanosPerKB
		}
		_, _, _, _, err = fes.blockchain.AddInputsAndChangeToTransaction(txn, minFee, fes.mempool)
		if err != nil {
			return nil, fmt.Errorf("SendSeedBitClout: Error adding inputs for seed BitClout: %v", err)
		}

		txnSignature, err := txn.Sign(starterPrivKey)
		if err != nil {
			return nil, fmt.Errorf("SendSeedBitClout: Error adding inputs for seed BitClout: %v", err)
		}
		txn.Signature = txnSignature

		err = fes.backendServer.VerifyAndBroadcastTransaction(txn)
		if err != nil {
			return nil, fmt.Errorf("SendSeedBitClout: Problem processing starter seed transaction: %v", err)
		}

		return txn.Hash(), nil
	}

	// Here we retry sending BitClout once if there is an error.  This is concerning, but we believe it is safe at this
	// time as no Clout will be sent if there is an error.  We wait for 5 seconds
	var hash *lib.BlockHash
	hash, err = sendBitClout()
	if err != nil {
		publicKeyBase58Check := lib.PkToString(recipientPkBytes, fes.Params)
		glog.Errorf("SendSeedBitClout: 1st attempt - error sending %d nanos of Clout to public key %v: error - %v", amountNanos, publicKeyBase58Check, err)
		time.Sleep(5 * time.Second)
		hash, err = sendBitClout()
		if err != nil {
			glog.Errorf("SendSeedBitClout: 2nd attempt - error sending %d nanos of Clout to public key %v: error - %v", amountNanos, publicKeyBase58Check, err)
		}
	}
	return hash, err
}
