package routes

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"github.com/deso-protocol/uint256"
	"net/http"
	"time"

	"github.com/deso-protocol/core/lib"
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
	//Transaction    *lib.MsgDeSoTxn

	// Unix timestamp (seconds since epoch).
	TimeAdded int64
}

// MessageEntryResponse ...
type MessageEntryResponse struct {
	// SenderPublicKeyBase58Check is the main public key of the sender in base58check.
	SenderPublicKeyBase58Check string

	// RecipientPublicKeyBase58Check is the main public key of the recipient in base58check.
	RecipientPublicKeyBase58Check string

	// EncryptedText is the encrypted message in hex format.
	EncryptedText string
	// TstampNanos is the message's timestamp.
	TstampNanos uint64

	// Whether or not the user is the sender of the message.
	IsSender bool

	// Indicate if message was encrypted using shared secret
	V2 bool // Deprecated

	// Indicate message version
	Version uint32

	// ---------------------------------------------------------
	// DeSo V3 Messages Fields
	// ---------------------------------------------------------

	// SenderMessagingPublicKey is the sender's messaging public key that was used
	// to encrypt the corresponding message.
	SenderMessagingPublicKey string

	// SenderMessagingGroupKeyName is the sender's group key name of SenderMessagingPublicKey
	SenderMessagingGroupKeyName string

	// RecipientMessagingPublicKey is the recipient's messaging public key that was
	// used to encrypt the corresponding message.
	RecipientMessagingPublicKey string

	// RecipientMessagingGroupKeyName is the recipient's group key name of RecipientMessagingPublicKey
	RecipientMessagingGroupKeyName string

	// ExtraData is an arbitrary key value map
	ExtraData map[string]string
}

// MessageContactResponse ...
type MessageContactResponse struct {
	// PublicKeyBase58Check is the public key in base58check format of the message contact.
	PublicKeyBase58Check string

	// Messages is the list of messages within this contact.
	Messages []*MessageEntryResponse

	// ProfileEntryResponse is the profile entry corresponding to the contact.
	ProfileEntryResponse *ProfileEntryResponse

	// The number of messages this user has read from this contact. This is
	// used to show a notification badge for unread messages.
	NumMessagesRead int64
}

// MessagingGroupEntryResponse ...
type MessagingGroupEntryResponse struct {
	// GroupOwnerPublicKeyBase58Check is the main public key of the group owner, or, equivalently, the public key that
	// registered the group.
	GroupOwnerPublicKeyBase58Check string

	// MessagingPublicKeyBase58Check is the group messaging public key in base58check.
	MessagingPublicKeyBase58Check string

	// MessagingGroupKeyName is the name of the group messaging key.
	MessagingGroupKeyName string

	// MessagingGroupMembers is the list of the members in the group chat.
	MessagingGroupMembers []*MessagingGroupMemberResponse

	// EncryptedKey is the hex string of the encrypted private corresponding with the MessagingPublicKeyBase58Check.
	EncryptedKey string

	// ExtraData is an arbitrary key value map
	ExtraData map[string]string
}

type MessagingGroupMemberResponse struct {
	// GroupMemberPublicKeyBase58Check is the main public key of the group member.
	GroupMemberPublicKeyBase58Check string

	// GroupMemberKeyName is the key name of the member that we encrypt the group messaging public key to. The group
	// messaging public key should not be confused with the GroupMemberPublicKeyBase58Check, the former is the public
	// key of the whole group, while the latter is the public key of the group member.
	GroupMemberKeyName string

	// EncryptedKey is the encrypted private key corresponding to the group messaging public key that's encrypted
	// to the member's registered messaging key labeled with GroupMemberKeyName.
	EncryptedKey string
}

// User ...
type User struct {
	// The public key for the user is computed from the seed using the exact
	// parameters used to generate the BTC deposit address below. Because
	// of this, the DeSo private and public key pair is also the key
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
	JumioVerified bool
	// JumioReturned = jumio webhook called
	JumioReturned bool

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

// Create a new type of BalanceEntryResponse so we don't break any existing
// code that relies on the old version.
type ExtendedBalanceEntryResponse struct {
	UnlockedBalanceEntry *BalanceEntryResponse

	LockedBalanceEntrys    []*LockedBalanceEntryResponse
	LockedBalanceBaseUnits *uint256.Int
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

	// For simplicity, we create a new field for the uint256 balance for DAO coins
	BalanceNanosUint256 *uint256.Int

	// The net effect of transactions in the mempool on a given BalanceEntry's BalanceNanos.
	// This is used by the frontend to convey info about mining.
	NetBalanceInMempool int64

	ProfileEntryResponse *ProfileEntryResponse `json:",omitempty"`

	// We add the DESO balance of the hodler for convenience
	HodlerDESOBalanceNanos uint64
}

// GetVerifiedUsernameToPKIDMapFromGlobalState
//
// Acts as a helper function for dealing with the verified usernames map.
// If the map does not already exist, this function will create one in global state.
// Returns nil it encounters an error. Returning nil is not dangerous, as
// _profileEntryToResponse() will ignore the map entirely in that case.
func (fes *APIServer) GetVerifiedUsernameToPKIDMapFromGlobalState() (_verificationMap map[string]*lib.PKID, _err error) {
	// Pull the verified map from global state.
	verifiedMapBytes, err := fes.GlobalState.Get(_GlobalStatePrefixForVerifiedMap)
	if err != nil {
		return nil, fmt.Errorf("GetVerifiedUsernameToPKIDMapFromGlobalState: Cannot Decode Verification Map: %v", err)
	}
	verifiedMapStruct := VerifiedUsernameToPKID{}

	// Check if a map exists right now
	if len(verifiedMapBytes) > 0 {
		err = gob.NewDecoder(bytes.NewReader(verifiedMapBytes)).Decode(&verifiedMapStruct)
		if err != nil {
			return nil, fmt.Errorf("GetVerifiedUsernameToPKIDMapFromGlobalState: Cannot Decode Verification Map: %v", err)
		}
	} else {
		// Create the inital map structure
		verifiedMapStruct.VerifiedUsernameToPKID = make(map[string]*lib.PKID)

		// Encode the map and stick it in the database.
		// TODO: Disabled code below because it was causing a blank verifiedusername map. We should investigate why.
		// metadataDataBuf := bytes.NewBuffer([]byte{})
		// if err = gob.NewEncoder(metadataDataBuf).Encode(verifiedMapStruct); err != nil {
		// 	return nil, fmt.Errorf("GetVerifiedUsernameToPKIDMapFromGlobalState: cannot encode verifiedMap struct: %v", err)
		// }
		// err = fes.GlobalState.Put(_GlobalStatePrefixForVerifiedMap, metadataDataBuf.Bytes())
		// if err != nil {
		// 	return nil, fmt.Errorf("GetVerifiedUsernameToPKIDMapFromGlobalState: Cannot Decode Verification Map: %v", err)
		// }
	}
	// Return the verificationMap
	return verifiedMapStruct.VerifiedUsernameToPKID, nil
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
	userMetadataBytes, err := fes.GlobalState.Get(dbKey)
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf(
			"getUserMetadataFromGlobalStateByPublicKeyBytes: Problem with Get: %v", err), "")
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
	err := fes.GlobalState.Put(dbKey, metadataDataBuf.Bytes())
	if err != nil {
		return errors.Wrap(fmt.Errorf(
			"AdminUpdateUserGlobalMetadata: Problem putting updated user metadata: %v", err), "")
	}

	return nil
}

func (fes *APIServer) SendSeedDeSo(recipientPkBytes []byte, amountNanos uint64, useBuyDeSoSeed bool) (txnHash *lib.BlockHash, _err error) {
	fes.mtxSeedDeSo.Lock()
	defer fes.mtxSeedDeSo.Unlock()

	senderSeed := fes.Config.StarterDESOSeed
	if useBuyDeSoSeed {
		senderSeed = fes.Config.BuyDESOSeed
	}
	starterSeedBytes, err := bip39.NewSeedWithErrorChecking(senderSeed, "")
	if err != nil {
		glog.Errorf("SendSeedDeSo: error converting mnemonic: %v", err)
		return nil, fmt.Errorf("SendSeedDeSo: Error converting mnemonic: %+v", err)
	}

	starterPubKey, starterPrivKey, _, err := lib.ComputeKeysFromSeed(starterSeedBytes, 0, fes.Params)
	if err != nil {
		glog.Errorf("SendSeedDeSo: Error computing keys from seed: %v", err)
		return nil, fmt.Errorf("SendSeedDeSo: Error computing keys from seed: %+v", err)
	}

	sendDeSo := func() (txnHash *lib.BlockHash, _err error) {
		// Create the transaction outputs and add the recipient's public key and the
		// amount we want to pay them
		txnOutputs := []*lib.DeSoOutput{}
		txnOutputs = append(txnOutputs, &lib.DeSoOutput{
			PublicKey: recipientPkBytes,
			// If we get here we know the amount is non-negative.
			AmountNanos: amountNanos,
		})

		// Assemble the transaction so that inputs can be found and fees can
		// be computed.
		txn := &lib.MsgDeSoTxn{
			// The inputs will be set below.
			TxInputs:  []*lib.DeSoInput{},
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
		if utxoView.GetCurrentGlobalParamsEntry() != nil &&
			utxoView.GetCurrentGlobalParamsEntry().MinimumNetworkFeeNanosPerKB > 0 {
			minFee = utxoView.GetCurrentGlobalParamsEntry().MinimumNetworkFeeNanosPerKB
		}
		_, _, _, _, err = fes.blockchain.AddInputsAndChangeToTransaction(txn, minFee, fes.backendServer.GetMempool())
		if err != nil {
			return nil, fmt.Errorf("SendSeedDeSo: Error adding inputs for seed DeSo: %v", err)
		}

		txnSignature, err := txn.Sign(starterPrivKey)
		if err != nil {
			return nil, fmt.Errorf("SendSeedDeSo: Error adding inputs for seed DeSo: %v", err)
		}
		txn.Signature.SetSignature(txnSignature)

		err = fes.backendServer.VerifyAndBroadcastTransaction(txn)
		if err != nil {
			return nil, fmt.Errorf("SendSeedDeSo: Problem processing starter seed transaction: %v", err)
		}

		return txn.Hash(), nil
	}

	// Here we retry sending DeSo once if there is an error.  This is concerning, but we believe it is safe at this
	// time as no DESO will be sent if there is an error.  We wait for 5 seconds
	var hash *lib.BlockHash
	hash, err = sendDeSo()
	if err != nil {
		publicKeyBase58Check := lib.PkToString(recipientPkBytes, fes.Params)
		glog.Errorf("SendSeedDeSo: 1st attempt - error sending %d nanos of DESO to public key %v: error - %v", amountNanos, publicKeyBase58Check, err)
		time.Sleep(5 * time.Second)
		hash, err = sendDeSo()
		if err != nil {
			glog.Errorf("SendSeedDeSo: 2nd attempt - error sending %d nanos of DESO to public key %v: error - %v", amountNanos, publicKeyBase58Check, err)
		}
	}
	return hash, err
}

func (fes *APIServer) AddNodeSourceToTxnMetadata(txn *lib.MsgDeSoTxn) {
	if fes.Config.NodeSource != 0 {
		if len(txn.ExtraData) == 0 {
			txnExtraData := make(map[string][]byte)
			txnExtraData[lib.NodeSourceMapKey] = lib.UintToBuf(fes.Config.NodeSource)
			txn.ExtraData = txnExtraData
		} else {
			txn.ExtraData[lib.NodeSourceMapKey] = lib.UintToBuf(fes.Config.NodeSource)
		}
	}
}
