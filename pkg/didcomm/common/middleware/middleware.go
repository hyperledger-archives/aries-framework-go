/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package middleware

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	didcomm "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofbandv2"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/jwkkid"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/peer"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

var logger = log.New("didcomm/common/middleware")

// DIDCommMessageMiddleware performs inbound/outbound message handling tasks that apply to all DIDComm V2 messages.
//  - Rotates DIDs on outbound messages, and handles inbound messages that rotate DIDs.
type DIDCommMessageMiddleware struct {
	kms               kms.KeyManager
	crypto            crypto.Crypto
	vdr               vdrapi.Registry
	connStore         *connection.Recorder
	mediaTypeProfiles []string
}

type provider interface {
	Crypto() crypto.Crypto
	KMS() kms.KeyManager
	VDRegistry() vdrapi.Registry
	StorageProvider() storage.Provider
	ProtocolStateStorageProvider() storage.Provider
	MediaTypeProfiles() []string
}

// New creates a DIDCommMessageMiddleware.
func New(p provider) (*DIDCommMessageMiddleware, error) {
	connRecorder, err := connection.NewRecorder(p)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize connection recorder: %w", err)
	}

	return &DIDCommMessageMiddleware{
		kms:               p.KMS(),
		crypto:            p.Crypto(),
		vdr:               p.VDRegistry(),
		connStore:         connRecorder,
		mediaTypeProfiles: p.MediaTypeProfiles(),
	}, nil
}

type rotatePayload struct {
	Sub string `json:"sub"`
	ISS string `json:"iss"`
	IAT int64  `json:"iat"`
}

const (
	fromPriorJSONKey  = "from_prior"
	fromDIDJSONKey    = "from"
	initialStateParam = "initialState"
)

// HandleInboundMessage processes did rotation, peer DID sharing, and invitee connection creation on inbound messages.
func (h *DIDCommMessageMiddleware) HandleInboundMessage( // nolint:gocyclo,funlen
	msg didcomm.DIDCommMsgMap,
	theirDID, myDID string,
) error {
	if isV2, err := didcomm.IsDIDCommV2(&msg); !isV2 || err != nil {
		return err
	}

	// TODO: clean up connection record management across all the handler methods. Currently correct but messy.

	// TODO: clean up some logic:
	//  - inbound invitation acceptance cannot be a rotation

	// handle inbound peer DID initial state
	err := h.handleInboundPeerDID(msg) // no connection read/write
	if err != nil {
		return fmt.Errorf("handling inbound peer DID: %w", err)
	}

	// GetConnectionRecordByDIDs(myDID, theirDID)
	// if no connection, create connection
	rec, err := h.handleInboundInvitationAcceptance(theirDID, myDID)
	if err != nil {
		return err
	}

	var updatedConnRec bool

	// if they don't rotate: GetConnectionRecordByTheirDID(theirDID)
	// if they do rotate: GetConnectionRecordByTheirDID(theirOldDID), GetConnectionRecordByTheirDID(theirNewDID)
	rec2, stepUpdated, err := h.handleInboundRotate(msg, theirDID, myDID, rec)
	if err != nil {
		return err
	}

	updatedConnRec = updatedConnRec || stepUpdated

	if rec2 != nil {
		rec = rec2
	}

	if rec == nil {
		rec, err = h.connStore.GetConnectionRecordByTheirDID(theirDID)
		if err != nil {
			return err
		}
	}

	rec2, stepUpdated, err = h.handleInboundRotateAck(myDID, rec)
	if err != nil {
		return err
	}

	updatedConnRec = updatedConnRec || stepUpdated

	if rec2 != nil {
		rec = rec2
	}

	// handle inbound ack of peer DID
	if rec != nil && rec.PeerDIDInitialState != "" && myDID == rec.MyDID {
		rec.PeerDIDInitialState = ""
		updatedConnRec = true
	}

	if updatedConnRec && rec != nil {
		err = h.connStore.SaveConnectionRecord(rec)
		if err != nil {
			return fmt.Errorf("updating connection: %w", err)
		}
	}

	return nil
}

// HandleOutboundMessage processes an outbound message.
func (h *DIDCommMessageMiddleware) HandleOutboundMessage(msg didcomm.DIDCommMsgMap, rec *connection.Record,
) didcomm.DIDCommMsgMap {
	if isV2, err := didcomm.IsDIDCommV2(&msg); !isV2 || err != nil {
		return msg
	}

	if rec.MyDIDRotation != nil {
		msg[fromPriorJSONKey] = rec.MyDIDRotation.FromPrior
	}

	if rec.PeerDIDInitialState != "" {
		msg[fromDIDJSONKey] = rec.MyDID + "?" + initialStateParam + "=" + rec.PeerDIDInitialState
	}

	return msg
}

func (h *DIDCommMessageMiddleware) handleInboundInvitationAcceptance(senderDID, recipientDID string,
) (*connection.Record, error) {
	didParsed, err := did.Parse(recipientDID)
	if err != nil {
		return nil, fmt.Errorf("parsing inbound recipient DID: %w", err)
	}

	if didParsed.Method == peer.DIDMethod { // TODO any more exception cases like peer?
		// can't be an invitation DID
		return nil, nil
	}

	inv := &outofbandv2.Invitation{}

	err = h.connStore.GetOOBv2Invitation(recipientDID, inv)
	if errors.Is(err, storage.ErrDataNotFound) {
		// if there's no invitation, this message isn't an acceptance
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	rec, err := h.connStore.GetConnectionRecordByDIDs(recipientDID, senderDID)
	if !errors.Is(err, storage.ErrDataNotFound) {
		// either an error, or a record exists
		logger.Warnf("record present, or error=%v", err)
		return rec, err
	}

	// if we created an invitation with this DID, and have no connection, we create a connection.

	rec = &connection.Record{
		ConnectionID:      uuid.New().String(),
		MyDID:             recipientDID,
		TheirDID:          senderDID,
		State:             connection.StateNameCompleted,
		Namespace:         connection.MyNSPrefix,
		MediaTypeProfiles: h.mediaTypeProfiles,
		DIDCommVersion:    didcomm.V2,
	}

	err = h.connStore.SaveConnectionRecord(rec)
	if err != nil {
		return nil, fmt.Errorf("failed to save new connection: %w", err)
	}

	return rec, nil
}

func (h *DIDCommMessageMiddleware) handleInboundPeerDID(msg didcomm.DIDCommMsgMap) error {
	from, ok := msg[fromDIDJSONKey].(string)
	if !ok {
		return nil
	}

	didURL, err := did.ParseDIDURL(from)
	if err != nil {
		return fmt.Errorf("parsing their DID: %w", err)
	}

	if didURL.Method != peer.DIDMethod {
		return nil
	}

	initialState, ok := didURL.Queries[initialStateParam]
	if !ok {
		return nil
	}

	if len(initialState) == 0 {
		return fmt.Errorf("expected initialState to have value")
	}

	theirDoc, err := peer.DocFromGenesisDelta(initialState[0])
	if err != nil {
		return fmt.Errorf("parsing DID doc from peer DID initialState: %w", err)
	}

	_, err = h.vdr.Create(peer.DIDMethod, theirDoc, vdrapi.WithOption("store", true))
	if err != nil {
		return fmt.Errorf("saving their peer DID: %w", err)
	}

	msg[fromDIDJSONKey] = didURL.DID.String()

	return nil
}

func (h *DIDCommMessageMiddleware) handleInboundRotate( // nolint:funlen,gocyclo
	msg didcomm.DIDCommMsgMap,
	senderDID, recipientDID string,
	recIn *connection.Record,
) (*connection.Record, bool, error) {
	var (
		jws            *jose.JSONWebSignature
		payload        *rotatePayload
		err            error
		alreadyRotated bool
		updatedConnRec bool
	)

	fromPriorInterface, theyRotate := msg[fromPriorJSONKey]
	if !theyRotate {
		return recIn, false, nil
	}

	fromPrior, ok := fromPriorInterface.(string)
	if !ok {
		return nil, false, fmt.Errorf("didcomm message 'from_prior' field should be a string")
	}

	jws, payload, err = h.getUnverifiedJWS(senderDID, fromPrior)
	if err != nil {
		return nil, false, err
	}

	theirOldDID := payload.ISS
	theirNewDID := payload.Sub

	// Note: if we rotated our DID, we need to accept messages to either our old DID or our new DID.
	// When we rotate a connection, we store the connection's record twice - once under our old DID and their DID,
	//  and once under our new DID and their DID.
	// On top of that, when we receive a message containing a DID rotation, we might need to check for a record under
	//  their old DID and their new DID

	// TODO: maybe useful if connection.Lookup would be able to look up a connection record given
	//  two candidate DIDs for myDID and two candidate DIDs for theirDID?

	rec, err := h.connStore.GetConnectionRecordByDIDs(recipientDID, theirOldDID)
	if err != nil {
		_, err = h.connStore.GetConnectionRecordByDIDs(recipientDID, theirNewDID)
		if err == nil {
			// if we have a connection under their new DID, then we've already rotated.
			alreadyRotated = true
		}
	}

	if errors.Is(err, storage.ErrDataNotFound) {
		// if the connection isn't found, we assume that this inbound message is the start of the communication,
		// in which case there can be no rotation
		return nil, false, fmt.Errorf("inbound message cannot rotate without an existing prior connection")
	} else if err != nil {
		return nil, false, fmt.Errorf("looking up did rotation connection record: %w", err)
	}

	if !alreadyRotated {
		err = h.verifyJWSAndPayload(jws, payload)
		if err != nil {
			return nil, false, fmt.Errorf("'from_prior' validation: %w", err)
		}

		// update our connection to use their new DID
		rec.TheirDID = payload.Sub
		updatedConnRec = true
	}

	if rec != nil {
		recIn = rec
	}

	return recIn, updatedConnRec, nil
}

func (h *DIDCommMessageMiddleware) handleInboundRotateAck(recipientDID string, rec *connection.Record,
) (*connection.Record, bool, error) {
	var updatedConnRec bool

	// if we performed a did rotation, check if they acknowledge it
	if rec.MyDIDRotation != nil {
		// check if they sent to our old DID or our new DID
		switch recipientDID {
		case rec.MyDIDRotation.OldDID:
			// they used our old DID
		case rec.MyDIDRotation.NewDID:
			// they used our new DID, so we don't need to rotate anymore
			rec.MyDIDRotation = nil
			updatedConnRec = true
		default:
			return nil, false, fmt.Errorf("inbound message sent to unexpected DID")
		}
	}

	return rec, updatedConnRec, nil
}

// RotateConnectionDID rotates the agent's DID on the connection under connectionID.
func (h *DIDCommMessageMiddleware) RotateConnectionDID(connectionID, signingKID, newDID string) error { // nolint:funlen
	record, err := h.connStore.GetConnectionRecord(connectionID)
	if err != nil {
		return fmt.Errorf("getting connection record: %w", err)
	}

	// TODO: known issue: if you perform multiple DID rotations without sending a message to the other party,
	//  they won't be able to validate the rotation.

	oldDID := record.MyDID

	oldDocRes, err := h.vdr.Resolve(oldDID)
	if err != nil {
		return fmt.Errorf("resolving my DID: %w", err)
	}

	fromPrior, err := h.Create(oldDocRes.DIDDocument, signingKID, newDID)
	if err != nil {
		return fmt.Errorf("creating did rotation from_prior: %w", err)
	}

	record.MyDIDRotation = &connection.DIDRotationRecord{
		NewDID:    newDID,
		OldDID:    oldDID,
		FromPrior: fromPrior,
	}

	// if newDID is a peer DID, we need to provide initialState to the recipient.
	didParsed, err := did.Parse(newDID)
	if err != nil {
		return fmt.Errorf("parsing new DID: %w", err)
	}

	if didParsed.Method == peer.DIDMethod {
		newDoc, e := h.vdr.Resolve(newDID)
		if e != nil {
			return fmt.Errorf("resolving new DID: %w", e)
		}

		initialState, e := peer.UnsignedGenesisDelta(newDoc.DIDDocument)
		if e != nil {
			return fmt.Errorf("generating peer DID initialState for new DID: %w", e)
		}

		record.PeerDIDInitialState = initialState
	}

	record.MyDID = newDID

	err = h.connStore.SaveConnectionRecord(record)
	if err != nil {
		return fmt.Errorf("saving connection record under my new DID: %w", err)
	}

	// save a backup record under our old DID
	record.MyDID = oldDID
	record.ConnectionID = uuid.New().String()

	err = h.connStore.SaveConnectionRecord(record)
	if err != nil {
		return fmt.Errorf("saving connection record under my old DID: %w", err)
	}

	return nil
}

// Create creates a didcomm/v2 DID rotation `from_prior`, as a compact-serialized JWS.
func (h *DIDCommMessageMiddleware) Create(oldDoc *did.Doc, oldKID, newDID string) (string, error) {
	payload := rotatePayload{
		Sub: newDID,
		ISS: oldDoc.ID,
		IAT: time.Now().Unix(),
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshalling did rotate payload: %w", err)
	}

	vm, found := did.LookupPublicKey(oldKID, oldDoc)
	if !found {
		return "", fmt.Errorf("sender KID not found in doc provided")
	}

	keyBytes, kty, crv, err := vmToBytesTypeCrv(vm)
	if err != nil {
		return "", err
	}

	kmsKID, err := jwkkid.CreateKID(keyBytes, kty)
	if err != nil {
		return "", fmt.Errorf("get signing key KMS KID: %w", err)
	}

	kh, err := h.kms.Get(kmsKID)
	if err != nil {
		return "", fmt.Errorf("get signing key handle: %w", err)
	}

	var alg string

	if vm.Type == ed25519VerificationKey2018 {
		alg = "EdDSA"
	} else if vm.Type == jsonWebKey2020 {
		jwkKey := vm.JSONWebKey()
		alg = jwkKey.Algorithm
	}

	protected := jose.Headers(map[string]interface{}{
		"typ": "JWT",
		"alg": alg,
		"crv": crv,
		"kid": oldKID,
	})

	jws, err := jose.NewJWS(protected, nil, payloadBytes, &cryptoSigner{kh: kh, crypto: h.crypto})
	if err != nil {
		return "", fmt.Errorf("creating DID rotation JWS: %w", err)
	}

	return jws.SerializeCompact(false)
}

func (h *DIDCommMessageMiddleware) getUnverifiedJWS(senderDID, fromPrior string,
) (*jose.JSONWebSignature, *rotatePayload, error) {
	skipVerify := jose.SignatureVerifierFunc(func(_ jose.Headers, _, _, _ []byte) error {
		return nil
	})

	jws, err := jose.ParseJWS(fromPrior, skipVerify)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing DID rotation JWS: %w", err)
	}

	payload := rotatePayload{}

	err = json.Unmarshal(jws.Payload, &payload)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing DID rotation payload: %w", err)
	}

	if payload.ISS == "" || payload.Sub == "" {
		return nil, nil, fmt.Errorf("from_prior payload missing iss or sub, both are required")
	}

	if senderDID != payload.Sub {
		return nil, nil, fmt.Errorf("from_prior payload sub must be the DID of the message sender")
	}

	return jws, &payload, nil
}

// Verify verifies a didcomm/v2 DID rotation.
//  - senderDID: the DID of the sender of the message containing this DID Rotation, known from the envelope
//    or from the message's `to` field.
//  - fromPrior: the `from_prior` field of the rotated message.
// Returns the sender's old DID (superseded by the new DID), if verification succeeds, or an error otherwise.
func (h *DIDCommMessageMiddleware) Verify(senderDID, fromPrior string) (string, error) {
	jws, payload, err := h.getUnverifiedJWS(senderDID, fromPrior)
	if err != nil {
		return "", err
	}

	err = h.verifyJWSAndPayload(jws, payload)
	if err != nil {
		return "", err
	}

	return payload.ISS, nil
}

func (h *DIDCommMessageMiddleware) verifyJWSAndPayload(jws *jose.JSONWebSignature, payload *rotatePayload) error {
	oldKID, ok := jws.ProtectedHeaders.KeyID()
	if !ok {
		return fmt.Errorf("from_prior protected headers missing KID")
	}

	oldDocRes, err := h.vdr.Resolve(payload.ISS)
	if err != nil {
		return fmt.Errorf("resolving prior DID doc: %w", err)
	}

	vm, found := did.LookupPublicKey(oldKID, oldDocRes.DIDDocument)
	if !found {
		return fmt.Errorf("kid not found in doc")
	}

	keyBytes, kty, _, err := vmToBytesTypeCrv(vm)
	if err != nil {
		return err
	}

	pubKH, err := h.kms.PubKeyBytesToHandle(keyBytes, kty)
	if err != nil {
		return fmt.Errorf("get verification key handle: %w", err)
	}

	verify := jose.DefaultSigningInputVerifier(
		func(joseHeaders jose.Headers, payload, signingInput, signature []byte) error {
			return h.crypto.Verify(signature, signingInput, pubKH)
		})

	err = verify.Verify(jws.ProtectedHeaders, jws.Payload, nil, jws.Signature())
	if err != nil {
		return fmt.Errorf("signature verification: %w", err)
	}

	return nil
}

type cryptoSigner struct {
	kh     interface{}
	crypto crypto.Crypto
}

// Sign signs the input using the stored key handle.
func (c *cryptoSigner) Sign(data []byte) ([]byte, error) {
	return c.crypto.Sign(data, c.kh)
}

// Headers returns nil, cryptoSigner doesn't add its own headers.
func (c *cryptoSigner) Headers() jose.Headers {
	return nil
}

const (
	jsonWebKey2020             = "JsonWebKey2020"
	jwsVerificationKey2020     = "JwsVerificationKey2020"
	ed25519VerificationKey2018 = "Ed25519VerificationKey2018"
)

func vmToBytesTypeCrv(vm *did.VerificationMethod) ([]byte, kms.KeyType, string, error) {
	switch vm.Type {
	case ed25519VerificationKey2018:
		return vm.Value, kms.ED25519Type, "Ed25519", nil
	case jsonWebKey2020, jwsVerificationKey2020:
		k := vm.JSONWebKey()

		kb, err := k.PublicKeyBytes()
		if err != nil {
			return nil, "", "", fmt.Errorf("getting []byte key for verification key: %w", err)
		}

		kt, err := k.KeyType()
		if err != nil {
			return nil, "", "", fmt.Errorf("getting kms.KeyType of verification key: %w", err)
		}

		return kb, kt, k.Crv, nil
	default:
		return nil, "", "", fmt.Errorf("vm.Type '%s' not supported", vm.Type)
	}
}
