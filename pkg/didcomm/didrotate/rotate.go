/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didrotate

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	didcomm "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/jwkkid"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// DIDRotator performs didcomm/v2 DID rotation.
type DIDRotator struct {
	kms       kms.KeyManager
	crypto    crypto.Crypto
	vdr       vdrapi.Registry
	connStore *connection.Recorder
}

type provider interface {
	Crypto() crypto.Crypto
	KMS() kms.KeyManager
	VDRegistry() vdrapi.Registry
	StorageProvider() storage.Provider
	ProtocolStateStorageProvider() storage.Provider
}

// New creates a DIDRotator.
func New(p provider) (*DIDRotator, error) {
	connRecorder, err := connection.NewRecorder(p)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize connection recorder: %w", err)
	}

	return &DIDRotator{
		kms:       p.KMS(),
		crypto:    p.Crypto(),
		vdr:       p.VDRegistry(),
		connStore: connRecorder,
	}, nil
}

type rotatePayload struct {
	Sub string `json:"sub"`
	ISS string `json:"iss"`
	IAT int64  `json:"iat"`
}

const (
	fromPriorJSONKey = "from_prior"
)

// HandleInboundMessage checks an inbound message for the `from_prior` field, performing DID rotation if it's present.
func (dr *DIDRotator) HandleInboundMessage(msg didcomm.DIDCommMsgMap, senderDID, recipientDID string) error { // nolint:funlen,gocognit,gocyclo,lll
	if isV2, err := didcomm.IsDIDCommV2(&msg); !isV2 || err != nil {
		return err
	}

	var (
		jws            *jose.JSONWebSignature
		payload        *rotatePayload
		err            error
		theirNewDID    string
		theirOldDID    string
		alreadyRotated bool
		updatedConnRec bool
	)

	fromPriorInterface, theyRotate := msg[fromPriorJSONKey]

	if theyRotate {
		fromPrior, ok := fromPriorInterface.(string)
		if !ok {
			return fmt.Errorf("didcomm message 'from_prior' field should be a string")
		}

		jws, payload, err = dr.getUnverifiedJWS(senderDID, fromPrior)
		if err != nil {
			return err
		}

		theirOldDID = payload.ISS
		theirNewDID = payload.Sub
	} else {
		theirOldDID = senderDID
	}

	rec, err := dr.connStore.GetConnectionRecordByTheirDID(theirOldDID)
	if err != nil && theirNewDID != "" {
		_, err = dr.connStore.GetConnectionRecordByTheirDID(theirNewDID)
		if err == nil {
			// if we have a connection under their new DID, then we've already rotated.
			alreadyRotated = true
		}
	}

	if errors.Is(err, storage.ErrDataNotFound) {
		// if the connection isn't found, we assume that this inbound message is the start of the communication,
		// in which case there can be no rotation
		if theyRotate {
			return fmt.Errorf("inbound message cannot rotate without an existing prior connection")
		}
	} else if err != nil {
		return fmt.Errorf("looking up did rotation connection record: %w", err)
	}

	if theyRotate && !alreadyRotated {
		err = dr.verifyJWSAndPayload(jws, payload)
		if err != nil {
			return fmt.Errorf("'from_prior' validation: %w", err)
		}

		// update our connection to use their new DID
		rec.TheirDID = payload.Sub
		updatedConnRec = true
	}

	// if we performed a did rotation, check if they acknowledge it
	if rec != nil && rec.MyDIDRotation != nil {
		// check if they sent to our old DID or our new DID
		switch recipientDID {
		case rec.MyDIDRotation.OldDID:
			// they used our old DID
		case rec.MyDIDRotation.NewDID:
			// they used our new DID, so we don't need to rotate anymore
			rec.MyDIDRotation = nil
			updatedConnRec = true
		default:
			return fmt.Errorf("inbound message sent to unexpected DID")
		}
	}

	if updatedConnRec {
		err = dr.connStore.SaveConnectionRecord(rec)
		if err != nil {
			return fmt.Errorf("updating connection with DID rotation: %w", err)
		}
	}

	return nil
}

// HandleOutboundMessage processes an outbound message.
func (dr *DIDRotator) HandleOutboundMessage(msg didcomm.DIDCommMsgMap, rec *connection.Record,
) (didcomm.DIDCommMsgMap, error) {
	if isV2, err := didcomm.IsDIDCommV2(&msg); !isV2 || err != nil {
		return msg, err
	}

	if rec.MyDIDRotation != nil {
		msg[fromPriorJSONKey] = rec.MyDIDRotation.FromPrior
	}

	return msg, nil
}

// RotateConnectionDID rotates the agent's DID on the connection under connectionID.
func (dr *DIDRotator) RotateConnectionDID(connectionID, signingKID, newDID string) error {
	record, err := dr.connStore.GetConnectionRecord(connectionID)
	if err != nil {
		return fmt.Errorf("getting connection record: %w", err)
	}

	// TODO: known issue: if you perform multiple DID rotations without sending a message to the other party,
	//  they won't be able to validate the rotation.

	oldDocRes, err := dr.vdr.Resolve(record.MyDID)
	if err != nil {
		return fmt.Errorf("resolving my DID: %w", err)
	}

	fromPrior, err := dr.Create(oldDocRes.DIDDocument, signingKID, newDID)
	if err != nil {
		return fmt.Errorf("creating did rotation from_prior: %w", err)
	}

	record.MyDIDRotation = &connection.DIDRotationRecord{
		NewDID:    newDID,
		OldDID:    oldDocRes.DIDDocument.ID,
		FromPrior: fromPrior,
	}

	record.MyDID = newDID

	err = dr.connStore.SaveConnectionRecord(record)
	if err != nil {
		return fmt.Errorf("saving connection record: %w", err)
	}

	return nil
}

// Create creates a didcomm/v2 DID rotation `from_prior`, as a compact-serialized JWS.
func (dr *DIDRotator) Create(oldDoc *did.Doc, oldKID, newDID string) (string, error) {
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

	kh, err := dr.kms.Get(kmsKID)
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

	jws, err := jose.NewJWS(protected, nil, payloadBytes, &cryptoSigner{kh: kh, crypto: dr.crypto})
	if err != nil {
		return "", fmt.Errorf("creating DID rotation JWS: %w", err)
	}

	return jws.SerializeCompact(false)
}

func (dr *DIDRotator) getUnverifiedJWS(senderDID, fromPrior string) (*jose.JSONWebSignature, *rotatePayload, error) {
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
func (dr *DIDRotator) Verify(senderDID, fromPrior string) (string, error) {
	jws, payload, err := dr.getUnverifiedJWS(senderDID, fromPrior)
	if err != nil {
		return "", err
	}

	err = dr.verifyJWSAndPayload(jws, payload)
	if err != nil {
		return "", err
	}

	return payload.ISS, nil
}

func (dr *DIDRotator) verifyJWSAndPayload(jws *jose.JSONWebSignature, payload *rotatePayload) error {
	oldKID, ok := jws.ProtectedHeaders.KeyID()
	if !ok {
		return fmt.Errorf("from_prior protected headers missing KID")
	}

	oldDocRes, err := dr.vdr.Resolve(payload.ISS)
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

	pubKH, err := dr.kms.PubKeyBytesToHandle(keyBytes, kty)
	if err != nil {
		return fmt.Errorf("get verification key handle: %w", err)
	}

	verify := jose.DefaultSigningInputVerifier(
		func(joseHeaders jose.Headers, payload, signingInput, signature []byte) error {
			return dr.crypto.Verify(signature, signingInput, pubKH)
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
