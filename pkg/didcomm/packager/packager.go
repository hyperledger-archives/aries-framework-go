/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package packager

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer/authcrypt"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/jwkkid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/kmsdidkey"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

const (
	authSuffix                = "-authcrypt"
	jsonWebKey2020            = "JsonWebKey2020"
	x25519KeyAgreementKey2019 = "X25519KeyAgreementKey2019"
)

var logger = log.New("aries-framework/pkg/didcomm/packager")

// Provider contains dependencies for the base packager and is typically created by using aries.Context().
type Provider interface {
	Packers() []packer.Packer
	PrimaryPacker() packer.Packer
	VDRegistry() vdr.Registry
}

// Creator method to create new packager service.
type Creator func(prov Provider) (transport.Packager, error)

// Packager is the basic implementation of Packager.
type Packager struct {
	primaryPacker packer.Packer
	packers       map[string]packer.Packer
	vdrRegistry   vdr.Registry
}

// PackerCreator holds a creator function for a Packer and the name of the Packer's encoding method.
type PackerCreator struct {
	PackerName string
	Creator    packer.Creator
}

// New return new instance of Packager implementation of transport.Packager.
func New(ctx Provider) (*Packager, error) {
	basePackager := Packager{
		primaryPacker: nil,
		packers:       map[string]packer.Packer{},
		vdrRegistry:   ctx.VDRegistry(),
	}

	for _, packerType := range ctx.Packers() {
		basePackager.addPacker(packerType)
	}

	basePackager.primaryPacker = ctx.PrimaryPacker()
	if basePackager.primaryPacker == nil {
		return nil, fmt.Errorf("need primary packer to initialize packager")
	}

	basePackager.addPacker(basePackager.primaryPacker)

	return &basePackager, nil
}

func (bp *Packager) addPacker(pack packer.Packer) {
	packerID := pack.EncodingType()

	_, ok := pack.(*authcrypt.Packer)
	if ok {
		// anoncrypt and authcrypt have the same encoding type
		// so authcrypt will have an appended suffix
		packerID += authSuffix
	}

	if bp.packers[packerID] == nil {
		bp.packers[packerID] = pack
	}
}

// PackMessage Pack a message for one or more recipients.
func (bp *Packager) PackMessage(messageEnvelope *transport.Envelope) ([]byte, error) {
	if messageEnvelope == nil {
		return nil, errors.New("packMessage: envelope argument is nil")
	}

	cty, p, err := bp.getCTYAndPacker(messageEnvelope)
	if err != nil {
		return nil, fmt.Errorf("packMessage: %w", err)
	}

	senderKey, recipients, err := bp.prepareSenderAndRecipientKeys(cty, messageEnvelope)
	if err != nil {
		return nil, fmt.Errorf("packMessage: %w", err)
	}

	marshalledEnvelope, err := p.Pack(cty, messageEnvelope.Message, senderKey, recipients)
	if err != nil {
		return nil, fmt.Errorf("packMessage: failed to pack: %w", err)
	}

	return marshalledEnvelope, nil
}

//nolint:funlen,gocyclo
func (bp *Packager) prepareSenderAndRecipientKeys(cty string, envelope *transport.Envelope) ([]byte, [][]byte, error) {
	var recipients [][]byte

	isLegacy := isMediaTypeForLegacyPacker(cty)

	for i, receiverKey := range envelope.ToKeys {
		switch {
		case strings.HasPrefix(receiverKey, "did:key"):
			marshalledKey, err := addDIDKeyToRecipients(i, receiverKey, isLegacy)
			if err != nil {
				return nil, nil, err
			}

			recipients = append(recipients, marshalledKey)
		case strings.Index(receiverKey, "#") > 0:
			marshalledKey, err := bp.resolveKeyAgreementFromDIDDoc(receiverKey)
			if err != nil {
				return nil, nil, fmt.Errorf("prepareSenderAndRecipientKeys: for recipient %d: %w", i+1, err)
			}

			recipients = append(recipients, marshalledKey)
		default:
			recipients = append(recipients, []byte(receiverKey))
		}
	}

	var senderKID []byte

	switch {
	case strings.HasPrefix(string(envelope.FromKey), "did:key"):
		senderKey, err := kmsdidkey.EncryptionPubKeyFromDIDKey(string(envelope.FromKey))
		if err != nil {
			return nil, nil, fmt.Errorf("prepareSenderAndRecipientKeys: failed to extract pubKeyBytes from "+
				"senderVerKey: %w", err)
		}

		if isLegacy {
			senderKID = senderKey.X // for legacy, use the sender raw key (Ed25519 key)
		} else {
			senderKID = buildSenderKID(senderKey, envelope)
		}
	//nolint:gocritic // need to check with strings not bytes
	case strings.Index(string(envelope.FromKey), "#") > 0:
		marshalledSenderKey, err := bp.resolveKeyAgreementFromDIDDoc(string(envelope.FromKey))
		if err != nil {
			return nil, nil, fmt.Errorf("prepareSenderAndRecipientKeys: for sender: %w", err)
		}

		senderKey := &crypto.PublicKey{}

		err = json.Unmarshal(marshalledSenderKey, senderKey)
		if err != nil {
			return nil, nil, fmt.Errorf("prepareSenderAndRecipientKeys: for sender: %w", err)
		}

		senderKMSKID, err := jwkkid.CreateKID(marshalledSenderKey, getKMSKeyType(senderKey.Type, senderKey.Curve))
		if err != nil {
			return nil, nil, fmt.Errorf("prepareSenderAndRecipientKeys: for sender KMS KID: %w", err)
		}

		senderKey.KID = senderKMSKID

		senderKID = buildSenderKID(senderKey, envelope)
	default:
		senderKID = envelope.FromKey
	}

	return senderKID, recipients, nil
}

func addDIDKeyToRecipients(i int, receiverKey string, isLegacy bool) ([]byte, error) {
	recKey, err := kmsdidkey.EncryptionPubKeyFromDIDKey(receiverKey)
	if err != nil {
		return nil, fmt.Errorf("prepareSenderAndRecipientKeys: failed to parse public key bytes from "+
			"did:key verKey for recipient %d: %w", i+1, err)
	}

	if isLegacy {
		return recKey.X, nil
	}

	var marshalledKey []byte

	// for packing purposes, recipient kid header is the did:key value, the packers must parse it and extract
	// the kms kid value during unpack.
	recKey.KID = receiverKey

	marshalledKey, err = json.Marshal(recKey)
	if err != nil {
		return nil, fmt.Errorf("prepareSenderAndRecipientKeys: for recipient %d did:key marshal: %w", i+1, err)
	}

	return marshalledKey, nil
}

func getKMSKeyType(keyType, curve string) kms.KeyType {
	switch keyType {
	case "EC":
		switch curve {
		case "P-256":
			return kms.NISTP256ECDHKWType
		case "P-384":
			return kms.NISTP384ECDHKWType
		case "P-521":
			return kms.NISTP521ECDHKWType
		}
	case "OKP":
		return kms.X25519ECDHKWType
	}

	return ""
}

func isMediaTypeForLegacyPacker(cty string) bool {
	var isLegacy bool

	switch cty {
	case transport.MediaTypeRFC0019EncryptedEnvelope, transport.MediaTypeAIP2RFC0019Profile,
		transport.MediaTypeProfileDIDCommAIP1:
		isLegacy = true
	default:
		isLegacy = false
	}

	return isLegacy
}

func buildSenderKID(senderPubKey *crypto.PublicKey, envelopeSenderKey *transport.Envelope) []byte {
	// Authcrypt/Anoncrypt for DIDComm V2 only require the sender KID as senderKey. Its value is:
	// "kms kid value"."kid did:key value" without the double-quotes. The packer should parse it, then use kms kid value
	// to fetch the key from kms and use the did:key or KeyAgreement.ID value as the 'skid' header.
	senderKey := []byte(senderPubKey.KID + ".")
	senderKey = append(senderKey, envelopeSenderKey.FromKey...)

	return senderKey
}

type envelopeStub struct {
	Protected string `json:"protected,omitempty"`
}

type headerStub struct {
	Type string `json:"typ,omitempty"`
	SKID string `json:"skid,omitempty"`
}

func getEncodingType(encMessage []byte) (string, error) {
	env := &envelopeStub{}

	if strings.HasPrefix(string(encMessage), "{") { // full serialized
		err := json.Unmarshal(encMessage, env)
		if err != nil {
			return "", fmt.Errorf("parse envelope: %w", err)
		}
	} else { // compact serialized
		env.Protected = strings.Split(string(encMessage), ".")[0]
	}

	var protBytes []byte

	protBytes1, err1 := base64.URLEncoding.DecodeString(env.Protected)
	protBytes2, err2 := base64.RawURLEncoding.DecodeString(env.Protected)

	switch {
	case err1 == nil:
		protBytes = protBytes1
	case err2 == nil:
		protBytes = protBytes2
	default:
		return "", fmt.Errorf("decode header: %w", err1)
	}

	prot := &headerStub{}

	err := json.Unmarshal(protBytes, prot)
	if err != nil {
		return "", fmt.Errorf("parse header: %w", err)
	}

	packerID := prot.Type

	if prot.SKID != "" {
		// since Type protected header is the same for authcrypt and anoncrypt, the differentiating factor is SKID.
		// If it is present, then it's authcrypt.
		packerID += authSuffix
	}

	return packerID, nil
}

// UnpackMessage Unpack a message.
func (bp *Packager) UnpackMessage(encMessage []byte) (*transport.Envelope, error) {
	encType, err := getEncodingType(encMessage)
	if err != nil {
		return nil, fmt.Errorf("getEncodingType: %w", err)
	}

	p, ok := bp.packers[encType]
	if !ok {
		return nil, fmt.Errorf("message Type not recognized")
	}

	envelope, err := p.Unpack(encMessage)
	if err != nil {
		return nil, fmt.Errorf("unpack: %w", err)
	}

	return envelope, nil
}

func (bp *Packager) getCTYAndPacker(envelope *transport.Envelope) (string, packer.Packer, error) {
	switch envelope.MediaTypeProfile {
	case transport.MediaTypeAIP2RFC0019Profile, transport.MediaTypeProfileDIDCommAIP1:
		return transport.MediaTypeRFC0019EncryptedEnvelope, bp.packers[transport.MediaTypeRFC0019EncryptedEnvelope], nil
	case transport.MediaTypeRFC0019EncryptedEnvelope:
		return envelope.MediaTypeProfile, bp.packers[transport.MediaTypeRFC0019EncryptedEnvelope], nil
	case transport.MediaTypeV2EncryptedEnvelope, transport.MediaTypeV2PlaintextPayload,
		transport.MediaTypeAIP2RFC0587Profile, transport.MediaTypeDIDCommV2Profile:
		packerName := transport.MediaTypeV2EncryptedEnvelope
		if len(envelope.FromKey) > 0 {
			packerName += authSuffix
		}

		return transport.MediaTypeV2PlaintextPayload, bp.packers[packerName], nil
	case transport.MediaTypeV2EncryptedEnvelopeV1PlaintextPayload, transport.MediaTypeV1PlaintextPayload:
		packerName := transport.MediaTypeV2EncryptedEnvelope
		if len(envelope.FromKey) > 0 {
			packerName += authSuffix
		}

		return transport.MediaTypeV1PlaintextPayload, bp.packers[packerName], nil
	default:
		// use primaryPacker if mediaProfile not registered.
		if bp.primaryPacker != nil {
			return bp.primaryPacker.EncodingType(), bp.primaryPacker, nil
		}
	}

	// this should never happen since outbound calls use the framework's default media type profile (unless the default
	// was overridden with an empty value during framework instance creation).
	return "", nil, fmt.Errorf("no packer found for mediatype profile: '%v'", envelope.MediaTypeProfile)
}

func (bp *Packager) resolveKeyAgreementFromDIDDoc(keyAgrID string) ([]byte, error) {
	i := strings.Index(keyAgrID, "#")

	docResolution, err := bp.vdrRegistry.Resolve(keyAgrID[:i])
	if err != nil {
		return nil, fmt.Errorf("resolveKeyAgreementFromDIDDoc: for recipient DID doc resolution %w", err)
	}

	for _, ka := range docResolution.DIDDocument.KeyAgreement {
		kaID := ka.VerificationMethod.ID[strings.Index(ka.VerificationMethod.ID, "#")+1:]
		if strings.EqualFold(kaID, keyAgrID[i+1:]) {
			var (
				marshalledKey []byte
				recKey        *crypto.PublicKey
			)

			switch ka.VerificationMethod.Type {
			case jsonWebKey2020:
				jwkKey := ka.VerificationMethod.JSONWebKey()

				recKey, err = jwksupport.PublicKeyFromJWK(jwkKey)
				if err != nil {
					return nil, fmt.Errorf("resolveKeyAgreementFromDIDDoc: for recipient JWK to PubKey %d: %w", i+1, err)
				}

				// for packing purposes, recipient kid header is the keyAgreement.ID value, the packers must resolve it and extract
				// the kms kid value during unpack.
				recKey.KID = keyAgrID
			case x25519KeyAgreementKey2019:
				recKey = &crypto.PublicKey{
					KID:   keyAgrID,
					X:     ka.VerificationMethod.Value,
					Curve: "X25519",
					Type:  "OKP",
				}
			default:
				return nil, fmt.Errorf("resolveKeyAgreementFromDIDDoc: invalid KeyAgreement type %d: %T", i+1,
					ka.VerificationMethod.Type)
			}

			marshalledKey, err = json.Marshal(recKey)
			if err != nil {
				return nil, fmt.Errorf("resolveKeyAgreementFromDIDDoc: for recipient DID keyAgreement key marshal %d: %w",
					i+1, err)
			}

			return marshalledKey, nil
		}

		logger.Debugf("skipping keyID %s since it's not found in didDoc.KeyAgreement of did %s", kaID, keyAgrID[:i])
	}

	return nil, fmt.Errorf("resolveKeyAgreementFromDIDDoc: keyAgreement ID '%s' not found in DID '%s'", keyAgrID,
		docResolution.DIDDocument.ID)
}
