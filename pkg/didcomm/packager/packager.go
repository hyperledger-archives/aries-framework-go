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

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer/authcrypt"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const authSuffix = "-authcrypt"

// Provider contains dependencies for the base packager and is typically created by using aries.Context().
type Provider interface {
	Packers() []packer.Packer
	PrimaryPacker() packer.Packer
	StorageProvider() storage.Provider
	VDRegistry() vdr.Registry
}

// Creator method to create new packager service.
type Creator func(prov Provider) (transport.Packager, error)

// Packager is the basic implementation of Packager.
type Packager struct {
	primaryPacker packer.Packer
	packers       map[string]packer.Packer
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

	var recipients [][]byte

	for _, didKey := range messageEnvelope.ToKeys {
		verKeyBytes, err := fingerprint.PubKeyFromDIDKey(didKey)
		if err != nil {
			return nil, fmt.Errorf("packMessage: failed to parse public key bytes from did:key verKey: %w", err)
		}

		// create 32 byte key
		recipients = append(recipients, verKeyBytes)
	}

	cty, p, err := bp.getCTYAndPacker(messageEnvelope)
	if err != nil {
		return nil, fmt.Errorf("packMessage: %w", err)
	}

	bytes, err := p.Pack(cty, messageEnvelope.Message, messageEnvelope.FromKey, recipients)
	if err != nil {
		return nil, fmt.Errorf("packMessage: failed to pack: %w", err)
	}

	return bytes, nil
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
	case transport.MediaTypeAIP2RFC0019Profile:
		return transport.MediaTypeRFC0019EncryptedEnvelope, bp.packers[transport.MediaTypeRFC0019EncryptedEnvelope], nil
	case transport.MediaTypeRFC0019EncryptedEnvelope, transport.MediaTypeV1PlaintextPayload:
		return envelope.MediaTypeProfile, bp.packers[transport.MediaTypeRFC0019EncryptedEnvelope], nil
	case transport.MediaTypeV2EncryptedEnvelope, transport.MediaTypeV2PlaintextPayload,
		transport.MediaTypeAIP2RFC0587Profile, transport.MediaTypeDIDCommV2Profile:
		packerName := transport.MediaTypeV2EncryptedEnvelope
		if len(envelope.FromKey) > 0 {
			packerName += authSuffix
		}

		return transport.MediaTypeV2PlaintextPayload, bp.packers[packerName], nil
	case transport.MediaTypeV2EncryptedEnvelopeV1PlaintextPayload:
		packerName := transport.MediaTypeV2EncryptedEnvelope
		if len(envelope.FromKey) > 0 {
			packerName += authSuffix
		}

		return transport.MediaTypeV1PlaintextPayload, bp.packers[packerName], nil
	default:
		// use primaryPacker if mediaProfile not registered.
		if bp.primaryPacker != nil {
			if bp.primaryPacker.EncodingType() == transport.MediaTypeRFC0019EncryptedEnvelope {
				return transport.MediaTypeRFC0019EncryptedEnvelope, bp.primaryPacker, nil
			}

			// assuming primaryPacker is V2 version (currently primaryPacker is legacyPacker, ie V1).
			return transport.MediaTypeV2PlaintextPayload, bp.primaryPacker, nil
		}
	}

	// this should never happen since outbound calls use the framework's default media type profile (unless the default
	// was overridden with an empty value during framework instance creation).
	return "", nil, fmt.Errorf("no packer found for mediatype profile: '%v'", envelope.MediaTypeProfile)
}
