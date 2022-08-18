/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anoncrypt

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/kid/resolver"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

// Package anoncrypt includes a Packer implementation to build and parse JWE messages using Anoncrypt. It allows sending
// messages anonymously between parties with message repudiation, ie the sender identity is not revealed (and therefore
// not authenticated) to the recipient(s).

var logger = log.New("aries-framework/pkg/didcomm/packer/anoncrypt")

// Packer represents an Anoncrypt Pack/Unpacker that outputs/reads Aries envelopes.
type Packer struct {
	kms           kms.KeyManager
	encAlg        jose.EncAlg
	cryptoService cryptoapi.Crypto
	kidResolvers  []resolver.KIDResolver
}

// New will create an Packer instance to 'AnonCrypt' payloads for a given list of recipients.
// The returned Packer contains all the information required to pack and unpack payloads.
func New(ctx packer.Provider, encAlg jose.EncAlg) (*Packer, error) {
	k := ctx.KMS()
	if k == nil {
		return nil, errors.New("anoncrypt: failed to create packer because KMS is empty")
	}

	c := ctx.Crypto()
	if c == nil {
		return nil, errors.New("anoncrypt: failed to create packer because crypto service is empty")
	}

	vdrReg := ctx.VDRegistry()
	if vdrReg == nil {
		return nil, errors.New("anoncrypt: failed to create packer because vdr registry is empty")
	}

	var kidResolvers []resolver.KIDResolver

	kidResolvers = append(kidResolvers, &resolver.DIDKeyResolver{}, &resolver.DIDDocResolver{VDRRegistry: vdrReg})

	return &Packer{
		kms:           k,
		encAlg:        encAlg,
		cryptoService: c,
		kidResolvers:  kidResolvers,
	}, nil
}

// Pack will encode the payload argument using the protocol defined by the Anoncrypt message of Aries RFC 0334.
// Anoncrypt ignores the sender argument, it's added to meet the Packer interface. It uses DIDComm typ V2 header value
// (default envelope 'typ' protected header).
func (p *Packer) Pack(contentType string, payload, _ []byte, recipientsPubKeys [][]byte) ([]byte, error) {
	if len(recipientsPubKeys) == 0 {
		return nil, fmt.Errorf("anoncrypt Pack: empty recipientsPubKeys")
	}

	recECKeys, aad, err := unmarshalRecipientKeys(recipientsPubKeys)
	if err != nil {
		return nil, fmt.Errorf("anoncrypt Pack: failed to convert recipient keys: %w", err)
	}

	jweEncrypter, err := jose.NewJWEEncrypt(p.encAlg, p.EncodingType(), contentType, "",
		nil, recECKeys, p.cryptoService)
	if err != nil {
		return nil, fmt.Errorf("anoncrypt Pack: failed to new JWEEncrypt instance: %w", err)
	}

	jwe, err := jweEncrypter.EncryptWithAuthData(payload, aad)
	if err != nil {
		return nil, fmt.Errorf("anoncrypt Pack: failed to encrypt payload: %w", err)
	}

	mPh, err := json.Marshal(jwe.ProtectedHeaders)
	if err != nil {
		return nil, fmt.Errorf("anoncrypt Pack: %w", err)
	}

	logger.Debugf("protected headers: %s", mPh)

	var s string

	if len(recipientsPubKeys) == 1 {
		s, err = jwe.CompactSerialize(json.Marshal)
	} else {
		s, err = jwe.FullSerialize(json.Marshal)
	}

	if err != nil {
		return nil, fmt.Errorf("anoncrypt Pack: failed to serialize JWE message: %w", err)
	}

	return []byte(s), nil
}

func unmarshalRecipientKeys(keys [][]byte) ([]*cryptoapi.PublicKey, []byte, error) {
	var (
		pubKeys []*cryptoapi.PublicKey
		aad     []byte
	)

	for _, key := range keys {
		var ecKey *cryptoapi.PublicKey

		err := json.Unmarshal(key, &ecKey)
		if err != nil {
			return nil, nil, err
		}

		pubKeys = append(pubKeys, ecKey)
	}

	return pubKeys, aad, nil
}

// Unpack will decode the envelope using a standard format.
func (p *Packer) Unpack(envelope []byte) (*transport.Envelope, error) {
	// TODO validate incoming `typ` and `cty` values
	jwe, _, _, err := deserializeEnvelope(envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize JWE envelope: %w", err)
	}

	for i := range jwe.Recipients {
		recKey, recKID, err := p.pubKey(i, jwe)
		if err != nil {
			return nil, fmt.Errorf("anoncrypt Unpack: %w", err)
		}

		// verify recKey.KID is found in kms to prove ownership of key.
		_, err = p.kms.Get(recKey.KID)
		if err != nil {
			if errors.Is(err, kms.ErrKeyNotFound) {
				retriesMsg := ""

				if i < len(jwe.Recipients) {
					retriesMsg = ", will try another recipient"
				}

				logger.Debugf("anoncrypt Unpack: recipient keyID not found in KMS: %v%s", recKey.KID, retriesMsg)

				continue
			}

			return nil, fmt.Errorf("anoncrypt Unpack: failed to get key from kms: %w", err)
		}

		jweDecrypter := jose.NewJWEDecrypt(p.kidResolvers, p.cryptoService, p.kms)

		pt, err := jweDecrypter.Decrypt(jwe)
		if err != nil {
			return nil, fmt.Errorf("anoncrypt Unpack: failed to decrypt JWE envelope: %w", err)
		}

		// set original recKID in recKey to keep original source of key (ie not the KMS kid)
		recKey.KID = recKID

		ecdhesPubKeyByes, err := json.Marshal(recKey)
		if err != nil {
			return nil, fmt.Errorf("anoncrypt Unpack: failed to marshal public key: %w", err)
		}

		return &transport.Envelope{
			Message: pt,
			ToKey:   ecdhesPubKeyByes,
		}, nil
	}

	return nil, fmt.Errorf("anoncrypt Unpack: no matching recipient in envelope")
}

func deserializeEnvelope(envelope []byte) (*jose.JSONWebEncryption, string, string, error) {
	jwe, err := jose.Deserialize(string(envelope))
	if err != nil {
		return nil, "", "", fmt.Errorf("anoncrypt Unpack: failed to deserialize JWE message: %w", err)
	}

	typ, _ := jwe.ProtectedHeaders.Type()
	cty, _ := jwe.ProtectedHeaders.ContentType()

	return jwe, typ, cty, nil
}

// pubKey will resolve recipient kid at i and returns the corresponding full public key with KID as the kms KID value.
func (p *Packer) pubKey(i int, jwe *jose.JSONWebEncryption) (*cryptoapi.PublicKey, string, error) {
	var (
		kid         string
		kidResolver resolver.KIDResolver
	)

	if i == 0 && len(jwe.Recipients) == 1 { // compact serialization, recipient headers are in jwe.ProtectedHeaders
		var ok bool

		kid, ok = jwe.ProtectedHeaders.KeyID()
		if !ok {
			return nil, "", fmt.Errorf("single recipient missing 'KID' in jwe.ProtectHeaders")
		}
	} else {
		kid = jwe.Recipients[i].Header.KID
	}

	keySource := "did:key"

	switch {
	case strings.HasPrefix(kid, keySource):
		kidResolver = p.kidResolvers[0]
	case strings.Index(kid, "#") > 0:
		kidResolver = p.kidResolvers[1]
		keySource = "didDoc.KeyAgreement[].VerificationMethod.ID"
	default:
		return nil, "", fmt.Errorf("invalid kid format, must be a did:key or a DID doc verificaitonMethod ID")
	}

	// recipient kid header is the did:Key or KeyAgreement.ID, extract the public key and build a kms kid
	recKey, err := kidResolver.Resolve(kid)
	if err != nil {
		return nil, "", fmt.Errorf("failed to resolve recipient key from %s value: %w", keySource, err)
	}

	return recKey, kid, nil
}

// EncodingType for didcomm.
func (p *Packer) EncodingType() string {
	return transport.MediaTypeV2EncryptedEnvelope
}
