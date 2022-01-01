/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/tink/go/keyset"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/kid/resolver"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// Package authcrypt includes a Packer implementation to build and parse JWE messages using Authcrypt. It allows sending
// messages between parties with non-repudiation messages, ie the sender identity is revealed (and therefore
// authenticated) to the recipient(s). The assumption of using this package is that public keys exchange has previously
// occurred between the sender and the recipient(s).

var logger = log.New("aries-framework/pkg/didcomm/packer/authcrypt")

// Packer represents an Authcrypt Pack/Unpacker that outputs/reads Aries envelopes.
type Packer struct {
	kms           kms.KeyManager
	encAlg        jose.EncAlg
	cryptoService cryptoapi.Crypto
	kidResolvers  []resolver.KIDResolver
}

// New will create a Packer instance to 'AuthCrypt' payloads for a given sender and list of recipients keys using
// DIDComm typ V2 value (default envelope 'typ' protected header).
// It opens thirdPartyKS store (or fetch cached one) that contains third party keys. This store must be
// pre-populated with the sender key required by a recipient to Unpack a JWE envelope. It is not needed by the sender
// (as the sender packs the envelope with its own key).
// The returned Packer contains all the information required to pack and unpack payloads.
func New(ctx packer.Provider, encAlg jose.EncAlg) (*Packer, error) {
	err := validateEncAlg(encAlg)
	if err != nil {
		return nil, fmt.Errorf("authcrypt: %w", err)
	}

	k := ctx.KMS()
	if k == nil {
		return nil, errors.New("authcrypt: failed to create packer because KMS is empty")
	}

	c := ctx.Crypto()
	if c == nil {
		return nil, errors.New("authcrypt: failed to create packer because crypto service is empty")
	}

	vdrReg := ctx.VDRegistry()
	if vdrReg == nil {
		return nil, errors.New("authcrypt: failed to create packer because vdr registry is empty")
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

func validateEncAlg(alg jose.EncAlg) error {
	switch alg {
	// authcrypt supports AES-CBC+HMAC-SHA algorithms only, anoncrypt supports the same and AES256-GCM.
	case jose.A128CBCHS256, jose.A192CBCHS384ALG, jose.A256CBCHS384, jose.A256CBCHS512, jose.XC20P:
		return nil
	default:
		return fmt.Errorf("unsupported content encrytpion algorithm: %v", alg)
	}
}

// Pack will encode the payload argument with contentType argument
// Using the protocol defined by the Authcrypt message of Aries RFC 0334
// with the following arguments:
// payload: the payload message that will be protected
// senderID: the key id of the sender (stored in the KMS)
// recipientsPubKeys: public keys.
func (p *Packer) Pack(contentType string, payload, senderID []byte, recipientsPubKeys [][]byte) ([]byte, error) {
	if len(recipientsPubKeys) == 0 {
		return nil, fmt.Errorf("authcrypt Pack: empty recipientsPubKeys")
	}

	recECKeys, aad, err := unmarshalRecipientKeys(recipientsPubKeys)
	if err != nil {
		return nil, fmt.Errorf("authcrypt Pack: failed to convert recipient keys: %w", err)
	}

	senderKID := string(senderID)
	skid := senderKID

	if idx := strings.Index(senderKID, "."); idx > 0 {
		senderKID = senderKID[:idx] // senderKID is the kms kid.
		skid = skid[idx+1:]         // skid as did:key or didDoc.KeyAgreement[].VerificationMethod.ID value.
	}

	kh, err := p.kms.Get(senderKID)
	if err != nil {
		return nil, fmt.Errorf("authcrypt Pack: failed to get sender key from KMS: %w", err)
	}

	jweEncrypter, err := jose.NewJWEEncrypt(p.encAlg, p.EncodingType(), contentType, skid,
		kh.(*keyset.Handle), recECKeys, p.cryptoService)
	if err != nil {
		return nil, fmt.Errorf("authcrypt Pack: failed to new JWEEncrypt instance: %w", err)
	}

	jwe, err := jweEncrypter.EncryptWithAuthData(payload, aad)
	if err != nil {
		return nil, fmt.Errorf("authcrypt Pack: failed to encrypt payload: %w", err)
	}

	mPh, err := json.Marshal(jwe.ProtectedHeaders)
	if err != nil {
		return nil, fmt.Errorf("authcrypt Pack: %w", err)
	}

	logger.Debugf("protected headers: %s", mPh)

	var s string

	if len(recipientsPubKeys) == 1 {
		s, err = jwe.CompactSerialize(json.Marshal)
	} else {
		s, err = jwe.FullSerialize(json.Marshal)
	}

	if err != nil {
		return nil, fmt.Errorf("authcrypt Pack: failed to serialize JWE message: %w", err)
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

// Unpack will decode the envelope using a standard format. Using either did:key KID resolver or the
// DIDDoc.KeyAgreement[].VerificationMethod.ID resolver which are set in p.resolvers.
func (p *Packer) Unpack(envelope []byte) (*transport.Envelope, error) {
	// TODO validate `typ` and `cty` values
	jwe, _, _, err := deserializeEnvelope(envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize envelope: %w", err)
	}

	for i := range jwe.Recipients {
		var (
			recKey *cryptoapi.PublicKey
			pt     []byte
			recKID string
			env    *transport.Envelope
		)

		recKey, recKID, err = p.pubKey(i, jwe)
		if err != nil {
			return nil, fmt.Errorf("authcrypt Unpack: %w", err)
		}

		// verify recKey.KID is found in kms to prove ownership of key.
		_, err = p.kms.Get(recKey.KID)
		if err != nil {
			if errors.Is(err, storage.ErrDataNotFound) {
				retriesMsg := ""

				if i < len(jwe.Recipients) {
					retriesMsg = ", will try another recipient"
				}

				logger.Debugf("authcrypt Unpack: recipient keyID not found in KMS: %v%s", recKey.KID, retriesMsg)

				continue
			}

			return nil, fmt.Errorf("authcrypt Unpack: failed to get key from kms: %w", err)
		}

		jweDecrypter := jose.NewJWEDecrypt(p.kidResolvers, p.cryptoService, p.kms)

		pt, err = jweDecrypter.Decrypt(jwe)
		if err != nil {
			return nil, fmt.Errorf("authcrypt Unpack: failed to decrypt JWE envelope: %w", err)
		}

		env, err = p.buildEnvelope(recKey, recKID, pt, jwe)
		if err != nil {
			return nil, fmt.Errorf("authcrypt Unpack: %w", err)
		}

		return env, nil
	}

	return nil, fmt.Errorf("authcrypt Unpack: no matching recipient in envelope")
}

func (p *Packer) buildEnvelope(recKey *cryptoapi.PublicKey, recKID string, message []byte,
	jwe *jose.JSONWebEncryption) (*transport.Envelope, error) {
	// set original recKID in recKey to keep original source of key (ie not the KMS kid)
	recKey.KID = recKID

	ecdh1puPubKeyByes, err := json.Marshal(recKey)
	if err != nil {
		return nil, fmt.Errorf("buildEnvelope: failed to marshal recipient public key: %w", err)
	}

	mSenderPubKey, err := p.extractSenderKey(jwe)
	if err != nil {
		return nil, err
	}

	return &transport.Envelope{
		Message: message,
		FromKey: mSenderPubKey,
		ToKey:   ecdh1puPubKeyByes,
	}, nil
}

func (p *Packer) extractSenderKey(jwe *jose.JSONWebEncryption) ([]byte, error) {
	var (
		senderKey     *cryptoapi.PublicKey
		mSenderPubKey []byte
		err           error
	)

	skidHeader, ok := jwe.ProtectedHeaders["skid"]
	if ok { //nolint:nestif
		skid, ok := skidHeader.(string)
		if ok {
			for _, r := range p.kidResolvers {
				senderKey, err = r.Resolve(skid)
				if err != nil {
					logger.Debugf("authcrypt Unpack: unpack successful, but resolving sender key failed [%v] "+
						"using %T resolver, skipping it.", err.Error(), r)
				}

				if senderKey != nil {
					logger.Debugf("authcrypt Unpack: unpack successful with resolving sender key success "+
						"using %T resolver, will be using resolved senderKey for skid: %v", r, skid)
					break
				}
			}

			if senderKey != nil {
				// original senderKey.KID is a kms kid. The agent unpacking the envelope doesn't have this kid in kms.
				// Set value as skid to keep trace of the origin of the key (didDoc.keyAgreement[].VerificationMehod.ID)
				senderKey.KID = skid
				mSenderPubKey, err = json.Marshal(senderKey)

				if err != nil {
					return nil, fmt.Errorf("authcrypt Unpack: failed to marshal sender public key: %w", err)
				}
			} else {
				logger.Debugf("authcrypt Unpack: senderKey not resolved, skipping FromKey in envelope")
			}
		}
	}

	return mSenderPubKey, nil
}

func deserializeEnvelope(envelope []byte) (*jose.JSONWebEncryption, string, string, error) {
	jwe, err := jose.Deserialize(string(envelope))
	if err != nil {
		return nil, "", "", fmt.Errorf("authcrypt Unpack: failed to deserialize JWE message: %w", err)
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

	// recipient kid header is the did:Key or KeyAgreement.ID, extract the public key and build a kms kid.
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
