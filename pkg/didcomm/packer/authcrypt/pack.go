/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/tink/go/keyset"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/store/wrapper/prefix"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// Package authcrypt includes a Packer implementation to build and parse JWE messages using Authcrypt. It allows sending
// messages between parties with non-repudiation messages, ie the sender identity is revealed (and therefore
// authenticated) to the recipient(s). The assumption of using this package is that public keys exchange has previously
// occurred between the sender and the recipient(s).

const (
	// ThirdPartyKeysDB is a store name containing keys of third party agents.
	ThirdPartyKeysDB = "thirdpartykeysdb"
)

var logger = log.New("aries-framework/pkg/didcomm/packer/authcrypt")

// Packer represents an Authcrypt Pack/Unpacker that outputs/reads Aries envelopes.
type Packer struct {
	kms           kms.KeyManager
	encAlg        jose.EncAlg
	thirdPartyKS  storage.Store
	cryptoService cryptoapi.Crypto
}

// New will create a Packer instance to 'AuthCrypt' payloads for a given sender and list of recipients keys using
// DIDComm typ V2 value (default envelope 'typ' protected header).
// It opens thirdPartyKS store (or fetch cached one) that contains third party keys. This store must be
// pre-populated with the sender key required by a recipient to Unpack a JWE envelope. It is not needed by the sender
// (as the sender packs the envelope with its own key).
// The returned Packer contains all the information required to pack and unpack payloads.
func New(ctx packer.Provider, encAlg jose.EncAlg) (*Packer, error) {
	k := ctx.KMS()
	if k == nil {
		return nil, errors.New("authcrypt: failed to create packer because KMS is empty")
	}

	c := ctx.Crypto()
	if c == nil {
		return nil, errors.New("authcrypt: failed to create packer because crypto service is empty")
	}

	sp := ctx.StorageProvider()
	if sp == nil {
		return nil, errors.New("authcrypt: failed to create packer because StorageProvider is empty")
	}

	store, err := sp.OpenStore(ThirdPartyKeysDB)
	if err != nil {
		return nil, fmt.Errorf("authcrypt: %w", err)
	}

	store, err = prefix.NewPrefixStoreWrapper(store, prefix.StorageKIDPrefix)
	if err != nil {
		return nil, fmt.Errorf("authcrypt: failed to wrap key store: %w", err)
	}

	return &Packer{
		kms:           k,
		encAlg:        encAlg,
		thirdPartyKS:  store,
		cryptoService: c,
	}, nil
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

	kh, err := p.kms.Get(string(senderID))
	if err != nil {
		return nil, fmt.Errorf("authcrypt Pack: failed to get sender key from KMS: %w", err)
	}

	jweEncrypter, err := jose.NewJWEEncrypt(p.encAlg, p.EncodingType(), contentType, string(senderID),
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
		return nil, fmt.Errorf("authcrypt Pack: failed to serialize JWE message: %w", err)
	}

	return []byte(s), nil
}

func unmarshalRecipientKeys(keys [][]byte) ([]*cryptoapi.PublicKey, []byte, error) {
	var (
		pubKeys []*cryptoapi.PublicKey
		kids    []string
		aad     []byte
	)

	for _, key := range keys {
		var ecKey *cryptoapi.PublicKey

		err := json.Unmarshal(key, &ecKey)
		if err != nil {
			return nil, nil, err
		}

		kids = append(kids, ecKey.KID)
		pubKeys = append(pubKeys, ecKey)
	}

	if len(keys) > 1 {
		sort.Strings(kids)

		kidsStr := strings.Join(kids, ".")
		logger.Infof("Authcrypt Pack KIDs for AAD: %s", kidsStr)

		aad32 := sha256.Sum256([]byte(kidsStr))
		aad = make([]byte, 32)
		copy(aad, aad32[:])
		logger.Infof("Authcrypt Pack AAD: %s", base64.RawURLEncoding.EncodeToString(aad))
	}

	return pubKeys, aad, nil
}

// Unpack will decode the envelope using a standard format.
func (p *Packer) Unpack(envelope []byte) (*transport.Envelope, error) {
	jwe, cty, err := deserializeEnvelope(envelope)
	if err != nil {
		return nil, err
	}

	for i := range jwe.Recipients {
		var (
			kid                   string
			kh                    interface{}
			pt, ecdh1puPubKeyByes []byte
		)

		kid, err = getKID(i, jwe)
		if err != nil {
			return nil, fmt.Errorf("authcrypt Unpack: %w", err)
		}

		kh, err = p.kms.Get(kid)
		if err != nil {
			if errors.Is(err, storage.ErrDataNotFound) {
				retriesMsg := ""

				if i < len(jwe.Recipients) {
					retriesMsg = ", will try another recipient"
				}

				logger.Debugf("authcrypt Unpack: recipient keyID not found in KMS: %v%s", kid, retriesMsg)

				continue
			}

			return nil, fmt.Errorf("authcrypt Unpack: failed to get key from kms: %w", err)
		}

		keyHandle, ok := kh.(*keyset.Handle)
		if !ok {
			return nil, fmt.Errorf("authcrypt Unpack: invalid keyset handle")
		}

		jweDecrypter := jose.NewJWEDecrypt(p.thirdPartyKS, p.cryptoService, p.kms)

		pt, err = jweDecrypter.Decrypt(jwe)
		if err != nil {
			return nil, fmt.Errorf("authcrypt Unpack: failed to decrypt JWE envelope: %w", err)
		}

		// TODO get mapped verKey for the recipient encryption key (kid)
		ecdh1puPubKeyByes, err = exportPubKeyBytes(keyHandle)
		if err != nil {
			return nil, fmt.Errorf("authcrypt Unpack: failed to export public key bytes: %w", err)
		}

		return &transport.Envelope{
			CTY:     cty,
			Message: pt,
			ToKey:   ecdh1puPubKeyByes,
		}, nil
	}

	return nil, fmt.Errorf("authcrypt Unpack: no matching recipient in envelope")
}

func deserializeEnvelope(envelope []byte) (*jose.JSONWebEncryption, string, error) {
	jwe, err := jose.Deserialize(string(envelope))
	if err != nil {
		return nil, "", fmt.Errorf("authcrypt Unpack: failed to deserialize JWE message: %w", err)
	}

	cty, _ := jwe.ProtectedHeaders.ContentType()

	return jwe, cty, nil
}

func getKID(i int, jwe *jose.JSONWebEncryption) (string, error) {
	var kid string

	if i == 0 && len(jwe.Recipients) == 1 { // compact serialization, recipient headers are in jwe.ProtectedHeaders
		ok := false

		kid, ok = jwe.ProtectedHeaders.KeyID()
		if !ok {
			return "", fmt.Errorf("single recipient missing 'KID' in jwe.ProtectHeaders")
		}
	} else {
		kid = jwe.Recipients[i].Header.KID
	}

	return kid, nil
}

func exportPubKeyBytes(keyHandle *keyset.Handle) ([]byte, error) {
	pubKH, err := keyHandle.Public()
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	pubKeyWriter := keyio.NewWriter(buf)

	err = pubKH.WriteWithNoSecrets(pubKeyWriter)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// EncodingType for didcomm.
func (p *Packer) EncodingType() string {
	return packer.EnvelopeEncodingTypeV2
}
