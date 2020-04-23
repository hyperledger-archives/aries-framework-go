/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/subtle/hybrid"
	"github.com/square/go-jose/v3"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/api"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdhes"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdhes/subtle"
)

// EncAlg represents the JWE content encryption algorithm
type EncAlg string

const (
	// A256GCM for AES256GCM content encryption
	A256GCM = EncAlg(subtle.A256GCM)
)

// Encrypter interface to Encrypt/Decrypt JWE messages
type Encrypter interface {
	// Encrypt plaintext and aad sent to 1 or more recipients and return a valid JSONWebEncryption instance
	Encrypt(plaintext, aad []byte) (*JSONWebEncryption, error)
	// Decrypt a marshalledJWE, extract the corresponding recipient key to decrypt plaintext and return it
	Decrypt(marshalledJWE []byte) ([]byte, error)
}

type encPrimitiveFunc func(*keyset.Handle) (api.CompositeEncrypt, error)

// JWEEncrypt is responsible for encrypting a plaintext and its AAD into a protected JWE and decrypting it
type JWEEncrypt struct {
	recipients   []subtle.ECPublicKey
	senderKH     *keyset.Handle
	getPrimitive encPrimitiveFunc
	encAlg       EncAlg
}

// NewJWEEncrypt creates a new JWEEncrypt instance to build/parse JWE with recipientsPubKeys
func NewJWEEncrypt(encAlg EncAlg, recipientsPubKeys []subtle.ECPublicKey) (*JWEEncrypt, error) {
	if len(recipientsPubKeys) == 0 {
		return nil, fmt.Errorf("empty recipientsPubKeys list")
	}

	var (
		kt  *tinkpb.KeyTemplate
		err error
	)

	// TODO add support for Chacha content encryption, issue #1684
	switch encAlg {
	case A256GCM:
		kt, err = ecdhes.ECDHES256KWAES256GCMKeyTemplateWithRecipients(recipientsPubKeys)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("encryption algorithm '%s' not supported", encAlg)
	}

	senderKH, err := keyset.NewHandle(kt)
	if err != nil {
		return nil, err
	}

	return &JWEEncrypt{
		recipients:   recipientsPubKeys,
		senderKH:     senderKH,
		getPrimitive: getEncryptionPrimitive,
		encAlg:       encAlg,
	}, nil
}

func getEncryptionPrimitive(senderKH *keyset.Handle) (api.CompositeEncrypt, error) {
	senderPubKH, err := senderKH.Public()
	if err != nil {
		return nil, err
	}

	return ecdhes.NewECDHESEncrypt(senderPubKH)
}

// Encrypt plaintext with AAD and return a JSONWebEncryption instance to serialize JWE instance
func (je *JWEEncrypt) Encrypt(plaintext, aad []byte) (*JSONWebEncryption, error) {
	encPrimitive, err := je.getPrimitive(je.senderKH)
	if err != nil {
		return nil, fmt.Errorf("jweencrypt: failed to get encryption primitive: %w", err)
	}

	protectedHeaders := map[string]interface{}{
		HeaderEncryption: je.encAlg,
	}

	// TODO - Go jose adds CEK as part of protectedHeaders, see if this is valid. Also, for a single recipient,
	//  Go jose merges recipient header into JWE protect protectedHeaders. See if this is needed too.

	authData, err := computeAuthData(protectedHeaders, aad)
	if err != nil {
		return nil, err
	}

	serializedEncData, err := encPrimitive.Encrypt(plaintext, authData)
	if err != nil {
		return nil, fmt.Errorf("jweencrypt: failed to Encrypt: %w", err)
	}

	encData := new(subtle.EncryptedData)

	err = json.Unmarshal(serializedEncData, encData)
	if err != nil {
		return nil, fmt.Errorf("jweencrypt: unmarshal encrypted data failed: %w", err)
	}

	var recipients []*Recipient

	for _, rec := range encData.Recipients {
		var mRecJWK []byte

		mRecJWK, err = convertRecKeyToMarshalledJWK(rec)
		if err != nil {
			return nil, fmt.Errorf("jweencrypt: failed to convert recipient key to marshalled JWK: %w", err)
		}

		recipients = append(recipients, &Recipient{
			EncryptedKey: string(rec.EncryptedCEK),
			Header: RecipientHeaders{
				Alg: rec.Alg,
				EPK: string(mRecJWK),
			},
		})
	}

	jsonEncryption := &JSONWebEncryption{
		IV:               string(encData.IV),
		Tag:              string(encData.Tag),
		Ciphertext:       string(encData.Ciphertext),
		Recipients:       recipients,
		ProtectedHeaders: protectedHeaders,
	}

	return jsonEncryption, nil
}

func convertRecKeyToMarshalledJWK(rec *subtle.RecipientWrappedKey) ([]byte, error) {
	var c elliptic.Curve

	c, err := hybrid.GetCurve(rec.EPK.Curve)
	if err != nil {
		return nil, err
	}

	recJWK := JWK{
		JSONWebKey: jose.JSONWebKey{
			Use: HeaderEncryption,
			Key: &ecdsa.PublicKey{
				Curve: c,
				X:     new(big.Int).SetBytes(rec.EPK.X),
				Y:     new(big.Int).SetBytes(rec.EPK.Y),
			},
		},
		Kty: "EC", // TODO add support for X25519 content encryption, issue #1684
		Crv: rec.EPK.Curve,
	}

	return recJWK.MarshalJSON()
}

// Decrypt serializedJWE by first deserializing it, then decrypting the underlying JWE instance and return plaintext
func (je *JWEEncrypt) Decrypt(serializedJWE []byte) ([]byte, error) {
	// TODO will need JWE Deserialization: https://github.com/hyperledger/aries-framework-go/issues/1507 to
	//  implement this function
	return nil, fmt.Errorf("TODO - implement me")
}

// Get the additional authenticated data from a JWE object.
func computeAuthData(protectedHeaders map[string]interface{}, aad []byte) ([]byte, error) {
	var protected string

	if protectedHeaders != nil {
		mProtected, err := json.Marshal(protectedHeaders)
		if err != nil {
			return nil, fmt.Errorf("jwe computeAuthData: marshal error %w", err)
		}

		protected = base64.RawURLEncoding.EncodeToString(mProtected)
	} else {
		protected = ""
	}

	output := []byte(protected)
	if len(aad) > 0 {
		output = append(output, '.')

		encLen := base64.RawURLEncoding.EncodedLen(len(aad))
		aadEncoded := make([]byte, encLen)

		base64.RawURLEncoding.Encode(aadEncoded, aad)
		output = append(output, aadEncoded...)
	}

	return output, nil
}
