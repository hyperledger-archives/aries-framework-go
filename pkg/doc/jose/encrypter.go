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
	"errors"
	"fmt"
	"math/big"

	hybrid "github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/subtle/random"
	"github.com/square/go-jose/v3"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/api"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh"
	ecdhpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
)

// EncAlg represents the JWE content encryption algorithm.
type EncAlg string

const (
	// A256GCM for AES256GCM content encryption.
	A256GCM = EncAlg(A256GCMALG)
)

// Encrypter interface to Encrypt/Decrypt JWE messages.
type Encrypter interface {
	// EncryptWithAuthData encrypt plaintext and aad sent to more than 1 recipients and returns a valid
	// JSONWebEncryption instance
	EncryptWithAuthData(plaintext, aad []byte) (*JSONWebEncryption, error)

	// Encrypt plaintext with empty aad sent to 1 or more recipients and returns a valid JSONWebEncryption instance
	Encrypt(plaintext []byte) (*JSONWebEncryption, error)
}

// JWEEncrypt is responsible for encrypting a plaintext and its AAD into a protected JWE and decrypting it.
type JWEEncrypt struct {
	recipientsKeys []*cryptoapi.PublicKey
	skid           string
	senderKH       *keyset.Handle
	encAlg         EncAlg
	encTyp         string
	crypto         cryptoapi.Crypto
}

// NewJWEEncrypt creates a new JWEEncrypt instance to build JWE with recipientsPubKeys
// senderKID and senderKH are used for Authcrypt (to authenticate the sender), if not set JWEEncrypt assumes Anoncrypt.
func NewJWEEncrypt(encAlg EncAlg, encType, senderKID string, senderKH *keyset.Handle,
	recipientsPubKeys []*cryptoapi.PublicKey, crypto cryptoapi.Crypto) (*JWEEncrypt, error) {
	if len(recipientsPubKeys) == 0 {
		return nil, fmt.Errorf("empty recipientsPubKeys list")
	}

	// TODO add support for Chacha content encryption, issue #1684
	switch encAlg {
	case A256GCM:
	default:
		return nil, fmt.Errorf("encryption algorithm '%s' not supported", encAlg)
	}

	if crypto == nil {
		return nil, errors.New("crypto service is required to create a JWEEncrypt instance")
	}

	if senderKH != nil {
		// senderKID is required with non empty senderKH
		if senderKID == "" {
			return nil, errors.New("senderKID is required with senderKH")
		}
	}

	return &JWEEncrypt{
		recipientsKeys: recipientsPubKeys,
		skid:           senderKID,
		senderKH:       senderKH,
		encAlg:         encAlg,
		encTyp:         encType,
		crypto:         crypto,
	}, nil
}

func getECDHEncPrimitive(cek []byte) (api.CompositeEncrypt, error) {
	kt := ecdh.NISTPECDHAES256GCMKeyTemplateWithCEK(cek)

	kh, err := keyset.NewHandle(kt)
	if err != nil {
		return nil, err
	}

	pubKH, err := kh.Public()
	if err != nil {
		return nil, err
	}

	return ecdh.NewECDHEncrypt(pubKH)
}

// Encrypt encrypt plaintext with AAD and returns a JSONWebEncryption instance to serialize a JWE instance.
func (je *JWEEncrypt) Encrypt(plaintext []byte) (*JSONWebEncryption, error) {
	return je.EncryptWithAuthData(plaintext, nil)
}

// EncryptWithAuthData encrypt plaintext with AAD and returns a JSONWebEncryption instance to serialize a JWE instance.
func (je *JWEEncrypt) EncryptWithAuthData(plaintext, aad []byte) (*JSONWebEncryption, error) {
	protectedHeaders := map[string]interface{}{
		HeaderEncryption: je.encAlg,
		HeaderType:       je.encTyp,
	}

	if je.skid != "" {
		protectedHeaders[HeaderSenderKeyID] = je.skid
	}

	cek := random.GetRandomBytes(uint32(cryptoapi.DefKeySize))

	// creating the crypto primitive requires a pre-built cek
	encPrimitive, err := getECDHEncPrimitive(cek)
	if err != nil {
		return nil, fmt.Errorf("jweencrypt: failed to get encryption primitive: %w", err)
	}

	authData, err := computeAuthData(protectedHeaders, aad)
	if err != nil {
		return nil, fmt.Errorf("jweencrypt: computeAuthData: marshal error %w", err)
	}

	recipients, singleRecipientHeaderADDs, err := je.wrapCEKForRecipients(cek, []byte{}, []byte{}, authData, json.Marshal)
	if err != nil {
		return nil, fmt.Errorf("jweencrypt: failed to wrap cek: %w", err)
	}

	if len(singleRecipientHeaderADDs) > 0 {
		authData = singleRecipientHeaderADDs
	}

	recipientsHeaders, singleRecipientHeaders, err := je.buildRecs(recipients)
	if err != nil {
		return nil, fmt.Errorf("jweencrypt: failed to build recipients: %w", err)
	}

	serializedEncData, err := encPrimitive.Encrypt(plaintext, authData)
	if err != nil {
		return nil, fmt.Errorf("jweencrypt: failed to Encrypt: %w", err)
	}

	encData := new(composite.EncryptedData)

	err = json.Unmarshal(serializedEncData, encData)
	if err != nil {
		return nil, fmt.Errorf("jweencrypt: unmarshal encrypted data failed: %w", err)
	}

	if singleRecipientHeaders != nil {
		mergeRecipientHeaders(protectedHeaders, singleRecipientHeaders)
	}

	return getJSONWebEncryption(encData, recipientsHeaders, protectedHeaders, aad), nil
}

func getJSONWebEncryption(encData *composite.EncryptedData, recipientsHeaders []*Recipient,
	protectedHeaders map[string]interface{}, aad []byte) *JSONWebEncryption {
	return &JSONWebEncryption{
		IV:               string(encData.IV),
		Tag:              string(encData.Tag),
		Ciphertext:       string(encData.Ciphertext),
		Recipients:       recipientsHeaders,
		ProtectedHeaders: protectedHeaders,
		AAD:              string(aad),
	}
}

func (je *JWEEncrypt) wrapCEKForRecipients(cek, apu, apv, aad []byte,
	marshaller marshalFunc) ([]*cryptoapi.RecipientWrappedKey, []byte, error) {
	if len(je.recipientsKeys) == 0 {
		return nil, nil, fmt.Errorf("JWEEncrypt - wrapCEKForRecipients: missing recipients public keys for " +
			"key wrapping")
	}

	var (
		senderOpt          cryptoapi.WrapKeyOpts
		recipientsWK       []*cryptoapi.RecipientWrappedKey
		singleRecipientAAD []byte
	)

	kwAlg := tinkcrypto.ECDHESA256KWAlg

	if je.skid != "" && je.senderKH != nil {
		kwAlg = tinkcrypto.ECDH1PUA256KWAlg
		senderOpt = cryptoapi.WithSender(je.senderKH)
	}

	for i, recPubKey := range je.recipientsKeys {
		var (
			kek *cryptoapi.RecipientWrappedKey
			err error
		)

		if senderOpt != nil {
			kek, err = je.crypto.WrapKey(cek, apu, apv, recPubKey, senderOpt)
		} else {
			kek, err = je.crypto.WrapKey(cek, apu, apv, recPubKey)
		}

		if err != nil {
			return nil, nil, fmt.Errorf("wrapCEKForRecipient %d failed: %w", i+1, err)
		}

		kek.Alg = kwAlg
		recipientsWK = append(recipientsWK, kek)

		if len(je.recipientsKeys) == 1 {
			singleRecipientAAD, err = mergeSingleRecipientHeaders(kek, aad, marshaller)
			if err != nil {
				return nil, nil, fmt.Errorf("wrapCEKForRecipient merge recipent headers failed for %d: %w", i+1, err)
			}
		}
	}

	return recipientsWK, singleRecipientAAD, nil
}

// mergeSingleRecipientHeaders for single recipient encryption, recipient header info is available in the key, update
// AAD with this info and return the marshalled merged result.
func mergeSingleRecipientHeaders(recipientWK *cryptoapi.RecipientWrappedKey,
	aad []byte, marshaller marshalFunc) ([]byte, error) {
	newAAD, err := base64.RawURLEncoding.DecodeString(string(aad))
	if err != nil {
		return nil, err
	}

	rawHeaders := map[string]json.RawMessage{}

	err = json.Unmarshal(newAAD, &rawHeaders)
	if err != nil {
		return nil, err
	}

	kid, err := marshaller(recipientWK.KID)
	if err != nil {
		return nil, err
	}

	rawHeaders["kid"] = kid

	alg, err := marshaller(recipientWK.Alg)
	if err != nil {
		return nil, err
	}

	rawHeaders["alg"] = alg

	mEPK, err := convertRecEPKToMarshalledJWK(recipientWK)
	if err != nil {
		return nil, err
	}

	rawHeaders["epk"] = mEPK

	mAAD, err := marshaller(rawHeaders)
	if err != nil {
		return nil, err
	}

	return []byte(base64.RawURLEncoding.EncodeToString(mAAD)), nil
}

func mergeRecipientHeaders(headers map[string]interface{}, recHeaders *RecipientHeaders) {
	headers[HeaderAlgorithm] = recHeaders.Alg
	headers[HeaderKeyID] = recHeaders.KID

	// EPK will be marshalled by Serialize
	headers[HeaderEPK] = recHeaders.EPK
}

func (je *JWEEncrypt) buildRecs(recWKs []*cryptoapi.RecipientWrappedKey) ([]*Recipient, *RecipientHeaders, error) {
	var (
		recipients             []*Recipient
		singleRecipientHeaders *RecipientHeaders
	)

	for _, rec := range recWKs {
		recHeaders, err := buildRecipientHeaders(rec)
		if err != nil {
			return nil, nil, err
		}

		recipients = append(recipients, &Recipient{
			EncryptedKey: string(rec.EncryptedCEK),
			Header:       recHeaders,
		})
	}

	// if we have only 1 recipient, then assume compact JWE serialization format. This means recipient header should
	// be merged with the JWE envelope's protected headers and not added to the recipients
	if len(recWKs) == 1 {
		singleRecipientHeaders = &RecipientHeaders{
			Alg: recipients[0].Header.Alg,
			KID: recipients[0].Header.KID,
			EPK: recipients[0].Header.EPK,
		}

		recipients[0].Header = nil
	}

	return recipients, singleRecipientHeaders, nil
}

func buildRecipientHeaders(rec *cryptoapi.RecipientWrappedKey) (*RecipientHeaders, error) {
	mRecJWK, err := convertRecEPKToMarshalledJWK(rec)
	if err != nil {
		return nil, fmt.Errorf("failed to convert recipient key to marshalled JWK: %w", err)
	}

	return &RecipientHeaders{
		KID: rec.KID,
		Alg: rec.Alg,
		EPK: mRecJWK,
	}, nil
}

func convertRecEPKToMarshalledJWK(rec *cryptoapi.RecipientWrappedKey) ([]byte, error) {
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
		Kty: ecdhpb.KeyType_EC.String(), // TODO add support for X25519 (OKP) content encryption, issue #1684
		Crv: rec.EPK.Curve,
	}

	return recJWK.MarshalJSON()
}

// Get the additional authenticated data from a JWE object.
func computeAuthData(protectedHeaders map[string]interface{}, aad []byte) ([]byte, error) {
	var protected string

	if protectedHeaders != nil {
		protectedHeadersJSON := map[string]json.RawMessage{}

		for k, v := range protectedHeaders {
			mV, err := json.Marshal(v)
			if err != nil {
				return nil, err
			}

			rawMsg := json.RawMessage(mV) // need to explicitly convert []byte to RawMessage (same as go-jose)
			protectedHeadersJSON[k] = rawMsg
		}

		mProtected, err := json.Marshal(protectedHeadersJSON)
		if err != nil {
			return nil, err
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
