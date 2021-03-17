/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jose

import (
	"bytes"
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
	// XC20P for XChacha20Poly1305 content encryption.
	XC20P = EncAlg(XC20PALG)
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
	cty            string
	crypto         cryptoapi.Crypto
}

// NewJWEEncrypt creates a new JWEEncrypt instance to build JWE with recipientsPubKeys
// senderKID and senderKH are used for Authcrypt (to authenticate the sender), if not set JWEEncrypt assumes Anoncrypt.
func NewJWEEncrypt(encAlg EncAlg, encType, cty, senderKID string, senderKH *keyset.Handle,
	recipientsPubKeys []*cryptoapi.PublicKey, crypto cryptoapi.Crypto) (*JWEEncrypt, error) {
	if len(recipientsPubKeys) == 0 {
		return nil, fmt.Errorf("empty recipientsPubKeys list")
	}

	switch encAlg {
	case A256GCM, XC20P:
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
		cty:            cty,
		crypto:         crypto,
	}, nil
}

func (je *JWEEncrypt) getECDHEncPrimitive(cek []byte) (api.CompositeEncrypt, error) {
	kt := ecdh.NISTPECDHAES256GCMKeyTemplateWithCEK(cek)

	if je.encAlg == XC20P {
		kt = ecdh.X25519ECDHXChachaKeyTemplateWithCEK(cek)
	}

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

	je.addExtraProtectedHeaders(protectedHeaders)

	cek := random.GetRandomBytes(uint32(cryptoapi.DefKeySize))

	// creating the crypto primitive requires a pre-built cek
	encPrimitive, err := je.getECDHEncPrimitive(cek)
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
		recipientsWK       []*cryptoapi.RecipientWrappedKey
		singleRecipientAAD []byte
	)

	for i, recPubKey := range je.recipientsKeys {
		var (
			kek *cryptoapi.RecipientWrappedKey
			err error
		)

		wrapOpts := je.getWrapKeyOpts()

		if len(apv) == 0 {
			apv = append(apv, recPubKey.KID...)
		}

		if len(apu) == 0 && je.skid != "" {
			apu = append(apu, je.skid...)
		}

		if len(wrapOpts) > 0 {
			kek, err = je.crypto.WrapKey(cek, apu, apv, recPubKey, wrapOpts...)
		} else {
			kek, err = je.crypto.WrapKey(cek, apu, apv, recPubKey)
		}

		if err != nil {
			return nil, nil, fmt.Errorf("wrapCEKForRecipient %d failed: %w", i+1, err)
		}

		je.encodeAPUAPV(kek)

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

func (je *JWEEncrypt) encodeAPUAPV(kek *cryptoapi.RecipientWrappedKey) {
	// APU and APV must be base64URL encoded.
	if len(kek.APU) > 0 {
		apuBytes := make([]byte, len(kek.APU))
		copy(apuBytes, kek.APU)
		kek.APU = make([]byte, base64.RawURLEncoding.EncodedLen(len(apuBytes)))
		base64.RawURLEncoding.Encode(kek.APU, apuBytes)
	}

	if len(kek.APV) > 0 {
		apvBytes := make([]byte, len(kek.APV))
		copy(apvBytes, kek.APV)
		kek.APV = make([]byte, base64.RawURLEncoding.EncodedLen(len(apvBytes)))
		base64.RawURLEncoding.Encode(kek.APV, apvBytes)
	}
}

func (je *JWEEncrypt) getWrapKeyOpts() []cryptoapi.WrapKeyOpts {
	var wrapOpts []cryptoapi.WrapKeyOpts

	if je.encAlg == XC20P {
		wrapOpts = append(wrapOpts, cryptoapi.WithXC20PKW())
	}

	if je.skid != "" && je.senderKH != nil {
		wrapOpts = append(wrapOpts, cryptoapi.WithSender(je.senderKH))
	}

	return wrapOpts
}

// mergeSingleRecipientHeaders for single recipient encryption, recipient header info is available in the key, update
// AAD with this info and return the marshalled merged result.
func mergeSingleRecipientHeaders(recipientWK *cryptoapi.RecipientWrappedKey,
	aad []byte, marshaller marshalFunc) ([]byte, error) {
	var externalAAD []byte

	aadIdx := len(aad)

	if i := bytes.Index(aad, []byte(".")); i > 0 {
		aadIdx = i
		externalAAD = append(externalAAD, aad[aadIdx+1:]...)
	}

	newAAD, err := base64.RawURLEncoding.DecodeString(string(aad[:aadIdx]))
	if err != nil {
		return nil, err
	}

	rawHeaders := map[string]json.RawMessage{}

	err = json.Unmarshal(newAAD, &rawHeaders)
	if err != nil {
		return nil, err
	}

	if recipientWK.KID != "" {
		var kid []byte

		kid, err = marshaller(recipientWK.KID)
		if err != nil {
			return nil, err
		}

		rawHeaders["kid"] = kid
	}

	alg, err := marshaller(recipientWK.Alg)
	if err != nil {
		return nil, err
	}

	rawHeaders["alg"] = alg

	err = addKDFHeaders(rawHeaders, recipientWK, marshaller)
	if err != nil {
		return nil, err
	}

	mAAD, err := marshaller(rawHeaders)
	if err != nil {
		return nil, err
	}

	mAADStr := []byte(base64.RawURLEncoding.EncodeToString(mAAD))

	if len(externalAAD) > 0 {
		mAADStr = append(mAADStr, byte('.'))
		mAADStr = append(mAADStr, externalAAD...)
	}

	return mAADStr, nil
}

func addKDFHeaders(rawHeaders map[string]json.RawMessage, recipientWK *cryptoapi.RecipientWrappedKey,
	marshaller marshalFunc) error {
	var err error

	mEPK, err := convertRecEPKToMarshalledJWK(recipientWK)
	if err != nil {
		return err
	}

	rawHeaders["epk"] = mEPK

	if len(recipientWK.APU) != 0 {
		rawHeaders["apu"], err = marshaller(fmt.Sprintf("%s", recipientWK.APU))
		if err != nil {
			return err
		}
	}

	if len(recipientWK.APV) != 0 {
		rawHeaders["apv"], err = marshaller(fmt.Sprintf("%s", recipientWK.APV))
		if err != nil {
			return err
		}
	}

	return nil
}

func mergeRecipientHeaders(headers map[string]interface{}, recHeaders *RecipientHeaders) {
	headers[HeaderAlgorithm] = recHeaders.Alg
	if recHeaders.KID != "" {
		headers[HeaderKeyID] = recHeaders.KID
	}

	// EPK, APU, APV will be marshalled by Serialize
	headers[HeaderEPK] = recHeaders.EPK
	if recHeaders.APU != "" {
		headers["apu"] = base64.RawURLEncoding.EncodeToString([]byte(recHeaders.APU))
	}

	if recHeaders.APV != "" {
		headers["apv"] = base64.RawURLEncoding.EncodeToString([]byte(recHeaders.APV))
	}
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
		var (
			decodedAPU []byte
			decodedAPV []byte
			err        error
		)

		decodedAPU, decodedAPV, err = decodeAPUAPV(recipients[0].Header)
		if err != nil {
			return nil, nil, err
		}

		singleRecipientHeaders = &RecipientHeaders{
			Alg: recipients[0].Header.Alg,
			KID: recipients[0].Header.KID,
			EPK: recipients[0].Header.EPK,
			APU: string(decodedAPU),
			APV: string(decodedAPV),
		}

		recipients[0].Header = nil
	}

	return recipients, singleRecipientHeaders, nil
}

func (je *JWEEncrypt) addExtraProtectedHeaders(protectedHeaders map[string]interface{}) {
	// set cty if it's not empty
	if je.cty != "" {
		protectedHeaders[HeaderContentType] = je.cty
	}

	// set skid if it's not empty
	if je.skid != "" {
		protectedHeaders[HeaderSenderKeyID] = je.skid
	}
}

func decodeAPUAPV(headers *RecipientHeaders) ([]byte, []byte, error) {
	var (
		decodedAPU []byte
		decodedAPV []byte
		err        error
	)

	if len(headers.APU) > 0 {
		decodedAPU, err = base64.RawURLEncoding.DecodeString(headers.APU)
		if err != nil {
			return nil, nil, err
		}
	}

	if len(headers.APV) > 0 {
		decodedAPV, err = base64.RawURLEncoding.DecodeString(headers.APV)
		if err != nil {
			return nil, nil, err
		}
	}

	return decodedAPU, decodedAPV, nil
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
		APU: string(rec.APU),
		APV: string(rec.APV),
	}, nil
}

func convertRecEPKToMarshalledJWK(rec *cryptoapi.RecipientWrappedKey) ([]byte, error) {
	var (
		c   elliptic.Curve
		err error
		key interface{}
	)

	switch rec.EPK.Type {
	case ecdhpb.KeyType_EC.String():
		c, err = hybrid.GetCurve(rec.EPK.Curve)
		if err != nil {
			return nil, err
		}

		key = &ecdsa.PublicKey{
			Curve: c,
			X:     new(big.Int).SetBytes(rec.EPK.X),
			Y:     new(big.Int).SetBytes(rec.EPK.Y),
		}
	case ecdhpb.KeyType_OKP.String():
		key = rec.EPK.X
	default:
		return nil, errors.New("invalid key type")
	}

	recJWK := JWK{
		JSONWebKey: jose.JSONWebKey{
			Key: key,
		},
		Kty: rec.EPK.Type,
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
