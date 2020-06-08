/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jose

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"

	"github.com/google/tink/go/keyset"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/api"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdhes"
)

// Decrypter interface to Decrypt JWE messages
type Decrypter interface {
	// Decrypt a deserialized JWE, extracts the corresponding recipient key to decrypt plaintext and returns it
	Decrypt(jwe *JSONWebEncryption) ([]byte, error)
}

type decPrimitiveFunc func(*keyset.Handle) (api.CompositeDecrypt, error)

// JWEDecrypt is responsible for decrypting a JWE message and returns its protected plaintext
type JWEDecrypt struct {
	recipientKH  *keyset.Handle
	getPrimitive decPrimitiveFunc
}

// NewJWEDecrypt creates a new JWEDecrypt instance to parse and decrypt a JWE message for a given recipient
func NewJWEDecrypt(recipientKH *keyset.Handle) *JWEDecrypt {
	return &JWEDecrypt{
		recipientKH:  recipientKH,
		getPrimitive: getDecryptionPrimitive,
	}
}

func getDecryptionPrimitive(recipientKH *keyset.Handle) (api.CompositeDecrypt, error) {
	return ecdhes.NewECDHESDecrypt(recipientKH)
}

// Decrypt a deserialized JWE, decrypts its protected content and returns plaintext
func (jd *JWEDecrypt) Decrypt(jwe *JSONWebEncryption) ([]byte, error) {
	if jwe == nil {
		return nil, fmt.Errorf("jwedecrypt: jwe is nil")
	}

	protectedHeaders := jwe.ProtectedHeaders

	encAlg, ok := protectedHeaders.Encryption()
	if !ok {
		return nil, fmt.Errorf("jwedecrypt: jwe is missing encryption algorithm 'enc' header")
	}

	// TODO add support for Chacha content encryption, issue #1684
	switch encAlg {
	case string(A256GCM):
	default:
		return nil, fmt.Errorf("jwedecrypt: encryption algorithm '%s' not supported", encAlg)
	}

	decPrimitive, err := jd.getPrimitive(jd.recipientKH)
	if err != nil {
		return nil, fmt.Errorf("jwedecrypt: failed to get decryption primitive: %w", err)
	}

	encryptedData, err := buildEncryptedData(encAlg, jwe)
	if err != nil {
		return nil, fmt.Errorf("jwedecrypt: failed to build encryptedData for Decrypt(): %w", err)
	}

	authData, err := computeAuthData(protectedHeaders, []byte(jwe.AAD))
	if err != nil {
		return nil, err
	}

	if len(jwe.Recipients) == 1 {
		authData = []byte(jwe.OrigProtectedHders)
	}

	return decPrimitive.Decrypt(encryptedData, authData)
}

func buildEncryptedData(encAlg string, jwe *JSONWebEncryption) ([]byte, error) {
	var recipients []*composite.RecipientWrappedKey

	if len(jwe.Recipients) == 1 { // compact serialization: it has only 1 recipient with no headers
		rHeaders, err := extractRecipientHeaders(jwe.ProtectedHeaders)
		if err != nil {
			return nil, err
		}

		rec, err := convertMarshalledJWKToRecKey(rHeaders.EPK)
		if err != nil {
			return nil, err
		}

		rec.KID = rHeaders.KID
		rec.Alg = rHeaders.Alg
		rec.EncryptedCEK = []byte(jwe.Recipients[0].EncryptedKey)

		recipients = []*composite.RecipientWrappedKey{
			rec,
		}
	} else { // full serialization
		for _, recJWE := range jwe.Recipients {
			rec, err := convertMarshalledJWKToRecKey(recJWE.Header.EPK)
			if err != nil {
				return nil, err
			}

			rec.KID = recJWE.Header.KID
			rec.Alg = recJWE.Header.Alg
			rec.EncryptedCEK = []byte(recJWE.EncryptedKey)

			recipients = append(recipients, rec)
		}
	}

	encData := new(composite.EncryptedData)
	encData.Recipients = recipients
	encData.Tag = []byte(jwe.Tag)
	encData.IV = []byte(jwe.IV)
	encData.Ciphertext = []byte(jwe.Ciphertext)
	encData.EncAlg = encAlg

	return json.Marshal(encData)
}

// extractRecipientHeaders will extract RecipientHeaders from headers argument
func extractRecipientHeaders(headers map[string]interface{}) (*RecipientHeaders, error) {
	// Since headers is a generic map, epk value is converted to a generic map by Serialize(), ie we lose RawMessage
	// type of epk. We need to convert epk value (generic map) to marshaled json so we can call RawMessage.Unmarshal()
	// to get the original epk value (RawMessage type).
	mapData, ok := headers[HeaderEPK].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("JSON value is not a map (%#v)", headers[HeaderEPK])
	}

	epkBytes, err := json.Marshal(mapData)
	if err != nil {
		return nil, err
	}

	epk := json.RawMessage{}

	err = epk.UnmarshalJSON(epkBytes)
	if err != nil {
		return nil, err
	}

	alg := ""
	if headers[HeaderAlgorithm] != nil {
		alg = fmt.Sprintf("%v", headers[HeaderAlgorithm])
	}

	kid := ""
	if headers[HeaderKeyID] != nil {
		kid = fmt.Sprintf("%v", headers[HeaderKeyID])
	}

	recHeaders := &RecipientHeaders{
		Alg: alg,
		KID: kid,
		EPK: epk,
	}

	// now delete from headers
	delete(headers, HeaderAlgorithm)
	delete(headers, HeaderKeyID)
	delete(headers, HeaderEPK)

	return recHeaders, nil
}

func convertMarshalledJWKToRecKey(marshalledJWK []byte) (*composite.RecipientWrappedKey, error) {
	jwk := &JWK{}

	err := jwk.UnmarshalJSON(marshalledJWK)
	if err != nil {
		return nil, err
	}

	epk := composite.PublicKey{
		Curve: jwk.Crv,
		Type:  jwk.Kty,
	}

	switch key := jwk.Key.(type) {
	case *ecdsa.PublicKey:
		epk.X = key.X.Bytes()
		epk.Y = key.Y.Bytes()
	default:
		return nil, fmt.Errorf("unsupported recipient key type")
	}

	return &composite.RecipientWrappedKey{
		KID: jwk.KeyID,
		EPK: epk,
	}, nil
}
