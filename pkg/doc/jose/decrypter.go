/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jose

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/tink/go/keyset"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/api"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh1pu"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdhes"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// Decrypter interface to Decrypt JWE messages.
type Decrypter interface {
	// Decrypt a deserialized JWE, extracts the corresponding recipient key to decrypt plaintext and returns it
	Decrypt(jwe *JSONWebEncryption) ([]byte, error)
}

type decPrimitiveFunc func(*keyset.Handle) (api.CompositeDecrypt, error)

// JWEDecrypt is responsible for decrypting a JWE message and returns its protected plaintext.
type JWEDecrypt struct {
	recipientKH  *keyset.Handle
	getPrimitive decPrimitiveFunc
	// store is required for Authcrypt/ECDH1PU only (Anoncrypt doesn't as the sender is anonymous)
	store storage.Store
}

// NewJWEDecrypt creates a new JWEDecrypt instance to parse and decrypt a JWE message for a given recipient
// store is needed for Authcrypt only (to fetch sender's pre agreed upon public key), it is not needed for Anoncrypt.
func NewJWEDecrypt(store storage.Store, recipientKH *keyset.Handle) *JWEDecrypt {
	return &JWEDecrypt{
		recipientKH:  recipientKH,
		getPrimitive: getECDHESDecPrimitive,
		store:        store,
	}
}

func getECDHESDecPrimitive(recipientKH *keyset.Handle) (api.CompositeDecrypt, error) {
	return ecdhes.NewECDHESDecrypt(recipientKH)
}

func getECDH1PUDecPrimitive(recipientKH *keyset.Handle) (api.CompositeDecrypt, error) {
	return ecdh1pu.NewECDH1PUDecrypt(recipientKH)
}

// Decrypt a deserialized JWE, decrypts its protected content and returns plaintext.
func (jd *JWEDecrypt) Decrypt(jwe *JSONWebEncryption) ([]byte, error) {
	var (
		err              error
		protectedHeaders Headers
		encAlg           string
	)

	protectedHeaders, encAlg, err = jd.validateAndExtractProtectedHeaders(jwe)
	if err != nil {
		return nil, fmt.Errorf("jwedecrypt: %w", err)
	}

	skid, ok := protectedHeaders.SenderKeyID()
	if ok {
		err = jd.addSenderKey(skid)
		if err != nil {
			return nil, fmt.Errorf("jwedecrypt: failed to add sender key: %w", err)
		}

		jd.getPrimitive = getECDH1PUDecPrimitive
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

func (jd *JWEDecrypt) fetchSenderPubKey(skid string) (*composite.PublicKey, error) {
	mKey, err := jd.store.Get(skid)
	if err != nil {
		return nil, fmt.Errorf("failed to get sender key from DB: %w", err)
	}

	var senderKey *composite.PublicKey

	err = json.Unmarshal(mKey, &senderKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal sender key from DB: %w", err)
	}

	return senderKey, nil
}

func (jd *JWEDecrypt) addSenderKey(skid string) error {
	var senderPubKey *composite.PublicKey

	// addSenderKey requires the store where to fetch the sender public key
	if jd.store == nil {
		return errors.New("unable to decrypt JWE with 'skid' header, third party key store is nil")
	}

	senderPubKey, err := jd.fetchSenderPubKey(skid)
	if err != nil {
		return err
	}

	jd.recipientKH, err = ecdh1pu.AddSenderKey(jd.recipientKH, senderPubKey)
	if err != nil {
		return err
	}

	return nil
}

func (jd *JWEDecrypt) validateAndExtractProtectedHeaders(jwe *JSONWebEncryption) (Headers, string, error) {
	if jwe == nil {
		return nil, "", fmt.Errorf("jwe is nil")
	}

	protectedHeaders := jwe.ProtectedHeaders

	encAlg, ok := protectedHeaders.Encryption()
	if !ok {
		return nil, "", fmt.Errorf("jwe is missing encryption algorithm 'enc' header")
	}

	// TODO add support for Chacha content encryption, issue #1684
	switch encAlg {
	case string(A256GCM):
	default:
		return nil, "", fmt.Errorf("encryption algorithm '%s' not supported", encAlg)
	}

	return protectedHeaders, encAlg, nil
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

// extractRecipientHeaders will extract RecipientHeaders from headers argument.
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
