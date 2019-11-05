/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	chacha "golang.org/x/crypto/chacha20poly1305"
)

// decryptSPK will decrypt a recipient's encrypted SPK (in the case of this package, it is represented as
// the sender's public key as a jwk). It uses the recipent's private/public keypair for decryption
// the returned decrypted value is the sender's public key
func (c *Crypter) decryptSPK(recipientPubKey *[chacha.KeySize]byte, spk string) ([]byte, error) {
	jwe := strings.Split(spk, ".")
	if len(jwe) != 5 {
		return nil, fmt.Errorf("bad SPK format")
	}

	headersEncoded := jwe[0]

	headers, err := base64.RawURLEncoding.DecodeString(headersEncoded)
	if err != nil {
		return nil, err
	}

	headersJSON := &recipientSPKJWEHeaders{
		EPK: jwk{},
	}

	err = json.Unmarshal(headers, headersJSON)
	if err != nil {
		return nil, err
	}

	cipherKEK, err := base64.RawURLEncoding.DecodeString(jwe[1])
	if err != nil {
		return nil, err
	}

	nonce, err := base64.RawURLEncoding.DecodeString(jwe[2])
	if err != nil {
		return nil, err
	}

	cipherJWK, err := base64.RawURLEncoding.DecodeString(jwe[3])
	if err != nil {
		return nil, err
	}

	tag, err := base64.RawURLEncoding.DecodeString(jwe[4])
	if err != nil {
		return nil, err
	}

	sharedKey, err := c.decryptJWKSharedKey(cipherKEK, headersJSON, recipientPubKey[:])
	if err != nil {
		return nil, err
	}

	// now that we have sharedKey, let's decrypt the sender JWK (cipherJWK)
	return c.decryptSenderJWK(nonce, sharedKey, []byte(headersEncoded), cipherJWK, tag)
}

// decryptJWKSharedKey will decrypt the cek using recPrivKey for decryption and rebuild the cipher text, nonce
// kek from headersJSON, the result is the sharedKey to be used for decrypting the sender JWK
func (c *Crypter) decryptJWKSharedKey(cipherKEK []byte, headersJSON *recipientSPKJWEHeaders, recPubKey []byte) ([]byte, error) { //nolint:lll
	epk, err := base64.RawURLEncoding.DecodeString(headersJSON.EPK.X)
	if err != nil {
		return nil, err
	}

	kek, err := c.kms.DeriveKEK([]byte(c.alg+"KW"), nil, recPubKey, epk)
	if err != nil {
		return nil, err
	}

	// create a cipher for the given nonceSize and generated kek above
	// to decrypt the symmetric shared key (by decrypting cipherKEK)
	crypter, err := createCipher(c.nonceSize, kek)
	if err != nil {
		return nil, err
	}

	// fetch symmetric shared key crypto info (kek's tag and nonce)
	kekTag, err := base64.RawURLEncoding.DecodeString(headersJSON.Tag)
	if err != nil {
		return nil, err
	}

	kekNonce, err := base64.RawURLEncoding.DecodeString(headersJSON.IV)
	if err != nil {
		return nil, err
	}

	// assemble kek for decryption
	cipherKEK = append(cipherKEK, kekTag...)

	symKey, err := crypter.Open(nil, kekNonce, cipherKEK, nil)
	if err != nil {
		return nil, err
	}

	return symKey, nil
}

// decryptSenderJWK will decrypt and extract the sender key from cipherJwk, tag and nonce using symKey for decryption
// and headersEncoded as AAD for the aead (chacha20poly1305) cipher
func (c *Crypter) decryptSenderJWK(nonce, symKey, headersEncoded, cipherJWK, tag []byte) ([]byte, error) {
	// now that we have symKey, let's decrypt the sender JWK (cipherJWK)
	jwkCrypter, err := createCipher(c.nonceSize, symKey)
	if err != nil {
		return nil, err
	}

	// assemble cipher JWK for decryption
	cipherTxt := append(cipherJWK, tag...)

	senderJWKJSONEncoded, err := jwkCrypter.Open(nil, nonce, cipherTxt, headersEncoded)
	if err != nil {
		return nil, err
	}

	senderJWK := &jwk{}

	err = json.Unmarshal(senderJWKJSONEncoded, senderJWK)
	if err != nil {
		return nil, err
	}

	senderKey, err := base64.RawURLEncoding.DecodeString(senderJWK.X)
	if err != nil {
		return nil, err
	}

	return senderKey, nil
}
