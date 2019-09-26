/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"encoding/base64"
	"encoding/json"

	chacha "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/box"
)

// generateSPK will encrypt a msg (in the case of this package, it will be
// the sender's public key) using the recipient's pubKey, the output will be
// a full JWE wrapping a JWK containing the (encrypted) sender's public key
func (c *Crypter) generateSPK(recipientPubKey, senderPubKey *[chacha.KeySize]byte) (string, error) {
	if recipientPubKey == nil {
		return "", errInvalidKey
	}

	// generate ephemeral asymmetric keys
	epk, esk, err := box.GenerateKey(randReader)
	if err != nil {
		return "", err
	}

	// create a new ephemeral key for the recipient
	kek, err := c.generateKEK([]byte(c.alg+"KW"), nil, esk, recipientPubKey)
	if err != nil {
		return "", err
	}

	// generate a sharedSymKey for encryption
	sharedSymKey := &[chacha.KeySize]byte{}
	_, err = randReader.Read(sharedSymKey[:])
	if err != nil {
		return "", err
	}

	kCipherEncoded, kTagEncoded, kNonceEncoded, err := c.encryptSymKey(kek, sharedSymKey[:])
	if err != nil {
		return "", err
	}

	headersEncoded, err := c.buildJWKHeaders(epk, kNonceEncoded, kTagEncoded)
	if err != nil {
		return "", err
	}

	// build sender key as jwk header
	senderJWK := jwk{
		Kty: "OKP", // OPK not 0PK
		Crv: "X25519",
		X:   base64.RawURLEncoding.EncodeToString(senderPubKey[:]),
	}
	// senderJWKJSON is the payload to be encrypted with sharedSymKey
	senderJWKJSON, err := json.Marshal(senderJWK)
	if err != nil {
		return "", err
	}

	return c.encryptSenderJWK(kCipherEncoded, headersEncoded, senderJWKJSON, sharedSymKey[:])
}

func (c *Crypter) buildJWKHeaders(epk *[32]byte, kNonceEncoded, kTagEncoded string) (string, error) {
	headers := recipientJWKHeaders{
		Typ: "jose",
		CTY: "jwk+json",
		Alg: "ECDH-ES+" + string(c.alg) + "KW",
		Enc: string(c.alg),
		EPK: jwk{
			Kty: "OKP", // OPK not 0PK
			Crv: "X25519",
			X:   base64.RawURLEncoding.EncodeToString(epk[:]),
		},
		IV:  kNonceEncoded,
		Tag: kTagEncoded,
	}

	headersJSON, err := json.Marshal(headers)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(headersJSON), nil
}

func (c *Crypter) encryptSenderJWK(encKey, headers string, senderJWKJSON, sharedSymKey []byte) (string, error) {
	// create a new nonce
	nonce := make([]byte, c.nonceSize)
	_, err := randReader.Read(nonce)
	if err != nil {
		return "", err
	}

	// create a cipher for the given nonceSize and generated sharedSymKey above
	crypter, err := createCipher(c.nonceSize, sharedSymKey)
	if err != nil {
		return "", err
	}

	// encrypt the sender's encoded JWK using generated nonce and JWK encoded headers as AAD
	// the output is a []byte containing the cipherText + tag
	symOutput := crypter.Seal(nil, nonce, senderJWKJSON, []byte(headers))

	tagEncoded := extractTag(symOutput)
	cipherJWKEncoded := extractCipherText(symOutput)

	return headers + "." +
			encKey + "." +
			base64.RawURLEncoding.EncodeToString(nonce) + "." +
			cipherJWKEncoded + "." +
			tagEncoded,
		nil
}
