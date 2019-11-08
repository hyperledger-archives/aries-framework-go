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

	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
)

// generateSPK will encrypt a msg (in the case of this package, it will be
// the sender's public key) using the recipient's pubKey, the output will be
// a compact JWE wrapping a JWK containing the (encrypted) sender's public key
func (p *Packer) generateSPK(recipientPubKey, senderPubKey *[chacha.KeySize]byte) (string, error) {
	if recipientPubKey == nil {
		return "", cryptoutil.ErrInvalidKey
	}

	// generate ephemeral asymmetric keys
	epk, esk, err := box.GenerateKey(randReader)
	if err != nil {
		return "", err
	}

	// derive an ephemeral key for the recipient and an ephemeral secret key (esk)
	kek, err := cryptoutil.Derive25519KEK([]byte(p.alg+"KW"), nil, esk, recipientPubKey)
	if err != nil {
		return "", err
	}

	// generate a cek for encryption
	cek := &[chacha.KeySize]byte{}

	_, err = randReader.Read(cek[:])
	if err != nil {
		return "", err
	}

	kCipherEncoded, kTagEncoded, kNonceEncoded, err := p.encryptCEK(kek, cek[:])
	if err != nil {
		return "", err
	}

	headersEncoded, err := p.buildJWKHeaders(epk, kNonceEncoded, kTagEncoded)
	if err != nil {
		return "", err
	}

	// build sender key as a jwk formatted header
	senderJWK := jwk{
		Kty: "OKP", // OPK not 0PK
		Crv: "X25519",
		X:   base64.RawURLEncoding.EncodeToString(senderPubKey[:]),
	}
	// senderJWKJSON is the payload to be encrypted with cek
	senderJWKJSON, err := json.Marshal(senderJWK)
	if err != nil {
		return "", err
	}

	return p.encryptSenderJWK(kCipherEncoded, headersEncoded, senderJWKJSON, cek[:])
}

func (p *Packer) buildJWKHeaders(epk *[32]byte, kNonceEncoded, kTagEncoded string) (string, error) {
	headers := recipientSPKJWEHeaders{
		Typ: "jose",
		CTY: "jwk+json",
		Alg: "ECDH-ES+" + string(p.alg) + "KW",
		Enc: string(p.alg),
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

func (p *Packer) encryptSenderJWK(encKey, headers string, senderJWKJSON, cek []byte) (string, error) {
	// create a new nonce
	nonce := make([]byte, p.nonceSize)

	_, err := randReader.Read(nonce)
	if err != nil {
		return "", err
	}

	// create a cipher for the given nonceSize and cek
	cipher, err := createCipher(p.nonceSize, cek)
	if err != nil {
		return "", err
	}

	// encrypt the sender's encoded JWK using generated nonce and JWK encoded headers as AAD
	// the output is a []byte containing the cipherText + tag
	symOutput := cipher.Seal(nil, nonce, senderJWKJSON, []byte(headers))

	tagEncoded := extractTag(symOutput)
	cipherJWKEncoded := extractCipherText(symOutput)

	return headers + "." +
			encKey + "." +
			base64.RawURLEncoding.EncodeToString(nonce) + "." +
			cipherJWKEncoded + "." +
			tagEncoded,
		nil
}
