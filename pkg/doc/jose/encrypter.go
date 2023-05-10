/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jose

import (
	"github.com/google/tink/go/keyset"

	jose2 "github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	cryptoapi "github.com/hyperledger/aries-framework-go/spi/crypto"
)

// EncAlg represents the JWE content encryption algorithm.
type EncAlg = jose2.EncAlg

const (
	// A256GCM for AES256GCM content encryption.
	A256GCM = EncAlg(A256GCMALG)
	// XC20P for XChacha20Poly1305 content encryption.
	XC20P = EncAlg(XC20PALG)
	// A128CBCHS256 for A128CBC-HS256 (AES128-CBC+HMAC-SHA256) content encryption.
	A128CBCHS256 = EncAlg(A128CBCHS256ALG)
	// A192CBCHS384 for A192CBC-HS384 (AES192-CBC+HMAC-SHA384) content encryption.
	A192CBCHS384 = EncAlg(A192CBCHS384ALG)
	// A256CBCHS384 for A256CBC-HS384 (AES256-CBC+HMAC-SHA384) content encryption.
	A256CBCHS384 = EncAlg(A256CBCHS384ALG)
	// A256CBCHS512 for A256CBC-HS512 (AES256-CBC+HMAC-SHA512) content encryption.
	A256CBCHS512 = EncAlg(A256CBCHS512ALG)
)

// Encrypter interface to Encrypt/Decrypt JWE messages.
type Encrypter = jose2.Encrypter

// JWEEncrypt is responsible for encrypting a plaintext and its AAD into a protected JWE and decrypting it.
type JWEEncrypt = jose2.JWEEncrypt

// NewJWEEncrypt creates a new JWEEncrypt instance to build JWE with recipientsPubKeys
// senderKID and senderKH are used for Authcrypt (to authenticate the sender), if not set JWEEncrypt assumes Anoncrypt.
func NewJWEEncrypt(encAlg EncAlg, envelopMediaType, cty, senderKID string, senderKH *keyset.Handle,
	recipientsPubKeys []*cryptoapi.PublicKey, crypto cryptoapi.Crypto) (*JWEEncrypt, error) {
	return jose2.NewJWEEncrypt(encAlg, envelopMediaType, cty, senderKID, senderKH, recipientsPubKeys, crypto)
}
