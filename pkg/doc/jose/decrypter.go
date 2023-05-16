/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jose

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	resolver "github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/kidresolver"
	cryptoapi "github.com/hyperledger/aries-framework-go/spi/crypto"
	"github.com/hyperledger/aries-framework-go/spi/kms"
)

// Decrypter interface to Decrypt JWE messages.
type Decrypter = jose.Decrypter

// JWEDecrypt is responsible for decrypting a JWE message and returns its protected plaintext.
type JWEDecrypt = jose.JWEDecrypt

// NewJWEDecrypt creates a new JWEDecrypt instance to parse and decrypt a JWE message for a given recipient
// store is needed for Authcrypt only (to fetch sender's pre agreed upon public key), it is not needed for Anoncrypt.
func NewJWEDecrypt(kidResolvers []resolver.KIDResolver, c cryptoapi.Crypto, k kms.KeyManager) *JWEDecrypt {
	return jose.NewJWEDecrypt(kidResolvers, c, k)
}
