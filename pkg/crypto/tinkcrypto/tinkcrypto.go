/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package tinkcrypto provides the default implementation of the
// common pkg/common/api/crypto.Crypto interface and the SPI pkg/framework/aries.crypto interface
//
// It uses github.com/tink/go crypto primitives
package tinkcrypto

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto"
)

const (
	// ECDHESA256KWAlg is the ECDH-ES with AES-GCM 256 key wrapping algorithm.
	ECDHESA256KWAlg = tinkcrypto.ECDHESA256KWAlg
	// ECDH1PUA128KWAlg is the ECDH-1PU with AES-CBC 128+HMAC-SHA 256 key wrapping algorithm.
	ECDH1PUA128KWAlg = tinkcrypto.ECDH1PUA128KWAlg
	// ECDH1PUA192KWAlg is the ECDH-1PU with AES-CBC 192+HMAC-SHA 384 key wrapping algorithm.
	ECDH1PUA192KWAlg = tinkcrypto.ECDH1PUA192KWAlg
	// ECDH1PUA256KWAlg is the ECDH-1PU with AES-CBC 256+HMAC-SHA 512 key wrapping algorithm.
	ECDH1PUA256KWAlg = tinkcrypto.ECDH1PUA256KWAlg
	// ECDHESXC20PKWAlg is the ECDH-ES with XChacha20Poly1305 key wrapping algorithm.
	ECDHESXC20PKWAlg = tinkcrypto.ECDHESXC20PKWAlg
	// ECDH1PUXC20PKWAlg is the ECDH-1PU with XChacha20Poly1305 key wrapping algorithm.
	ECDH1PUXC20PKWAlg = tinkcrypto.ECDH1PUXC20PKWAlg
)

// Package tinkcrypto includes the default implementation of pkg/crypto. It uses Tink for executing crypto primitives
// and will be built as a framework option. It represents the main crypto service in the framework. `kh interface{}`
// arguments in this implementation represent Tink's `*keyset.Handle`, using this type provides easy integration with
// Tink and the default KMS service.

// Crypto is the default Crypto SPI implementation using Tink.
type Crypto = tinkcrypto.Crypto

// New creates a new Crypto instance.
func New() (*Crypto, error) {
	return tinkcrypto.New()
}
