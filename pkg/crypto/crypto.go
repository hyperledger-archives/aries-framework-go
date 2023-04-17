/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package crypto contains the Crypto interface to be used by the framework.
// It will be created via Options creation in pkg/framework/context.Provider.
// BBS+ signature scheme is not included in the main Crypto interface.
// It is defined separately under the primitive sub-package including its implementation which should not be referenced
// directly. It is accessible via the framework's KMS BBS+ keys and tinkcrypto's bbs package's Signer and Verifier
// primitives or via webkms for remote KMS BBS+ signing.
package crypto

import (
	"crypto/ecdsa"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto"
	cryptoapi "github.com/hyperledger/aries-framework-go/spi/crypto"
)

// Crypto interface provides all crypto operations needed in the Aries framework.
type Crypto = cryptoapi.Crypto

// DefKeySize is the default key size for crypto primitives.
const DefKeySize = crypto.DefKeySize

// RecipientWrappedKey contains recipient key material required to unwrap CEK.
type RecipientWrappedKey = cryptoapi.RecipientWrappedKey

// PublicKey mainly to exchange EPK in RecipientWrappedKey.
type PublicKey = cryptoapi.PublicKey

// PrivateKey mainly used to exchange ephemeral private key in JWE encrypter.
type PrivateKey = cryptoapi.PrivateKey

// ToECKey converts key to an ecdsa public key. It returns an error if the curve is invalid.
func ToECKey(key *PublicKey) (*ecdsa.PublicKey, error) {
	return crypto.ToECKey(key)
}

// WrapKeyOpts are the crypto.Wrap key options.
type WrapKeyOpts = cryptoapi.WrapKeyOpts

// WithSender option is for setting a sender key with crypto wrapping (eg: AuthCrypt). For Anoncrypt,
// this option must not be set.
// Sender is a key used for ECDH-1PU key agreement for authenticating the sender.
// senderkey can be of the following there types:
//   - *keyset.Handle (requires private key handle for crypto.WrapKey())
//   - *crypto.PublicKey (available for UnwrapKey() only)
//   - *ecdsa.PublicKey (available for UnwrapKey() only)
func WithSender(senderKey interface{}) WrapKeyOpts {
	return cryptoapi.WithSender(senderKey)
}

// WithXC20PKW option is a flag option for crypto wrapping. When used, key wrapping will use XChacha20Poly1305
// encryption as key wrapping. The absence of this option (default) uses AES256-GCM encryption as key wrapping. The KDF
// used in the crypto wrapping function is selected based on the type of recipient key argument of KeyWrap(), it is
// independent of this option.
func WithXC20PKW() WrapKeyOpts {
	return cryptoapi.WithXC20PKW()
}

// WithTag option is to instruct the key wrapping function of the authentication tag to be used in the wrapping process.
// It is mainly used with CBC+HMAC content encryption to authenticate the sender of an encrypted JWE message (ie
// authcrypt/ECDH-1PU). The absence of this option means the sender's identity is not revealed (ie anoncrypt/ECDH-ES).
func WithTag(tag []byte) WrapKeyOpts {
	return cryptoapi.WithTag(tag)
}

// WithEPK option is to instruct the key wrapping function of the ephemeral key to be used in the wrapping process.
// It is mainly used for ECDH-1PU during KDF. This option allows passing a predefined EPK instead of generating a new
// one when wrapping. It is useful for Wrap() call only since Unwrap() already uses a predefined EPK. The absence of
// this option means a new EPK will be generated internally.
func WithEPK(epk *PrivateKey) WrapKeyOpts {
	return cryptoapi.WithEPK(epk)
}
