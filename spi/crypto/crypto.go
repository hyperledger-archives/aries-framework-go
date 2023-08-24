/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package crypto contains the Crypto interface to be used by the framework.
// It will be created via Options creation in pkg/framework/context.Provider.
// BBS+ signature scheme is not included in the main Crypto interface.
// It is defined separately under the primitive sub-package including its implementation which should not be referenced
// directly. It is accessible via the framework's KMS BBS+ keys and tinkcrypto's bbs package's Signer and Verifier
// primitives or via webkms for remote KMS BBS+ signing.
package crypto

import "github.com/trustbloc/kms-go/spi/crypto"

// Crypto interface provides all crypto operations needed in the Aries framework.
type Crypto = crypto.Crypto

// RecipientWrappedKey contains recipient key material required to unwrap CEK.
type RecipientWrappedKey = crypto.RecipientWrappedKey

// PublicKey mainly to exchange EPK in RecipientWrappedKey.
type PublicKey = crypto.PublicKey

// PrivateKey mainly used to exchange ephemeral private key in JWE encrypter.
type PrivateKey = crypto.PrivateKey
