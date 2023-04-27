/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	mockcrypto "github.com/hyperledger/aries-framework-go/component/kmscrypto/mock/crypto"
)

// SignFunc mocks Crypto's Sign() function, it's useful for executing custom signing with the help of SignKey.
type SignFunc = mockcrypto.SignFunc

// BBSSignFunc mocks Crypto's BBSSign() function, it's useful for executing custom BBS+ signing with the help of
// Signing private Key.
type BBSSignFunc = mockcrypto.BBSSignFunc

// DeriveProofFunc mocks Crypto's DeriveProofFunc() function, it's useful for executing custom BBS+ signing with the
// help of Signing public Key.
type DeriveProofFunc = mockcrypto.DeriveProofFunc

// Crypto mock.
type Crypto = mockcrypto.Crypto
