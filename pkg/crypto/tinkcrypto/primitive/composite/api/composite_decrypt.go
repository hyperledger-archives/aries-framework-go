/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/api"

// CompositeDecrypt will decrypt a `ciphertext` representing a composite encryption with a protected cek for the
// recipient caller of this interface. In order to get the plaintext embedded, this type is configured with the
// recipient key type that will decrypt the embedded cek first.
type CompositeDecrypt = api.CompositeDecrypt
