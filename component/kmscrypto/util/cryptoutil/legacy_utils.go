/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cryptoutil

import (
	"github.com/trustbloc/kms-go/util/cryptoutil"
)

// Nonce makes a nonce using blake2b, to match the format expected by libsodium.
func Nonce(pub1, pub2 []byte) (*[NonceSize]byte, error) {
	return cryptoutil.Nonce(pub1, pub2)
}
