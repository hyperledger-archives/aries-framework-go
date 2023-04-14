//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"github.com/google/tink/go/keyset"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/cl/signer"
)

// ExportCredDefPubKey will export corresponding pubKey in bytes.
func ExportCredDefPubKey(kh *keyset.Handle) ([]byte, error) {
	return signer.ExportCredDefPubKey(kh)
}
