/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key

import (
	"github.com/hyperledger/aries-framework-go/component/vdr/key"
)

const (
	// DIDMethod did method.
	DIDMethod = "key"
	// EncryptionKey encryption key.
	EncryptionKey = "encryptionKey"
	// KeyType option to create a new kms key for DIDDocs with empty VerificationMethod.
	KeyType = "keyType"
)

// VDR implements did:key method support.
type VDR = key.VDR

// New returns new instance of VDR that works with did:key method.
func New() *VDR {
	return key.New()
}
