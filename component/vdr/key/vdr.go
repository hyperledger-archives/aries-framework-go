/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key

import (
	"fmt"

	diddoc "github.com/hyperledger/aries-framework-go/component/models/did"
	vdrapi "github.com/hyperledger/aries-framework-go/spi/vdr"
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
type VDR struct{}

// New returns new instance of VDR that works with did:key method.
func New() *VDR {
	return &VDR{}
}

// Accept accepts did:key method.
func (v *VDR) Accept(method string, opts ...vdrapi.DIDMethodOption) bool {
	return method == DIDMethod
}

// Close frees resources being maintained by VDR.
func (v *VDR) Close() error {
	return nil
}

// Update did doc.
func (v *VDR) Update(didDoc *diddoc.Doc, opts ...vdrapi.DIDMethodOption) error {
	return fmt.Errorf("not supported")
}

// Deactivate did doc.
func (v *VDR) Deactivate(didID string, opts ...vdrapi.DIDMethodOption) error {
	return fmt.Errorf("not supported")
}
