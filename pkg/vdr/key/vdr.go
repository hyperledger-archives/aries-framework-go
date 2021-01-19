/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key

const (

	// DIDMethod did method.
	DIDMethod = "key"
	// EncryptionKey encryption key.
	EncryptionKey = "encryptionKey"
)

// VDR implements did:key method support.
type VDR struct {
}

// New returns new instance of VDR that works with did:key method.
func New() *VDR {
	return &VDR{}
}

// Accept accepts did:key method.
func (v *VDR) Accept(method string) bool {
	return method == DIDMethod
}

// Close frees resources being maintained by VDR.
func (v *VDR) Close() error {
	return nil
}
