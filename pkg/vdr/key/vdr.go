/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
)

const didMethod = "key"

// VDR implements did:key method support.
type VDR struct {
}

// New returns new instance of VDR that works with did:key method.
func New() *VDR {
	return &VDR{}
}

// Accept accepts did:key method.
func (v *VDR) Accept(method string) bool {
	return method == didMethod
}

// Store saves a DID Document along with user key/signature.
func (v *VDR) Store(doc *did.Doc, by *[]vdr.ModifiedBy) error {
	return nil
}

// Close frees resources being maintained by VDR.
func (v *VDR) Close() error {
	return nil
}
