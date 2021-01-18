/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/deactivate"
	vdrdoc "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/doc"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/recovery"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/update"
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
func (v *VDR) Store(doc *did.Doc, by *[]vdrdoc.ModifiedBy) error {
	return nil
}

// Close frees resources being maintained by VDR.
func (v *VDR) Close() error {
	return nil
}

// Update DID Document.
func (v *VDR) Update(didID string, opts ...update.Option) error {
	return fmt.Errorf("update not supported")
}

// Recover DID Document.
func (v *VDR) Recover(didID string, opts ...recovery.Option) error {
	return fmt.Errorf("recover not supported")
}

// Deactivate DID Document.
func (v *VDR) Deactivate(didID string, opts ...deactivate.Option) error {
	return fmt.Errorf("deactivate not supported")
}
