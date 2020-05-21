/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
)

const didMethod = "key"

// VDRI implements did:key method support.
type VDRI struct {
}

// New returns new instance of VDRI that works with did:key method.
func New() *VDRI {
	return &VDRI{}
}

// Accept accepts did:key method.
func (v *VDRI) Accept(method string) bool {
	return method == didMethod
}

// Store saves a DID Document along with user key/signature.
func (v *VDRI) Store(doc *did.Doc, by *[]vdri.ModifiedBy) error {
	return nil
}

// Close frees resources being maintained by VDRI.
func (v *VDRI) Close() error {
	return nil
}
