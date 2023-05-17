/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package web

import (
	"fmt"

	diddoc "github.com/hyperledger/aries-framework-go/component/models/did"
	vdrspi "github.com/hyperledger/aries-framework-go/spi/vdr"
)

const (
	namespace = "web"
)

// VDR implements the VDR interface.
type VDR struct{}

// New creates a new VDR struct.
func New() *VDR {
	return &VDR{}
}

// Accept method of the VDR interface.
func (v *VDR) Accept(method string, opts ...vdrspi.DIDMethodOption) bool {
	return method == namespace
}

// Update did doc.
func (v *VDR) Update(didDoc *diddoc.Doc, opts ...vdrspi.DIDMethodOption) error {
	return fmt.Errorf("not supported")
}

// Deactivate did doc.
func (v *VDR) Deactivate(did string, opts ...vdrspi.DIDMethodOption) error {
	return fmt.Errorf("not supported")
}

// Close method of the VDR interface.
func (v *VDR) Close() error {
	return nil
}
