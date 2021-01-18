/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package web

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/deactivate"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/recovery"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/update"
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
func (v *VDR) Accept(method string) bool {
	return method == namespace
}

// Close method of the VDR interface.
func (v *VDR) Close() error {
	return nil
}

// Update DID Document.
func (v *VDR) Update(did string, opts ...update.Option) error {
	return fmt.Errorf("update not supported")
}

// Recover DID Document.
func (v *VDR) Recover(did string, opts ...recovery.Option) error {
	return fmt.Errorf("recover not supported")
}

// Deactivate DID Document.
func (v *VDR) Deactivate(did string, opts ...deactivate.Option) error {
	return fmt.Errorf("deactivate not supported")
}
