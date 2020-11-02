/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package web

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
