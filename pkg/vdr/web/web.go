/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package web

import (
	"github.com/hyperledger/aries-framework-go/component/vdr/web"
)

const (
	// HTTPClientOpt http client opt.
	HTTPClientOpt = web.HTTPClientOpt

	// UseHTTPOpt use http option.
	UseHTTPOpt = web.UseHTTPOpt
)

// VDR implements the VDR interface.
type VDR = web.VDR

// New creates a new VDR struct.
func New() *VDR {
	return web.New()
}
