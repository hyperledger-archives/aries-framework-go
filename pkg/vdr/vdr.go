/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdr

import (
	"github.com/hyperledger/aries-framework-go/component/vdr"
	vdrapi "github.com/hyperledger/aries-framework-go/component/vdr/api"
)

// Option is a vdr instance option.
type Option = vdr.Option

// Registry vdr registry.
type Registry = vdr.Registry

// New return new instance of vdr.
func New(opts ...Option) *Registry {
	return vdr.New(opts...)
}

// WithVDR adds did method implementation for store.
func WithVDR(method vdrapi.VDR) Option {
	return vdr.WithVDR(method)
}

// WithDefaultServiceType is default service type for this creator.
func WithDefaultServiceType(serviceType string) Option {
	return vdr.WithDefaultServiceType(serviceType)
}

// WithDefaultServiceEndpoint allows for setting default service endpoint.
func WithDefaultServiceEndpoint(serviceEndpoint string) Option {
	return vdr.WithDefaultServiceEndpoint(serviceEndpoint)
}

// GetDidMethod get did method.
func GetDidMethod(didID string) (string, error) {
	return vdr.GetDidMethod(didID)
}
