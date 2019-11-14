/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	// StoreNamespace store name space for DID Store
	StoreNamespace = "peer"
)

// Option configures the peer vdri
type Option func(opts *VDRI)

// VDRI implements building new peer dids
type VDRI struct {
	serviceEndpoint string
	serviceType     string
	store           storage.Store
}

// New return new instance of peer vdri
func New(s storage.Provider, opts ...Option) (*VDRI, error) {
	didDBStore, err := s.OpenStore(StoreNamespace)
	if err != nil {
		return nil, fmt.Errorf("open store : %w", err)
	}

	vdri := &VDRI{store: didDBStore}

	for _, option := range opts {
		option(vdri)
	}

	return vdri, nil
}

// Accept did method
func (v *VDRI) Accept(method string) bool {
	return method == didMethod
}

// WithCreatorServiceType is service type for this creator
func WithCreatorServiceType(serviceType string) Option {
	return func(opts *VDRI) {
		opts.serviceType = serviceType
	}
}

// WithCreatorServiceEndpoint allows for setting service endpoint
func WithCreatorServiceEndpoint(serviceEndpoint string) Option {
	return func(opts *VDRI) {
		opts.serviceEndpoint = serviceEndpoint
	}
}
