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
	// StoreNamespace store name space for DID Store.
	StoreNamespace = "peer"
	// DefaultServiceType default service type.
	DefaultServiceType = "defaultServiceType"
	// DefaultServiceEndpoint default service endpoint.
	DefaultServiceEndpoint = "defaultServiceEndpoint"
)

// VDR implements building new peer dids.
type VDR struct {
	store storage.Store
}

// New return new instance of peer vdr.
func New(s storage.Provider) (*VDR, error) {
	didDBStore, err := s.OpenStore(StoreNamespace)
	if err != nil {
		return nil, fmt.Errorf("open store : %w", err)
	}

	return &VDR{store: didDBStore}, nil
}

// Accept did method.
func (v *VDR) Accept(method string) bool {
	return method == DIDMethod
}
