/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"fmt"

	diddoc "github.com/hyperledger/aries-framework-go/component/models/did"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	vdrspi "github.com/hyperledger/aries-framework-go/spi/vdr"
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

// Update did doc.
func (v *VDR) Update(didDoc *diddoc.Doc, opts ...vdrspi.DIDMethodOption) error {
	return fmt.Errorf("not supported")
}

// Deactivate did doc.
func (v *VDR) Deactivate(did string, opts ...vdrspi.DIDMethodOption) error {
	return fmt.Errorf("not supported")
}

// Accept did method.
func (v *VDR) Accept(method string, opts ...vdrspi.DIDMethodOption) bool {
	return method == DIDMethod
}
