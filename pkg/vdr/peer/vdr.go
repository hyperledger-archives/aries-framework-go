/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"fmt"

	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/spi/storage"
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
func (v *VDR) Update(didDoc *diddoc.Doc, opts ...vdrapi.DIDMethodOption) error {
	return fmt.Errorf("not supported")
}

// Deactivate did doc.
func (v *VDR) Deactivate(did string, opts ...vdrapi.DIDMethodOption) error {
	return fmt.Errorf("not supported")
}

// Accept did method.
func (v *VDR) Accept(method string, opts ...vdrapi.DIDMethodOption) bool {
	return method == DIDMethod
}
