/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/deactivate"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/recovery"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/update"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	// StoreNamespace store name space for DID Store.
	StoreNamespace = "peer"
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
