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
)

// VDRI implements building new peer dids.
type VDRI struct {
	store storage.Store
}

// New return new instance of peer vdri.
func New(s storage.Provider) (*VDRI, error) {
	didDBStore, err := s.OpenStore(StoreNamespace)
	if err != nil {
		return nil, fmt.Errorf("open store : %w", err)
	}

	return &VDRI{store: didDBStore}, nil
}

// Accept did method.
func (v *VDRI) Accept(method string) bool {
	return method == didMethod
}
