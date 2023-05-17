/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/component/models/did"
	vdrapi "github.com/hyperledger/aries-framework-go/component/vdr/api"
	vdrspi "github.com/hyperledger/aries-framework-go/spi/vdr"
)

// Read implements didresolver.DidMethod.Read interface (https://w3c-ccg.github.io/did-resolution/#resolving-input)
func (v *VDR) Read(didID string, _ ...vdrspi.DIDMethodOption) (*did.DocResolution, error) {
	// get the document from the store
	doc, err := v.Get(didID)
	if err != nil {
		return nil, fmt.Errorf("fetching data from store failed: %w", err)
	}

	if doc == nil {
		return nil, vdrapi.ErrNotFound
	}

	return &did.DocResolution{Context: []string{schemaResV1}, DIDDocument: doc}, nil
}
