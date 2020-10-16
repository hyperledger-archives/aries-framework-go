/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
)

// Read implements didresolver.DidMethod.Read interface (https://w3c-ccg.github.io/did-resolution/#resolving-input)
func (v *VDR) Read(didID string, _ ...vdrapi.ResolveOpts) (*did.Doc, error) {
	// get the document from the store
	doc, err := v.Get(didID)
	if err != nil {
		return nil, fmt.Errorf("fetching data from store failed: %w", err)
	}

	if doc == nil {
		return nil, vdrapi.ErrNotFound
	}

	return doc, nil
}
