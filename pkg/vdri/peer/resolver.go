/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
)

// Read implements didresolver.DidMethod.Read interface (https://w3c-ccg.github.io/did-resolution/#resolving-input)
func (v *VDRI) Read(didID string, _ ...vdriapi.ResolveOpts) (*did.Doc, error) {
	// get the document from the store
	doc, err := v.Get(didID)
	if err != nil {
		return nil, fmt.Errorf("fetching data from store failed: %w", err)
	}

	if doc == nil {
		return nil, vdriapi.ErrNotFound
	}

	return doc, nil
}
