/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package web

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
)

// Build creates a did:web diddoc (unsupported at the moment).
func (v *VDR) Build(pubKey *vdr.PubKey, opts ...vdr.DocOpts) (*did.Doc, error) {
	return nil, fmt.Errorf("error building did:web did doc --> build not supported in http binding vdr")
}
