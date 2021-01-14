/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package web

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/create"
)

// Build creates a did:web diddoc (unsupported at the moment).
func (v *VDR) Build(opts ...create.Option) (*did.Doc, error) {
	return nil, fmt.Errorf("error building did:web did doc --> build not supported in http binding vdr")
}
