/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package web

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

// Store method (unsupported at the moment).
func (v *VDR) Store(doc *did.Doc) error {
	return fmt.Errorf("error storing did:web did doc --> store not supported in http binding vdr")
}
