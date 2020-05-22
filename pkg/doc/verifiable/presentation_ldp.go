/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
)

// AddLinkedDataProof appends proof to the Verifiable Presentation.
func (vp *Presentation) AddLinkedDataProof(context *LinkedDataProofContext, jsonldOpts ...jsonld.ProcessorOpts) error {
	vcBytes, err := vp.MarshalJSON()
	if err != nil {
		return fmt.Errorf("add linked data proof to VP: %w", err)
	}

	proofs, err := addLinkedDataProof(context, vcBytes, jsonldOpts...)
	if err != nil {
		return err
	}

	vp.Proofs = proofs

	return nil
}
