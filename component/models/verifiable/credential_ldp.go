/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/component/models/ld/processor"
)

// AddLinkedDataProof appends proof to the Verifiable Credential.
func (vc *Credential) AddLinkedDataProof(context *LinkedDataProofContext, jsonldOpts ...processor.Opts) error {
	vcBytes, err := vc.MarshalJSON()
	if err != nil {
		return fmt.Errorf("add linked data proof to VC: %w", err)
	}

	proofs, err := addLinkedDataProof(context, vcBytes, jsonldOpts...)
	if err != nil {
		return err
	}

	vc.Proofs = proofs

	return nil
}
