package verifiable

import (
	"fmt"
)

// AddLinkedDataProof appends proof to the Verifiable Credential.
func (vc *Credential) AddLinkedDataProof(context *LinkedDataProofContext) error {
	vcBytes, err := vc.MarshalJSON()
	if err != nil {
		return fmt.Errorf("add linked data proof to VC: %w", err)
	}

	proofs, err := addLinkedDataProof(context, vcBytes)
	if err != nil {
		return err
	}

	vc.Proofs = proofs

	return nil
}
