package verifiable

import (
	"fmt"
)

// AddLinkedDataProof appends proof to the Verifiable Presentation.
func (vp *Presentation) AddLinkedDataProof(context *LinkedDataProofContext) error {
	vcBytes, err := vp.MarshalJSON()
	if err != nil {
		return fmt.Errorf("add linked data proof to VP: %w", err)
	}

	proofs, err := addLinkedDataProof(context, vcBytes)
	if err != nil {
		return err
	}

	vp.Proofs = proofs

	return nil
}
