//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import (
	"github.com/hyperledger/ursa-wrapper-go/pkg/libursa/ursa"
)

type CredentialDefinition struct {
	CredPubKey              *ursa.CredentialDefPubKey
	CredDefCorrectnessProof *ursa.CredentialDefKeyCorrectnessProof
	Attrs                   []string
}

func (s *CredentialDefinition) Free() error {
	err := s.CredPubKey.Free()
	if err != nil {
		return err
	}
	err = s.CredDefCorrectnessProof.Free()
	if err != nil {
		return err
	}
	return nil
}

type CredentialOffer struct {
	Nonce *ursa.Nonce
}

func (s *CredentialOffer) Free() error {
	err := s.Nonce.Free()
	if err != nil {
		return err
	}
	return nil
}

type CredentialRequest struct {
	BlindedCredentialSecrets *ursa.BlindedCredentialSecrets
	Nonce                    *ursa.Nonce
	ProverId                 string
}

func (s *CredentialRequest) Free() error {
	err := s.BlindedCredentialSecrets.Handle.Free()
	if err != nil {
		return err
	}
	err = s.BlindedCredentialSecrets.BlindingFactor.Free()
	if err != nil {
		return err
	}
	err = s.BlindedCredentialSecrets.CorrectnessProof.Free()
	if err != nil {
		return err
	}
	err = s.Nonce.Free()
	if err != nil {
		return err
	}
	return nil
}

type Credential struct {
	Signature *ursa.CredentialSignature
	Values    map[string]interface{}
	SigProof  *ursa.CredentialSignatureCorrectnessProof
}

func (s *Credential) Free() error {
	err := s.Signature.Free()
	if err != nil {
		return err
	}
	err = s.SigProof.Free()
	if err != nil {
		return err
	}
	return nil
}

type PresentationRequest struct {
	Items []*PresentationRequestItem
	Nonce *ursa.Nonce
}

func (s *PresentationRequest) Free() error {
	err := s.Nonce.Free()
	if err != nil {
		return err
	}
	return nil
}

type PresentationRequestItem struct {
	RevealedAttrs []string
	Predicates    []*Predicate
}

type Predicate struct {
	Attr  string
	PType string
	Value int32
}

type Proof struct {
	Proof     *ursa.ProofHandle
	SubProofs []*SubProof
}

func (s *Proof) Free() error {
	err := s.Proof.Free()
	if err != nil {
		return err
	}
	for _, subProof := range s.SubProofs {
		err = subProof.Free()
		if err != nil {
			return err
		}
	}
	return nil
}

type SubProof struct {
	SubProof *ursa.SubProofRequestHandle
	Attrs    []string
}

func (s *SubProof) Free() error {
	err := s.SubProof.Free()
	if err != nil {
		return err
	}
	return nil
}
