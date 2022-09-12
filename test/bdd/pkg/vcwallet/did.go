/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcwallet

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/peer"
)

const (
	jsonWebKey2020 = "JsonWebKey2020"
)

type creator struct {
	vdrRegistry vdrapi.Registry
}

func newCreator(vdr vdrapi.Registry) *creator {
	return &creator{
		vdrRegistry: vdr,
	}
}

func (s *SDKSteps) createDid(agent string) error {
	kid := s.keyIds[agent]
	vdr := s.bddContext.AgentCtx[agent].VDRegistry()

	didDoc, err := newCreator(vdr).CreatePeerDIDV2(kid, s.bddContext.PublicKeys[agent])
	if err != nil {
		return err
	}

	s.bddContext.PublicDIDDocs[agent] = didDoc
	s.bddContext.PublicDIDs[agent] = didDoc.ID

	return nil
}

func (s *SDKSteps) getPublicDID(agentName string) *did.Doc {
	return s.bddContext.PublicDIDDocs[agentName]
}

func (c *creator) CreatePeerDIDV2(kid string, jsonWebKey *jwk.JWK) (*did.Doc, error) {
	newDID := &did.Doc{Service: []did.Service{{Type: vdrapi.DIDCommV2ServiceType}}}

	err := c.createNewKeyAndVM(newDID, kid, jsonWebKey)
	if err != nil {
		return nil, fmt.Errorf("creating new keys and VMS for DID document failed: %w", err)
	}

	myDID, err := c.vdrRegistry.Create(peer.DIDMethod, newDID)
	if err != nil {
		return nil, fmt.Errorf("creating new peer DID via VDR failed: %w", err)
	}

	return myDID.DIDDocument, nil
}

func (c *creator) createNewKeyAndVM(didDoc *did.Doc, kid string, jsonWebKey *jwk.JWK) error {
	vm, err := c.createSigningVM(kid, jsonWebKey)
	if err != nil {
		return err
	}

	didDoc.VerificationMethod = append(didDoc.VerificationMethod, *vm)
	didDoc.Authentication = append(didDoc.Authentication, *did.NewReferencedVerification(vm, did.Authentication))
	didDoc.AssertionMethod = append(didDoc.AssertionMethod, *did.NewReferencedVerification(vm, did.AssertionMethod))

	return nil
}

func (c *creator) createSigningVM(kid string, jsonWebKey *jwk.JWK) (*did.VerificationMethod, error) {
	pubKeyBytes, err := jsonWebKey.PublicKeyBytes()
	if err != nil {
		return nil, err
	}

	kt, err := jsonWebKey.KeyType()
	if err != nil {
		return nil, err
	}

	j, err := jwksupport.PubKeyBytesToJWK(pubKeyBytes, kt)
	if err != nil {
		return nil, fmt.Errorf("createSigningVM: failed to convert public key to JWK for VM: %w", err)
	}

	return did.NewVerificationMethodFromJWK("#"+kid, jsonWebKey2020, "", j)
}
