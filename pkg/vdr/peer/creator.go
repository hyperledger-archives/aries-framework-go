/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"fmt"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
)

const ed25519VerificationKey2018 = "Ed25519VerificationKey2018"

// Build builds new DID Document.
func (v *VDR) Build(pubKey *vdrapi.PubKey, opts ...vdrapi.DocOpts) (*did.Doc, error) {
	docOpts := &vdrapi.CreateDIDOpts{}
	// Apply options
	for _, opt := range opts {
		opt(docOpts)
	}

	didDoc, err := build(pubKey, docOpts)
	if err != nil {
		return nil, fmt.Errorf("create peer DID : %w", err)
	}

	return didDoc, nil
}

func build(pubKey *vdrapi.PubKey, docOpts *vdrapi.CreateDIDOpts) (*did.Doc, error) {
	var publicKey did.VerificationMethod

	switch pubKey.Type {
	case ed25519VerificationKey2018:
		// TODO keyID of VerificationMethod should have the DID doc id as controller, since the DID document is created after
		//      the publicKey, its id is unknown until NewDoc() is called below. The controller and key ID of publicKey
		//		needs to be sorted out.
		publicKey = *did.NewVerificationMethodFromBytes(pubKey.ID, ed25519VerificationKey2018, "#id", pubKey.Value)
	default:
		return nil, fmt.Errorf("not supported public key type: %s", pubKey.Type)
	}

	// Service model to be included only if service type is provided through opts
	var service []did.Service

	for i := range docOpts.Services {
		if docOpts.Services[i].ID == "" {
			docOpts.Services[i].ID = uuid.New().String()
		}

		if docOpts.Services[i].Type == "" {
			docOpts.Services[i].Type = docOpts.DefaultServiceType
		}

		if docOpts.Services[i].ServiceEndpoint == "" {
			docOpts.Services[i].ServiceEndpoint = docOpts.DefaultServiceEndpoint
		}

		if docOpts.Services[i].Type == vdrapi.DIDCommServiceType {
			docOpts.Services[i].RecipientKeys = []string{base58.Encode(pubKey.Value)}
			docOpts.Services[i].Priority = 0
		}

		service = append(service, docOpts.Services[i])
	}

	// Created/Updated time
	t := time.Now()

	return NewDoc(
		[]did.VerificationMethod{publicKey},
		did.WithService(service),
		did.WithCreatedTime(t),
		did.WithUpdatedTime(t),
		did.WithAuthentication([]did.Verification{{
			VerificationMethod: publicKey,
			Relationship:       did.Authentication,
		}}),
		did.WithAssertion([]did.Verification{{
			VerificationMethod: publicKey,
			Relationship:       did.AssertionMethod,
		}}),
	)
}
