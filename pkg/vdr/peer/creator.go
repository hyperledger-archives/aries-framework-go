/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/google/uuid"
	gojose "github.com/square/go-jose/v3"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/create"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/doc"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

const ed25519VerificationKey2018 = "Ed25519VerificationKey2018"

// Build builds new DID Document.
func (v *VDR) Build(keyManager kms.KeyManager, opts ...create.Option) (*did.Doc, error) {
	docOpts := &create.Opts{}
	// Apply options
	for _, opt := range opts {
		opt(docOpts)
	}

	didDoc, err := build(keyManager, docOpts)
	if err != nil {
		return nil, fmt.Errorf("create peer DID : %w", err)
	}

	return didDoc, nil
}

func build(keyManager kms.KeyManager, docOpts *create.Opts) (*did.Doc, error) { //nolint: funlen
	if len(docOpts.PublicKeys) == 0 {
		id, pubKeyBytes, err := keyManager.CreateAndExportPubKeyBytes(kms.ED25519Type)
		if err != nil {
			return nil, fmt.Errorf("failed to create and export public key: %w", err)
		}

		docOpts.PublicKeys = append(docOpts.PublicKeys, doc.PublicKey{
			ID:   "#" + id,
			Type: ed25519VerificationKey2018,
			JWK:  gojose.JSONWebKey{Key: ed25519.PublicKey(pubKeyBytes)},
		})
	}

	var publicKey did.VerificationMethod

	switch docOpts.PublicKeys[0].Type {
	case ed25519VerificationKey2018:
		// TODO keyID of VerificationMethod should have the DID doc id as controller, since the DID document is created after
		//      the publicKey, its id is unknown until NewDoc() is called below. The controller and key ID of publicKey
		//		needs to be sorted out.
		publicKey = *did.NewVerificationMethodFromBytes(docOpts.PublicKeys[0].ID, ed25519VerificationKey2018, "#id",
			docOpts.PublicKeys[0].JWK.Key.(ed25519.PublicKey))
	default:
		return nil, fmt.Errorf("not supported public key type: %s", docOpts.PublicKeys[0].Type)
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
			docOpts.Services[i].RecipientKeys = []string{base58.Encode(
				docOpts.PublicKeys[0].JWK.Key.(ed25519.PublicKey))}
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
