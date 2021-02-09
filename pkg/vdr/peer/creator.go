/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
)

const ed25519VerificationKey2018 = "Ed25519VerificationKey2018"

// Create create new DID Document.
// TODO https://github.com/hyperledger/aries-framework-go/issues/2466
func (v *VDR) Create(keyManager kms.KeyManager, didDoc *did.Doc,
	opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	docOpts := &vdrapi.DIDMethodOpts{Values: make(map[string]interface{})}
	// Apply options
	for _, opt := range opts {
		opt(docOpts)
	}

	store := false

	storeOpt := docOpts.Values["store"]
	if storeOpt != nil {
		var ok bool

		store, ok = storeOpt.(bool)
		if !ok {
			return nil, fmt.Errorf("store opt not boolean")
		}
	}

	if !store {
		docResolution, err := build(keyManager, didDoc, docOpts)
		if err != nil {
			return nil, fmt.Errorf("create peer DID : %w", err)
		}

		didDoc = docResolution.DIDDocument
	}

	if err := v.storeDID(didDoc, nil); err != nil {
		return nil, err
	}

	return &did.DocResolution{DIDDocument: didDoc}, nil
}

//nolint: funlen,gocyclo
func build(keyManager kms.KeyManager, didDoc *did.Doc,
	docOpts *vdrapi.DIDMethodOpts) (*did.DocResolution, error) {
	if len(didDoc.VerificationMethod) == 0 {
		id, pubKeyBytes, err := keyManager.CreateAndExportPubKeyBytes(kms.ED25519Type)
		if err != nil {
			return nil, fmt.Errorf("failed to create and export public key: %w", err)
		}

		didDoc.VerificationMethod = append(didDoc.VerificationMethod, did.VerificationMethod{
			ID:    "#" + id,
			Type:  ed25519VerificationKey2018,
			Value: pubKeyBytes,
		})
	}

	var publicKey did.VerificationMethod

	switch didDoc.VerificationMethod[0].Type {
	case ed25519VerificationKey2018:
		// TODO keyID of VerificationMethod should have the DID doc id as controller, since the DID document is created after
		//      the publicKey, its id is unknown until NewDoc() is called below. The controller and key ID of publicKey
		//		needs to be sorted out.
		publicKey = *did.NewVerificationMethodFromBytes(didDoc.VerificationMethod[0].ID, ed25519VerificationKey2018, "#id",
			didDoc.VerificationMethod[0].Value)
	default:
		return nil, fmt.Errorf("not supported public key type: %s", didDoc.VerificationMethod[0].Type)
	}

	// Service model to be included only if service type is provided through opts
	var service []did.Service

	for i := range didDoc.Service {
		if didDoc.Service[i].ID == "" {
			didDoc.Service[i].ID = uuid.New().String()
		}

		if didDoc.Service[i].Type == "" && docOpts.Values[DefaultServiceType] != nil {
			v, ok := docOpts.Values[DefaultServiceType].(string)
			if !ok {
				return nil, fmt.Errorf("defaultServiceType not string")
			}

			didDoc.Service[i].Type = v
		}

		if didDoc.Service[i].ServiceEndpoint == "" && docOpts.Values[DefaultServiceEndpoint] != nil {
			v, ok := docOpts.Values[DefaultServiceEndpoint].(string)
			if !ok {
				return nil, fmt.Errorf("defaultServiceEndpoint not string")
			}

			didDoc.Service[i].ServiceEndpoint = v
		}

		if didDoc.Service[i].Type == vdrapi.DIDCommServiceType {
			didKey, _ := fingerprint.CreateDIDKey(didDoc.VerificationMethod[0].Value)
			didDoc.Service[i].RecipientKeys = []string{didKey}
			didDoc.Service[i].Priority = 0
		}

		service = append(service, didDoc.Service[i])
	}

	// Created/Updated time
	t := time.Now()

	assertion := []did.Verification{{
		VerificationMethod: publicKey,
		Relationship:       did.AssertionMethod,
	}}

	authentication := []did.Verification{{
		VerificationMethod: publicKey,
		Relationship:       did.Authentication,
	}}

	didDoc, err := NewDoc(
		[]did.VerificationMethod{publicKey},
		did.WithService(service),
		did.WithCreatedTime(t),
		did.WithUpdatedTime(t),
		did.WithAuthentication(authentication),
		did.WithAssertion(assertion),
	)
	if err != nil {
		return nil, err
	}

	return &did.DocResolution{DIDDocument: didDoc}, nil
}
