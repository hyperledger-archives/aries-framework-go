/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"fmt"
	"time"

	"github.com/btcsuite/btcutil/base58"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
)

const ed25519VerificationKey2018 = "Ed25519VerificationKey2018"

// Build builds new DID Document.
func (v *VDRI) Build(pubKey *vdriapi.PubKey, opts ...vdriapi.DocOpts) (*did.Doc, error) {
	docOpts := &vdriapi.CreateDIDOpts{}
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

func build(pubKey *vdriapi.PubKey, docOpts *vdriapi.CreateDIDOpts) (*did.Doc, error) {
	var (
		publicKey did.PublicKey
		didKey    string
	)

	switch pubKey.Type {
	case ed25519VerificationKey2018:
		// TODO keyID of PublicKey should have the DID doc id as controller, since the DID document is created after
		//      the publicKey, its id is unknown until NewDoc() is called below. The controller and key ID of publicKey
		//		needs to be sorted out.
		publicKey = *did.NewPublicKeyFromBytes(pubKey.ID, ed25519VerificationKey2018, "#id", pubKey.Value)
	default:
		return nil, fmt.Errorf("not supported public key type: %s", pubKey.Type)
	}

	// Service model to be included only if service type is provided through opts
	var service []did.Service

	verificationMethods := []did.VerificationMethod{
		{PublicKey: publicKey},
	}

	if docOpts.ServiceType != "" {
		s := did.Service{
			ID:              "#agent",
			Type:            docOpts.ServiceType,
			ServiceEndpoint: docOpts.ServiceEndpoint,
			RoutingKeys:     docOpts.RoutingKeys,
		}

		if docOpts.ServiceType == vdriapi.DIDCommServiceType {
			s.RecipientKeys = []string{base58.Encode(pubKey.Value)}
			s.Priority = 0
		}

		if docOpts.EncryptionKey != nil {
			encKey, err := vdriapi.RetrieveEncryptionKey(didKey, docOpts.EncryptionKey)
			if err != nil {
				return nil, fmt.Errorf("invalid encryption key: %w", err)
			}

			keyAgreementMethod := *did.NewEmbeddedVerificationMethod(encKey, did.KeyAgreement)

			verificationMethods = append(verificationMethods, keyAgreementMethod)
		}

		service = append(service, s)
	}

	// Created/Updated time
	t := time.Now()

	return NewDoc(
		[]did.PublicKey{publicKey},
		verificationMethods,
		did.WithService(service),
		did.WithCreatedTime(t),
		did.WithUpdatedTime(t),
	)
}
