/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"fmt"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
)

// Build builds new DID Document
func (v *VDRI) Build(pubKey *vdriapi.PubKey, opts ...vdriapi.DocOpts) (*did.Doc, error) {
	docOpts := &vdriapi.CreateDIDOpts{}
	// Apply options
	for _, opt := range opts {
		opt(docOpts)
	}

	didDoc, err := build(pubKey, v.applyCreatorOpts(docOpts))
	if err != nil {
		return nil, fmt.Errorf("create peer DID : %w", err)
	}

	return didDoc, nil
}

// applyCreatorOpts applies creator options to doc options
func (v *VDRI) applyCreatorOpts(docOpts *vdriapi.CreateDIDOpts) *vdriapi.CreateDIDOpts {
	if docOpts == nil {
		docOpts = &vdriapi.CreateDIDOpts{ServiceType: v.serviceType, ServiceEndpoint: v.serviceEndpoint}
	}

	if docOpts.ServiceType == "" {
		docOpts.ServiceType = v.serviceType
	}

	if docOpts.ServiceEndpoint == "" {
		docOpts.ServiceEndpoint = v.serviceEndpoint
	}

	return docOpts
}

func build(pubKey *vdriapi.PubKey, docOpts *vdriapi.CreateDIDOpts) (*did.Doc, error) {
	publicKey := did.PublicKey{
		ID:         pubKey.Value[0:7],
		Type:       pubKey.Type,
		Controller: "#id",
		Value:      []byte(pubKey.Value),
	}

	// Service model to be included only if service type is provided through opts
	var service []did.Service
	if docOpts.ServiceType != "" {
		// Service endpoints
		service = []did.Service{
			{
				ID:              "#agent",
				Type:            docOpts.ServiceType,
				ServiceEndpoint: docOpts.ServiceEndpoint,
			},
		}
	}

	// Created/Updated time
	t := time.Now()

	didDoc, err := NewDoc(
		[]did.PublicKey{publicKey},
		[]did.VerificationMethod{
			{PublicKey: publicKey},
		},
		did.WithService(service),
		did.WithCreatedTime(t),
		did.WithUpdatedTime(t),
	)
	if err != nil {
		return nil, err
	}

	return didDoc, nil
}
