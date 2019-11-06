/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"fmt"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	api "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/didcreator"
)

// Option configures the did creator
type Option func(opts *DIDCreator)

// DIDCreator implements building new dids
type DIDCreator struct {
	serviceEndpoint string
	serviceType     string
}

// NewDIDCreator return new instance of did creator
func NewDIDCreator(opts ...Option) *DIDCreator {
	creator := &DIDCreator{}

	for _, option := range opts {
		option(creator)
	}

	return creator
}

// Build builds new DID Document
func (dc *DIDCreator) Build(pubKey *api.PubKey, opts *api.CreateDIDOpts) (*did.Doc, error) {
	docOpts := dc.applyCreatorOpts(opts)

	didDoc, err := build(pubKey, docOpts)
	if err != nil {
		return nil, fmt.Errorf("create peer DID : %w", err)
	}

	return didDoc, nil
}

// Accept did method
func (dc *DIDCreator) Accept(method string) bool {
	return method == didMethod
}

// applyCreatorOpts applies creator options to doc options
func (dc *DIDCreator) applyCreatorOpts(docOpts *api.CreateDIDOpts) *api.CreateDIDOpts {
	if docOpts == nil {
		docOpts = &api.CreateDIDOpts{ServiceType: dc.serviceType, ServiceEndpoint: dc.serviceEndpoint}
	}

	if docOpts.ServiceType == "" {
		docOpts.ServiceType = dc.serviceType
	}

	if docOpts.ServiceEndpoint == "" {
		docOpts.ServiceEndpoint = dc.serviceEndpoint
	}

	return docOpts
}

func build(pubKey *api.PubKey, docOpts *api.CreateDIDOpts) (*did.Doc, error) {
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

// WithCreatorServiceType is service type for this creator
func WithCreatorServiceType(serviceType string) Option {
	return func(opts *DIDCreator) {
		opts.serviceType = serviceType
	}
}

// WithCreatorServiceEndpoint allows for setting service endpoint
func WithCreatorServiceEndpoint(serviceEndpoint string) Option {
	return func(opts *DIDCreator) {
		opts.serviceEndpoint = serviceEndpoint
	}
}
