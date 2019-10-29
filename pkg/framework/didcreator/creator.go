/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didcreator

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	api "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/didcreator"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

const (
	peerDIDMethod  = "peer"
	defaultKeyType = "Ed25519VerificationKey2018"
)

// provider contains dependencies for the did creator
type provider interface {
	KMS() kms.KeyManager
}

// Option configures the did creator
type Option func(opts *DIDCreator)

// DIDCreator implements creation of new dids
type DIDCreator struct {
	crypto          kms.KeyManager
	keyType         string
	serviceEndpoint string
	serviceType     string
	didMethods      []api.DidMethod
}

// New return new instance of did creator
func New(provider provider, opts ...Option) (*DIDCreator, error) {
	creator := &DIDCreator{crypto: provider.KMS()}
	for _, option := range opts {
		option(creator)
	}
	setDefaultOpts(creator)

	return creator, nil
}

// Create returns new DID Document
func (dc *DIDCreator) Create(didMethod string, opts ...api.DocOpts) (*did.Doc, error) {
	docOpts := &api.CreateDIDOpts{}
	for _, opt := range opts {
		opt(docOpts)
	}

	applyCreatorOpts(docOpts, dc)

	_, base58PubKey, err := dc.crypto.CreateKeySet()
	if err != nil {
		return nil, fmt.Errorf("failed to create DID: %w", err)
	}

	method, err := dc.resolveDidMethod(didMethod)
	if err != nil {
		return nil, err
	}

	didDoc, err := method.Build(&api.PubKey{Value: base58PubKey, Type: docOpts.KeyType}, docOpts)
	if err != nil {
		return nil, err
	}

	return didDoc, nil
}

// applyCreatorOpts applies creator options to doc options
func applyCreatorOpts(docOpts *api.CreateDIDOpts, creatorOpts *DIDCreator) {
	if docOpts.KeyType == "" {
		docOpts.KeyType = creatorOpts.keyType
	}

	if docOpts.ServiceType == "" {
		docOpts.ServiceType = creatorOpts.serviceType
	}

	if docOpts.ServiceEndpoint == "" {
		docOpts.ServiceEndpoint = creatorOpts.serviceEndpoint
	}
}

// resolveDidMethod resolves did method
func (dc *DIDCreator) resolveDidMethod(method string) (api.DidMethod, error) {
	for _, v := range dc.didMethods {
		if v.Accept(method) {
			return v, nil
		}
	}
	return nil, fmt.Errorf("did method %s not supported for did creator", method)
}

// setDefaultOpts provides default creator options
func setDefaultOpts(creatorOpts *DIDCreator) {
	if creatorOpts.keyType == "" {
		creatorOpts.keyType = defaultKeyType
	}
}

// WithCreatorServiceType is service type for this creator
func WithCreatorServiceType(serviceType string) Option {
	return func(opts *DIDCreator) {
		opts.serviceType = serviceType
	}
}

// WithCreatorKeyType allows for setting key type
func WithCreatorKeyType(keyType string) Option {
	return func(opts *DIDCreator) {
		opts.keyType = keyType
	}
}

// WithCreatorServiceEndpoint allows for setting service endpoint
func WithCreatorServiceEndpoint(serviceEndpoint string) Option {
	return func(opts *DIDCreator) {
		opts.serviceEndpoint = serviceEndpoint
	}
}

// WithDidMethod adds did method implementation for creator
func WithDidMethod(method api.DidMethod) Option {
	return func(opts *DIDCreator) {
		opts.didMethods = append(opts.didMethods, method)
	}
}
