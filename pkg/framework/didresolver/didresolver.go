/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package didresolver

import (
	"errors"
	"fmt"
	"strings"

	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

// DIDResolver did resolver
type DIDResolver struct {
	didMethods []DidMethod
}

// New return new instance of did resolver
func New(opts ...Opt) *DIDResolver {
	resolverOpts := &didResolverOpts{didMethods: make([]DidMethod, 0)}
	// Apply options
	for _, opt := range opts {
		opt(resolverOpts)
	}

	return &DIDResolver{didMethods: resolverOpts.didMethods}
}

// Resolve did document
func (r *DIDResolver) Resolve(did string, opts ...ResolveOpt) (*diddoc.Doc, error) {
	resolveOpts := &resolveOpts{}
	// Apply options
	for _, opt := range opts {
		opt(resolveOpts)
	}
	// TODO Validate that the input DID conforms to the did rule of the Generic DID Syntax
	// TODO Reference: https://w3c-ccg.github.io/did-spec/#generic-did-syntax
	// For now we do simple validation
	didParts := strings.SplitN(did, ":", 3)
	if len(didParts) != 3 {
		return nil, errors.New("wrong format did input")
	}

	// Determine if the input DID method is supported by the DID Resolver
	didMethod := didParts[1]
	// resolve did method
	method, err := r.resolveDidMethod(didMethod)
	if err != nil {
		return nil, err
	}

	// Obtain the DID Document
	didDoc, err := method.Read(did, opts...)
	if err != nil {
		if err == ErrNotFound {
			return nil, err
		}

		return nil, fmt.Errorf("did method read failed failed: %w", err)
	}

	if resolveOpts.resultType == ResolutionResult {
		// TODO Support resolution-result
		return nil, errors.New("result type 'resolution-result' not supported")
	}

	return didDoc, nil
}

// resolveDidMethod resolve did method
func (r *DIDResolver) resolveDidMethod(method string) (DidMethod, error) {
	for _, v := range r.didMethods {
		if v.Accept(method) {
			return v, nil
		}
	}

	return nil, fmt.Errorf("did method %s not supported", method)
}
