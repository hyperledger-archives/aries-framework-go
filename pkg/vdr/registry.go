/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdr

import (
	"errors"
	"fmt"
	"strings"

	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/peer"
)

// Option is a vdr instance option.
type Option func(opts *Registry)

// provider contains dependencies for the did creator.
type provider interface {
	KMS() kms.KeyManager
}

// Registry vdr registry.
type Registry struct {
	vdr                []vdrapi.VDR
	kms                kms.KeyManager
	defServiceEndpoint string
	defServiceType     string
}

// New return new instance of vdr.
func New(ctx provider, opts ...Option) *Registry {
	baseVDR := &Registry{kms: ctx.KMS()}

	// Apply options
	for _, opt := range opts {
		opt(baseVDR)
	}

	return baseVDR
}

// Resolve did document.
func (r *Registry) Resolve(did string, opts ...vdrapi.ResolveOption) (*diddoc.DocResolution, error) {
	didMethod, err := GetDidMethod(did)
	if err != nil {
		return nil, err
	}

	// resolve did method
	method, err := r.resolveVDR(didMethod)
	if err != nil {
		return nil, err
	}

	// Obtain the DID Document
	didDocResolution, err := method.Read(did, opts...)
	if err != nil {
		if errors.Is(err, vdrapi.ErrNotFound) {
			return nil, err
		}

		return nil, fmt.Errorf("did method read failed failed: %w", err)
	}

	return didDocResolution, nil
}

// Update did document.
func (r *Registry) Update(didDoc *diddoc.Doc, opts ...vdrapi.DIDMethodOption) error {
	didMethod, err := GetDidMethod(didDoc.ID)
	if err != nil {
		return err
	}

	// resolve did method
	method, err := r.resolveVDR(didMethod)
	if err != nil {
		return err
	}

	return method.Update(didDoc, opts...)
}

// Deactivate did document.
func (r *Registry) Deactivate(did string, opts ...vdrapi.DIDMethodOption) error {
	didMethod, err := GetDidMethod(did)
	if err != nil {
		return err
	}

	// resolve did method
	method, err := r.resolveVDR(didMethod)
	if err != nil {
		return err
	}

	return method.Deactivate(did, opts...)
}

// Create a new DID Document and store it in this registry.
func (r *Registry) Create(didMethod string, did *diddoc.Doc,
	opts ...vdrapi.DIDMethodOption) (*diddoc.DocResolution, error) {
	docOpts := &vdrapi.DIDMethodOpts{Values: make(map[string]interface{})}

	// TODO add EncryptionKey as option in docOpts here to support Anoncrypt/Authcrypt packing

	for _, opt := range opts {
		opt(docOpts)
	}

	method, err := r.resolveVDR(didMethod)
	if err != nil {
		return nil, err
	}

	didDocResolution, err := method.Create(r.kms, did, r.applyDefaultDocOpts(docOpts, opts...)...)
	if err != nil {
		return nil, err
	}

	return didDocResolution, nil
}

// applyDefaultDocOpts applies default creator options to doc options.
func (r *Registry) applyDefaultDocOpts(docOpts *vdrapi.DIDMethodOpts,
	opts ...vdrapi.DIDMethodOption) []vdrapi.DIDMethodOption {
	if docOpts.Values[peer.DefaultServiceType] == nil {
		opts = append(opts, vdrapi.WithOption(peer.DefaultServiceType, r.defServiceType))
	}

	if docOpts.Values[peer.DefaultServiceEndpoint] == nil {
		opts = append(opts, vdrapi.WithOption(peer.DefaultServiceEndpoint, r.defServiceEndpoint))
	}

	return opts
}

// Close frees resources being maintained by vdr.
func (r *Registry) Close() error {
	for _, v := range r.vdr {
		if err := v.Close(); err != nil {
			return fmt.Errorf("close vdr: %w", err)
		}
	}

	return nil
}

func (r *Registry) resolveVDR(method string) (vdrapi.VDR, error) {
	for _, v := range r.vdr {
		if v.Accept(method) {
			return v, nil
		}
	}

	return nil, fmt.Errorf("did method %s not supported for vdr", method)
}

// WithVDR adds did method implementation for store.
func WithVDR(method vdrapi.VDR) Option {
	return func(opts *Registry) {
		opts.vdr = append(opts.vdr, method)
	}
}

// WithDefaultServiceType is default service type for this creator.
func WithDefaultServiceType(serviceType string) Option {
	return func(opts *Registry) {
		opts.defServiceType = serviceType
	}
}

// WithDefaultServiceEndpoint allows for setting default service endpoint.
func WithDefaultServiceEndpoint(serviceEndpoint string) Option {
	return func(opts *Registry) {
		opts.defServiceEndpoint = serviceEndpoint
	}
}

// GetDidMethod get did method.
func GetDidMethod(didID string) (string, error) {
	// TODO https://github.com/hyperledger/aries-framework-go/issues/20 Validate that the input DID conforms to
	//  the did rule of the Generic DID Syntax. Reference: https://w3c-ccg.github.io/did-spec/#generic-did-syntax
	// For now we do simple validation
	const numPartsDID = 3

	didParts := strings.Split(didID, ":")
	if len(didParts) < numPartsDID {
		return "", fmt.Errorf("wrong format did input: %s", didID)
	}

	return didParts[1], nil
}
