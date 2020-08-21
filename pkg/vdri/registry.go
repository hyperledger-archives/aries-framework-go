/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdri

import (
	"errors"
	"fmt"
	"strings"

	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

const (
	defaultKeyType = "Ed25519VerificationKey2018"
)

// Option is a vdri instance option.
type Option func(opts *Registry)

// provider contains dependencies for the did creator.
type provider interface {
	KMS() kms.KeyManager
}

// Registry vdri registry.
type Registry struct {
	vdri               []vdriapi.VDRI
	kms                kms.KeyManager
	defServiceEndpoint string
	defServiceType     string
}

// New return new instance of vdri.
func New(ctx provider, opts ...Option) *Registry {
	baseVDRI := &Registry{kms: ctx.KMS()}

	// Apply options
	for _, opt := range opts {
		opt(baseVDRI)
	}

	return baseVDRI
}

// Resolve did document.
func (r *Registry) Resolve(did string, opts ...vdriapi.ResolveOpts) (*diddoc.Doc, error) {
	resolveOpts := &vdriapi.ResolveDIDOpts{}
	// Apply options
	for _, opt := range opts {
		opt(resolveOpts)
	}

	didMethod, err := getDidMethod(did)
	if err != nil {
		return nil, err
	}

	// resolve did method
	method, err := r.resolveVDRI(didMethod)
	if err != nil {
		return nil, err
	}

	// Obtain the DID Document
	didDoc, err := method.Read(did, opts...)
	if err != nil {
		if errors.Is(err, vdriapi.ErrNotFound) {
			return nil, err
		}

		return nil, fmt.Errorf("did method read failed failed: %w", err)
	}

	if resolveOpts.ResultType == vdriapi.ResolutionResult {
		// TODO https://github.com/hyperledger/aries-framework-go/issues/745 Support resolution-result
		return nil, errors.New("result type 'resolution-result' not supported")
	}

	return didDoc, nil
}

// Create a new DID Document and store it in this registry.
func (r *Registry) Create(didMethod string, opts ...vdriapi.DocOpts) (*diddoc.Doc, error) {
	docOpts := &vdriapi.CreateDIDOpts{KeyType: defaultKeyType}

	// TODO add EncryptionKey as option in docOpts here to support Anoncrypt/Authcrypt packing

	for _, opt := range opts {
		opt(docOpts)
	}

	id, pubKey, err := r.kms.CreateAndExportPubKeyBytes(kms.ED25519Type)
	if err != nil {
		return nil, fmt.Errorf("failed to create DID: %w", err)
	}

	method, err := r.resolveVDRI(didMethod)
	if err != nil {
		return nil, err
	}

	// using kms KID in order for the key resolver to find the matching key.
	doc, err := method.Build(&vdriapi.PubKey{ID: "#" + id, Value: pubKey, Type: docOpts.KeyType},
		r.applyDefaultDocOpts(docOpts, opts...)...)
	if err != nil {
		return nil, err
	}

	err = r.Store(doc)
	if err != nil {
		return nil, err
	}

	return doc, nil
}

// applyDefaultDocOpts applies default creator options to doc options.
func (r *Registry) applyDefaultDocOpts(docOpts *vdriapi.CreateDIDOpts, opts ...vdriapi.DocOpts) []vdriapi.DocOpts {
	if docOpts.ServiceType == "" {
		opts = append(opts, vdriapi.WithServiceType(r.defServiceType))
	}

	if docOpts.ServiceEndpoint == "" {
		opts = append(opts, vdriapi.WithServiceEndpoint(r.defServiceEndpoint))
	}

	return opts
}

// Store did store.
func (r *Registry) Store(doc *diddoc.Doc) error {
	didMethod, err := getDidMethod(doc.ID)
	if err != nil {
		return err
	}

	method, err := r.resolveVDRI(didMethod)
	if err != nil {
		return err
	}

	return method.Store(doc, nil)
}

// Close frees resources being maintained by vdri.
func (r *Registry) Close() error {
	for _, v := range r.vdri {
		if err := v.Close(); err != nil {
			return fmt.Errorf("close vdri: %w", err)
		}
	}

	return nil
}

func (r *Registry) resolveVDRI(method string) (vdriapi.VDRI, error) {
	for _, v := range r.vdri {
		if v.Accept(method) {
			return v, nil
		}
	}

	return nil, fmt.Errorf("did method %s not supported for vdri", method)
}

// WithVDRI adds did method implementation for store.
func WithVDRI(method vdriapi.VDRI) Option {
	return func(opts *Registry) {
		opts.vdri = append(opts.vdri, method)
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

func getDidMethod(didID string) (string, error) {
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
