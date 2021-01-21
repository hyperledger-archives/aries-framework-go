/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdr

import (
	"errors"
	"net/http"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

// ErrNotFound is returned when a DID resolver does not find the DID.
var ErrNotFound = errors.New("DID not found")

// DIDCommServiceType default DID Communication service endpoint type.
const DIDCommServiceType = "did-communication"

// Registry vdr registry.
type Registry interface {
	Resolve(did string, opts ...ResolveOption) (*did.DocResolution, error)
	Create(method string, did *did.Doc, opts ...DIDMethodOption) (*did.DocResolution, error)
	Update(did *did.Doc, opts ...DIDMethodOption) error
	Deactivate(did string, opts ...DIDMethodOption) error
	Close() error
}

// VDR verifiable data registry interface.
// TODO https://github.com/hyperledger/aries-framework-go/issues/2475
type VDR interface {
	Read(did string, opts ...ResolveOption) (*did.DocResolution, error)
	Create(keyManager kms.KeyManager, did *did.Doc, opts ...DIDMethodOption) (*did.DocResolution, error)
	Accept(method string) bool
	Update(did *did.Doc, opts ...DIDMethodOption) error
	Deactivate(did string, opts ...DIDMethodOption) error
	Close() error
}

// ResolveOpts holds the options for did resolve.
type ResolveOpts struct {
	HTTPClient  *http.Client
	VersionID   interface{}
	VersionTime string
	NoCache     bool
}

// ResolveOption is a did resolve option.
type ResolveOption func(opts *ResolveOpts)

// WithHTTPClient the HTTP client input option can be used to resolve with a specific http client.
// TODO https://github.com/hyperledger/aries-framework-go/issues/2465
func WithHTTPClient(httpClient *http.Client) ResolveOption {
	return func(opts *ResolveOpts) {
		opts.HTTPClient = httpClient
	}
}

// WithVersionID the version id input option can be used to request a specific version of a DID Document.
// TODO https://github.com/hyperledger/aries-framework-go/issues/2465
func WithVersionID(versionID interface{}) ResolveOption {
	return func(opts *ResolveOpts) {
		opts.VersionID = versionID
	}
}

// WithVersionTime the version time input option can used to request a specific version of a DID Document.
// TODO https://github.com/hyperledger/aries-framework-go/issues/2465
func WithVersionTime(versionTime time.Time) ResolveOption {
	return func(opts *ResolveOpts) {
		opts.VersionTime = versionTime.Format(time.RFC3339)
	}
}

// WithNoCache the no-cache input option can be used to turn cache on or off.
// TODO https://github.com/hyperledger/aries-framework-go/issues/2465
func WithNoCache(noCache bool) ResolveOption {
	return func(opts *ResolveOpts) {
		opts.NoCache = noCache
	}
}

// DIDMethodOpts did method opts.
type DIDMethodOpts struct {
	Values map[string]interface{}
}

// DIDMethodOption is a did method option.
type DIDMethodOption func(opts *DIDMethodOpts)

// WithOption add option for did method.
func WithOption(name string, value interface{}) DIDMethodOption {
	return func(didMethodOpts *DIDMethodOpts) {
		didMethodOpts.Values[name] = value
	}
}
