/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package didresolver

import (
	"errors"
	"time"
)

// ResultType input option can be used to request a certain type of result.
type ResultType int

const (
	// DidDocumentResult Request a DID Document as output
	DidDocumentResult ResultType = iota
	// ResolutionResult Request a DID Resolution Result
	ResolutionResult
)

// ErrNotFound is returned when a DID resolver does not find the DID.
var ErrNotFound = errors.New("DID not found")

// DidMethod resolves a DID into a result type (default: DidDocumentResult).
// See the DID resolution spec: https://w3c-ccg.github.io/did-resolution.
type DidMethod interface {
	// Read implements the 'DID Resolution' algorithm defined in
	// https://w3c-ccg.github.io/did-resolution/#resolving.
	Read(did string, opts ...ResolveOpt) ([]byte, error)
	// Accept registers this DID method resolver with the given method.
	Accept(method string) bool
}

// resolveOpts holds the options for did resolve
type resolveOpts struct {
	resultType  ResultType
	versionID   interface{}
	versionTime string
	noCache     bool
}

// ResolveOpt is a did resolve option
type ResolveOpt func(opts *resolveOpts)

// WithResultType the result type input option can be used to request a certain type of result
func WithResultType(resultType ResultType) ResolveOpt {
	return func(opts *resolveOpts) {
		opts.resultType = resultType
	}
}

// WithVersionID the version id input option can be used to request a specific version of a DID Document
func WithVersionID(versionID interface{}) ResolveOpt {
	return func(opts *resolveOpts) {
		opts.versionID = versionID
	}
}

// WithVersionTime the version time input option can used to request a specific version of a DID Document
func WithVersionTime(versionTime time.Time) ResolveOpt {
	return func(opts *resolveOpts) {
		opts.versionTime = versionTime.Format(time.RFC3339)
	}
}

// WithNoCache the no-cache input option can be used to turn cache on or off
func WithNoCache(noCache bool) ResolveOpt {
	return func(opts *resolveOpts) {
		opts.noCache = noCache
	}
}

// didResolverOpts holds the options for resolver instance
type didResolverOpts struct {
	didMethods []DidMethod
}

// Opt is a resolver instance option
type Opt func(opts *didResolverOpts)

// WithDidMethod to add did method
// DID methods are checked in the order added
func WithDidMethod(method DidMethod) Opt {
	return func(opts *didResolverOpts) {
		opts.didMethods = append(opts.didMethods, method)
	}
}
