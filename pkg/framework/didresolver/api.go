/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package didresolver

import "time"

// ResultType input option can be used to request a certain type of result.
type ResultType int

const (
	// DidDocumentResult Request a DID Document as output
	DidDocumentResult ResultType = iota
	// ResolutionResult Request a DID Resolution Result
	ResolutionResult
)

// DidMethod operations
type DidMethod interface {
	Read(did string, versionID interface{}, versionTime string, noCache bool) ([]byte, error)
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
	didMethods map[string]DidMethod
}

// Opt is a resolver instance option
type Opt func(opts *didResolverOpts)

// WithDidMethod to add did method
func WithDidMethod(id string, method DidMethod) Opt {
	return func(opts *didResolverOpts) {
		opts.didMethods[id] = method
	}
}
