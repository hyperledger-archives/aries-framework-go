/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resolve

import (
	"net/http"
	"time"
)

// Opts holds the options for did resolve.
type Opts struct {
	HTTPClient  *http.Client
	VersionID   interface{}
	VersionTime string
	NoCache     bool
}

// Option is a did resolve option.
type Option func(opts *Opts)

// WithHTTPClient the HTTP client input option can be used to resolve with a specific http client.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(opts *Opts) {
		opts.HTTPClient = httpClient
	}
}

// WithVersionID the version id input option can be used to request a specific version of a DID Document.
func WithVersionID(versionID interface{}) Option {
	return func(opts *Opts) {
		opts.VersionID = versionID
	}
}

// WithVersionTime the version time input option can used to request a specific version of a DID Document.
func WithVersionTime(versionTime time.Time) Option {
	return func(opts *Opts) {
		opts.VersionTime = versionTime.Format(time.RFC3339)
	}
}

// WithNoCache the no-cache input option can be used to turn cache on or off.
func WithNoCache(noCache bool) Option {
	return func(opts *Opts) {
		opts.NoCache = noCache
	}
}
