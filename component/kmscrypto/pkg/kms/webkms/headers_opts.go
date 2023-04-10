/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webkms

import (
	"encoding/json"
	"net/http"

	"github.com/bluele/gcache"
)

// AddHeaders function supports adding custom http headers.
type AddHeaders func(req *http.Request) (*http.Header, error)

// Opts represents option.
type Opts struct {
	HeadersFunc     AddHeaders
	ComputeMACCache gcache.Cache
	marshal         MarshalFunc
}

// NewOpt creates a new empty option.
// Not to be used directly. It's intended for implementations of remoteKMS.
// Use WithHeaders() option function below instead.
func NewOpt() *Opts {
	return &Opts{marshal: json.Marshal}
}

// Opt are the remoteKMS option.
type Opt func(opts *Opts)

// WithHeaders option is for setting additional http request headers (since it's a function, it can call a remote
// authorization server to fetch the necessary info needed in these headers).
func WithHeaders(addHeadersFunc AddHeaders) Opt {
	return func(opts *Opts) {
		opts.HeadersFunc = addHeadersFunc
	}
}

// WithCache add cache. if size is zero cache content will not be purged.
func WithCache(cacheSize int) Opt {
	return func(opts *Opts) {
		opts.ComputeMACCache = gcache.New(cacheSize).Build()
	}
}

// WithMarshalFn allows providing marshal function.
func WithMarshalFn(fn MarshalFunc) Opt {
	return func(opts *Opts) {
		opts.marshal = fn
	}
}
