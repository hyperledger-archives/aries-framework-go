/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webkms

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms/webkms"
)

// Opts represents option.
type Opts = webkms.Opts

// NewOpt creates a new empty option.
// Not to be used directly. It's intended for implementations of remoteKMS.
// Use WithHeaders() option function below instead.
func NewOpt() *Opts {
	return webkms.NewOpt()
}

// Opt are the remoteKMS option.
type Opt = webkms.Opt

// WithHeaders option is for setting additional http request headers (since it's a function, it can call a remote
// authorization server to fetch the necessary info needed in these headers).
func WithHeaders(addHeadersFunc webkms.AddHeaders) Opt {
	return webkms.WithHeaders(addHeadersFunc)
}

// WithCache add cache. if size is zero cache content will not be purged.
func WithCache(cacheSize int) Opt {
	return webkms.WithCache(cacheSize)
}

// WithMarshalFn allows providing marshal function.
func WithMarshalFn(fn marshalFunc) Opt {
	return webkms.WithMarshalFn(fn)
}
