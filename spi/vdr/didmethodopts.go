/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package vdr

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
