/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

// keyOpts holds options for Create, Rotate and CreateAndExportPubKeyBytes.
type keyOpts struct {
	attrs []string
}

// NewKeyOpt creates a new empty key option.
// Not to be used directly. It's intended for implementations of KeyManager interface
// Use WithAttrs() option function below instead.
func NewKeyOpt() *keyOpts { // nolint
	return &keyOpts{}
}

// Attrs gets the additional attributes to be used for a key creation.
// Not to be used directly. It's intended for implementations of KeyManager interface
// Use WithAttrs() option function below instead.
func (pk *keyOpts) Attrs() []string {
	return pk.attrs
}

// KeyOpts are the create key option.
type KeyOpts func(opts *keyOpts)

// WithAttrs option is for creating a key that requires extra attributes.
func WithAttrs(attrs []string) KeyOpts {
	return func(opts *keyOpts) {
		opts.attrs = attrs
	}
}
