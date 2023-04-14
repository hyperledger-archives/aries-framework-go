/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

// privateKeyOpts holds options for ImportPrivateKey.
type privateKeyOpts struct {
	ksID string
}

// NewOpt creates a new empty private key option.
// Not to be used directly. It's intended for implementations of KeyManager interface
// Use WithKeyID() option function below instead.
func NewOpt() *privateKeyOpts { // nolint
	return &privateKeyOpts{}
}

// KsID gets the KsID to be used for import a private key.
// Not to be used directly. It's intended for implementations of KeyManager interface
// Use WithKeyID() option function below instead.
func (pk *privateKeyOpts) KsID() string {
	return pk.ksID
}

// PrivateKeyOpts are the import private key option.
type PrivateKeyOpts func(opts *privateKeyOpts)

// WithKeyID option is for importing a private key with a specified KeyID.
func WithKeyID(keyID string) PrivateKeyOpts {
	return func(opts *privateKeyOpts) {
		opts.ksID = keyID
	}
}
