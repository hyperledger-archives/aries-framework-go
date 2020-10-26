/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

type wrapKeyOpts struct {
	senderKH interface{}
}

// NewOpt creates a new empty wrap key option.
// Not to be used directly. It's intended for implementations of Crypto interface
// Use WithSenderKH() option function below instead.
func NewOpt() *wrapKeyOpts { // nolint // unexported type doesn't need to be used outside of crypto package
	return &wrapKeyOpts{}
}

// SenderKH gets the Sender key handle to be used for kew wrapping with a sender key (authcrypt).
// Not to be used directly. It's intended for implementations of Crypto interface
// Use WithSenderKH() option function below instead.
func (pk *wrapKeyOpts) SenderKH() interface{} {
	return pk.senderKH
}

// WrapKeyOpts are the crypto.Wrap key options.
type WrapKeyOpts func(opts *wrapKeyOpts)

// WithSenderKH option is for setting a sender key handle with crypto wrapping (eg: AuthCrypt). For Anoncrypt,
// this option must not be set.
func WithSenderKH(senderKH interface{}) WrapKeyOpts {
	return func(opts *wrapKeyOpts) {
		opts.senderKH = senderKH
	}
}
