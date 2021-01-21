/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

type wrapKeyOpts struct {
	senderKey  interface{}
	useXC20PKW bool
}

// NewOpt creates a new empty wrap key option.
// Not to be used directly. It's intended for implementations of Crypto interface
// Use WithSender() option function below instead.
func NewOpt() *wrapKeyOpts { // nolint // unexported type doesn't need to be used outside of crypto package
	return &wrapKeyOpts{}
}

// SenderKey gets the Sender key to be used for key wrapping using a sender key (authcrypt).
// Not to be used directly. It's intended for implementations of Crypto interface.
// Use WithSender() option function below instead.
func (pk *wrapKeyOpts) SenderKey() interface{} {
	return pk.senderKey
}

// UseXC20PKW instructs to use XC20P key wrapping as apposed to the default A256KW.
func (pk *wrapKeyOpts) UseXC20PKW() bool {
	return pk.useXC20PKW
}

// WrapKeyOpts are the crypto.Wrap key options.
type WrapKeyOpts func(opts *wrapKeyOpts)

// WithSender option is for setting a sender key with crypto wrapping (eg: AuthCrypt). For Anoncrypt,
// this option must not be set.
// Sender is a key used for ECDH-1PU key agreement for authenticating the sender.
// senderkey can be of the following there types:
//   - *keyset.Handle (requires private key handle for crypto.WrapKey())
//   - *crypto.PublicKey (available for UnwrapKey() only)
//   - *ecdsa.PublicKey (available for UnwrapKey() only)
func WithSender(senderKey interface{}) WrapKeyOpts {
	return func(opts *wrapKeyOpts) {
		opts.senderKey = senderKey
	}
}

// WithXC20PKW options is a flag option for crypto wrapping. When used, key wrapping will use XChacha20Poly1305
// encryption as key wrapping. The absence of this option (default) uses AES256-GCM encryption as key wrapping. The KDF
// used in the crypto wrapping function is selected based on the type of recipient key argument of KeyWrap(), it is
// independent of this option.
func WithXC20PKW() WrapKeyOpts {
	return func(opts *wrapKeyOpts) {
		opts.useXC20PKW = true
	}
}
