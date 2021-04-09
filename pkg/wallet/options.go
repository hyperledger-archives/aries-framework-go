/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"encoding/json"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
)

// kmsOpts contains options for creating verifiable credential wallet.
type kmsOpts struct {
	// local kms options
	secretLockSvc secretlock.Service
	passphrase    string

	// remote(web) kms options
	keyServerURL string
}

// ProfileKeyManagerOptions is option for verifiable credential wallet key manager.
type ProfileKeyManagerOptions func(opts *kmsOpts)

// WithSecretLockService option, when provided then wallet will use local kms for key operations.
func WithSecretLockService(svc secretlock.Service) ProfileKeyManagerOptions {
	return func(opts *kmsOpts) {
		opts.secretLockSvc = svc
	}
}

// WithPassphrase option to provide passphrase for local kms for key operations.
func WithPassphrase(passphrase string) ProfileKeyManagerOptions {
	return func(opts *kmsOpts) {
		opts.passphrase = passphrase
	}
}

// WithKeyServerURL option, when provided then wallet will use remote kms for key operations.
// This option will be ignore if provided with 'WithSecretLockService' option.
func WithKeyServerURL(url string) ProfileKeyManagerOptions {
	return func(opts *kmsOpts) {
		opts.keyServerURL = url
	}
}

// unlockOpts contains options for unlocking VC wallet client.
type unlockOpts struct {
	// local kms options
	passphrase    string
	secretLockSvc secretlock.Service

	// remote(web) kms options
	authToken string

	// expiry
	tokenExpiry time.Duration
}

// UnlockOptions is option for unlocking verifiable credential wallet key manager.
// Wallet unlocking instantiates KMS instance for wallet operations.
// Type of key manager (local or remote) to be used will be decided based on options passed.
// Note: unlock options should match key manager options set for given wallet profile.
type UnlockOptions func(opts *unlockOpts)

// WithUnlockByPassphrase option for supplying passphrase to open wallet.
// This option takes precedence when provided along with other options.
func WithUnlockByPassphrase(passphrase string) UnlockOptions {
	return func(opts *unlockOpts) {
		opts.passphrase = passphrase
	}
}

// WithUnlockBySecretLockService option for supplying secret lock service to open wallet.
// This option will be ignored when supplied with 'WithPassphrase' option.
func WithUnlockBySecretLockService(svc secretlock.Service) UnlockOptions {
	return func(opts *unlockOpts) {
		opts.secretLockSvc = svc
	}
}

// WithUnlockByAuthorizationToken option for supplying remote kms auth token to open wallet.
// This option will be ignore when supplied with localkms options.
func WithUnlockByAuthorizationToken(url string) UnlockOptions {
	return func(opts *unlockOpts) {
		opts.authToken = url
	}
}

// WithUnlockExpiry time duration after which wallet key manager will be expired.
// Wallet should be reopened by using 'client.Open()' once expired or a new instance needs to be created.
func WithUnlockExpiry(tokenExpiry time.Duration) UnlockOptions {
	return func(opts *unlockOpts) {
		opts.tokenExpiry = tokenExpiry
	}
}

// proveOpts contains options for proving credentials.
type proveOpts struct {
	// IDs of credentials already saved in wallet.
	storedCredentials []string
	// raw credentials to be supplied to wallet to prove.
	rawCredentials []json.RawMessage
	// verifiable credentials to be supplied to wallet to prove.
	credentials []*verifiable.Credential
	// presentation to be supplied to wallet to prove.
	presentation *verifiable.Presentation
}

// ProveOptions options for proving credential to present from wallet.
type ProveOptions func(opts *proveOpts)

// WithStoredCredentialsToPresent option for providing stored credential IDs for wallet to present.
func WithStoredCredentialsToPresent(ids ...string) ProveOptions {
	return func(opts *proveOpts) {
		opts.storedCredentials = ids
	}
}

// WithRawCredentialsToPresent option for providing raw credential for wallet to present.
func WithRawCredentialsToPresent(raw ...json.RawMessage) ProveOptions {
	return func(opts *proveOpts) {
		opts.rawCredentials = raw
	}
}

// WithCredentialsToPresent option for providing verifiable credential instances for wallet to present.
func WithCredentialsToPresent(credentials ...*verifiable.Credential) ProveOptions {
	return func(opts *proveOpts) {
		opts.credentials = credentials
	}
}

// WithPresentation option for providing presentation for wallet to present.
// If passed along with other credentials options, response verifiable presentation will be normalized
// to include all the credentials.
func WithPresentation(presentation *verifiable.Presentation) ProveOptions {
	return func(opts *proveOpts) {
		opts.presentation = presentation
	}
}

// verifyOpts contains options for verifying credentials.
type verifyOpts struct {
	// ID of the credential to be verified from wallet.
	credentialID string
	// raw credentials to be verified from wallet.
	rawCredential json.RawMessage
	// raw presentation to be verified from wallet.
	rawPresentation json.RawMessage
}

// VerificationOption options for verifying credential from wallet.
type VerificationOption func(opts *verifyOpts)

// WithStoredCredentialToVerify option for providing ID of the stored credential to be verified from wallet.
func WithStoredCredentialToVerify(id string) VerificationOption {
	return func(opts *verifyOpts) {
		opts.credentialID = id
	}
}

// WithRawCredentialToVerify option for providing raw credential to be verified from wallet.
func WithRawCredentialToVerify(raw json.RawMessage) VerificationOption {
	return func(opts *verifyOpts) {
		opts.rawCredential = raw
	}
}

// WithRawPresentationToVerify option for providing raw presentation to be verified from wallet.
func WithRawPresentationToVerify(raw json.RawMessage) VerificationOption {
	return func(opts *verifyOpts) {
		opts.rawPresentation = raw
	}
}

// verifyOpts contains options for deriving credentials.
type deriveOpts struct {
	// for deriving credential from stored credential.
	credentialID string
	// for deriving credential from raw credential.
	rawCredential json.RawMessage
	// for deriving credential from credential instance.
	credential *verifiable.Credential
}

// CredentialToDerive is credential option for deriving a credential from wallet.
type CredentialToDerive func(opts *deriveOpts)

// FromStoredCredential for deriving credential from stored credential.
func FromStoredCredential(id string) CredentialToDerive {
	return func(opts *deriveOpts) {
		opts.credentialID = id
	}
}

// FromRawCredential for deriving credential from raw credential bytes.
func FromRawCredential(raw json.RawMessage) CredentialToDerive {
	return func(opts *deriveOpts) {
		opts.rawCredential = raw
	}
}

// FromCredential option for deriving credential from a credential instance.
func FromCredential(cred *verifiable.Credential) CredentialToDerive {
	return func(opts *deriveOpts) {
		opts.credential = cred
	}
}
