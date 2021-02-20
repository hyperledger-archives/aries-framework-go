/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcwallet

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// provider contains dependencies for the verifiable credential wallet client
// and is typically created by using aries.Context().
type provider interface {
	StorageProvider() storage.Provider
}

// kmsOpts contains options for creating verifiable credential wallet client.
type kmsOpts struct {
	// local kms options
	secretLockSvc secretlock.Service
	passphrase    string

	// remote(web) kms options
	keyServerURL string
}

// KeyManagerOptions is option for verifiable credential wallet client key manager.
type KeyManagerOptions func(opts *kmsOpts)

// WithSecretLockService option, when provided then wallet client will use local kms for key operations.
func WithSecretLockService(svc secretlock.Service) KeyManagerOptions {
	return func(opts *kmsOpts) {
		opts.secretLockSvc = svc
	}
}

// WithPassphrase option to provide passphrase for local kms for key operations.
func WithPassphrase(passphrase string) KeyManagerOptions {
	return func(opts *kmsOpts) {
		opts.passphrase = passphrase
	}
}

// WithKeyServerURL option, when provided then wallet client will use remote kms for key operations.
// This option will be ignore if provided with 'WithSecretLockService' option.
func WithKeyServerURL(url string) KeyManagerOptions {
	return func(opts *kmsOpts) {
		opts.keyServerURL = url
	}
}

// Client enable access to verifiable credential wallet features.
type Client struct {
	// ID of wallet content owner
	userID string

	// wallet profile
	profile *profile

	// storage provider
	storeProvider storage.Provider
}

// New returns new verifiable credential wallet client for given user.
// returns error if wallet profile is not found.
// To create a new wallet profile, use `CreateProfile()`.
// To update an existing profile, use `UpdateProfile()`.
func New(userID string, ctx provider) (*Client, error) {
	store, err := newProfileStore(ctx.StorageProvider())
	if err != nil {
		return nil, fmt.Errorf("failed to get store to fetch VC wallet profile info: %w", err)
	}

	profile, err := store.get(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get VC wallet profile: %w", err)
	}

	return &Client{userID: userID, profile: profile, storeProvider: ctx.StorageProvider()}, nil
}

// CreateProfile creates a new verifiable credential wallet profile for given user.
// returns error if wallet profile is already created.
// Use `UpdateProfile()` for replacing an already created verifiable credential wallet profile.
func CreateProfile(userID string, ctx provider, options ...KeyManagerOptions) error {
	return createOrUpdate(userID, ctx, false, options...)
}

// UpdateProfile updates existing verifiable credential wallet profile.
// Will create new profile if no profile exists for given user.
// Caution: you might lose your existing keys if you change kms options.
func UpdateProfile(userID string, ctx provider, options ...KeyManagerOptions) error {
	return createOrUpdate(userID, ctx, true, options...)
}

func createOrUpdate(userID string, ctx provider, update bool, options ...KeyManagerOptions) error {
	opts := &kmsOpts{}

	for _, opt := range options {
		opt(opts)
	}

	profile, err := createProfile(userID, opts.passphrase, opts.secretLockSvc, opts.keyServerURL)
	if err != nil {
		return fmt.Errorf("failed to create new VC wallet client: %w", err)
	}

	store, err := newProfileStore(ctx.StorageProvider())
	if err != nil {
		return fmt.Errorf("failed to get store to save VC wallet profile: %w", err)
	}

	err = store.save(profile, update)
	if err != nil {
		return fmt.Errorf("failed to save VC wallet profile: %w", err)
	}

	return nil
}

// Open unlocks wallet client's key manager instance and returns a token for subsequent use of wallet features.
//
//	Args:
//		- auth : auth token in case of remotekms or passphrase in case of localkms.
//		- secretLockSvc: secret lock service for localkms if you choose not to provide passphrase.
//		- tokenExpiry : (optional, default: 10 * time.minute) time duration after which issued token will expiry.
//
//	Returns token with expiry that can be used for subsequent use of wallet features.
func (c *Client) Open(auth string, secretLockSvc secretlock.Service, tokenExpiry time.Duration) (string, error) {
	return keyManager().createKeyManager(c.profile, c.storeProvider, auth, secretLockSvc, tokenExpiry)
}

// Close expires token issued to this VC wallet client.
// returns false if token is not found or already expired for this wallet user.
func (c *Client) Close() bool {
	return keyManager().removeKeyManager(c.userID)
}

// Export produces a serialized exported wallet representation.
// Only ciphertext wallet contents can be exported.
//
//	Args:
//		- auth: token to be used to lock the wallet before exporting.
//
//	Returns exported locked wallet.
//
// Supported data models:
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Profile
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
//
func (c *Client) Export(auth string) (json.RawMessage, error) {
	// TODO to be added #2433
	return nil, fmt.Errorf("to be implemented")
}

// Import Takes a serialized exported wallet representation as input
// and imports all contents into wallet.
//
//	Args:
//		- contents: wallet content to be imported.
//		- auth: token used while exporting the wallet.
//
// Supported data models:
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Profile
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
//
func (c *Client) Import(auth string, contents json.RawMessage) error {
	// TODO to be added #2433
	return fmt.Errorf("to be implemented")
}

// Add adds given data model to wallet contents store.
//
// Supported data models:
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Profile
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
//
func (c *Client) Add(model json.RawMessage) error {
	// TODO to be added #2433
	return fmt.Errorf("to be implemented")
}

// Remove removes wallet content by content ID.
//
// Supported data models:
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Profile
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
//
func (c *Client) Remove(contentID string) error {
	// TODO to be added #2433
	return fmt.Errorf("to be implemented")
}

// Get fetches a wallet content by content ID.
//
// Supported data models:
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Profile
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
//
func (c *Client) Get(contentID string) (json.RawMessage, error) {
	// TODO to be added #2433
	return nil, fmt.Errorf("to be implemented")
}

// Query returns a collection of results based on current wallet contents.
//
// Supported Query Types:
// 	- https://www.w3.org/TR/json-ld11-framing
// 	- https://identity.foundation/presentation-exchange
//
func (c *Client) Query(query *QueryParams) ([]json.RawMessage, error) {
	// TODO to be added #2433
	return nil, fmt.Errorf("to be implemented")
}

// Issue adds proof to a Verifiable Credential.
//
//	Args:
//		- A verifiable credential with or without proof
//		- Proof options
//
func (c *Client) Issue(credential json.RawMessage, options *ProofOptions) (json.RawMessage, error) {
	// TODO to be added #2433
	return nil, fmt.Errorf("to be implemented")
}

// Prove produces a Verifiable Presentation.
//
//	Args:
//		- List of verifiable credentials IDs.
//		- Proof options
//
func (c *Client) Prove(credentialIDs []string, options *ProofOptions) (json.RawMessage, error) {
	// TODO to be added #2433
	return nil, fmt.Errorf("to be implemented")
}

// Verify takes Takes a Verifiable Credential or Verifiable Presentation as input,.
//
//	Args:
//		- a Verifiable Credential or Verifiable Presentation
//
// Returns: a boolean verified, and an error if verified is false.
func (c *Client) Verify(raw json.RawMessage) (bool, error) {
	// TODO to be added #2433
	return false, fmt.Errorf("to be implemented")
}
