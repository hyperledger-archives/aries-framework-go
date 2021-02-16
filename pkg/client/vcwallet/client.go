/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcwallet

import (
	"encoding/json"
	"fmt"
)

// provider contains dependencies for the verifiable credential wallet client
// and is typically created by using aries.Context().
type provider interface {
	// TODO to be added #2433
}

// Client enable access to verifiable credential wallet features.
type Client struct {
	// ID of wallet content owner
	userID string
}

// New returns new verifiable credential wallet client for given user.
func New(userID string, ctx provider) *Client {
	// TODO initialize providers for stores, VDR, KMS #2433
	// TODO create user profile if not already created #2433
	return &Client{userID: userID}
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
