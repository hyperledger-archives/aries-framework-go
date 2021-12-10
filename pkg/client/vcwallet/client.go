/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcwallet

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

var logger = log.New("aries-framework/client/vcwallet")

// ErrWalletLocked when key manager related operation attempted on locked wallet.
var ErrWalletLocked = errors.New("wallet locked")

// provider contains dependencies for the verifiable credential wallet client
// and is typically created by using aries.Context().
type provider interface {
	StorageProvider() storage.Provider
	VDRegistry() vdr.Registry
	Crypto() crypto.Crypto
	JSONLDDocumentLoader() ld.DocumentLoader
	MediaTypeProfiles() []string
	didCommProvider // to be used only if wallet needs to be participated in DIDComm.
}

// didCommProvider to be used only if wallet needs to be participated in DIDComm operation.
// TODO: using wallet KMS instead of provider KMS.
// TODO: reconcile Protocol storage with wallet store.
type didCommProvider interface {
	KMS() kms.KeyManager
	ServiceEndpoint() string
	ProtocolStateStorageProvider() storage.Provider
	Service(id string) (interface{}, error)
	KeyType() kms.KeyType
	KeyAgreementType() kms.KeyType
}

// walletAuth is auth function which returns wallet unlock token.
type walletAuth func() (string, error)

// noAuth default auth when wallet is still locked.
// nolint:gochecknoglobals
var noAuth walletAuth = func() (string, error) { return "", ErrWalletLocked }

// Client enable access to verifiable credential wallet features.
type Client struct {
	wallet *wallet.Wallet
	auth   walletAuth
}

// New returns new verifiable credential wallet client for given user.
//
//	Args:
//		- userID : unique user identifier used for login.
//		- provider: dependencies for the verifiable credential wallet client.
//		- options : options for unlocking wallet. Any other existing wallet instance of same wallet user will be locked
//		once this instance is unlocked.
//
// returns error if wallet profile is not found.
// To create a new wallet profile, use `CreateProfile()`.
// To update an existing profile, use `UpdateProfile()`.
func New(userID string, ctx provider, options ...wallet.UnlockOptions) (*Client, error) {
	w, err := wallet.New(userID, ctx)
	if err != nil {
		return nil, err
	}

	client := &Client{wallet: w, auth: noAuth}

	if len(options) > 0 {
		if client.Close() {
			logger.Debugf("wallet was already open, existing wallet instance key manager is now closed")
		}

		err = client.Open(options...)
		if err != nil {
			return nil, err
		}
	}

	return client, nil
}

// CreateProfile creates a new verifiable credential wallet profile for given user.
// returns error if wallet profile is already created.
// Use `UpdateProfile()` for replacing an already created verifiable credential wallet profile.
func CreateProfile(userID string, ctx provider, options ...wallet.ProfileOptions) error {
	return wallet.CreateProfile(userID, ctx, options...)
}

// UpdateProfile updates existing verifiable credential wallet profile.
// Will create new profile if no profile exists for given user.
// Caution: you might lose your existing keys if you change kms options.
func UpdateProfile(userID string, ctx provider, options ...wallet.ProfileOptions) error {
	return wallet.UpdateProfile(userID, ctx, options...)
}

// ProfileExists checks if profile exists for given wallet user, returns error if not found.
func ProfileExists(userID string, ctx provider) error {
	return wallet.ProfileExists(userID, ctx)
}

// Open unlocks wallet client's key manager instance and returns a token for subsequent use of wallet features.
//
//	Args:
//		- unlock options for opening wallet.
//
//	Returns token with expiry that can be used for subsequent use of wallet features.
func (c *Client) Open(options ...wallet.UnlockOptions) error {
	authToken, err := c.wallet.Open(options...)
	if err != nil {
		return err
	}

	c.auth = func() (s string, e error) {
		return authToken, nil
	}

	return nil
}

// Close expires token issued to this VC wallet client.
// returns false if token is not found or already expired for this wallet user.
func (c *Client) Close() bool {
	c.auth = noAuth

	return c.wallet.Close()
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
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Collection
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#DIDResolutionResponse
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
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
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Collection
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#DIDResolutionResponse
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Key
//
func (c *Client) Import(auth string, contents json.RawMessage) error {
	// TODO to be added #2433
	return fmt.Errorf("to be implemented")
}

// Add adds given data model to wallet contents store.
//
// Supported data models:
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Collection
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#DIDResolutionResponse
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Key
//
// TODO: (#2433) support for correlation between wallet contents (ex: credentials to a profile/collection).
func (c *Client) Add(contentType wallet.ContentType, content json.RawMessage, options ...wallet.AddContentOptions) error { //nolint: lll
	auth, err := c.auth()
	if err != nil {
		return err
	}

	return c.wallet.Add(auth, contentType, content, options...)
}

// Remove removes wallet content by content ID.
//
// Supported data models:
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Collection
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#DIDResolutionResponse
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
//
func (c *Client) Remove(contentType wallet.ContentType, contentID string) error {
	auth, err := c.auth()
	if err != nil {
		return err
	}

	return c.wallet.Remove(auth, contentType, contentID)
}

// Get fetches a wallet content by content ID.
//
// Supported data models:
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Collection
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#DIDResolutionResponse
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
//
func (c *Client) Get(contentType wallet.ContentType, contentID string) (json.RawMessage, error) {
	auth, err := c.auth()
	if err != nil {
		return nil, err
	}

	return c.wallet.Get(auth, contentType, contentID)
}

// GetAll fetches all wallet contents of given type.
//
// Supported data models:
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Collection
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#DIDResolutionResponse
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
//
func (c *Client) GetAll(contentType wallet.ContentType, options ...wallet.GetAllContentsOptions) (map[string]json.RawMessage, error) { //nolint: lll
	auth, err := c.auth()
	if err != nil {
		return nil, err
	}

	return c.wallet.GetAll(auth, contentType, options...)
}

// Query runs query against wallet credential contents and returns presentation containing credential results.
//
// https://w3c-ccg.github.io/universal-wallet-interop-spec/#query
//
// Supported Query Types:
// 	- https://www.w3.org/TR/json-ld11-framing
// 	- https://identity.foundation/presentation-exchange
// 	- https://w3c-ccg.github.io/vp-request-spec/#query-by-example
//
func (c *Client) Query(params ...*wallet.QueryParams) ([]*verifiable.Presentation, error) {
	auth, err := c.auth()
	if err != nil {
		return nil, err
	}

	return c.wallet.Query(auth, params...)
}

// Issue adds proof to a Verifiable Credential.
//
//	Args:
//		- A verifiable credential with or without proof
//		- Proof options
//
func (c *Client) Issue(credential json.RawMessage,
	options *wallet.ProofOptions) (*verifiable.Credential, error) {
	auth, err := c.auth()
	if err != nil {
		return nil, err
	}

	return c.wallet.Issue(auth, credential, options)
}

// Prove produces a Verifiable Presentation.
//
//	Args:
//		- list of interfaces (string of credential IDs which can be resolvable to stored credentials in wallet or
//		raw credential).
//		- proof options
//
func (c *Client) Prove(opts *wallet.ProofOptions, creds ...wallet.ProveOptions) (*verifiable.Presentation, error) { //nolint: lll
	auth, err := c.auth()
	if err != nil {
		return nil, err
	}

	return c.wallet.Prove(auth, opts, creds...)
}

// Verify takes Takes a Verifiable Credential or Verifiable Presentation as input,.
//
//	Args:
//		- verification option for sending different models (stored credential ID, raw credential, raw presentation).
//
// Returns: a boolean verified, and an error if verified is false.
func (c *Client) Verify(option wallet.VerificationOption) (bool, error) {
	auth, err := c.auth()
	if err != nil {
		return false, err
	}

	return c.wallet.Verify(auth, option)
}

// Derive derives a credential and returns response credential.
//
//	Args:
//		- credential to derive (ID of the stored credential, raw credential or credential instance).
//		- derive options.
//
func (c *Client) Derive(credential wallet.CredentialToDerive, options *wallet.DeriveOptions) (*verifiable.Credential, error) { //nolint: lll
	auth, err := c.auth()
	if err != nil {
		return nil, err
	}

	return c.wallet.Derive(auth, credential, options)
}

// CreateKeyPair creates key pair inside a wallet.
//
//	Args:
//		- authToken: authorization for performing create key pair operation.
//		- keyType: type of the key to be created.
//
func (c *Client) CreateKeyPair(keyType kms.KeyType) (*wallet.KeyPair, error) {
	auth, err := c.auth()
	if err != nil {
		return nil, err
	}

	return c.wallet.CreateKeyPair(auth, keyType)
}

// Connect accepts out-of-band invitations and performs DID exchange.
//
// Args:
// 		- invitation: out-of-band invitation.
// 		- options: connection options.
//
// Returns:
// 		- connection ID if DID exchange is successful.
// 		- error if operation false.
//
func (c *Client) Connect(invitation *outofband.Invitation, options ...wallet.ConnectOptions) (string, error) {
	auth, err := c.auth()
	if err != nil {
		return "", err
	}

	return c.wallet.Connect(auth, invitation, options...)
}

// ProposePresentation accepts out-of-band invitation and sends message proposing presentation
// from wallet to relying party.
//
// https://w3c-ccg.github.io/universal-wallet-interop-spec/#proposepresentation
//
// Currently Supporting
// [0454-present-proof-v2](https://github.com/hyperledger/aries-rfcs/tree/master/features/0454-present-proof-v2)
//
// Args:
// 		- invitation: out-of-band invitation from relying party.
// 		- options: options for accepting invitation and send propose presentation message.
//
// Returns:
// 		- DIDCommMsgMap containing request presentation message if operation is successful.
// 		- error if operation fails.
//
func (c *Client) ProposePresentation(invitation *wallet.GenericInvitation, options ...wallet.InitiateInteractionOption) (*service.DIDCommMsgMap, error) { //nolint: lll
	auth, err := c.auth()
	if err != nil {
		return nil, err
	}

	return c.wallet.ProposePresentation(auth, invitation, options...)
}

// PresentProof sends message present proof message from wallet to relying party.
// https://w3c-ccg.github.io/universal-wallet-interop-spec/#presentproof
//
// Currently Supporting
// [0454-present-proof-v2](https://github.com/hyperledger/aries-rfcs/tree/master/features/0454-present-proof-v2)
//
// Args:
// 		- thID: thread ID (action ID) of request presentation.
// 		- presentation: presentation to be sent.
//
// Returns:
// 		- Credential interaction status containing status, redirectURL.
// 		- error if operation fails.
//
func (c *Client) PresentProof(thID string, presentProofFrom ...wallet.ConcludeInteractionOptions) (*wallet.CredentialInteractionStatus, error) { //nolint: lll
	auth, err := c.auth()
	if err != nil {
		return nil, err
	}

	return c.wallet.PresentProof(auth, thID, presentProofFrom...)
}

// ProposeCredential sends propose credential message from wallet to issuer.
// https://w3c-ccg.github.io/universal-wallet-interop-spec/#requestcredential
//
// Currently Supporting : 0453-issueCredentialV2
// https://github.com/hyperledger/aries-rfcs/blob/main/features/0453-issue-credential-v2/README.md
//
// Args:
// 		- invitation: out-of-band invitation from issuer.
// 		- options: options for accepting invitation and send propose credential message.
//
// Returns:
// 		- DIDCommMsgMap containing offer credential message if operation is successful.
// 		- error if operation fails.
//
func (c *Client) ProposeCredential(invitation *wallet.GenericInvitation, options ...wallet.InitiateInteractionOption) (*service.DIDCommMsgMap, error) { // nolint: lll
	auth, err := c.auth()
	if err != nil {
		return nil, err
	}

	return c.wallet.ProposeCredential(auth, invitation, options...)
}

// RequestCredential sends request credential message from wallet to issuer and
// optionally waits for credential fulfillment.
// https://w3c-ccg.github.io/universal-wallet-interop-spec/#proposecredential
//
// Currently Supporting : 0453-issueCredentialV2
// https://github.com/hyperledger/aries-rfcs/blob/main/features/0453-issue-credential-v2/README.md
//
// Args:
// 		- thID: thread ID (action ID) of offer credential message previously received.
// 		- concludeInteractionOptions: options to conclude interaction like presentation to be shared etc.
//
// Returns:
// 		- Credential interaction status containing status, redirectURL.
// 		- error if operation fails.
//
func (c *Client) RequestCredential(thID string, options ...wallet.ConcludeInteractionOptions) (*wallet.CredentialInteractionStatus, error) { // nolint: lll
	auth, err := c.auth()
	if err != nil {
		return nil, err
	}

	return c.wallet.RequestCredential(auth, thID, options...)
}
