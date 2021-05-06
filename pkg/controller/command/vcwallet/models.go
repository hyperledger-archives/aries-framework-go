/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcwallet

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

// CreateOrUpdateProfileRequest is request model for
// creating a new wallet profile or updating an existing wallet profile.
type CreateOrUpdateProfileRequest struct {
	// Unique identifier to identify wallet user
	UserID string `json:"userID"`

	// passphrase for local kms for key operations.
	// Optional, if this option is provided then wallet for this profile will use local KMS for key operations.
	LocalKMSPassphrase string `json:"localKMSPassphrase,omitempty"`

	// passphrase for web/remote kms for key operations.
	// Optional, if this option is provided then wallet for this profile will use web/remote KMS for key operations.
	KeyStoreURL string `json:"keyStoreURL,omitempty"`

	// edv configuration for storing wallet contents for this profile
	// Optional, if not provided then agent storage provider will be used as store provider.
	EDVConfiguration *EDVConfiguration `json:"edvConfiguration,omitempty"`
}

// EDVConfiguration contains configuration for EDV settings for profile creation.
type EDVConfiguration struct {
	// EDV server URL for storing wallet contents.
	ServerURL string `json:"serverURL,omitempty"`

	// EDV vault ID for storing the wallet contents.
	VaultID string `json:"vaultID,omitempty"`

	// Encryption key ID of already existing key in wallet profile kms.
	// If profile is using localkms then wallet will create this key set for wallet user.
	EncryptionKeyID string `json:"encryptionKID,omitempty"`

	// MAC operation key ID of already existing key in wallet profile kms.
	// If profile is using localkms then wallet will create this key set for wallet user.
	MACKeyID string `json:"macKID,omitempty"`
}

// UnlockWalletRequest contains different options for unlocking wallet.
type UnlockWalletRequest struct {
	// user ID of the wallet to be unlocked.
	UserID string `json:"userID"`

	// passphrase for local kms for key operations.
	// Optional, to be used if profile for this wallet user is setup with local KMS.
	LocalKMSPassphrase string `json:"localKMSPassphrase,omitempty"`

	// WebKMSAuth for authorizing acccess to web/remote kms.
	// Optional, to be used if profile for this wallet user is setup with web/remote KMS.
	WebKMSAuth *UnlockAuth `json:"webKMSAuth,omitempty"`

	// Options for authorizing access to wallet's EDV content store.
	// Optional, to be used only if profile for this wallet user is setup to use EDV as content store.
	EDVUnlock *UnlockAuth `json:"edvUnlock,omitempty"`
}

// UnlockAuth contains different options for authorizing access to wallet's EDV content store & webkms.
type UnlockAuth struct {
	// Http header 'authorization' bearer token to be used.
	// Optional, only if required by wallet user.
	AuthToken string `json:"authToken,omitempty"`

	// Capability if ZCAP sign header feature to be used for authorizing access.
	// Optional, can be used only if ZCAP sign header feature is configured with command controller.
	// Note: will not be considered When provided with `AuthToken` option.
	Capability string `json:"capability,omitempty"`
}

// UnlockWalletResponse contains response for wallet unlock operation.
type UnlockWalletResponse struct {
	// Token for granting access to wallet for subsequent wallet operations.
	Token string `json:"token,omitempty"`
}

// LockWalletRequest contains options for locking wallet.
type LockWalletRequest struct {
	// user ID of the wallet to be locked.
	UserID string `json:"userID"`
}

// LockWalletResponse contains response for wallet lock operation.
type LockWalletResponse struct {
	// Closed status of the wallet lock operation.
	// if true, wallet is closed successfully
	// if false, wallet is already closed or never unlocked.
	Closed bool `json:"closed"`
}

// WalletAuth contains wallet auth parameters for performing wallet operations.
type WalletAuth struct {
	// Authorization token for performing wallet operations.
	Auth string `json:"auth"`

	// ID of wallet user.
	UserID string `json:"userID"`
}

// AddContentRequest is request for adding a content to wallet.
type AddContentRequest struct {
	WalletAuth

	// type of the content to be added to the wallet.
	// supported types: collection, credential, didResolutionResponse, metadata, connection, key
	ContentType wallet.ContentType `json:"contentType"`

	// content to be added to wallet content store.
	Content json.RawMessage `json:"content"`

	// ID of the wallet collection to which this content should belong.
	CollectionID string `json:"collectionID"`
}

// RemoveContentRequest is request for removing a content from wallet.
type RemoveContentRequest struct {
	WalletAuth

	// type of the content to be removed from the wallet.
	// supported types: collection, credential, didResolutionResponse, metadata, connection
	ContentType wallet.ContentType `json:"contentType"`

	// ID of the content to be removed from wallet
	ContentID string `json:"contentID"`
}

// GetContentRequest is request for getting a content from wallet.
type GetContentRequest struct {
	WalletAuth

	// type of the content to be returned from wallet.
	// supported types: collection, credential, didResolutionResponse, metadata, connection
	ContentType wallet.ContentType `json:"contentType"`

	// ID of the content to be returned from wallet
	ContentID string `json:"contentID"`
}

// GetContentResponse response for get content from wallet operation.
type GetContentResponse struct {
	// content retrieved from wallet content store.
	Content json.RawMessage `json:"content"`
}

// GetAllContentRequest is request for getting all contents from wallet for given content type.
type GetAllContentRequest struct {
	WalletAuth

	// type of the contents to be returned from wallet.
	// supported types: collection, credential, didResolutionResponse, metadata, connection
	ContentType wallet.ContentType `json:"contentType"`
}

// GetAllContentResponse response for get all content by content type wallet operation.
type GetAllContentResponse struct {
	// contents retrieved from wallet content store.
	// map of content ID to content.
	Contents map[string]json.RawMessage `json:"contents"`
}

// ContentQueryRequest is request model for querying wallet contents.
type ContentQueryRequest struct {
	WalletAuth

	// credential query(s) for querying wallet contents.
	Query []*wallet.QueryParams `json:"query"`
}

// ContentQueryResponse response for wallet content query.
type ContentQueryResponse struct {
	// contents retrieved from wallet content store.
	// map of content ID to content.
	Results []*verifiable.Presentation `json:"results"`
}

// IssueRequest is request model for issuing credential from wallet.
type IssueRequest struct {
	WalletAuth

	// raw credential to be issued from wallet.
	Credential json.RawMessage `json:"credential"`

	// proof options for issuing credential
	ProofOptions *wallet.ProofOptions `json:"proofOptions"`
}

// IssueResponse is response for issue credential interface from wallet.
type IssueResponse struct {
	// credential issued.
	Credential *verifiable.Credential `json:"credential"`
}

// ProveRequest for producing verifiable presentation from wallet.
// Contains options for proofs and credential. Any combination of credential option can be mixed.
type ProveRequest struct {
	WalletAuth

	// IDs of credentials already saved in wallet content store.
	StoredCredentials []string `json:"storedCredentials"`

	// List of raw credentials to be presented.
	RawCredentials []json.RawMessage `json:"rawCredentials"`

	// Presentation to be proved.
	Presentation json.RawMessage `json:"presentation"`

	// proof options for issuing credential.
	ProofOptions *wallet.ProofOptions `json:"proofOptions"`
}

// ProveResponse contains response presentation from prove operation.
type ProveResponse struct {
	// presentation response from prove operation.
	Presentation *verifiable.Presentation `json:"presentation"`
}

// VerifyRequest request for verifying a credential or presentation from wallet.
// Any one of the credential option should be used.
type VerifyRequest struct {
	WalletAuth

	// ID of the credential already saved in wallet content store.
	// optional, if provided then this option takes precedence over other options.
	StoredCredentialID string `json:"storedCredentialID"`

	// List of raw credential to be presented.
	// optional, if provided then this option takes precedence over presentation options.
	RawCredential json.RawMessage `json:"rawCredential"`

	// Presentation to be proved.
	// optional, will be used only if other options are not provided.
	Presentation json.RawMessage `json:"presentation"`
}

// VerifyResponse is response model for wallet verify operation.
type VerifyResponse struct {
	// if true then verification is successful.
	Verified bool `json:"verified"`

	// error details if verified is false.
	Error string `json:"error,omitempty"`
}

// DeriveRequest is request model for deriving a credential from wallet.
type DeriveRequest struct {
	WalletAuth

	// ID of the credential already saved in wallet content store.
	// optional, if provided then this option takes precedence.
	StoredCredentialID string `json:"storedCredentialID"`

	// List of raw credential to be presented.
	// optional, will be used only if other options is not provided.
	RawCredential json.RawMessage `json:"rawCredential"`

	// DeriveOptions options for deriving credential
	*wallet.DeriveOptions `json:"deriveOption"`
}

// DeriveResponse is response for derived credential operation.
type DeriveResponse struct {
	// credential derived.
	Credential *verifiable.Credential `json:"credential"`
}
