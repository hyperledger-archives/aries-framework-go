/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"encoding/json"
	"time"

	"github.com/hyperledger/aries-framework-go/component/storage/edv"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
)

// profileOpts contains options for creating verifiable credential wallet.
type profileOpts struct {
	// local kms options
	secretLockSvc secretlock.Service
	passphrase    string

	// remote(web) kms options
	keyServerURL string

	// EDV options
	edvConf *edvConf
}

// ProfileOptions is option for verifiable credential wallet key manager.
type ProfileOptions func(opts *profileOpts)

// WithSecretLockService option, when provided then wallet will use local kms for key operations.
func WithSecretLockService(svc secretlock.Service) ProfileOptions {
	return func(opts *profileOpts) {
		opts.secretLockSvc = svc
	}
}

// WithPassphrase option to provide passphrase for local kms for key operations.
func WithPassphrase(passphrase string) ProfileOptions {
	return func(opts *profileOpts) {
		opts.passphrase = passphrase
	}
}

// WithKeyServerURL option, when provided then wallet will use remote kms for key operations.
// This option will be ignore if provided with 'WithSecretLockService' option.
func WithKeyServerURL(url string) ProfileOptions {
	return func(opts *profileOpts) {
		opts.keyServerURL = url
	}
}

// WithEDVStorage option, for wallet profile to use EDV as storage.
// If provided then all wallet contents will use EDV for storage.
// Note: key manager options supplied for profile creation and management will be reused for EDV operations.
func WithEDVStorage(url, vaultID, encryptionKID, macKID string) ProfileOptions {
	return func(opts *profileOpts) {
		opts.edvConf = &edvConf{
			ServerURL:       url,
			VaultID:         vaultID,
			EncryptionKeyID: encryptionKID,
			MACKeyID:        macKID,
		}
	}
}

// unlockOpts contains options for unlocking VC wallet client.
type unlockOpts struct {
	// local kms options
	passphrase    string
	secretLockSvc secretlock.Service

	// remote(web) kms options
	authToken  string
	webkmsOpts []webkms.Opt

	// expiry
	tokenExpiry time.Duration

	// edv opts
	edvOpts []edv.RESTProviderOption
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

// WithUnlockWebKMSOptions can be used to provide custom aries web kms options for unlocking wallet.
// This option can be used to set web kms client http header function instead of using WithUnlockByAuthorizationToken.
func WithUnlockWebKMSOptions(webkmsOpts ...webkms.Opt) UnlockOptions {
	return func(opts *unlockOpts) {
		opts.webkmsOpts = webkmsOpts
	}
}

// WithUnlockEDVOptions can be used to provide custom aries edv options for unlocking wallet.
// Provided options will be considered only if given wallet profile is using EDV configurations.
func WithUnlockEDVOptions(edvOpts ...edv.RESTProviderOption) UnlockOptions {
	return func(opts *unlockOpts) {
		opts.edvOpts = edvOpts
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
	// rawPresentation to be supplied to wallet to prove.
	rawPresentation json.RawMessage
}

// ProveOptions options for proving credential to present from wallet.
type ProveOptions func(opts *proveOpts)

// WithStoredCredentialsToProve option for providing stored credential IDs for wallet to present.
func WithStoredCredentialsToProve(ids ...string) ProveOptions {
	return func(opts *proveOpts) {
		opts.storedCredentials = ids
	}
}

// WithRawCredentialsToProve option for providing raw credential for wallet to present.
func WithRawCredentialsToProve(raw ...json.RawMessage) ProveOptions {
	return func(opts *proveOpts) {
		opts.rawCredentials = raw
	}
}

// WithCredentialsToProve option for providing verifiable credential instances for wallet to present.
func WithCredentialsToProve(credentials ...*verifiable.Credential) ProveOptions {
	return func(opts *proveOpts) {
		opts.credentials = credentials
	}
}

// WithPresentationToProve option for providing presentation for wallet to present.
// If passed along with other credentials options, response verifiable presentation will be normalized
// to include all the credentials.
func WithPresentationToProve(presentation *verifiable.Presentation) ProveOptions {
	return func(opts *proveOpts) {
		opts.presentation = presentation
	}
}

// WithRawPresentationToProve option for providing raw presentation for wallet to present.
// Ignored if passed along with WithPresentationToProve option.
// If passed along with other credentials options, response verifiable presentation will be normalized
// to include all the credentials.
func WithRawPresentationToProve(presentation json.RawMessage) ProveOptions {
	return func(opts *proveOpts) {
		opts.rawPresentation = presentation
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

// AddContentOptions is option for adding contents to wallet.
type AddContentOptions func(opts *addContentOpts)

// addContentOpts contains options for adding contents to wallet.
type addContentOpts struct {
	// ID of the collection to which the content belongs.
	collectionID string
}

// AddByCollection option for grouping wallet contents by collection ID.
func AddByCollection(collectionID string) AddContentOptions {
	return func(opts *addContentOpts) {
		opts.collectionID = collectionID
	}
}

// GetAllContentsOptions is option for getting all contents from wallet.
type GetAllContentsOptions func(opts *getAllContentsOpts)

// getAllContentsOpts contains options for getting all contents from wallet.
type getAllContentsOpts struct {
	// ID of the collection to filter get all results by collection.
	collectionID string
}

// FilterByCollection option for getting all contents by collection from wallet.
func FilterByCollection(collectionID string) GetAllContentsOptions {
	return func(opts *getAllContentsOpts) {
		opts.collectionID = collectionID
	}
}

// connectOpts contains options for wallet's DIDComm connect features.
type connectOpts struct {
	outofband.EventOptions
	// timeout duration to wait before waiting for status 'completed'.
	timeout time.Duration
}

// ConnectOptions options for accepting incoming out-of-band invitation and connecting.
type ConnectOptions func(opts *connectOpts)

// WithMyLabel option for providing label to be shared with the other agent during the subsequent did-exchange.
func WithMyLabel(label string) ConnectOptions {
	return func(opts *connectOpts) {
		opts.Label = label
	}
}

// WithReuseAnyConnection option to use any recognized DID in the services array for a reusable connection.
func WithReuseAnyConnection(reuse bool) ConnectOptions {
	return func(opts *connectOpts) {
		opts.ReuseAny = reuse
	}
}

// WithReuseDID option to provide DID to be used when reusing a connection.
func WithReuseDID(did string) ConnectOptions {
	return func(opts *connectOpts) {
		opts.ReuseDID = did
	}
}

// WithRouterConnections option to provide for router connections to be used.
func WithRouterConnections(conns ...string) ConnectOptions {
	return func(opts *connectOpts) {
		opts.Connections = conns
	}
}

// WithConnectTimeout option providing connect timeout, to wait for connection status to be 'completed'.
func WithConnectTimeout(timeout time.Duration) ConnectOptions {
	return func(opts *connectOpts) {
		opts.timeout = timeout
	}
}

// getOobMessageOptions gets out-of-band message options to accept invitation from connect opts.
func getOobMessageOptions(opts *connectOpts) []outofband.MessageOption {
	var result []outofband.MessageOption

	if len(opts.Connections) > 0 {
		result = append(result, outofband.WithRouterConnections(opts.Connections...))
	}

	if opts.ReuseAny {
		result = append(result, outofband.ReuseAnyConnection())
	}

	return append(result, outofband.ReuseConnection(opts.ReuseDID))
}

// initiateInteractionOpts contains options for proposing presentation/credential from wallet by
// accepting out-of-band invitation from verifier/issuer.
type initiateInteractionOpts struct {
	// optional from DID option to customize message sender DID.
	from string
	// connect options.
	connectOpts []ConnectOptions
	// timeout duration to wait for response from invitee.
	timeout time.Duration
}

// InitiateInteractionOption options for initiating credential interaction by proposing presentation/credential
// from wallet.
type InitiateInteractionOption func(opts *initiateInteractionOpts)

// WithFromDID option for providing customized from DID for sending propose message.
func WithFromDID(from string) InitiateInteractionOption {
	return func(opts *initiateInteractionOpts) {
		opts.from = from
	}
}

// WithConnectOptions for customizing options for accepting invitation.
func WithConnectOptions(options ...ConnectOptions) InitiateInteractionOption {
	return func(opts *initiateInteractionOpts) {
		opts.connectOpts = options
	}
}

// WithInitiateTimeout to provide timeout duration to wait for response for propose message.
func WithInitiateTimeout(timeout time.Duration) InitiateInteractionOption {
	return func(opts *initiateInteractionOpts) {
		opts.timeout = timeout
	}
}

// concludeInteractionOpts contains options to conclude credential interaction by sending
// present proof or request credential message from wallet.
type concludeInteractionOpts struct {
	// presenting proof or requesting credential from raw credential.
	rawPresentation json.RawMessage
	// presenting proof or requesting credential from verifiable presentation instance.
	// this option takes precedence when provided with other options.
	presentation *verifiable.Presentation
	// if provided then wallet will wait till it gets acknowledgement or problem report from other party.
	waitForDone bool
	// time duration to wait for status to be done or abanoned.
	timeout time.Duration
}

// ConcludeInteractionOptions is option to conclude credential interaction between wallet and verifier/issuer by sending
// present proof or request credential message.
type ConcludeInteractionOptions func(opts *concludeInteractionOpts)

// FromPresentation for sending aries verifiable presentation as message attachment.
func FromPresentation(presentation *verifiable.Presentation) ConcludeInteractionOptions {
	return func(opts *concludeInteractionOpts) {
		opts.presentation = presentation
	}
}

// FromRawPresentation for sending raw JSON as presentation as message attachment.
func FromRawPresentation(raw json.RawMessage) ConcludeInteractionOptions {
	return func(opts *concludeInteractionOpts) {
		opts.rawPresentation = raw
	}
}

// WaitForDone if provided then wallet will wait for credential interaction protocol status to be
// done or abandoned till given timeout. If used then wallet will wait for acknowledgement or problem report
// from other party and also will return web redirect info if found in incoming message.
// If timeout is zero then wallet will use its default timeout.
func WaitForDone(timeout time.Duration) ConcludeInteractionOptions {
	return func(opts *concludeInteractionOpts) {
		opts.waitForDone = true

		if timeout <= 0 {
			opts.timeout = defaultWaitForPresentProofDone
		} else {
			opts.timeout = timeout
		}
	}
}
