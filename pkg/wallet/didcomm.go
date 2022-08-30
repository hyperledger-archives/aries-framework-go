/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofbandv2"
	"github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	didexchangeSvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	issuecredentialsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	outofbandv2svc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofbandv2"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// miscellaneous constants.
const (
	msgEventBufferSize = 10
	ldJSONMimeType     = "application/ld+json"

	// protocol states.
	stateNameAbandoned  = "abandoned"
	stateNameAbandoning = "abandoning"
	stateNameDone       = "done"

	// timeout constants.
	defaultDIDExchangeTimeOut                = 120 * time.Second
	defaultWaitForRequestPresentationTimeOut = 120 * time.Second
	defaultWaitForPresentProofDone           = 120 * time.Second
	retryDelay                               = 500 * time.Millisecond
)

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

type combinedDidCommWalletProvider interface {
	provider
	didCommProvider
}

// DidComm enables access to verifiable credential wallet features.
type DidComm struct {
	// wallet implementation
	wallet *Wallet

	// present proof client
	presentProofClient *presentproof.Client

	// issue credential client
	issueCredentialClient *issuecredential.Client

	// out of band client
	oobClient *outofband.Client

	// out of band v2 client
	oobV2Client *outofbandv2.Client

	// did-exchange client
	didexchangeClient *didexchange.Client

	// connection lookup
	connectionLookup *connection.Lookup
}

// NewDidComm returns new verifiable credential wallet for given user.
// returns error if wallet profile is not found.
// To create a new wallet profile, use `CreateProfile()`.
// To update an existing profile, use `UpdateProfile()`.
func NewDidComm(wallet *Wallet, ctx combinedDidCommWalletProvider) (*DidComm, error) {
	presentProofClient, err := presentproof.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize present proof client: %w", err)
	}

	issueCredentialClient, err := issuecredential.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize issue credential client: %w", err)
	}

	oobClient, err := outofband.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize out-of-band client: %w", err)
	}

	oobV2Client, err := outofbandv2.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize out-of-band v2 client: %w", err)
	}

	connectionLookup, err := connection.NewLookup(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize connection lookup: %w", err)
	}

	didexchangeClient, err := didexchange.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize didexchange client: %w", err)
	}

	return &DidComm{
		wallet:                wallet,
		presentProofClient:    presentProofClient,
		issueCredentialClient: issueCredentialClient,
		oobClient:             oobClient,
		oobV2Client:           oobV2Client,
		didexchangeClient:     didexchangeClient,
		connectionLookup:      connectionLookup,
	}, nil
}

// Connect accepts out-of-band invitations and performs DID exchange.
//
// Args:
// 		- authToken: authorization for performing create key pair operation.
// 		- invitation: out-of-band invitation.
// 		- options: connection options.
//
// Returns:
// 		- connection ID if DID exchange is successful.
// 		- error if operation false.
//
func (c *DidComm) Connect(authToken string, invitation *outofband.Invitation, options ...ConnectOptions) (string, error) { //nolint: lll
	statusCh := make(chan service.StateMsg, msgEventBufferSize)

	err := c.didexchangeClient.RegisterMsgEvent(statusCh)
	if err != nil {
		return "", fmt.Errorf("failed to register msg event : %w", err)
	}

	defer func() {
		e := c.didexchangeClient.UnregisterMsgEvent(statusCh)
		if e != nil {
			logger.Warnf("Failed to unregister msg event for connect: %w", e)
		}
	}()

	opts := &connectOpts{}
	for _, opt := range options {
		opt(opts)
	}

	connID, err := c.oobClient.AcceptInvitation(invitation, opts.Label, getOobMessageOptions(opts)...)
	if err != nil {
		return "", fmt.Errorf("failed to accept invitation : %w", err)
	}

	if opts.timeout == 0 {
		opts.timeout = defaultDIDExchangeTimeOut
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()

	err = waitForConnect(ctx, statusCh, connID)
	if err != nil {
		return "", fmt.Errorf("wallet connect failed : %w", err)
	}

	return connID, nil
}

// ProposePresentation accepts out-of-band invitation and sends message proposing presentation
// from wallet to relying party.
// https://w3c-ccg.github.io/universal-wallet-interop-spec/#proposepresentation
//
// Currently Supporting
// [0454-present-proof-v2](https://github.com/hyperledger/aries-rfcs/tree/master/features/0454-present-proof-v2)
//
// Args:
// 		- authToken: authorization for performing operation.
// 		- invitation: out-of-band invitation from relying party.
// 		- options: options for accepting invitation and send propose presentation message.
//
// Returns:
// 		- DIDCommMsgMap containing request presentation message if operation is successful.
// 		- error if operation fails.
//
func (c *DidComm) ProposePresentation(authToken string, invitation *GenericInvitation, options ...InitiateInteractionOption) (*service.DIDCommMsgMap, error) { //nolint: lll
	opts := &initiateInteractionOpts{}
	for _, opt := range options {
		opt(opts)
	}

	var (
		connID string
		err    error
	)

	switch invitation.Version() {
	default:
		fallthrough
	case service.V1:
		connID, err = c.Connect(authToken, (*outofband.Invitation)(invitation.AsV1()), opts.connectOpts...)
		if err != nil {
			return nil, fmt.Errorf("failed to perform did connection : %w", err)
		}
	case service.V2:
		connOpts := &connectOpts{}

		for _, opt := range opts.connectOpts {
			opt(connOpts)
		}

		connID, err = c.oobV2Client.AcceptInvitation(
			invitation.AsV2(),
			outofbandv2svc.WithRouterConnections(connOpts.Connections),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to accept OOB v2 invitation : %w", err)
		}
	}

	connRecord, err := c.connectionLookup.GetConnectionRecord(connID)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup connection for propose presentation : %w", err)
	}

	opts = prepareInteractionOpts(connRecord, opts)

	_, err = c.presentProofClient.SendProposePresentation(&presentproof.ProposePresentation{}, connRecord)
	if err != nil {
		return nil, fmt.Errorf("failed to propose presentation from wallet: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()

	return c.waitForRequestPresentation(ctx, connRecord)
}

// PresentProof sends message present proof message from wallet to relying party.
// https://w3c-ccg.github.io/universal-wallet-interop-spec/#presentproof
//
// Currently Supporting
// [0454-present-proof-v2](https://github.com/hyperledger/aries-rfcs/tree/master/features/0454-present-proof-v2)
//
// Args:
// 		- authToken: authorization for performing operation.
// 		- thID: thread ID (action ID) of request presentation.
// 		- presentProofFrom: presentation to be sent.
//
// Returns:
// 		- Credential interaction status containing status, redirectURL.
// 		- error if operation fails.
//
func (c *DidComm) PresentProof(authToken, thID string, options ...ConcludeInteractionOptions) (*CredentialInteractionStatus, error) { //nolint: lll
	opts := &concludeInteractionOpts{}

	for _, option := range options {
		option(opts)
	}

	var presentation interface{}
	if opts.presentation != nil {
		presentation = opts.presentation
	} else {
		presentation = opts.rawPresentation
	}

	err := c.presentProofClient.AcceptRequestPresentation(thID, &presentproof.Presentation{
		Attachments: []decorator.GenericAttachment{{
			ID: uuid.New().String(),
			Data: decorator.AttachmentData{
				JSON: presentation,
			},
		}},
	}, nil)
	if err != nil {
		return nil, err
	}

	// wait for ack or problem-report.
	if opts.waitForDone {
		statusCh := make(chan service.StateMsg, msgEventBufferSize)

		err = c.presentProofClient.RegisterMsgEvent(statusCh)
		if err != nil {
			return nil, fmt.Errorf("failed to register present proof msg event : %w", err)
		}

		defer func() {
			e := c.presentProofClient.UnregisterMsgEvent(statusCh)
			if e != nil {
				logger.Warnf("Failed to unregister msg event for present proof: %w", e)
			}
		}()

		ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
		defer cancel()

		return waitCredInteractionCompletion(ctx, statusCh, thID)
	}

	return &CredentialInteractionStatus{Status: model.AckStatusPENDING}, nil
}

// ProposeCredential sends propose credential message from wallet to issuer.
// https://w3c-ccg.github.io/universal-wallet-interop-spec/#proposecredential
//
// Currently Supporting : 0453-issueCredentialV2
// https://github.com/hyperledger/aries-rfcs/blob/main/features/0453-issue-credential-v2/README.md
//
// Args:
// 		- authToken: authorization for performing operation.
// 		- invitation: out-of-band invitation from issuer.
// 		- options: options for accepting invitation and send propose credential message.
//
// Returns:
// 		- DIDCommMsgMap containing offer credential message if operation is successful.
// 		- error if operation fails.
//
func (c *DidComm) ProposeCredential(authToken string, invitation *GenericInvitation, options ...InitiateInteractionOption) (*service.DIDCommMsgMap, error) { //nolint: lll
	opts := &initiateInteractionOpts{}
	for _, opt := range options {
		opt(opts)
	}

	var (
		connID string
		err    error
	)

	switch invitation.Version() {
	default:
		fallthrough
	case service.V1:
		connID, err = c.Connect(authToken, (*outofband.Invitation)(invitation.AsV1()), opts.connectOpts...)
		if err != nil {
			return nil, fmt.Errorf("failed to perform did connection : %w", err)
		}
	case service.V2:
		connOpts := &connectOpts{}

		for _, opt := range opts.connectOpts {
			opt(connOpts)
		}

		connID, err = c.oobV2Client.AcceptInvitation(
			invitation.AsV2(),
			outofbandv2svc.WithRouterConnections(connOpts.Connections),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to accept OOB v2 invitation : %w", err)
		}
	}

	connRecord, err := c.connectionLookup.GetConnectionRecord(connID)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup connection for propose presentation : %w", err)
	}

	opts = prepareInteractionOpts(connRecord, opts)

	_, err = c.issueCredentialClient.SendProposal(
		&issuecredential.ProposeCredential{InvitationID: invitation.ID},
		connRecord,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to propose credential from wallet: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()

	return c.waitForOfferCredential(ctx, connRecord)
}

// RequestCredential sends request credential message from wallet to issuer and
// optionally waits for credential response.
// https://w3c-ccg.github.io/universal-wallet-interop-spec/#requestcredential
//
// Currently Supporting : 0453-issueCredentialV2
// https://github.com/hyperledger/aries-rfcs/blob/main/features/0453-issue-credential-v2/README.md
//
// Args:
// 		- authToken: authorization for performing operation.
// 		- thID: thread ID (action ID) of offer credential message previously received.
// 		- concludeInteractionOptions: options to conclude interaction like presentation to be shared etc.
//
// Returns:
// 		- Credential interaction status containing status, redirectURL.
// 		- error if operation fails.
//
func (c *DidComm) RequestCredential(authToken, thID string, options ...ConcludeInteractionOptions) (*CredentialInteractionStatus, error) { //nolint: lll
	opts := &concludeInteractionOpts{}

	for _, option := range options {
		option(opts)
	}

	var presentation interface{}
	if opts.presentation != nil {
		presentation = opts.presentation
	} else {
		presentation = opts.rawPresentation
	}

	attachmentID := uuid.New().String()

	err := c.issueCredentialClient.AcceptOffer(thID, &issuecredential.RequestCredential{
		Type: issuecredentialsvc.RequestCredentialMsgTypeV2,
		Formats: []issuecredentialsvc.Format{{
			AttachID: attachmentID,
			Format:   ldJSONMimeType,
		}},
		Attachments: []decorator.GenericAttachment{{
			ID: attachmentID,
			Data: decorator.AttachmentData{
				JSON: presentation,
			},
		}},
	})
	if err != nil {
		return nil, err
	}

	// wait for credential response.
	if opts.waitForDone {
		statusCh := make(chan service.StateMsg, msgEventBufferSize)

		err = c.issueCredentialClient.RegisterMsgEvent(statusCh)
		if err != nil {
			return nil, fmt.Errorf("failed to register issue credential action event : %w", err)
		}

		defer func() {
			e := c.issueCredentialClient.UnregisterMsgEvent(statusCh)
			if e != nil {
				logger.Warnf("Failed to unregister action event for issue credential: %w", e)
			}
		}()

		ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
		defer cancel()

		return waitCredInteractionCompletion(ctx, statusCh, thID)
	}

	return &CredentialInteractionStatus{Status: model.AckStatusPENDING}, nil
}

// currently correlating response action by connection due to limitation in current present proof V1 implementation.
func (c *DidComm) waitForRequestPresentation(ctx context.Context, record *connection.Record) (*service.DIDCommMsgMap, error) { //nolint: lll
	done := make(chan *service.DIDCommMsgMap)

	go func() {
		for {
			actions, err := c.presentProofClient.Actions()
			if err != nil {
				continue
			}

			if len(actions) > 0 {
				for _, action := range actions {
					if action.MyDID == record.MyDID && action.TheirDID == record.TheirDID {
						done <- &action.Msg
						return
					}
				}
			}

			select {
			default:
				time.Sleep(retryDelay)
			case <-ctx.Done():
				return
			}
		}
	}()

	select {
	case msg := <-done:
		return msg, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("timeout waiting for request presentation message")
	}
}

// currently correlating response action by connection due to limitation in current issue credential V1 implementation.
func (c *DidComm) waitForOfferCredential(ctx context.Context, record *connection.Record) (*service.DIDCommMsgMap, error) { //nolint: lll
	done := make(chan *service.DIDCommMsgMap)

	go func() {
		for {
			actions, err := c.issueCredentialClient.Actions()
			if err != nil {
				continue
			}

			if len(actions) > 0 {
				for _, action := range actions {
					if action.MyDID == record.MyDID && action.TheirDID == record.TheirDID {
						done <- &action.Msg
						return
					}
				}
			}

			select {
			default:
				time.Sleep(retryDelay)
			case <-ctx.Done():
				return
			}
		}
	}()

	select {
	case msg := <-done:
		return msg, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("timeout waiting for offer credential message")
	}
}

func waitForConnect(ctx context.Context, didStateMsgs chan service.StateMsg, connID string) error {
	done := make(chan struct{})

	go func() {
		for msg := range didStateMsgs {
			if msg.Type != service.PostState || msg.StateID != didexchangeSvc.StateIDCompleted {
				continue
			}

			var event model.Event

			switch p := msg.Properties.(type) {
			case model.Event:
				event = p
			default:
				logger.Warnf("failed to cast didexchange event properties")

				continue
			}

			if event.ConnectionID() == connID {
				logger.Debugf(
					"Received connection complete event for invitationID=%s connectionID=%s",
					event.InvitationID(), event.ConnectionID())

				close(done)

				break
			}
		}
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("time out waiting for did exchange state 'completed'")
	}
}

// wait for credential interaction to be completed (done or abandoned protocol state).
func waitCredInteractionCompletion(ctx context.Context, didStateMsgs chan service.StateMsg, thID string) (*CredentialInteractionStatus, error) { // nolint:gocognit,gocyclo,lll
	done := make(chan *CredentialInteractionStatus)

	go func() {
		for msg := range didStateMsgs {
			// match post state.
			if msg.Type != service.PostState {
				continue
			}

			// invalid state msg.
			if msg.Msg == nil {
				continue
			}

			msgThID, err := msg.Msg.ThreadID()
			if err != nil {
				continue
			}

			// match parent thread ID.
			if msg.Msg.ParentThreadID() != thID && msgThID != thID {
				continue
			}

			// match protocol state.
			if msg.StateID != stateNameDone && msg.StateID != stateNameAbandoned && msg.StateID != stateNameAbandoning {
				continue
			}

			properties := msg.Properties.All()

			response := &CredentialInteractionStatus{}
			response.RedirectURL, response.Status = getWebRedirectInfo(properties)

			// if redirect status missing, then use protocol state, done -> OK, abandoned -> FAIL.
			if response.Status == "" {
				if msg.StateID == stateNameAbandoned || msg.StateID == stateNameAbandoning {
					response.Status = model.AckStatusFAIL
				} else {
					response.Status = model.AckStatusOK
				}
			}

			done <- response

			return
		}
	}()

	select {
	case status := <-done:
		return status, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("time out waiting for credential interaction to get completed")
	}
}

func prepareInteractionOpts(connRecord *connection.Record, opts *initiateInteractionOpts) *initiateInteractionOpts {
	if opts.from == "" {
		opts.from = connRecord.TheirDID
	}

	if opts.timeout == 0 {
		opts.timeout = defaultWaitForRequestPresentationTimeOut
	}

	return opts
}

// getWebRedirectInfo reads web redirect info from properties.
func getWebRedirectInfo(properties map[string]interface{}) (string, string) {
	var redirect, status string

	if redirectURL, ok := properties[webRedirectURLKey]; ok {
		redirect = redirectURL.(string) //nolint: errcheck, forcetypeassert
	}

	if redirectStatus, ok := properties[webRedirectStatusKey]; ok {
		status = redirectStatus.(string) //nolint: errcheck, forcetypeassert
	}

	return redirect, status
}
