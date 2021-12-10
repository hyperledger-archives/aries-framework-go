/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rfc0593

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// Middleware is the RFC0593 issuecredential.Middleware that can be injected into the protocol service.
type Middleware issuecredential.Middleware

// RegisterMiddleware registers the Middleware in the IssueCredentialService looked up from the ServiceProvider.
//
// See also: NewMiddleware.
func RegisterMiddleware(mw Middleware, p ServiceProvider) error {
	typelessSvc, err := p.Service(issuecredential.Name)
	if err != nil {
		return fmt.Errorf("failed to lookup issuecredential service: %w", err)
	}

	svc, ok := typelessSvc.(IssueCredentialService)
	if !ok {
		return errors.New("unable to cast the issuecredential service to the required interface type")
	}

	svc.AddMiddleware(issuecredential.Middleware(mw))

	return nil
}

// NewMiddleware returns a new Middleware that can be used with the issuecredential protocol service
// in conjunction with AutoExecute when the protocol needs to be started with a request-credential
// message.
//
// Usage:
//     framework, err := aries.New()
//     if err != nil {
//         panic(err)
//     }
//     ctx, err := framework.Context()
//     if err != nil {
//         panic(err)
//     }
//     mw, err := NewMiddleware(ctx)
//     if err != nil {
//         panic(err)
//     }
//     err = RegisterMiddleware(mw, ctx)
//     if err != nil {
//         panic(err)
//     }
//     client := issuecredential.Client = ...
//     events = make(chan service.DIDCommAction)
//     err := client.RegisterActionEvent(events)
//     if err != nil {
//         panic(err)
//     }
//     next := make(chan service.DIDCommAction)
//     go AutoExecute(ctx, next)(events)
//     for event := range next {
//         // handle events from issue-credential that do not conform to RFC0593
//     }
//
// See also: AutoExecute.
func NewMiddleware(p TransientStorage) (Middleware, error) {
	s, err := p.ProtocolStateStorageProvider().OpenStore(StoreName)
	if err != nil {
		return nil, fmt.Errorf("rfc0593: failed to open store: %w", err)
	}

	return func(next issuecredential.Handler) issuecredential.Handler {
		return &handler{
			next:  next,
			store: s,
		}
	}, nil
}

type handler struct {
	next  issuecredential.Handler
	store storage.Store
}

// Handle the issuecredential.Metadata.
func (h *handler) Handle(md issuecredential.Metadata) error {
	var (
		formats     []issuecredential.Format
		attachments []decorator.Attachment
		err         error
	)

	switch md.Message().Type() {
	case issuecredential.RequestCredentialMsgTypeV2:
		p := &issuecredential.RequestCredentialV2{}
		err = md.Message().Decode(p)
		formats = p.Formats
		attachments = p.RequestsAttach
	default:
		return h.next.Handle(md)
	}

	if err != nil {
		return fmt.Errorf("rfc0593: failed to decode msg type %s: %w", md.Message().Type(), err)
	}

	attachment, err := FindAttachment(ProofVCDetailFormat, formats, attachments)
	if errors.Is(err, ErrRFC0593NotApplicable) {
		return h.next.Handle(md)
	}

	if err != nil {
		return fmt.Errorf("rfc0593: failed to fetch attachment: %w", err)
	}

	spec := &CredentialSpec{}

	err = unmarshalAttachmentContents(attachment, spec)
	if err != nil {
		return fmt.Errorf("rfc0593: failed to unmarshal attachment contents: %w", err)
	}

	err = saveOptionsIfNoError(nil, h.store, md.Message(), spec.Options)
	if err != nil {
		return fmt.Errorf("rfc0593: failed to save credential spec options: %w", err)
	}

	return h.next.Handle(md)
}
