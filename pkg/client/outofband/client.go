/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
)

type (
	// Request is the out-of-band protocol's 'request' message.
	Request outofband.Request
	// Invitation is this protocol's `invitation` message
	Invitation outofband.Invitation
)

const (
	// RequestMsgType is the request message's '@type'.
	RequestMsgType = outofband.RequestMsgType
	// InvitationMsgType is the '@type' for the invitation message.
	InvitationMsgType = outofband.InvitationMsgType
)

// EventOptions are is a container of options that you can pass to an event's
// Continue function to customize the reaction to incoming out-of-band messages.
type EventOptions struct {
	// Label will be shared with the other agent during the subsequent did-exchange.
	Label string
}

// MyLabel will be shared with the other agent during the subsequent did-exchange.
func (e *EventOptions) MyLabel() string {
	return e.Label
}

// Event is a container of out-of-band protocol-specific properties for DIDCommActions and StateMsgs.
type Event interface {
	// ConnectionID of the connection record, once it's created.
	// This becomes available in a post-state event unless an error condition is encountered.
	ConnectionID() string
	// Error is non-nil if an error is encountered.
	Error() error
}

// MessageOption allow you to customize the way out-of-band messages are built.
type MessageOption func(*message) error

type message struct {
	Label    string
	Goal     string
	GoalCode string
	Service  []interface{}
}

type oobService interface {
	service.Event
	AcceptRequest(*outofband.Request, string) (string, error)
	AcceptInvitation(*outofband.Invitation, string) (string, error)
	SaveRequest(*outofband.Request) error
	SaveInvitation(*outofband.Invitation) error
}

// Provider provides the dependencies for the client.
type Provider interface {
	ServiceEndpoint() string
	Service(id string) (interface{}, error)
	LegacyKMS() legacykms.KeyManager
}

// Client for the Out-Of-Band protocol:
// https://github.com/hyperledger/aries-rfcs/blob/master/features/0434-outofband/README.md
type Client struct {
	service.Event
	didDocSvcFunc func() (*did.Service, error)
	oobService    oobService
}

// New returns a new Client for the Out-Of-Band protocol.
func New(p Provider) (*Client, error) {
	s, err := p.Service(outofband.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to look up service %s : %w", outofband.Name, err)
	}

	oobSvc, ok := s.(oobService)
	if !ok {
		return nil, fmt.Errorf("failed to cast service %s as a dependency", outofband.Name)
	}

	return &Client{
		Event:         oobSvc,
		didDocSvcFunc: didServiceBlockFunc(p),
		oobService:    oobSvc,
	}, nil
}

// CreateRequest creates and saves an Out-Of-Band request message.
// At least one attachment must be provided.
// Service entries can be optionally provided. If none are provided then a new one will be automatically created for
// you.
func (c *Client) CreateRequest(attchmnts []*decorator.Attachment, opts ...MessageOption) (*Request, error) {
	msg := &message{}

	for _, opt := range opts {
		if err := opt(msg); err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
	}

	req := &Request{
		ID:       uuid.New().String(),
		Type:     RequestMsgType,
		Label:    msg.Label,
		Goal:     msg.Goal,
		GoalCode: msg.GoalCode,
		Service:  msg.Service,
		Requests: attchmnts,
	}

	// TODO open question whether requests w/o attachments should be allowed:
	//  https://github.com/hyperledger/aries-rfcs/issues/451
	if len(req.Requests) == 0 {
		return nil, errors.New("must provide at least one attachment to create an out-of-band request")
	}

	if len(req.Service) == 0 {
		svc, err := c.didDocSvcFunc()
		if err != nil {
			return nil, fmt.Errorf("failed to create a new inlined did doc service block : %w", err)
		}

		req.Service = []interface{}{svc}
	}

	cast := outofband.Request(*req)

	err := c.oobService.SaveRequest(&cast)
	if err != nil {
		return nil, fmt.Errorf("outofband service failed to save request : %w", err)
	}

	return req, nil
}

// CreateInvitation creates and saves an out-of-band invitation.
// Protocols is an optional list of protocol identifier URIs that can be used to form connections. A default
// will be set if none are provided.
func (c *Client) CreateInvitation(protocols []string, opts ...MessageOption) (*Invitation, error) {
	msg := &message{}

	for _, opt := range opts {
		if err := opt(msg); err != nil {
			return nil, fmt.Errorf("failed to create invitation: %w", err)
		}
	}

	inv := &Invitation{
		ID:        uuid.New().String(),
		Type:      InvitationMsgType,
		Label:     msg.Label,
		Goal:      msg.Goal,
		GoalCode:  msg.GoalCode,
		Service:   msg.Service,
		Protocols: protocols,
	}

	if len(inv.Service) == 0 {
		svc, err := c.didDocSvcFunc()
		if err != nil {
			return nil, fmt.Errorf("failed to create a new inlined did doc service block : %w", err)
		}

		inv.Service = []interface{}{svc}
	}

	if len(inv.Protocols) == 0 {
		// TODO should be injected into client
		//  https://github.com/hyperledger/aries-framework-go/issues/1691
		inv.Protocols = []string{didexchange.PIURI}
	}

	cast := outofband.Invitation(*inv)

	err := c.oobService.SaveInvitation(&cast)
	if err != nil {
		return nil, fmt.Errorf("failed to save outofband invitation : %w", err)
	}

	return inv, nil
}

// AcceptRequest from another agent and return the ID of a new connection record.
func (c *Client) AcceptRequest(r *Request, myLabel string) (string, error) {
	cast := outofband.Request(*r)

	connID, err := c.oobService.AcceptRequest(&cast, myLabel)
	if err != nil {
		return "", fmt.Errorf("out-of-band service failed to accept request : %w", err)
	}

	return connID, err
}

// AcceptInvitation from another agent and return the ID of the new connection records.
func (c *Client) AcceptInvitation(i *Invitation, myLabel string) (string, error) {
	cast := outofband.Invitation(*i)

	connID, err := c.oobService.AcceptInvitation(&cast, myLabel)
	if err != nil {
		return "", fmt.Errorf("out-of-band service failed to accept invitation : %w", err)
	}

	return connID, err
}

// WithLabel allows you to specify the label on the message.
func WithLabel(l string) MessageOption {
	return func(m *message) error {
		m.Label = l
		return nil
	}
}

// WithGoal allows you to specify the `goal` and `goalCode` for the message.
func WithGoal(goal, goalCode string) MessageOption {
	return func(m *message) error {
		m.Goal = goal
		m.GoalCode = goalCode

		return nil
	}
}

// WithServices allows you to specify service entries to include in the request message.
// Each entry must be either a valid DID (string) or a `service` object.
func WithServices(svcs ...interface{}) MessageOption {
	return func(m *message) error {
		all := make([]interface{}, len(svcs))

		for i := range svcs {
			switch svc := svcs[i].(type) {
			case string:
				all[i] = svc

				// TODO uncomment this after fixing the sidetree implementation in BDD tests.
				//  That sidetree vdri is producing invalid DID IDs.
				//  https://github.com/hyperledger/aries-framework-go/issues/1642
				// _, err := did.Parse(svc)
			case *did.Service:
				all[i] = svc
			default:
				return fmt.Errorf("unsupported service data type : %+v", svc)
			}
		}

		m.Service = all

		return nil
	}
}

// DidDocServiceFunc returns a function that returns a DID doc `service` entry.
// Used when no service entries are specified when creating messages.
func didServiceBlockFunc(p Provider) func() (*did.Service, error) {
	return func() (*did.Service, error) {
		// TODO https://github.com/hyperledger/aries-framework-go/issues/623 'alias' should be passed as arg and persisted
		//  with connection record
		_, verKey, err := p.LegacyKMS().CreateKeySet()
		if err != nil {
			return nil, fmt.Errorf("failed CreateSigningKey: %w", err)
		}

		s, err := p.Service(mediator.Coordination)
		if err != nil {
			return nil, err
		}

		routeSvc, ok := s.(mediator.ProtocolService)
		if !ok {
			return nil, errors.New("cast service to Route Service failed")
		}

		// get the route configs
		serviceEndpoint, routingKeys, err := mediator.GetRouterConfig(routeSvc, p.ServiceEndpoint())
		if err != nil {
			return nil, fmt.Errorf("create invitation - fetch router config : %w", err)
		}

		svc := &did.Service{
			ID:              uuid.New().String(),
			Type:            "did-communication",
			Priority:        0,
			RecipientKeys:   []string{verKey},
			RoutingKeys:     routingKeys,
			ServiceEndpoint: serviceEndpoint,
		}

		if err = mediator.AddKeyToRouter(routeSvc, verKey); err != nil {
			return nil, fmt.Errorf("create invitation - add key to the router : %w", err)
		}

		return svc, nil
	}
}
