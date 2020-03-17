/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/route"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

const (
	protocolURI    = "https://didcomm.org/oob-request/1.0"
	requestMsgType = protocolURI + "/request"
)

// RequestOptions allow you to customize the way request messages are built.
type RequestOptions func(*Request) error

// ConnectionRecorder records connection records produced as byproducts of creation of messages.
type connectionRecorder interface {
	SaveInvitation(id string, i interface{}) error
}

// Provider provides the dependencies for the client.
type Provider interface {
	StorageProvider() storage.Provider
	TransientStorageProvider() storage.Provider
	ServiceEndpoint() string
	Service(id string) (interface{}, error)
	LegacyKMS() legacykms.KeyManager
}

// Client for the Out-Of-Band protocol:
// https://github.com/hyperledger/aries-rfcs/blob/master/features/0434-outofband/README.md
type Client struct {
	didDocSvcFunc func() (*did.Service, error)
	connRecorder  connectionRecorder
}

// New returns a new Client for the Out-Of-Band protocol.
func New(p Provider) (*Client, error) {
	r, err := connection.NewRecorder(p)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize outofband client : %w", err)
	}

	return &Client{
		didDocSvcFunc: didServiceBlockFunc(p),
		connRecorder:  r,
	}, nil
}

// CreateRequest creates and saves an Out-Of-Band request message.
// At least one attachment must be provided.
// Service entries can be optionally provided. If none are provided then a new one will be automatically created for
// you.
func (c *Client) CreateRequest(opts ...RequestOptions) (*Request, error) {
	req := &Request{}

	for _, opt := range opts {
		if err := opt(req); err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
	}

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

	req.ID = uuid.New().String()
	req.Type = requestMsgType

	err := c.connRecorder.SaveInvitation(req.ID, req)
	if err != nil {
		return nil, fmt.Errorf("failed to save request : %w", err)
	}

	return req, nil
}

// WithLabel allows you to specify the label on the message.
func WithLabel(l string) RequestOptions {
	return func(r *Request) error {
		r.Label = l
		return nil
	}
}

// WithAttachments allows you to specify attachments to include in the `request~attach` property.
func WithAttachments(a ...*decorator.Attachment) RequestOptions {
	return func(r *Request) error {
		r.Requests = a
		return nil
	}
}

// WithGoal allows you to specify the `goal` and `goalCode` for the message.
func WithGoal(goal, goalCode string) RequestOptions {
	return func(r *Request) error {
		r.Goal = goal
		r.GoalCode = goalCode

		return nil
	}
}

// WithServices allows you to specify service entries to include in the request message.
// Each entry must be either a valid DID (string) or a `service` object.
func WithServices(svcs ...interface{}) RequestOptions {
	return func(r *Request) error {
		all := make([]interface{}, len(svcs))

		for i := range svcs {
			switch svc := svcs[i].(type) {
			case string:
				_, err := did.Parse(svc)

				if err != nil {
					return fmt.Errorf("failed to parse did : %w", err)
				}

				all[i] = svc
			case *did.Service:
				all[i] = svc
			default:
				return fmt.Errorf("unsupported service data type : %+v", svc)
			}
		}

		r.Service = all

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

		s, err := p.Service(route.Coordination)
		if err != nil {
			return nil, err
		}

		routeSvc, ok := s.(route.ProtocolService)
		if !ok {
			return nil, errors.New("cast service to Route Service failed")
		}

		// get the route configs
		serviceEndpoint, routingKeys, err := route.GetRouterConfig(routeSvc, p.ServiceEndpoint())
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

		if err = route.AddKeyToRouter(routeSvc, verKey); err != nil {
			return nil, fmt.Errorf("create invitation - add key to the router : %w", err)
		}

		return svc, nil
	}
}
