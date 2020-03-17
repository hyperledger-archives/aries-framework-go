/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"errors"
	"fmt"

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
type ConnectionRecorder interface {
	SaveInvitation(id string, i interface{}) error
}

// Provider provides the dependencies for the client.
type Provider interface {
	// DidDocServiceFunc returns a function that returns a DID doc `service` entry.
	// Used when no service entries are specified when creating messages.
	DidDocServiceFunc() func() (*did.Service, error)
	ConnRecorder() ConnectionRecorder
}

// Client for the Out-Of-Band protocol:
// https://github.com/hyperledger/aries-rfcs/blob/master/features/0434-outofband/README.md
type Client struct {
	didDocSvcFunc func() (*did.Service, error)
	connRecorder  ConnectionRecorder
}

// New returns a new Client for the Out-Of-Band protocol.
func New(p Provider) *Client {
	return &Client{
		didDocSvcFunc: p.DidDocServiceFunc(),
		connRecorder:  p.ConnRecorder(),
	}
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
