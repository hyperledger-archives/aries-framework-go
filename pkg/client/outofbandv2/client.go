/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofbandv2

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	oobv2 "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofbandv2"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

const (
	// InvitationMsgType is the 'type' for the invitation message.
	InvitationMsgType = oobv2.InvitationMsgType
)

// MessageOption allow you to customize the way out-of-band messages are built.
type MessageOption func(*message)

type message struct {
	Label              string
	Goal               string
	GoalCode           string
	From               string
	RouterConnections  []string
	Service            []interface{}
	HandshakeProtocols []string
	Attachments        []*decorator.AttachmentV2
	Accept             []string
}

// OobService defines the outofband service.
type OobService interface {
	AcceptInvitation(*oobv2.Invitation) (string, error)
	SaveInvitation(inv *oobv2.Invitation) error
}

// Provider provides the dependencies for the client.
type Provider interface {
	ServiceEndpoint() string
	Service(id string) (interface{}, error)
	KMS() kms.KeyManager
	KeyType() kms.KeyType
	KeyAgreementType() kms.KeyType
	MediaTypeProfiles() []string
}

// Client for the Out-Of-Band protocol:
// https://github.com/hyperledger/aries-rfcs/blob/master/features/0434-outofband/README.md
type Client struct {
	oobService        OobService
	mediaTypeProfiles []string
}

// New returns a new Client for the Out-Of-Band protocol.
func New(p Provider) (*Client, error) {
	s, err := p.Service(oobv2.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to look up service %s : %w", oobv2.Name, err)
	}

	oobSvc, ok := s.(OobService)
	if !ok {
		return nil, fmt.Errorf("failed to cast service %s as a dependency", oobv2.Name)
	}

	mtp := p.MediaTypeProfiles()

	if len(mtp) == 0 {
		mtp = []string{transport.MediaTypeDIDCommV2Profile}
	}

	client := &Client{
		oobService:        oobSvc,
		mediaTypeProfiles: mtp,
	}

	return client, nil
}

// CreateInvitation creates and saves an out-of-band/v2 invitation.
func (c *Client) CreateInvitation(opts ...MessageOption) (*oobv2.Invitation, error) {
	msg := &message{}

	for _, opt := range opts {
		opt(msg)
	}

	inv := &oobv2.Invitation{
		ID:    uuid.New().String(),
		Type:  InvitationMsgType,
		Label: msg.Label,
		From:  msg.From,
		Body: &oobv2.InvitationBody{
			Goal:     msg.Goal,
			GoalCode: msg.GoalCode,
			Accept:   msg.Accept,
		},
		Requests: msg.Attachments,
	}

	if len(inv.Body.Accept) == 0 {
		inv.Body.Accept = c.mediaTypeProfiles
	}

	err := c.oobService.SaveInvitation(inv)
	if err != nil {
		return nil, fmt.Errorf("out-of-band/2.0 service failed to save invitation : %w", err)
	}

	return inv, nil
}

// AcceptInvitation from another agent and return the ID of the new connection records.
func (c *Client) AcceptInvitation(i *oobv2.Invitation) (string, error) {
	connID, err := c.oobService.AcceptInvitation(i)
	if err != nil {
		return "", fmt.Errorf("out-of-band/2.0 service failed to accept invitation : %w", err)
	}

	return connID, nil
}

// WithLabel allows you to specify the label on the message.
func WithLabel(l string) MessageOption {
	return func(m *message) {
		m.Label = l
	}
}

// WithFrom allows you to specify the sender's DID on the message.
func WithFrom(f string) MessageOption {
	return func(m *message) {
		m.From = f
	}
}

// WithGoal allows you to specify the `goal` and `goalCode` for the message.
func WithGoal(goal, goalCode string) MessageOption {
	return func(m *message) {
		m.Goal = goal
		m.GoalCode = goalCode
	}
}

// WithAttachments allows you to include attachments in the Invitation.
func WithAttachments(a ...*decorator.AttachmentV2) MessageOption {
	return func(m *message) {
		m.Attachments = a
	}
}

// WithAccept will set the given media type profiles in the Invitation's `accept` property.
// Only valid values from RFC 0044 are supported.
func WithAccept(a ...string) MessageOption {
	return func(m *message) {
		m.Accept = a
	}
}
