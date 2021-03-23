/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/cucumber/godog"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	didexcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/didexchange"
	outofbandcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/outofband"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	didexsteps "github.com/hyperledger/aries-framework-go/test/bdd/pkg/didexchange"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/util"
)

const (
	connections      = "/connections"
	createInvitation = "/outofband/create-invitation"
	acceptInvitation = "/outofband/accept-invitation"

	stateCompleted = "completed"
)

// ControllerSteps is steps for outofband with controller.
type ControllerSteps struct {
	bddContext         *context.BDDContext
	pendingInvitations map[string]*outofband.Invitation
	connections        map[string]string
	didexchange        *didexsteps.ControllerSteps
}

// NewOutofbandControllerSteps creates steps for outofband with controller.
func NewOutofbandControllerSteps() *ControllerSteps {
	return &ControllerSteps{
		didexchange:        didexsteps.NewDIDExchangeControllerSteps(),
		pendingInvitations: make(map[string]*outofband.Invitation),
		connections:        make(map[string]string),
	}
}

// SetContext sets every scenario with a fresh context.
func (s *ControllerSteps) SetContext(ctx *context.BDDContext) {
	s.bddContext = ctx
	s.didexchange.SetContext(s.bddContext)
}

// RegisterSteps registers agent steps
// nolint:lll
func (s *ControllerSteps) RegisterSteps(suite *godog.Suite) {
	suite.Step(`^"([^"]*)" constructs an out-of-band invitation \(controller\)$`, s.constructOOBInvitation)
	suite.Step(
		`^"([^"]*)" sends the invitation to "([^"]*)" through an out-of-band channel \(controller\)$`, s.sendInvitationThruOOBChannel)
	suite.Step(`^"([^"]*)" accepts the invitation and connects with "([^"]*)" \(controller\)$`, s.acceptInvitationAndConnect)
	suite.Step(`^"([^"]*)" and "([^"]*)" have a connection \(controller\)$`, s.CheckConnection)
}

// CheckConnection checks a connection between agents.
func (s *ControllerSteps) CheckConnection(receiverID, senderID string) error {
	_, err := s.GetConnection(receiverID, senderID)
	if err != nil {
		return err
	}

	_, err = s.GetConnection(senderID, receiverID)

	return err
}

func (s *ControllerSteps) acceptInvitationAndConnect(receiverID, senderID string) error {
	invitation, found := s.pendingInvitations[receiverID]
	if !found {
		return fmt.Errorf("no pending invitations found for %s", receiverID)
	}

	controllerURL, ok := s.bddContext.GetControllerURL(receiverID)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", receiverID)
	}

	payload, err := json.Marshal(outofbandcmd.AcceptInvitationArgs{
		Invitation: invitation,
		MyLabel:    receiverID,
	})
	if err != nil {
		return fmt.Errorf("marshal create invitation: %w", err)
	}

	res := outofbandcmd.AcceptInvitationResponse{}

	err = util.SendHTTP(http.MethodPost, controllerURL+acceptInvitation, payload, &res)
	if err != nil {
		return fmt.Errorf("accept invitation: %w", err)
	}

	s.connections[receiverID+senderID] = res.ConnectionID

	return s.DidExchangeApproveRequest(receiverID, senderID)
}

// DidExchangeApproveRequest approves request (didexchange).
func (s *ControllerSteps) DidExchangeApproveRequest(receiverID, senderID string) error {
	if err := s.didexchange.ApproveRequest(senderID); err != nil {
		return fmt.Errorf("approve request: %w", err)
	}

	if err := s.didexchange.WaitForPostEvent(receiverID, stateCompleted); err != nil {
		return fmt.Errorf("wait for post event: %w", err)
	}

	return s.didexchange.WaitForPostEvent(senderID, stateCompleted)
}

func (s *ControllerSteps) sendInvitationThruOOBChannel(sender, receiver string) error {
	inv, found := s.pendingInvitations[sender]
	if !found {
		return fmt.Errorf("no invitation found for %s", sender)
	}

	s.pendingInvitations[receiver] = inv

	return nil
}

func (s *ControllerSteps) constructOOBInvitation(agentID string) error {
	inv, err := s.newInvitation(agentID)
	if err != nil {
		return err
	}

	s.pendingInvitations[agentID] = inv

	return nil
}

func (s *ControllerSteps) newInvitation(agentID string) (*outofband.Invitation, error) {
	controllerURL, ok := s.bddContext.GetControllerURL(agentID)
	if !ok {
		return nil, fmt.Errorf("unable to find controller URL registered for agent [%s]", agentID)
	}

	req, err := json.Marshal(outofbandcmd.CreateInvitationArgs{
		Label: agentID,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal create invitation: %w", err)
	}

	res := outofbandcmd.CreateInvitationResponse{}

	return res.Invitation, util.SendHTTP(http.MethodPost, controllerURL+createInvitation, req, &res)
}

// QueryOpt describes query option.
type QueryOpt func(*queryArgs)

// WithInvitationID allows providing an invitation ID.
func WithInvitationID(id string) QueryOpt {
	return func(args *queryArgs) {
		args.InvitationID = id
	}
}

// WithParentThreadID allows providing a parent threadID.
func WithParentThreadID(id string) QueryOpt {
	return func(args *queryArgs) {
		args.ParentThreadID = id
	}
}

type queryArgs struct {
	State          string
	InvitationID   string
	ParentThreadID string
}

func (q *queryArgs) buildPath() string {
	params := url.Values{}

	if q.State != "" {
		params.Add("state", q.State)
	}

	if q.InvitationID != "" {
		params.Add("invitation_id", q.InvitationID)
	}

	if q.ParentThreadID != "" {
		params.Add("parent_thread_id", q.ParentThreadID)
	}

	return "?" + params.Encode()
}

// GetConnection returns a connection between agents.
func (s *ControllerSteps) GetConnection(receiver, sender string, opts ...QueryOpt) (*didexchange.Connection, error) {
	args := &queryArgs{State: stateCompleted}

	for _, fn := range opts {
		fn(args)
	}

	controllerURL, ok := s.bddContext.GetControllerURL(receiver)
	if !ok {
		return nil, fmt.Errorf("unable to find controller URL registered for agent [%s]", receiver)
	}

	var response didexcmd.QueryConnectionsResponse

	err := util.SendHTTP(http.MethodGet, controllerURL+connections+args.buildPath(), nil, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to query connections: %w", err)
	}

	for _, c := range response.Results {
		if c.State != stateCompleted {
			continue
		}

		if c.TheirLabel == sender {
			return c, nil
		}
	}

	return nil, errors.New("no connection between agents")
}

// NewInvitation creates a new request.
func (s *ControllerSteps) NewInvitation(agentID string) (*outofband.Invitation, error) {
	controllerURL, ok := s.bddContext.GetControllerURL(agentID)
	if !ok {
		return nil, fmt.Errorf("unable to find controller URL registered for agent [%s]", agentID)
	}

	req, err := json.Marshal(outofbandcmd.CreateInvitationArgs{
		Label: agentID,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal create request: %w", err)
	}

	res := outofbandcmd.CreateInvitationResponse{}

	return res.Invitation, util.SendHTTP(http.MethodPost, controllerURL+createInvitation, req, &res)
}

// ConnectAll connects all agents to each other.
// 'agents' is a comma-separated string of agent identifiers.
func (s *ControllerSteps) ConnectAll(agents string) error {
	all := strings.Split(agents, ",")

	for i := 0; i < len(all)-1; i++ {
		inviter := all[i]

		err := s.constructOOBInvitation(inviter)
		if err != nil {
			return err
		}

		for j := i + 1; j < len(all); j++ {
			invitee := all[j]

			// send outofband invitation to invitee
			err = s.sendInvitationThruOOBChannel(inviter, invitee)
			if err != nil {
				return err
			}

			// invitee accepts outofband invitation
			err = s.acceptInvitationAndConnect(invitee, inviter)
			if err != nil {
				return err
			}

			_, err = s.GetConnection(inviter, invitee)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
