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
	"strings"

	"github.com/cucumber/godog"
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	didexcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/didexchange"
	outofbandcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	didexsteps "github.com/hyperledger/aries-framework-go/test/bdd/pkg/didexchange"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/util"
)

const (
	connections      = "/connections"
	createRequest    = "/outofband/create-request"
	createInvitation = "/outofband/create-invitation"
	acceptRequest    = "/outofband/accept-request"
	acceptInvitation = "/outofband/accept-invitation"

	stateCompleted = "completed"
)

// ControllerSteps is steps for outofband with controller
type ControllerSteps struct {
	bddContext         *context.BDDContext
	pendingRequests    map[string]*outofband.Request
	pendingInvitations map[string]*outofband.Invitation
	connections        map[string]string
	didexchange        *didexsteps.ControllerSteps
}

// NewOutofbandControllerSteps creates steps for outofband with controller
func NewOutofbandControllerSteps() *ControllerSteps {
	return &ControllerSteps{
		didexchange:        didexsteps.NewDIDExchangeControllerSteps(),
		pendingRequests:    make(map[string]*outofband.Request),
		pendingInvitations: make(map[string]*outofband.Invitation),
		connections:        make(map[string]string),
	}
}

// SetContext sets every scenario with a fresh context
func (s *ControllerSteps) SetContext(ctx *context.BDDContext) {
	s.bddContext = ctx
	s.didexchange.SetContext(s.bddContext)
}

// RegisterSteps registers agent steps
// nolint:lll
func (s *ControllerSteps) RegisterSteps(suite *godog.Suite) {
	suite.Step(
		`^"([^"]*)" constructs an out-of-band request with no attachments \(controller\)$`, s.constructOOBRequestWithNoAttachments)
	suite.Step(`^"([^"]*)" constructs an out-of-band invitation \(controller\)$`, s.constructOOBInvitation)
	suite.Step(
		`^"([^"]*)" sends the request to "([^"]*)" through an out-of-band channel \(controller\)$`, s.sendRequestThruOOBChannel)
	suite.Step(
		`^"([^"]*)" sends the invitation to "([^"]*)" through an out-of-band channel \(controller\)$`, s.sendInvitationThruOOBChannel)
	suite.Step(`^"([^"]*)" accepts the request and connects with "([^"]*)" \(controller\)$`, s.acceptRequestAndConnect)
	suite.Step(`^"([^"]*)" accepts the invitation and connects with "([^"]*)" \(controller\)$`, s.acceptInvitationAndConnect)
	suite.Step(`^"([^"]*)" and "([^"]*)" have a connection \(controller\)$`, s.CheckConnection)
}

// CheckConnection checks a connection between agents
func (s *ControllerSteps) CheckConnection(receiverID, senderID string) error {
	_, err := s.GetConnection(receiverID, senderID)
	if err != nil {
		return err
	}

	_, err = s.GetConnection(senderID, receiverID)

	return err
}

func (s *ControllerSteps) acceptInvitationAndConnect(receiverID, senderID string) error { // nolint: dupl
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

// DidExchangeApproveRequest approves request (didexchange)
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

// GetConnection returns a connection between agents
func (s *ControllerSteps) GetConnection(receiverID, senderID string) (*didexchange.Connection, error) {
	controllerURL, ok := s.bddContext.GetControllerURL(receiverID)
	if !ok {
		return nil, fmt.Errorf("unable to find controller URL registered for agent [%s]", receiverID)
	}

	var response didexcmd.QueryConnectionsResponse

	err := util.SendHTTP(http.MethodGet, controllerURL+connections, nil, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to query connections: %w", err)
	}

	for _, c := range response.Results {
		if c.State != stateCompleted {
			continue
		}

		if c.TheirLabel == senderID {
			return c, nil
		}
	}

	return nil, errors.New("no connection between agents")
}

func (s *ControllerSteps) acceptRequestAndConnect(receiverID, senderID string) error { // nolint: dupl
	request, found := s.pendingRequests[receiverID]
	if !found {
		return fmt.Errorf("no pending requests found for %s", receiverID)
	}

	controllerURL, ok := s.bddContext.GetControllerURL(receiverID)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", receiverID)
	}

	payload, err := json.Marshal(outofbandcmd.AcceptRequestArgs{
		Request: request,
		MyLabel: receiverID,
	})
	if err != nil {
		return fmt.Errorf("marshal create request: %w", err)
	}

	res := outofbandcmd.AcceptRequestResponse{}

	err = util.SendHTTP(http.MethodPost, controllerURL+acceptRequest, payload, &res)
	if err != nil {
		return fmt.Errorf("accept request: %w", err)
	}

	s.connections[receiverID+senderID] = res.ConnectionID

	return s.DidExchangeApproveRequest(receiverID, senderID)
}

func (s *ControllerSteps) constructOOBRequestWithNoAttachments(agentID string) error {
	req, err := s.NewRequest(agentID)
	if err != nil {
		return fmt.Errorf("failed to create an out-of-band request : %w", err)
	}

	s.pendingRequests[agentID] = req

	return nil
}

// sends a the sender's pending request to the receiver and returns the sender and receiver's new connection IDs.
func (s *ControllerSteps) sendRequestThruOOBChannel(senderID, receiverID string) error {
	req, found := s.pendingRequests[senderID]
	if !found {
		return fmt.Errorf("no request found for %s", senderID)
	}

	delete(s.pendingRequests, senderID)

	s.pendingRequests[receiverID] = req

	return nil
}

// NewRequest creates a new request
func (s *ControllerSteps) NewRequest(agentID string) (*outofband.Request, error) {
	controllerURL, ok := s.bddContext.GetControllerURL(agentID)
	if !ok {
		return nil, fmt.Errorf("unable to find controller URL registered for agent [%s]", agentID)
	}

	req, err := json.Marshal(outofbandcmd.CreateRequestArgs{
		Label: agentID,
		Attachments: []*decorator.Attachment{{
			ID:          uuid.New().String(),
			Description: "dummy",
			MimeType:    "text/plain",
			Data: decorator.AttachmentData{
				JSON: map[string]interface{}{},
			},
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal create request: %w", err)
	}

	res := outofbandcmd.CreateRequestResponse{}

	return res.Request, util.SendHTTP(http.MethodPost, controllerURL+createRequest, req, &res)
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
