/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/cucumber/godog"
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	didexcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/didexchange"
	outofbandcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	didexsteps "github.com/hyperledger/aries-framework-go/test/bdd/pkg/didexchange"
)

var logger = log.New("aries-framework/bdd/outofband")

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
}

// NewOutofbandControllerSteps creates steps for outofband with controller
func NewOutofbandControllerSteps() *ControllerSteps {
	return &ControllerSteps{
		pendingRequests:    make(map[string]*outofband.Request),
		pendingInvitations: make(map[string]*outofband.Invitation),
		connections:        make(map[string]string),
	}
}

// SetContext sets every scenario with a fresh context
func (s *ControllerSteps) SetContext(ctx *context.BDDContext) {
	s.bddContext = ctx
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
	suite.Step(`^"([^"]*)" and "([^"]*)" confirm their connection \(controller\)$`, s.ConfirmConnections)
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

	err = sendHTTP(http.MethodPost, controllerURL+acceptInvitation, payload, &res)
	if err != nil {
		return fmt.Errorf("accept invitation: %w", err)
	}

	s.connections[receiverID+senderID] = res.ConnectionID

	return s.didExchangeApproveRequest(receiverID, senderID)
}

func (s *ControllerSteps) didExchangeApproveRequest(receiverID, senderID string) error {
	ds := didexsteps.NewDIDExchangeControllerSteps()
	ds.SetContext(s.bddContext)

	if err := ds.ApproveRequest(senderID); err != nil {
		return fmt.Errorf("approve request: %w", err)
	}

	if err := ds.WaitForPostEvent(receiverID, stateCompleted); err != nil {
		return fmt.Errorf("wait for post event: %w", err)
	}

	return ds.WaitForPostEvent(senderID, stateCompleted)
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

	return res.Invitation, sendHTTP(http.MethodPost, controllerURL+createInvitation, req, &res)
}

// ConfirmConnections confirms the connection between the sender and receiver is at the given status.
func (s *ControllerSteps) ConfirmConnections(senderID, receiverID string) error {
	_, err := s.getConnection(receiverID, senderID)

	return err
}

func (s *ControllerSteps) getConnection(receiverID, senderID string) (*didexchange.Connection, error) {
	controllerURL, ok := s.bddContext.GetControllerURL(receiverID)
	if !ok {
		return nil, fmt.Errorf("unable to find controller URL registered for agent [%s]", receiverID)
	}

	var response didexcmd.QueryConnectionsResponse

	err := sendHTTP(http.MethodGet, controllerURL+connections, nil, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to query connections: %w", err)
	}

	for _, conn := range response.Results {
		if conn.State != stateCompleted {
			continue
		}

		if conn.ConnectionID == s.connections[receiverID+senderID] {
			return conn, nil
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

	err = sendHTTP(http.MethodPost, controllerURL+acceptRequest, payload, &res)
	if err != nil {
		return fmt.Errorf("accept request: %w", err)
	}

	s.connections[receiverID+senderID] = res.ConnectionID

	return s.didExchangeApproveRequest(receiverID, senderID)
}

func (s *ControllerSteps) constructOOBRequestWithNoAttachments(agentID string) error {
	req, err := s.newRequest(agentID)
	if err != nil {
		return fmt.Errorf("failed to create an out-of-bound request : %w", err)
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

func (s *ControllerSteps) newRequest(agentID string) (*outofband.Request, error) {
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

	return res.Request, sendHTTP(http.MethodPost, controllerURL+createRequest, req, &res)
}

func sendHTTP(method, destination string, message []byte, result interface{}) error {
	// create request
	req, err := http.NewRequest(method, destination, bytes.NewBuffer(message))
	if err != nil {
		return fmt.Errorf("failed to create new http '%s' request for '%s', cause: %s", method, destination, err)
	}

	// set headers
	req.Header.Set("Content-Type", "application/json")

	// send http request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get response from '%s', cause :%s", destination, err)
	}

	defer closeResponse(resp.Body)

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read response from '%s', cause :%s", destination, err)
	}

	logger.Debugf("Got response from '%s' [method: %s], response payload: %s", destination, method, string(data))

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to get successful response from '%s', unexpected status code [%d], "+
			"and message [%s]", destination, resp.StatusCode, string(data))
	}

	if result == nil {
		return nil
	}

	return json.Unmarshal(data, result)
}

func closeResponse(c io.Closer) {
	if err := c.Close(); err != nil {
		logger.Errorf("failed to close response body: %s", err)
	}
}
