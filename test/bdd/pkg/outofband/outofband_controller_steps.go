/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	didexcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/didexchange"
	outofbandcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/outofband"
	outofbandcmdv2 "github.com/hyperledger/aries-framework-go/pkg/controller/command/outofbandv2"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	oobv2 "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofbandv2"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	didexsteps "github.com/hyperledger/aries-framework-go/test/bdd/pkg/didexchange"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/util"
)

const (
	connections      = "/connections"
	createInvitation = "/outofband/create-invitation"
	acceptInvitation = "/outofband/accept-invitation"

	createInvitationV2 = "/outofband/2.0/create-invitation"
	acceptInvitationV2 = "/outofband/2.0/accept-invitation"

	stateCompleted = "completed"
)

// ControllerSteps is steps for outofband with controller.
type ControllerSteps struct {
	bddContext         *context.BDDContext
	pendingInvitations map[string]*outofband.Invitation
	pendingV2Invites   map[string]*oobv2.Invitation
	connections        map[string]string
	didexchange        *didexsteps.ControllerSteps
	accept             string
}

// NewOutofbandControllerSteps creates steps for outofband with controller.
func NewOutofbandControllerSteps() *ControllerSteps {
	return &ControllerSteps{
		didexchange:        didexsteps.NewDIDExchangeControllerSteps(),
		pendingInvitations: make(map[string]*outofband.Invitation),
		pendingV2Invites:   make(map[string]*oobv2.Invitation),
		connections:        make(map[string]string),
	}
}

// SetContext sets every scenario with a fresh context.
func (s *ControllerSteps) SetContext(ctx *context.BDDContext) {
	s.bddContext = ctx
	s.didexchange.SetContext(s.bddContext)
}

// RegisterSteps registers agent steps.
func (s *ControllerSteps) RegisterSteps(suite *godog.Suite) {
	suite.Step(`^accept option ""([^"]*)""$`, s.scenario)
	suite.Step(`^"([^"]*)" constructs an out-of-band invitation \(controller\)$`, s.constructOOBInvitation)
	suite.Step(`^"([^"]*)" sends the invitation to "([^"]*)" through an out-of-band channel \(controller\)$`,
		s.sendInvitationThruOOBChannel)
	suite.Step(`^"([^"]*)" accepts the invitation and connects with "([^"]*)" \(controller\)$`,
		s.acceptInvitationAndConnect)
	suite.Step(`^"([^"]*)" and "([^"]*)" have a connection \(controller\)$`, s.CheckConnection)
	suite.Step(`^"([^"]*)" creates an out-of-band-v2 invitation with embedded present proof v3 request`+
		` as target service \(controller\)$`, s.createOOBV2WithPresentProof)
	suite.Step(`^"([^"]*)" creates an out-of-band-v2 invitation \(controller\)$`, s.CreateOOBV2)
	suite.Step(`^"([^"]*)" sends the request to "([^"]*)" and he accepts it by processing both OOBv2 and the `+
		`embedded present proof v3 request \(controller\)$`, s.acceptOOBV2InvitationStep)
	suite.Step(`^the OOBv2 invitation from "([^"]*)" is accepted by "([^"]*)" \(controller\)$`,
		s.acceptOOBV2InvitationStep)
}

func (s *ControllerSteps) scenario(accept string) error {
	s.accept = accept

	return nil
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

	createOOBInv := outofbandcmd.CreateInvitationArgs{
		Label: agentID,
	}

	if len(s.accept) > 0 {
		accepts := strings.Split(s.accept, ",")
		createOOBInv.Accept = accepts
	}

	req, err := json.Marshal(createOOBInv)
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

// CreateOOBV2 creates an OOBv2 invitation for the given agent.
func (s *ControllerSteps) CreateOOBV2(agentID string) error {
	controllerURL, ok := s.bddContext.GetControllerURL(agentID)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", agentID)
	}

	agentIDDIDDoc, ok := s.bddContext.PublicDIDDocs[agentID]
	if !ok {
		return fmt.Errorf("oobv2: missing DID Doc for %s", agentID)
	}

	createOOBInv := outofbandcmdv2.CreateInvitationArgs{
		Label: agentID,
		From:  agentIDDIDDoc.ID,
		Body:  oobv2.InvitationBody{},
	}

	if len(s.accept) > 0 {
		accepts := strings.Split(s.accept, ",")
		createOOBInv.Body.Accept = accepts
	}

	req, err := json.Marshal(createOOBInv)
	if err != nil {
		return fmt.Errorf("marshal create oob/2.0 invitation: %w", err)
	}

	res := outofbandcmdv2.CreateInvitationResponse{}

	err = util.SendHTTP(http.MethodPost, controllerURL+createInvitationV2, req, &res)
	if err != nil {
		return err
	}

	if res.Invitation == nil {
		return fmt.Errorf("response oob/2.0 invitation was not created")
	}

	s.pendingV2Invites[agentID] = res.Invitation

	return nil
}

//nolint:funlen
func (s *ControllerSteps) createOOBV2WithPresentProof(agentID string) error {
	controllerURL, ok := s.bddContext.GetControllerURL(agentID)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", agentID)
	}

	agentIDDIDDoc, ok := s.bddContext.PublicDIDDocs[agentID]
	if !ok {
		return fmt.Errorf("oobv2: missing DID Doc for %s", agentID)
	}

	ppfv3Req := service.NewDIDCommMsgMap(presentproof.PresentationV3{
		Type: presentproof.RequestPresentationMsgTypeV3,
		Attachments: []decorator.AttachmentV2{{
			Data: decorator.AttachmentData{
				Base64: base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(vpStr, agentIDDIDDoc.ID, agentIDDIDDoc.ID))),
			},
		}},
	})

	ppfv3Attachment := []*decorator.AttachmentV2{{
		ID:          uuid.New().String(),
		Description: "PresentProof V3 propose presentation request",
		FileName:    "presentproofv3.json",
		MediaType:   "application/json",
		LastModTime: time.Time{},
		Data: decorator.AttachmentData{
			JSON: ppfv3Req,
		},
	}}

	createOOBInv := outofbandcmdv2.CreateInvitationArgs{
		Label: agentID,
		From:  agentIDDIDDoc.ID,
		Body: oobv2.InvitationBody{
			Goal:     ppfGoal,
			GoalCode: ppfGoalCode,
		},
		Attachments: ppfv3Attachment,
	}

	if len(s.accept) > 0 {
		accepts := strings.Split(s.accept, ",")
		createOOBInv.Body.Accept = accepts
	}

	req, err := json.Marshal(createOOBInv)
	if err != nil {
		return fmt.Errorf("marshal create oob/2.0 invitation: %w", err)
	}

	res := outofbandcmdv2.CreateInvitationResponse{}

	err = util.SendHTTP(http.MethodPost, controllerURL+createInvitationV2, req, &res)
	if err != nil {
		return err
	}

	if res.Invitation == nil {
		return fmt.Errorf("response oob/2.0 invitation was not created")
	}

	s.pendingV2Invites[agentID] = res.Invitation

	return nil
}

// AcceptOOBV2Invitation makes invitee accept the OOB V2 invitation from inviter.
func (s *ControllerSteps) AcceptOOBV2Invitation(inviter, invitee string) (string, error) {
	controllerURL, ok := s.bddContext.GetControllerURL(invitee)
	if !ok {
		return "", fmt.Errorf("unable to find controller URL registered for agent [%s]", invitee)
	}

	inv := s.pendingV2Invites[inviter]

	acceptOOBInv := outofbandcmdv2.AcceptInvitationArgs{
		Invitation: inv,
		MyLabel:    inviter,
	}

	req, err := json.Marshal(acceptOOBInv)
	if err != nil {
		return "", fmt.Errorf("marshal accept oob/2.0 invitation: %w", err)
	}

	res := outofbandcmdv2.AcceptInvitationResponse{}

	err = util.SendHTTP(http.MethodPost, controllerURL+acceptInvitationV2, req, &res)
	if err != nil {
		return "", err
	}

	s.bddContext.SaveConnectionID(invitee, inviter, res.ConnectionID)

	return res.ConnectionID, nil
}

func (s *ControllerSteps) acceptOOBV2InvitationStep(inviter, invitee string) error {
	_, err := s.AcceptOOBV2Invitation(inviter, invitee)
	return err
}
