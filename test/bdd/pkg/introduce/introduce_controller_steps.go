/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cucumber/godog"

	client "github.com/hyperledger/aries-framework-go/pkg/client/introduce"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/introduce"
	protocol "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	bddoutofband "github.com/hyperledger/aries-framework-go/test/bdd/pkg/outofband"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/util"
)

const (
	acceptProposal                    = "/introduce/{piid}/accept-proposal"
	acceptProposalWithOOBRequest      = "/introduce/{piid}/accept-proposal-with-oob-invitation"
	acceptRequestWithPublicOOBRequest = "/introduce/{piid}/accept-request-with-public-oob-invitation"
	sendProposalWithOOBRequest        = "/introduce/send-proposal-with-oob-invitation"
	sendProposal                      = "/introduce/send-proposal"
	sendRequest                       = "/introduce/send-request"
	acceptRequestWithRecipients       = "/introduce/{piid}/accept-request-with-recipients"
	actionContinue                    = "/outofband/{piid}/action-continue"
)

// ControllerSteps is steps for introduce with controller.
type ControllerSteps struct {
	bddContext   *context.BDDContext
	outofband    *bddoutofband.ControllerSteps
	invitationID string
}

// NewIntroduceControllerSteps creates steps for introduce with controller.
func NewIntroduceControllerSteps() *ControllerSteps {
	return &ControllerSteps{
		outofband: bddoutofband.NewOutofbandControllerSteps(),
	}
}

// SetContext sets every scenario with a fresh context.
func (s *ControllerSteps) SetContext(ctx *context.BDDContext) {
	s.bddContext = ctx
	s.outofband.SetContext(s.bddContext)
}

// RegisterSteps registers agent steps
// nolint:lll
func (s *ControllerSteps) RegisterSteps(gs *godog.Suite) {
	gs.Step(`^"([^"]*)" has established connection with "([^"]*)" through the controller$`, s.establishConnection)
	gs.Step(`^"([^"]*)" sends introduce proposal to the "([^"]*)" with "([^"]*)" out-of-band invitation `+
		`through the controller$`,
		s.sendProposalWithInvitation)
	gs.Step(`^"([^"]*)" wants to know "([^"]*)" and sends introduce response with approve through the controller$`,
		s.checkAndContinue)
	gs.Step(`^"([^"]*)" has did exchange connection with "([^"]*)" through the controller$`,
		s.connectionEstablished)
	gs.Step(`^"([^"]*)" sends introduce request to the "([^"]*)" asking about "([^"]*)" through the controller$`, s.sendRequest)
	gs.Step(`^"([^"]*)" sends introduce proposal back to the requester with public out-of-band invitation through the controller$`,
		s.handleRequestWithInvitation)
	gs.Step(`^"([^"]*)" sends introduce proposal to the "([^"]*)" and "([^"]*)" through the controller$`, s.sendProposal)
	gs.Step(`^"([^"]*)" wants to know "([^"]*)" and sends introduce response with approve and provides an out-of-band invitation through the controller$`, //nolint:lll
		s.checkAndContinueWithInvitation)
	gs.Step(`^"([^"]*)" sends introduce proposal back to the "([^"]*)" and requested introduce through the controller$`, s.handleRequest)
}

func (s *ControllerSteps) handleRequest(agentID, introducee string) error {
	action, err := s.getAction(agentID)
	if err != nil {
		return fmt.Errorf("get action %s: %w", agentID, err)
	}

	request := &protocol.Request{}

	err = action.Msg.Decode(&request)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	conn, err := s.outofband.GetConnection(agentID, request.PleaseIntroduceTo.Name)
	if err != nil {
		return fmt.Errorf("get connection %s-%s: %w", agentID, request.PleaseIntroduceTo.Name, err)
	}

	controllerURL, ok := s.bddContext.GetControllerURL(agentID)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", agentID)
	}

	payload, err := json.Marshal(introduce.AcceptRequestWithRecipientsArgs{
		Recipient: &client.Recipient{
			To:       &protocol.To{Name: introducee},
			MyDID:    conn.MyDID,
			TheirDID: conn.TheirDID,
		},
		To: &client.To{Name: request.PleaseIntroduceTo.Name},
	})
	if err != nil {
		return err
	}

	url := controllerURL + strings.Replace(acceptRequestWithRecipients, "{piid}", action.PIID, 1)

	return util.SendHTTP(http.MethodPost, url, payload, nil)
}

func (s *ControllerSteps) checkAndContinueWithInvitation(agentID, introduceeID string) error {
	action, err := s.getAction(agentID)
	if err != nil {
		return fmt.Errorf("get action %s: %w", agentID, err)
	}

	proposal := protocol.Proposal{}

	err = action.Msg.Decode(&proposal)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	if proposal.To.Name != introduceeID {
		return fmt.Errorf("%s is not equal to %s", proposal.To.Name, introduceeID)
	}

	controllerURL, ok := s.bddContext.GetControllerURL(agentID)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", agentID)
	}

	req, err := s.outofband.NewInvitation(agentID)
	if err != nil {
		return err
	}

	// sets invitationID for the running scenario
	s.invitationID = req.ID

	payload, err := json.Marshal(introduce.AcceptProposalWithOOBInvitationArgs{
		Invitation: req,
	})
	if err != nil {
		return err
	}

	url := controllerURL + strings.Replace(acceptProposalWithOOBRequest, "{piid}", action.PIID, 1)

	return util.SendHTTP(http.MethodPost, url, payload, nil)
}

func (s *ControllerSteps) sendProposal(introducer, introducee1, introducee2 string) error {
	conn1, err := s.outofband.GetConnection(introducer, introducee1)
	if err != nil {
		return fmt.Errorf("get connection %s-%s: %w", introducer, introducee1, err)
	}

	conn2, err := s.outofband.GetConnection(introducer, introducee2)
	if err != nil {
		return fmt.Errorf("get connection %s-%s: %w", introducer, introducee2, err)
	}

	controllerURL, ok := s.bddContext.GetControllerURL(introducer)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", introducer)
	}

	req, err := json.Marshal(introduce.SendProposalArgs{
		Recipients: []*client.Recipient{
			{
				To:       &protocol.To{Name: conn2.TheirLabel},
				MyDID:    conn1.MyDID,
				TheirDID: conn1.TheirDID,
			},
			{
				To:       &protocol.To{Name: conn1.TheirLabel},
				MyDID:    conn2.MyDID,
				TheirDID: conn2.TheirDID,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("marshal send proposal: %w", err)
	}

	return util.SendHTTP(http.MethodPost, controllerURL+sendProposal, req, nil)
}

func (s *ControllerSteps) handleRequestWithInvitation(agentID string) error {
	controllerURL, ok := s.bddContext.GetControllerURL(agentID)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", agentID)
	}

	action, err := s.getAction(agentID)
	if err != nil {
		return fmt.Errorf("get action %s: %w", agentID, err)
	}

	request := protocol.Request{}

	err = action.Msg.Decode(&request)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	introduceTo := request.PleaseIntroduceTo.Name

	req, err := s.outofband.NewInvitation(introduceTo)
	if err != nil {
		return err
	}

	// sets invitationID for the running scenario
	s.invitationID = req.ID

	msg, err := json.Marshal(&introduce.AcceptRequestWithPublicOOBInvitationArgs{
		Invitation: req,
		To:         &client.To{Name: req.Label},
	})
	if err != nil {
		return err
	}

	url := controllerURL + strings.Replace(acceptRequestWithPublicOOBRequest, "{piid}", action.PIID, 1)

	return util.SendHTTP(http.MethodPost, url, msg, nil)
}

func (s *ControllerSteps) establishConnection(inviters, invitee string) error {
	for _, inviter := range strings.Split(inviters, ",") {
		if err := s.outofband.ConnectAll(inviter + "," + invitee); err != nil {
			return err
		}
	}

	return nil
}

func (s *ControllerSteps) sendRequest(introducee1, introducer, introducee2 string) error {
	conn, err := s.outofband.GetConnection(introducee1, introducer)
	if err != nil {
		return fmt.Errorf("get connection %s-%s: %w", introducee1, introducer, err)
	}

	controllerURL, ok := s.bddContext.GetControllerURL(introducee1)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", introducee1)
	}

	req, err := json.Marshal(introduce.SendRequestArgs{
		PleaseIntroduceTo: &client.PleaseIntroduceTo{To: protocol.To{Name: introducee2}},
		MyDID:             conn.MyDID,
		TheirDID:          conn.TheirDID,
	})
	if err != nil {
		return fmt.Errorf("marshal send proposal: %w", err)
	}

	return util.SendHTTP(http.MethodPost, controllerURL+sendRequest, req, nil)
}

func (s *ControllerSteps) sendProposalWithInvitation(introducer, introducee1, introducee2 string) error {
	conn, err := s.outofband.GetConnection(introducer, introducee1)
	if err != nil {
		return fmt.Errorf("get connection %s-%s: %w", introducer, introducee1, err)
	}

	oobReq, err := s.outofband.NewInvitation(introducee2)
	if err != nil {
		return fmt.Errorf("create OOBRequest for agent %s: %w", introducee2, err)
	}

	// sets invitationID for the running scenario
	s.invitationID = oobReq.ID

	controllerURL, ok := s.bddContext.GetControllerURL(introducer)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", introducer)
	}

	req, err := json.Marshal(introduce.SendProposalWithOOBInvitationArgs{
		Invitation: oobReq,
		Recipient: &client.Recipient{
			To:       &protocol.To{Name: introducee2},
			MyDID:    conn.MyDID,
			TheirDID: conn.TheirDID,
		},
	})
	if err != nil {
		return fmt.Errorf("marshal send proposal: %w", err)
	}

	return util.SendHTTP(http.MethodPost, controllerURL+sendProposalWithOOBRequest, req, nil)
}

func (s *ControllerSteps) getAction(agentID string) (*client.Action, error) {
	msg, err := util.PullEventsFromWebSocket(s.bddContext, agentID, util.FilterTopic("introduce_actions"))
	if err != nil {
		return nil, fmt.Errorf("pull events from WebSocket: %w", err)
	}

	return &client.Action{
		PIID:     msg.Message.Properties["piid"].(string),
		Msg:      msg.Message.Message,
		MyDID:    msg.Message.Properties["myDID"].(string),
		TheirDID: msg.Message.Properties["theirDID"].(string),
	}, nil
}

func (s *ControllerSteps) checkAndContinue(agentID, introduceeID string) error {
	action, err := s.getAction(agentID)
	if err != nil {
		return fmt.Errorf("get action %s: %w", agentID, err)
	}

	proposal := protocol.Proposal{}

	err = action.Msg.Decode(&proposal)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	if proposal.To.Name != introduceeID {
		return fmt.Errorf("%s is not equal to %s", proposal.To.Name, introduceeID)
	}

	controllerURL, ok := s.bddContext.GetControllerURL(agentID)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", agentID)
	}

	url := controllerURL + strings.Replace(acceptProposal, "{piid}", action.PIID, 1)

	errChan := make(chan error)

	go func() { errChan <- s.tryOutofbandContinue(agentID) }()

	err = util.SendHTTP(http.MethodPost, url, nil, nil)
	if err != nil {
		return fmt.Errorf("accept proposal: %w", err)
	}

	select {
	case err := <-errChan:
		return err
	case <-time.After(timeout):
		return errors.New("timeout: check and continue")
	}
}

func (s *ControllerSteps) tryOutofbandContinue(agent string) error {
	controllerURL, ok := s.bddContext.GetControllerURL(agent)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", agent)
	}

	msg, err := util.PullEventsFromWebSocket(s.bddContext, agent, util.FilterTopic("out-of-band_actions"))
	if err != nil {
		return fmt.Errorf("pull events from WebSocket: %w", err)
	}

	piid, err := msg.Message.Message.ThreadID()
	if err != nil {
		return fmt.Errorf("thread id: %w", err)
	}

	url := strings.Replace(controllerURL+actionContinue+"?label="+agent, "{piid}", piid, 1)

	return util.SendHTTP(http.MethodPost, url, nil, nil)
}

func (s *ControllerSteps) connectionEstablished(agent1, agent2 string) error {
	if err := s.outofband.DidExchangeApproveRequest(agent1, agent2); err != nil {
		return fmt.Errorf("approve request: %w", err)
	}

	_, err := s.outofband.GetConnection(agent1, agent2, bddoutofband.WithParentThreadID(s.invitationID))
	if err != nil {
		return err
	}

	_, err = s.outofband.GetConnection(agent2, agent1, bddoutofband.WithInvitationID(s.invitationID))

	return err
}
