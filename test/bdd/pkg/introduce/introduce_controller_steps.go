/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/cucumber/godog"

	client "github.com/hyperledger/aries-framework-go/pkg/client/introduce"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/introduce"
	outofbandcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/outofband"
	protocol "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	bddoutofband "github.com/hyperledger/aries-framework-go/test/bdd/pkg/outofband"
)

var logger = log.New("aries-framework/bdd/introduce")

var errNoActions = errors.New("no actions")

const (
	acceptProposal                    = "/introduce/{piid}/accept-proposal"
	acceptProposalWithOOBRequest      = "/introduce/{piid}/accept-proposal-with-oob-request"
	acceptRequestWithPublicOOBRequest = "/introduce/{piid}/accept-request-with-public-oob-request"
	sendProposalWithOOBRequest        = "/introduce/send-proposal-with-oob-request"
	sendProposal                      = "/introduce/send-proposal"
	sendRequest                       = "/introduce/send-request"
	actions                           = "/introduce/actions"
	acceptRequestWithRecipients       = "/introduce/{piid}/accept-request-with-recipients"
	outofbandActions                  = "/outofband/actions"
	actionContinue                    = "/outofband/{piid}/action-continue"

	maxRetries = 3
)

// ControllerSteps is steps for introduce with controller
type ControllerSteps struct {
	bddContext *context.BDDContext
	outofband  *bddoutofband.ControllerSteps
}

// NewIntroduceControllerSteps creates steps for introduce with controller
func NewIntroduceControllerSteps() *ControllerSteps {
	return &ControllerSteps{
		outofband: bddoutofband.NewOutofbandControllerSteps(),
	}
}

// SetContext sets every scenario with a fresh context
func (s *ControllerSteps) SetContext(ctx *context.BDDContext) {
	s.bddContext = ctx
	s.outofband.SetContext(s.bddContext)
}

// RegisterSteps registers agent steps
// nolint:lll
func (s *ControllerSteps) RegisterSteps(gs *godog.Suite) {
	gs.Step(`^"([^"]*)" has established connection with "([^"]*)" through the controller$`, s.establishConnection)
	gs.Step(`^"([^"]*)" sends introduce proposal to the "([^"]*)" with "([^"]*)" out-of-band request `+
		`through the controller$`,
		s.sendProposalWithInvitation)
	gs.Step(`^"([^"]*)" wants to know "([^"]*)" and sends introduce response with approve through the controller$`,
		s.checkAndContinue)
	gs.Step(`^"([^"]*)" has did exchange connection with "([^"]*)" through the controller$`,
		s.connectionEstablished)
	gs.Step(`^"([^"]*)" sends introduce request to the "([^"]*)" asking about "([^"]*)" through the controller$`, s.sendRequest)
	gs.Step(`^"([^"]*)" sends introduce proposal back to the requester with public out-of-band request through the controller$`,
		s.handleRequestWithInvitation)
	gs.Step(`^"([^"]*)" sends introduce proposal to the "([^"]*)" and "([^"]*)" through the controller$`, s.sendProposal)
	gs.Step(`^"([^"]*)" wants to know "([^"]*)" and sends introduce response with approve and provides an out-of-band request through the controller$`, //nolint:lll
		s.checkAndContinueWithInvitation)
	gs.Step(`^"([^"]*)" sends introduce proposal back to the "([^"]*)" and requested introduce through the controller$`, s.handleRequest)
}

func (s *ControllerSteps) handleRequest(agentID, introducee string) error {
	action, err := s.getAction(maxRetries, agentID)
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

	return sendHTTP(http.MethodPost, url, payload, nil)
}

func (s *ControllerSteps) checkAndContinueWithInvitation(agentID, introduceeID string) error {
	action, err := s.getAction(maxRetries, agentID)
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

	req, err := s.outofband.NewRequest(agentID)
	if err != nil {
		return err
	}

	payload, err := json.Marshal(introduce.AcceptProposalWithOOBRequestArgs{
		Request: req,
	})
	if err != nil {
		return err
	}

	url := controllerURL + strings.Replace(acceptProposalWithOOBRequest, "{piid}", action.PIID, 1)

	return sendHTTP(http.MethodPost, url, payload, nil)
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
		Recipients: []*client.Recipient{{
			To:       &protocol.To{Name: conn2.TheirLabel},
			MyDID:    conn1.MyDID,
			TheirDID: conn1.TheirDID,
		},
			{
				To:       &protocol.To{Name: conn1.TheirLabel},
				MyDID:    conn2.MyDID,
				TheirDID: conn2.TheirDID,
			}},
	})

	if err != nil {
		return fmt.Errorf("marshal send proposal: %w", err)
	}

	return sendHTTP(http.MethodPost, controllerURL+sendProposal, req, nil)
}

func (s *ControllerSteps) handleRequestWithInvitation(agentID string) error {
	controllerURL, ok := s.bddContext.GetControllerURL(agentID)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", agentID)
	}

	action, err := s.getAction(maxRetries, agentID)
	if err != nil {
		return fmt.Errorf("get action %s: %w", agentID, err)
	}

	request := protocol.Request{}

	err = action.Msg.Decode(&request)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	introduceTo := request.PleaseIntroduceTo.Name

	req, err := s.outofband.NewRequest(introduceTo)
	if err != nil {
		return err
	}

	msg, err := json.Marshal(&introduce.AcceptRequestWithPublicOOBRequestArgs{
		Request: req,
		To:      &client.To{Name: req.Label},
	})
	if err != nil {
		return err
	}

	url := controllerURL + strings.Replace(acceptRequestWithPublicOOBRequest, "{piid}", action.PIID, 1)

	return sendHTTP(http.MethodPost, url, msg, nil)
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

	return sendHTTP(http.MethodPost, controllerURL+sendRequest, req, nil)
}

func (s *ControllerSteps) sendProposalWithInvitation(introducer, introducee1, introducee2 string) error {
	conn, err := s.outofband.GetConnection(introducer, introducee1)
	if err != nil {
		return fmt.Errorf("get connection %s-%s: %w", introducer, introducee1, err)
	}

	oobReq, err := s.outofband.NewRequest(introducee2)
	if err != nil {
		return fmt.Errorf("create OOBRequest for agent %s: %w", introducee2, err)
	}

	controllerURL, ok := s.bddContext.GetControllerURL(introducer)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", introducer)
	}

	req, err := json.Marshal(introduce.SendProposalWithOOBRequestArgs{
		Request: oobReq,
		Recipient: &client.Recipient{
			To:       &protocol.To{Name: introducee2},
			MyDID:    conn.MyDID,
			TheirDID: conn.TheirDID,
		},
	})

	if err != nil {
		return fmt.Errorf("marshal send proposal: %w", err)
	}

	return sendHTTP(http.MethodPost, controllerURL+sendProposalWithOOBRequest, req, nil)
}

func (s *ControllerSteps) getAction(retries int, agentID string) (*client.Action, error) {
	if retries < 0 {
		return nil, errors.New("no actions")
	}

	controllerURL, ok := s.bddContext.GetControllerURL(agentID)
	if !ok {
		return nil, fmt.Errorf("unable to find controller URL registered for agent [%s]", agentID)
	}

	res := introduce.ActionsResponse{}

	err := sendHTTP(http.MethodGet, fmt.Sprintf(controllerURL+actions), nil, &res)
	if err != nil {
		return nil, fmt.Errorf("failed to get actions: %w", err)
	}

	if len(res.Actions) == 0 {
		retries--

		time.Sleep(time.Second)

		return s.getAction(retries, agentID)
	}

	if res.Actions[0].MyDID == "" {
		return nil, errors.New("myDID is empty")
	}

	if res.Actions[0].TheirDID == "" {
		return nil, errors.New("theirDID is empty")
	}

	return &res.Actions[0], nil
}

func (s *ControllerSteps) checkAndContinue(agentID, introduceeID string) error {
	action, err := s.getAction(maxRetries, agentID)
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

	err = sendHTTP(http.MethodPost, url, nil, nil)
	if err != nil {
		return fmt.Errorf("accept proposal: %w", err)
	}

	return s.outofbandContinue(maxRetries, agentID)
}

func (s *ControllerSteps) tryOutofbandContinue(agent1 string) error {
	controllerURL, ok := s.bddContext.GetControllerURL(agent1)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", agent1)
	}

	res := outofbandcmd.ActionsResponse{}

	err := sendHTTP(http.MethodGet, fmt.Sprintf(controllerURL+outofbandActions), nil, &res)
	if err != nil {
		return fmt.Errorf("failed to get actions: %w", err)
	}

	if len(res.Actions) == 0 {
		return errNoActions
	}

	url := strings.Replace(controllerURL+actionContinue+"?label="+agent1, "{piid}", res.Actions[0].PIID, 1)

	return sendHTTP(http.MethodPost, url, nil, &res)
}

func (s *ControllerSteps) outofbandContinue(retries int, agent string, agents ...string) error {
	if retries < 0 {
		return errors.New("no actions")
	}

	for _, agent := range append([]string{agent}, agents...) {
		err := s.tryOutofbandContinue(agent)
		if errors.Is(err, errNoActions) {
			continue
		}

		return err
	}

	retries--

	time.Sleep(time.Second)

	return s.outofbandContinue(retries, agent, agents...)
}

func (s *ControllerSteps) connectionEstablished(agent1, agent2 string) error {
	if err := s.outofband.DidExchangeApproveRequest(agent1, agent2); err != nil {
		return fmt.Errorf("approve request: %w", err)
	}

	return s.outofband.CheckConnection(agent1, agent2)
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
