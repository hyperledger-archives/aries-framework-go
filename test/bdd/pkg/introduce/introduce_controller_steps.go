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
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	client "github.com/hyperledger/aries-framework-go/pkg/client/introduce"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	didexcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/introduce"
	outofbandcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	protocol "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	didexsteps "github.com/hyperledger/aries-framework-go/test/bdd/pkg/didexchange"
)

var logger = log.New("aries-framework/bdd/introduce")

const (
	acceptProposalWithOOBRequest = "/introduce/{piid}/accept-proposal-with-oob-request"
	sendProposalWithOOBRequest   = "/introduce/send-proposal-with-oob-request"
	actions                      = "/introduce/actions"
	outofbandActions             = "/outofband/actions"
	actionContinue               = "/outofband/{piid}/action-continue"
	createRequest                = "/outofband/create-request"
	connections                  = "/connections"

	stateCompleted = "completed"
)

// ControllerSteps is steps for introduce with controller
type ControllerSteps struct {
	bddContext  *context.BDDContext
	connections map[string]string
}

// NewIntroduceControllerSteps creates steps for introduce with controller
func NewIntroduceControllerSteps() *ControllerSteps {
	return &ControllerSteps{connections: make(map[string]string)}
}

// SetContext sets every scenario with a fresh context
func (s *ControllerSteps) SetContext(ctx *context.BDDContext) {
	s.bddContext = ctx
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
}

func (s *ControllerSteps) establishConnection(inviters, invitee string) error {
	ds := didexsteps.NewDIDExchangeControllerSteps()
	ds.SetContext(s.bddContext)

	for _, inviter := range strings.Split(inviters, ",") {
		if err := ds.EstablishConnection(inviter, invitee); err != nil {
			return err
		}

		s.connections[invitee+inviter] = ds.ConnectionIDs()[invitee]
	}

	return nil
}

func (s *ControllerSteps) sendProposalWithInvitation(introducer, introducee1, introducee2 string) error {
	conn, err := s.getConnection(introducer, introducee1)
	if err != nil {
		return fmt.Errorf("get connection for agents %s and %s: %w", introducer, introducee1, err)
	}

	oobReq, err := s.newOOBRequest(introducee2)
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

func (s *ControllerSteps) checkAndContinue(agentID, introduceeID string) error {
	controllerURL, ok := s.bddContext.GetControllerURL(agentID)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", agentID)
	}

	res := introduce.ActionsResponse{}

	err := sendHTTP(http.MethodGet, fmt.Sprintf(controllerURL+actions), nil, &res)
	if err != nil {
		return fmt.Errorf("failed to get actions: %w", err)
	}

	oobReq, err := s.newOOBRequest(agentID)
	if err != nil {
		return fmt.Errorf("create OOBRequest for agent %s: %w", agentID, err)
	}

	req, err := json.Marshal(introduce.AcceptProposalWithOOBRequestArgs{
		Request: oobReq,
	})
	if err != nil {
		return fmt.Errorf("marshal accept proposal: %w", err)
	}

	url := controllerURL + strings.Replace(acceptProposalWithOOBRequest, "{piid}", res.Actions[0].PIID, 1)

	return sendHTTP(http.MethodPost, url, req, nil)
}

func (s *ControllerSteps) tryOutofbandContinue(agent1 string) (bool, error) {
	controllerURL, ok := s.bddContext.GetControllerURL(agent1)
	if !ok {
		return false, fmt.Errorf("unable to find controller URL registered for agent [%s]", agent1)
	}

	res := outofbandcmd.ActionsResponse{}

	err := sendHTTP(http.MethodGet, fmt.Sprintf(controllerURL+outofbandActions), nil, &res)
	if err != nil {
		return false, fmt.Errorf("failed to get actions: %w", err)
	}

	if len(res.Actions) == 0 {
		return false, nil
	}

	url := strings.Replace(controllerURL+actionContinue, "{piid}", res.Actions[0].PIID, 1)

	return true, sendHTTP(http.MethodPost, url, nil, &res)
}

func (s *ControllerSteps) outofbandContinue(agent1, agent2 string) error {
	for _, agent := range []string{agent1, agent2} {
		ok, err := s.tryOutofbandContinue(agent)
		if err != nil {
			return fmt.Errorf("try outofband continue: %w", err)
		}

		if ok {
			return nil
		}
	}

	return errors.New("no actions")
}

func (s *ControllerSteps) connectionEstablished(agent1, agent2 string) error {
	for i := 0; i < 5; i++ {
		err := s.outofbandContinue(agent1, agent2)
		if err != nil && err.Error() != "no actions" {
			return err
		}

		if err == nil {
			break
		}

		time.Sleep(time.Second)
	}

	ds := didexsteps.NewDIDExchangeControllerSteps()
	ds.SetContext(s.bddContext)

	if err := ds.ApproveRequest(agent2); err != nil {
		return fmt.Errorf("approve request: %w", err)
	}

	if err := ds.WaitForPostEvent(agent2, stateCompleted); err != nil {
		return fmt.Errorf("wait for post event: %w", err)
	}

	s.connections[agent2+agent1] = ds.ConnectionIDs()[agent2]
	_, err := s.getConnection(agent2, agent1)

	return err
}

func (s *ControllerSteps) newOOBRequest(agentID string) (*outofband.Request, error) {
	controllerURL, ok := s.bddContext.GetControllerURL(agentID)
	if !ok {
		return nil, fmt.Errorf("unable to find controller URL registered for agent [%s]", agentID)
	}

	req, err := json.Marshal(outofbandcmd.CreateRequestArgs{
		Label: agentID,
		Attachments: []*decorator.Attachment{{
			ID:          uuid.New().String(),
			Description: "test-rest",
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

func (s *ControllerSteps) getConnection(agent1, agent2 string) (*didexchange.Connection, error) {
	var response didexcmd.QueryConnectionsResponse

	controllerURL, ok := s.bddContext.GetControllerURL(agent1)
	if !ok {
		return nil, fmt.Errorf("unable to find controller URL registered for agent [%s]", agent1)
	}

	err := sendHTTP(http.MethodGet, controllerURL+connections, nil, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to query connections: %w", err)
	}

	for _, conn := range response.Results {
		if conn.State != stateCompleted {
			continue
		}

		if conn.ConnectionID == s.connections[agent1+agent2] {
			return conn, nil
		}
	}

	return nil, errors.New("no connection between agents")
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
