/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/cucumber/godog"

	"github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	didexcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/didexchange"
	protocol "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	didexsteps "github.com/hyperledger/aries-framework-go/test/bdd/pkg/didexchange"
)

const (
	operationID                  = "/presentproof"
	actions                      = operationID + "/actions"
	sendRequestPresentation      = operationID + "/send-request-presentation"
	sendProposalPresentation     = operationID + "/send-propose-presentation"
	acceptProposePresentation    = operationID + "/%s/accept-propose-presentation"
	acceptRequestPresentation    = operationID + "/%s/accept-request-presentation"
	negotiateRequestPresentation = operationID + "/%s/negotiate-request-presentation"
	acceptPresentation           = operationID + "/%s/accept-presentation"
)

var logger = log.New("aries-framework/presentproof-tests")

// ControllerSteps supports steps for Present Proof controller
type ControllerSteps struct {
	bddContext *context.BDDContext
	did        map[string]string
}

// NewPresentProofControllerSteps creates steps for Present Proof controller
func NewPresentProofControllerSteps() *ControllerSteps {
	return &ControllerSteps{
		did: make(map[string]string),
	}
}

// SetContext sets every scenario with a fresh context
func (s *ControllerSteps) SetContext(ctx *context.BDDContext) {
	s.bddContext = ctx
}

// RegisterSteps registers agent steps
// nolint:lll
func (s *ControllerSteps) RegisterSteps(gs *godog.Suite) {
	gs.Step(`^"([^"]*)" has established connection with "([^"]*)" through PresentProof controller$`, s.establishConnection)
	gs.Step(`^"([^"]*)" sends a request presentation to "([^"]*)" through PresentProof controller$`, s.sendRequestPresentation)
	gs.Step(`^"([^"]*)" sends a propose presentation to "([^"]*)" through PresentProof controller$`, s.sendProposePresentation)
	gs.Step(`^"([^"]*)" negotiates about the request presentation with a proposal through PresentProof controller$`, s.negotiateRequestPresentation)
	gs.Step(`^"([^"]*)" accepts a proposal and sends a request to the Prover through PresentProof controller$`, s.acceptProposePresentation)
	gs.Step(`^"([^"]*)" accepts a request and sends a presentation to the Verifier through PresentProof controller$`, s.acceptRequestPresentation)
	gs.Step(`^"([^"]*)" successfully accepts a presentation through PresentProof controller$`, s.acceptPresentation)
}

func (s *ControllerSteps) establishConnection(inviter, invitee string) error {
	ds := didexsteps.NewDIDExchangeControllerSteps()
	ds.SetContext(s.bddContext)

	err := ds.EstablishConnection(inviter, invitee)
	if err != nil {
		return fmt.Errorf("unable to establish connection between [%s] and [%s]: %w", inviter, invitee, err)
	}

	inviterDID, err := s.agentDID(ds, inviter)
	if err != nil {
		return err
	}

	s.did[inviter] = inviterDID

	inviteeDID, err := s.agentDID(ds, invitee)
	if err != nil {
		return err
	}

	s.did[invitee] = inviteeDID

	return nil
}

func (s *ControllerSteps) sendRequestPresentation(verifier, prover string) error {
	url, ok := s.bddContext.GetControllerURL(verifier)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", verifier)
	}

	msg := map[string]interface{}{
		"my_did":               s.did[verifier],
		"their_did":            s.did[prover],
		"request_presentation": &protocol.RequestPresentation{},
	}

	var result interface{}

	return postToURL(url+sendRequestPresentation, msg, &result)
}

func (s *ControllerSteps) sendProposePresentation(prover, verifier string) error {
	url, ok := s.bddContext.GetControllerURL(prover)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", prover)
	}

	msg := map[string]interface{}{
		"my_did":               s.did[prover],
		"their_did":            s.did[verifier],
		"propose_presentation": &protocol.ProposePresentation{},
	}

	var result interface{}

	return postToURL(url+sendProposalPresentation, msg, &result)
}

func (s *ControllerSteps) negotiateRequestPresentation(agent string) error {
	url, ok := s.bddContext.GetControllerURL(agent)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", agent)
	}

	piid, err := actionPIID(url)
	if err != nil {
		return err
	}

	msg := map[string]interface{}{
		"propose_presentation": &protocol.ProposePresentation{},
	}

	var result interface{}

	return postToURL(url+fmt.Sprintf(negotiateRequestPresentation, piid), msg, &result)
}

func (s *ControllerSteps) acceptProposePresentation(verifier string) error {
	url, ok := s.bddContext.GetControllerURL(verifier)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", verifier)
	}

	piid, err := actionPIID(url)
	if err != nil {
		return err
	}

	msg := &presentproof.RequestPresentation{
		RequestPresentations: nil,
	}

	var result interface{}

	return postToURL(url+fmt.Sprintf(acceptProposePresentation, piid), msg, &result)
}

func (s *ControllerSteps) acceptRequestPresentation(prover string) error {
	url, ok := s.bddContext.GetControllerURL(prover)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", prover)
	}

	piid, err := actionPIID(url)
	if err != nil {
		return err
	}

	// TODO: Send non-empty VP after resolving https://github.com/hyperledger/aries-framework-go/issues/1799
	msg := &presentproof.Presentation{
		Presentations: nil,
	}

	var result interface{}

	return postToURL(url+fmt.Sprintf(acceptRequestPresentation, piid), msg, &result)
}

func (s *ControllerSteps) acceptPresentation(verifier string) error {
	url, ok := s.bddContext.GetControllerURL(verifier)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", verifier)
	}

	piid, err := actionPIID(url)
	if err != nil {
		return err
	}

	var result interface{}

	return postToURL(url+fmt.Sprintf(acceptPresentation, piid), nil, &result)
}

func (s *ControllerSteps) agentDID(ds *didexsteps.ControllerSteps, agent string) (string, error) {
	connectionID, ok := ds.ConnectionIDs()[agent]
	if !ok {
		return "", fmt.Errorf("unable to find connection for agent [%s]", agent)
	}

	controllerURL, ok := s.bddContext.GetControllerURL(agent)
	if !ok {
		return "", fmt.Errorf("unable to find controller URL registered for agent [%s]", agent)
	}

	var response didexcmd.QueryConnectionResponse

	err := sendHTTP(http.MethodGet, fmt.Sprintf("%s/connections/%s", controllerURL, connectionID), nil, &response)
	if err != nil {
		return "", fmt.Errorf("failed to query connections: %w", err)
	}

	return response.Result.MyDID, nil
}

func actionPIID(endpoint string) (string, error) {
	const (
		timeoutWait = 10 * time.Second
		retryDelay  = 500 * time.Millisecond
	)

	start := time.Now()

	for {
		if time.Since(start) > timeoutWait {
			break
		}

		var result struct {
			Actions []protocol.Action `json:"actions"`
		}

		err := sendHTTP(http.MethodGet, endpoint+actions, nil, &result)
		if err != nil {
			return "", fmt.Errorf("failed to get action PIID: %w", err)
		}

		if len(result.Actions) == 0 {
			time.Sleep(retryDelay)
			continue
		}

		return result.Actions[0].PIID, nil
	}

	return "", fmt.Errorf("unable to get action PIID: timeout")
}

func postToURL(url string, payload, result interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	err = sendHTTP(http.MethodPost, url, body, &result)
	if err != nil {
		return fmt.Errorf("failed to send HTTP: %w", err)
	}

	return nil
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
	err := c.Close()
	if err != nil {
		logger.Errorf("failed to close response body: %s", err)
	}
}
