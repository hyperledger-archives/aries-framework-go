/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/cucumber/godog"

	"github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	didexcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/didexchange"
	presentproofcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
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
	verifiablePresentations      = "/verifiable/presentations"
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
	gs.Step(`^"([^"]*)" successfully accepts a presentation with "([^"]*)" name through PresentProof controller$`, s.acceptPresentation)
	gs.Step(`^"([^"]*)" checks that presentation is being stored under the "([^"]*)" name$`, s.checkPresentation)
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

	return postToURL(url+sendRequestPresentation, presentproofcmd.SendRequestPresentationArgs{
		MyDID:               s.did[verifier],
		TheirDID:            s.did[prover],
		RequestPresentation: &presentproof.RequestPresentation{},
	})
}

func (s *ControllerSteps) sendProposePresentation(prover, verifier string) error {
	url, ok := s.bddContext.GetControllerURL(prover)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", prover)
	}

	return postToURL(url+sendProposalPresentation, presentproofcmd.SendProposePresentationArgs{
		MyDID:               s.did[prover],
		TheirDID:            s.did[verifier],
		ProposePresentation: &presentproof.ProposePresentation{},
	})
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

	return postToURL(url+fmt.Sprintf(negotiateRequestPresentation, piid), presentproofcmd.NegotiateRequestPresentationArgs{
		ProposePresentation: &presentproof.ProposePresentation{},
	})
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

	return postToURL(url+fmt.Sprintf(acceptProposePresentation, piid), presentproofcmd.AcceptProposePresentationArgs{
		RequestPresentation: &presentproof.RequestPresentation{},
	})
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

	return postToURL(url+fmt.Sprintf(acceptRequestPresentation, piid), presentproofcmd.AcceptRequestPresentationArgs{
		Presentation: &presentproof.Presentation{
			PresentationsAttach: []decorator.Attachment{{
				Data: decorator.AttachmentData{
					Base64: "ZXlKaGJHY2lPaUp1YjI1bElpd2lkSGx3SWpvaVNsZFVJbjAuZXlKcGMzTWlPaUprYVdRNlpYaGhiWEJzWlRwbFltWmxZakZtTnpFeVpXSmpObVl4WXpJM05tVXhNbVZqTWpFaUxDSnFkR2tpT2lKMWNtNDZkWFZwWkRvek9UYzRNelEwWmkwNE5UazJMVFJqTTJFdFlUazNPQzA0Wm1OaFltRXpPVEF6WXpVaUxDSjJjQ0k2ZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3ZNakF4T0M5amNtVmtaVzUwYVdGc2N5OTJNU0lzSW1oMGRIQnpPaTh2ZDNkM0xuY3pMbTl5Wnk4eU1ERTRMMk55WldSbGJuUnBZV3h6TDJWNFlXMXdiR1Z6TDNZeElsMHNJbWh2YkdSbGNpSTZJbVJwWkRwbGVHRnRjR3hsT21WaVptVmlNV1kzTVRKbFltTTJaakZqTWpjMlpURXlaV015TVNJc0ltbGtJam9pZFhKdU9uVjFhV1E2TXprM09ETTBOR1l0T0RVNU5pMDBZek5oTFdFNU56Z3RPR1pqWVdKaE16a3dNMk0xSWl3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFVISmxjMlZ1ZEdGMGFXOXVJaXdpUTNKbFpHVnVkR2xoYkUxaGJtRm5aWEpRY21WelpXNTBZWFJwYjI0aVhTd2lkbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpT201MWJHeDlmUS4=", // nolint: lll,
				},
			}},
		},
	})
}

func (s *ControllerSteps) acceptPresentation(verifier, name string) error {
	url, ok := s.bddContext.GetControllerURL(verifier)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", verifier)
	}

	piid, err := actionPIID(url)
	if err != nil {
		return err
	}

	return postToURL(url+fmt.Sprintf(acceptPresentation, piid), presentproofcmd.AcceptPresentationArgs{
		Names: []string{name},
	})
}

func (s *ControllerSteps) checkPresentation(verifier, name string) error {
	url, ok := s.bddContext.GetControllerURL(verifier)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", verifier)
	}

	const (
		maxRetry = 10
		delay    = time.Second
	)

	for i := 0; i < maxRetry; i++ {
		var result verifiable.RecordResult
		if err := sendHTTP(http.MethodGet, url+verifiablePresentations, nil, &result); err != nil {
			return err
		}

		for _, val := range result.Result {
			if val.Name == name {
				return nil
			}
		}

		time.Sleep(delay)
	}

	return errors.New("presentation not found")
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

		if result.Actions[0].MyDID == "" {
			return "", errors.New("myDID is empty")
		}

		if result.Actions[0].TheirDID == "" {
			return "", errors.New("theirDID is empty")
		}

		return result.Actions[0].PIID, nil
	}

	return "", fmt.Errorf("unable to get action PIID: timeout")
}

func postToURL(url string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	return sendHTTP(http.MethodPost, url, body, nil)
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

	return json.Unmarshal(data, &result)
}

func closeResponse(c io.Closer) {
	err := c.Close()
	if err != nil {
		logger.Errorf("failed to close response body: %s", err)
	}
}
