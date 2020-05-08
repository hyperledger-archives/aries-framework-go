/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/cucumber/godog"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	didexcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	protocol "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	didexsteps "github.com/hyperledger/aries-framework-go/test/bdd/pkg/didexchange"
)

const (
	operationID       = "/issuecredential"
	actions           = operationID + "/actions"
	sendRequest       = operationID + "/send-request"
	sendOffer         = operationID + "/send-offer"
	sendProposal      = operationID + "/send-proposal"
	acceptProposal    = operationID + "/%s/accept-proposal"
	negotiateProposal = operationID + "/%s/negotiate-proposal"
	acceptOffer       = operationID + "/%s/accept-offer"
	acceptRequest     = operationID + "/%s/accept-request"
	acceptCredential  = operationID + "/%s/accept-credential"
)

var logger = log.New("aries-framework/issuecredential-tests")

// ControllerSteps is steps for issuecredential with controller
type ControllerSteps struct {
	bddContext *context.BDDContext
	did        map[string]string
}

// NewIssueCredentialControllerSteps creates steps for issuecredential with controller
func NewIssueCredentialControllerSteps() *ControllerSteps {
	return &ControllerSteps{}
}

// SetContext sets every scenario with a fresh context
func (s *ControllerSteps) SetContext(ctx *context.BDDContext) {
	s.bddContext = ctx
}

// RegisterSteps registers agent steps
// nolint:lll
func (s *ControllerSteps) RegisterSteps(gs *godog.Suite) {
	gs.Step(`^"([^"]*)" has established connection with "([^"]*)" through IssueCredential controller$`, s.establishConnection)
	gs.Step(`^"([^"]*)" requests credential from "([^"]*)" through IssueCredential controller$`, s.requestCredential)
	gs.Step(`^"([^"]*)" sends an offer to the "([^"]*)" through IssueCredential controller$`, s.sendOffer)
	gs.Step(`^"([^"]*)" sends proposal credential to the "([^"]*)" through IssueCredential controller$`, s.sendProposal)
	gs.Step(`^"([^"]*)" accepts a proposal and sends an offer to the Holder through IssueCredential controller$`, s.acceptProposal)
	gs.Step(`^"([^"]*)" does not like the offer and sends a new proposal to the Issuer through IssueCredential controller$`, s.negotiateProposal)
	gs.Step(`^"([^"]*)" accepts an offer and sends a request to the Issuer through IssueCredential controller$`, s.acceptOffer)
	gs.Step(`^"([^"]*)" accepts request and sends credential to the Holder through IssueCredential controller$`, s.acceptRequest)
	gs.Step(`^"([^"]*)" accepts credential with name "([^"]*)" through IssueCredential controller$`, s.acceptCredential)
	gs.Step(`^"([^"]*)" checks that issued credential is being stored under "([^"]*)" name$`, s.validateCredential)
}

func (s *ControllerSteps) establishConnection(holder, issuer string) error {
	ds := didexsteps.NewDIDExchangeControllerSteps()
	ds.SetContext(s.bddContext)

	err := ds.EstablishConnection(holder, issuer)
	if err != nil {
		return fmt.Errorf("unable to establish connection between [%s] and [%s]: %w", holder, issuer, err)
	}

	connID, ok := ds.ConnectionIDs()[holder]
	if !ok {
		return fmt.Errorf("unable to find connection for agent [%s]", holder)
	}

	controllerURL, ok := s.bddContext.GetControllerURL(holder)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", holder)
	}

	var response didexcmd.QueryConnectionResponse

	connectionsURL := fmt.Sprintf("%s/connections/%s", controllerURL, connID)

	err = sendHTTP(http.MethodGet, connectionsURL, nil, &response)
	if err != nil {
		return fmt.Errorf("failed to query connections: %w", err)
	}

	s.did = make(map[string]string)
	s.did[holder] = response.Result.MyDID
	s.did[issuer] = response.Result.TheirDID

	return nil
}

func (s *ControllerSteps) requestCredential(holder, issuer string) error {
	url, ok := s.bddContext.GetControllerURL(holder)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", holder)
	}

	msg := map[string]interface{}{
		"my_did":             s.did[holder],
		"their_did":          s.did[issuer],
		"request_credential": &protocol.RequestCredential{},
	}

	return postToURL(url+sendRequest, msg)
}

func (s *ControllerSteps) sendOffer(issuer, holder string) error {
	url, ok := s.bddContext.GetControllerURL(issuer)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", issuer)
	}

	msg := map[string]interface{}{
		"my_did":           s.did[issuer],
		"their_did":        s.did[holder],
		"offer_credential": &protocol.OfferCredential{},
	}

	return postToURL(url+sendOffer, msg)
}

func (s *ControllerSteps) sendProposal(holder, issuer string) error {
	url, ok := s.bddContext.GetControllerURL(holder)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", holder)
	}

	msg := map[string]interface{}{
		"my_did":             s.did[holder],
		"their_did":          s.did[issuer],
		"propose_credential": &protocol.ProposeCredential{},
	}

	return postToURL(url+sendProposal, msg)
}

func (s *ControllerSteps) acceptProposal(issuer string) error {
	url, ok := s.bddContext.GetControllerURL(issuer)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", issuer)
	}

	piid, err := actionPIID(url)
	if err != nil {
		return err
	}

	msg := &protocol.OfferCredential{}

	return postToURL(url+fmt.Sprintf(acceptProposal, piid), msg)
}

func (s *ControllerSteps) negotiateProposal(holder string) error {
	url, ok := s.bddContext.GetControllerURL(holder)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", holder)
	}

	piid, err := actionPIID(url)
	if err != nil {
		return err
	}

	msg := &protocol.ProposeCredential{}

	return postToURL(url+fmt.Sprintf(negotiateProposal, piid), msg)
}

func (s *ControllerSteps) acceptOffer(holder string) error {
	url, ok := s.bddContext.GetControllerURL(holder)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", holder)
	}

	piid, err := actionPIID(url)
	if err != nil {
		return err
	}

	return postToURL(url+fmt.Sprintf(acceptOffer, piid), nil)
}

func (s *ControllerSteps) acceptRequest(issuer string) error {
	url, ok := s.bddContext.GetControllerURL(issuer)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", issuer)
	}

	piid, err := actionPIID(url)
	if err != nil {
		return err
	}

	msg := &protocol.IssueCredential{
		CredentialsAttach: []decorator.Attachment{
			{Data: decorator.AttachmentData{JSON: getVCredential()}},
		},
	}

	return postToURL(url+fmt.Sprintf(acceptRequest, piid), msg)
}

func (s *ControllerSteps) acceptCredential(holder, credential string) error {
	url, ok := s.bddContext.GetControllerURL(holder)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", holder)
	}

	piid, err := actionPIID(url)
	if err != nil {
		return err
	}

	msg := []string{credential}

	return postToURL(url+fmt.Sprintf(acceptCredential, piid), msg)
}

func (s *ControllerSteps) validateCredential(holder, credential string) error {
	url, ok := s.bddContext.GetControllerURL(holder)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", holder)
	}

	const (
		timeoutWait = 10 * time.Second
		retryDelay  = 500 * time.Millisecond
	)

	start := time.Now()

	for {
		if time.Since(start) > timeoutWait {
			break
		}

		var result interface{}

		err := sendHTTP(http.MethodGet, fmt.Sprintf("%s/verifiable/credential/name/%s", url, credential), nil, &result)
		if err != nil {
			time.Sleep(retryDelay)
			continue
		}

		return nil
	}

	return fmt.Errorf("failed to validate credential: not found")
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

func postToURL(url string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	var result interface{}

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
