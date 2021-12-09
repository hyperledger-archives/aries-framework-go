/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rfc0593

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"

	"github.com/cucumber/godog"
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/client/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/client/issuecredential/rfc0593"
	rfc05932 "github.com/hyperledger/aries-framework-go/pkg/controller/command/rfc0593"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	protocol "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	bddcontext "github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	bddissuecred "github.com/hyperledger/aries-framework-go/test/bdd/pkg/issuecredential"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/util"
)

// RestSDKSteps runs BDD test steps for the REST API.
type RestSDKSteps struct {
	context        *bddcontext.BDDContext
	spec           *rfc0593.CredentialSpec
	dids           map[string]string
	issueCredSteps *bddissuecred.ControllerSteps
}

// NewRestSDKSteps returns a new RestSDKSteps.
func NewRestSDKSteps() *RestSDKSteps {
	return &RestSDKSteps{
		dids:           make(map[string]string),
		issueCredSteps: bddissuecred.NewIssueCredentialControllerSteps(),
	}
}

// SetContext sets the BDD contest.
func (s *RestSDKSteps) SetContext(ctx *bddcontext.BDDContext) {
	s.context = ctx
	s.issueCredSteps.SetContext(ctx)
}

// RegisterSteps for this BDD test.
func (s *RestSDKSteps) RegisterSteps(g *godog.Suite) {
	g.Step(`^"([^"]*)" and "([^"]*)" are connected via the controller API$`, s.connectAgents)
	g.Step(`^controller API options "([^"]*)" ""([^"]*)"" ""([^"]*)"" ""([^"]*)"" "([^"]*)"$`, s.scenario)
	g.Step(`^"([^"]*)" sends an RFC0593 proposal to the "([^"]*)" via the controller API$`, s.sendProposal)
	g.Step(`^"([^"]*)" sends an RFC0593 offer to the "([^"]*)" via the controller API$`, s.sendOffer)
	g.Step(`^"([^"]*)" sends an RFC0593 request to the "([^"]*)" via the controller API$`, s.sendRequest)
	g.Step(`^"([^"]*)" replies to the Issuer's offer with a request$`, s.replyToOffer)
	g.Step(`^"([^"]*)" is issued the verifiable credential in JSONLD format via the controller API$`, s.verifyCredential)
}

func (s *RestSDKSteps) connectAgents(holder, issuer string) error {
	err := s.issueCredSteps.EstablishConnection(holder, issuer)
	if err != nil {
		return fmt.Errorf("failed to connect '%s' with '%s': %w", holder, issuer, err)
	}

	return nil
}

func (s *RestSDKSteps) scenario(proofPurpose, created, domain, challenge, proofType string) error {
	template := newVCTemplate()

	raw, err := json.Marshal(template)
	if err != nil {
		return fmt.Errorf("failed to marshal VC template: %w", err)
	}

	s.spec = &rfc0593.CredentialSpec{
		Template: raw,
		Options: &rfc0593.CredentialSpecOptions{
			ProofPurpose: proofPurpose,
			Created:      created,
			Domain:       domain,
			Challenge:    challenge,
			ProofType:    proofType,
		},
	}

	return nil
}

func (s *RestSDKSteps) sendProposal(holder, issuer string) error {
	attachID := uuid.New().String()

	proposal := &issuecredential.ProposeCredentialV2{
		Formats: []protocol.Format{{
			AttachID: attachID,
			Format:   rfc0593.ProofVCDetailFormat,
		}},
		FiltersAttach: []decorator.Attachment{{
			ID: attachID,
			Data: decorator.AttachmentData{
				JSON: s.spec,
			},
		}},
	}

	err := s.issueCredSteps.SendProposalWithOpts(holder, issuer, bddissuecred.WithProposal(proposal))
	if err != nil {
		return fmt.Errorf("'%s' failed to send the proposal: %w", holder, err)
	}

	return nil
}

func (s *RestSDKSteps) sendOffer(issuer, holder string) error {
	attachID := uuid.New().String()

	offer := &issuecredential.OfferCredentialV2{
		Formats: []protocol.Format{{
			AttachID: attachID,
			Format:   rfc0593.ProofVCDetailFormat,
		}},
		OffersAttach: []decorator.Attachment{{
			ID: attachID,
			Data: decorator.AttachmentData{
				JSON: s.spec,
			},
		}},
	}

	err := s.issueCredSteps.SendOfferWithOpts(issuer, holder, bddissuecred.WithOffer(offer))
	if err != nil {
		return fmt.Errorf("'%s' failed to send the offer: %w", holder, err)
	}

	return nil
}

func (s *RestSDKSteps) sendRequest(holder, issuer string) error {
	attachID := uuid.New().String()

	request := &issuecredential.RequestCredentialV2{
		Formats: []protocol.Format{{
			AttachID: attachID,
			Format:   rfc0593.ProofVCDetailFormat,
		}},
		RequestsAttach: []decorator.Attachment{{
			ID: attachID,
			Data: decorator.AttachmentData{
				JSON: s.spec,
			},
		}},
	}

	err := s.issueCredSteps.RequestCredentialWithOpts(holder, issuer, bddissuecred.WithRequest(request))
	if err != nil {
		return fmt.Errorf("'%s' failed to send the request: %w", holder, err)
	}

	return nil
}

func (s *RestSDKSteps) replyToOffer(holder string) error {
	offer, err := util.PullEventsFromWebSocket(s.context, holder, util.FilterTopic("issue-credential_actions"))
	if err != nil {
		return fmt.Errorf("'%s' failed to fetch the offer message: %w", holder, err)
	}

	msg, err := json.Marshal(offer.Message.Message)
	if err != nil {
		return fmt.Errorf("failed to marshal offer message: %w", err)
	}

	payload, err := json.Marshal(&rfc05932.GetCredentialSpecArgs{
		Message: msg,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal GetCredentialSpecArgs: %w", err)
	}

	destination, ok := s.context.GetControllerURL(holder)
	if !ok {
		return fmt.Errorf("'%s' does not have a controller URL registered", holder)
	}

	response := &rfc05932.GetCredentialSpecResponse{}

	err = util.SendHTTP(http.MethodPost, destination+"/rfc0593/get-spec", payload, response)
	if err != nil {
		return fmt.Errorf("failed to execute http request: %w", err)
	}

	if !reflect.DeepEqual(s.spec, response.Spec) {
		return fmt.Errorf("options mismatch; expected [%+v] got [%+v]", s.spec, response.Spec)
	}

	err = s.issueCredSteps.AcceptOfferPIID(destination, offer.Message.Properties["piid"].(string))
	if err != nil {
		return fmt.Errorf("'%s' failed to accept the offer: %w", holder, err)
	}

	return nil
}

func (s *RestSDKSteps) verifyCredential(holder string) error {
	msg, err := util.PullEventsFromWebSocket(s.context, holder, util.FilterTopic("issue-credential_actions"))
	if err != nil {
		return fmt.Errorf("'%s' failed to pull messages from websocket: %w", holder, err)
	}

	issueCredential := &issuecredential.IssueCredentialV2{}

	err = msg.Message.Message.Decode(issueCredential)
	if err != nil {
		return fmt.Errorf("failed to decode the issue-credential message: %w", err)
	}

	attachment, err := rfc0593.FindAttachment(
		rfc0593.ProofVCFormat, issueCredential.Formats, issueCredential.CredentialsAttach)
	if err != nil {
		return fmt.Errorf("failed to find RFC0593 credential attachment: %w", err)
	}

	raw, err := attachment.Data.Fetch()
	if err != nil {
		return fmt.Errorf("failed to fetch attachment contents: %w", err)
	}

	payload, err := json.Marshal(&rfc05932.VerifyCredentialArgs{
		Credential: raw,
		Spec:       *s.spec,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	destination, ok := s.context.GetControllerURL(holder)
	if !ok {
		return fmt.Errorf("'%s' does not have a controller registered", holder)
	}

	err = util.SendHTTP(http.MethodPost, destination+"/rfc0593/verify-credential", payload, nil)
	if err != nil {
		return fmt.Errorf("'%s' failed to verify the credential: %w", holder, err)
	}

	err = s.issueCredSteps.AcceptCredentialPIID("test", destination, msg.Message.Properties["piid"].(string))
	if err != nil {
		return fmt.Errorf("'%s' failed to accept the credential: %w", holder, err)
	}

	return nil
}
