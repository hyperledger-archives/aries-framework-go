/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/cucumber/godog"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	verifiableStore "github.com/hyperledger/aries-framework-go/pkg/store/verifiable"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/issuecredential"
	bddverifiable "github.com/hyperledger/aries-framework-go/test/bdd/pkg/verifiable"
)

const timeout = time.Second * 15

const vpStrFromWallet = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
  "type": [
    "VerifiablePresentation",
    "UniversityDegreeCredential"
  ],
  "verifiableCredential": [
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "credentialSchema": [],
      "credentialSubject": {
        "degree": {
          "type": "BachelorDegree",
          "university": "MIT"
        },
        "id": "%s",
        "name": "Jayden Doe",
        "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
      },
      "expirationDate": "2020-01-01T19:23:24Z",
      "id": "http://example.edu/credentials/1872",
      "issuanceDate": "2010-01-01T19:23:24Z",
      "issuer": {
        "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
        "name": "Example University"
      },
      "referenceNumber": 83294847,
      "type": [
        "VerifiableCredential",
        "UniversityDegreeCredential"
      ]
    }
  ],
  "holder": "%s"
}
`

// SDKSteps is steps for the presentproof using client SDK
type SDKSteps struct {
	bddContext *context.BDDContext
	clients    map[string]*presentproof.Client
	actions    map[string]chan service.DIDCommAction
	events     map[string]chan service.StateMsg
}

// NewPresentProofSDKSteps creates steps for the presentproof with SDK
func NewPresentProofSDKSteps() *SDKSteps {
	return &SDKSteps{
		clients: make(map[string]*presentproof.Client),
		actions: make(map[string]chan service.DIDCommAction),
		events:  make(map[string]chan service.StateMsg),
	}
}

// SetContext is called before every scenario is run with a fresh new context
func (a *SDKSteps) SetContext(ctx *context.BDDContext) {
	a.bddContext = ctx
}

// RegisterSteps registers agent steps
func (a *SDKSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" sends a request presentation to the "([^"]*)"$`, a.sendRequestPresentation)
	s.Step(`^"([^"]*)" sends a propose presentation to the "([^"]*)"$`, a.sendProposePresentation)
	s.Step(`^"([^"]*)" negotiates about the request presentation with a proposal$`, a.negotiateRequestPresentation)
	s.Step(`^"([^"]*)" accepts a request and sends a presentation to the "([^"]*)"$`, a.acceptRequestPresentation)
	s.Step(`^"([^"]*)" declines a request presentation$`, a.declineRequestPresentation)
	s.Step(`^"([^"]*)" declines presentation$`, a.declinePresentation)
	s.Step(`^"([^"]*)" declines a propose presentation$`, a.declineProposePresentation)
	s.Step(`^"([^"]*)" accepts a proposal and sends a request to the Prover$`, a.acceptProposePresentation)
	s.Step(`^"([^"]*)" accepts a presentation with name "([^"]*)"$`, a.acceptPresentation)
	s.Step(`^"([^"]*)" checks that presentation is being stored under "([^"]*)" name$`, a.checkPresentation)
	s.Step(`^"([^"]*)" checks the history of events "([^"]*)"$`, a.checkHistoryEvents)
}

func (a *SDKSteps) waitFor(agent, name string) error {
	for {
		select {
		case e := <-a.events[agent]:
			if e.StateID == name {
				return nil
			}
		case <-time.After(timeout):
			return errors.New("timeout")
		}
	}
}

func (a *SDKSteps) checkPresentation(agent, name string) error {
	if err := a.waitFor(agent, "done"); err != nil {
		return err
	}

	store, err := verifiableStore.New(a.bddContext.AgentCtx[agent])
	if err != nil {
		return err
	}

	ID, err := store.GetPresentationIDByName(name)
	if err != nil {
		return err
	}

	_, err = store.GetPresentation(ID)

	return err
}

func (a *SDKSteps) checkHistoryEvents(agentID, events string) error {
	for _, stateID := range strings.Split(events, ",") {
		select {
		case e := <-a.events[agentID]:
			if stateID != e.StateID {
				return fmt.Errorf("history of events doesn't meet the expectation %q != %q", stateID, e.StateID)
			}
		case <-time.After(timeout):
			return fmt.Errorf("waited for %s: history of events doesn't meet the expectation", stateID)
		}
	}

	return nil
}

func (a *SDKSteps) sendProposePresentation(prover, verifier string) error {
	conn, err := a.getConnection(prover, verifier)
	if err != nil {
		return err
	}

	_, err = a.clients[prover].SendProposePresentation(&presentproof.ProposePresentation{}, conn.MyDID, conn.TheirDID)

	return err
}

func (a *SDKSteps) sendRequestPresentation(agent1, agent2 string) error {
	conn, err := a.getConnection(agent1, agent2)
	if err != nil {
		return err
	}

	_, err = a.clients[agent1].SendRequestPresentation(&presentproof.RequestPresentation{}, conn.MyDID, conn.TheirDID)

	return err
}

func (a *SDKSteps) getActionID(agent string) (string, error) {
	select {
	case e := <-a.actions[agent]:
		err := issuecredential.CheckProperties(e)
		if err != nil {
			return "", fmt.Errorf("check properties: %w", err)
		}

		return e.Message.ThreadID()
	case <-time.After(timeout):
		return "", errors.New("timeout")
	}
}

func (a *SDKSteps) acceptRequestPresentation(prover, verifier string) error {
	PIID, err := a.getActionID(prover)
	if err != nil {
		return err
	}

	conn, err := a.getConnection(prover, verifier)
	if err != nil {
		return err
	}

	vp, err := verifiable.ParseUnverifiedPresentation(
		[]byte(fmt.Sprintf(vpStrFromWallet, conn.MyDID, conn.MyDID)),
		verifiable.WithPresJSONLDDocumentLoader(bddverifiable.CachingJSONLDLoader()))
	if err != nil {
		return fmt.Errorf("failed to decode VP JSON: %w", err)
	}

	jwtClaims, err := vp.JWTClaims([]string{conn.MyDID}, true)
	if err != nil {
		return fmt.Errorf("failed to create JWT claims of VP: %w", err)
	}

	doc, err := a.bddContext.AgentCtx[prover].VDRIRegistry().Resolve(conn.MyDID)
	if err != nil {
		return err
	}

	pubKey := doc.PublicKey[0]
	kms := a.bddContext.AgentCtx[prover].Signer()

	vpJWS, err := jwtClaims.MarshalJWS(verifiable.EdDSA, newSigner(kms, base58.Encode(pubKey.Value)), "")
	if err != nil {
		return fmt.Errorf("failed to sign VP inside JWT: %w", err)
	}

	return a.clients[prover].AcceptRequestPresentation(PIID, &presentproof.Presentation{
		PresentationsAttach: []decorator.Attachment{{
			Data: decorator.AttachmentData{
				Base64: base64.StdEncoding.EncodeToString([]byte(vpJWS)),
			},
		}},
	})
}

func (a *SDKSteps) declineRequestPresentation(agent string) error {
	PIID, err := a.getActionID(agent)
	if err != nil {
		return err
	}

	return a.clients[agent].DeclineRequestPresentation(PIID, "rejected")
}

func (a *SDKSteps) declineProposePresentation(agent string) error {
	PIID, err := a.getActionID(agent)
	if err != nil {
		return err
	}

	return a.clients[agent].DeclineProposePresentation(PIID, "rejected")
}

func (a *SDKSteps) declinePresentation(agent string) error {
	PIID, err := a.getActionID(agent)
	if err != nil {
		return err
	}

	return a.clients[agent].DeclinePresentation(PIID, "rejected")
}

func (a *SDKSteps) acceptPresentation(agent, name string) error {
	PIID, err := a.getActionID(agent)
	if err != nil {
		return err
	}

	return a.clients[agent].AcceptPresentation(PIID, name)
}

func (a *SDKSteps) negotiateRequestPresentation(agent string) error {
	PIID, err := a.getActionID(agent)
	if err != nil {
		return err
	}

	return a.clients[agent].NegotiateRequestPresentation(PIID, &presentproof.ProposePresentation{})
}

func (a *SDKSteps) acceptProposePresentation(verifier string) error {
	PIID, err := a.getActionID(verifier)
	if err != nil {
		return err
	}

	return a.clients[verifier].AcceptProposePresentation(PIID, &presentproof.RequestPresentation{})
}

func (a *SDKSteps) createClient(agentID string) error {
	if a.clients[agentID] != nil {
		return nil
	}

	const stateMsgChanSize = 12

	client, err := presentproof.New(a.bddContext.AgentCtx[agentID])
	if err != nil {
		return err
	}

	a.clients[agentID] = client
	a.actions[agentID] = make(chan service.DIDCommAction, 1)
	a.events[agentID] = make(chan service.StateMsg, stateMsgChanSize)

	if err := client.RegisterMsgEvent(a.events[agentID]); err != nil {
		return err
	}

	return client.RegisterActionEvent(a.actions[agentID])
}

func (a *SDKSteps) getConnection(agent1, agent2 string) (*didexchange.Connection, error) {
	if err := a.createClient(agent1); err != nil {
		return nil, err
	}

	if err := a.createClient(agent2); err != nil {
		return nil, err
	}

	connections, err := a.bddContext.DIDExchangeClients[agent1].QueryConnections(&didexchange.QueryConnectionsParams{})
	if err != nil {
		return nil, err
	}

	for i := range connections {
		if connections[i].TheirLabel == agent2 {
			return connections[i], nil
		}
	}

	return nil, errors.New("no connection between agents")
}

type signer struct {
	kms   legacykms.Signer
	keyID string
}

func newSigner(kms legacykms.Signer, keyID string) *signer {
	return &signer{kms: kms, keyID: keyID}
}

func (s *signer) Sign(data []byte) ([]byte, error) {
	return s.kms.SignMessage(data, s.keyID)
}
