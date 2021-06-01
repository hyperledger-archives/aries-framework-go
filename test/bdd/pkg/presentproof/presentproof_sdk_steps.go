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

	"github.com/cucumber/godog"
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	protocol "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	verifiableStore "github.com/hyperledger/aries-framework-go/pkg/store/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/issuecredential"
	bddverifiable "github.com/hyperledger/aries-framework-go/test/bdd/pkg/verifiable"
)

const timeout = time.Second * 15

// nolint: gochecknoglobals
var (
	strFilterType = "string"
)

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

// SDKSteps is steps for the presentproof using client SDK.
type SDKSteps struct {
	bddContext *context.BDDContext
	clients    map[string]*presentproof.Client
	actions    map[string]chan service.DIDCommAction
	events     map[string]chan service.StateMsg
}

// NewPresentProofSDKSteps creates steps for the presentproof with SDK.
func NewPresentProofSDKSteps() *SDKSteps {
	return &SDKSteps{
		clients: make(map[string]*presentproof.Client),
		actions: make(map[string]chan service.DIDCommAction),
		events:  make(map[string]chan service.StateMsg),
	}
}

// SetContext is called before every scenario is run with a fresh new context.
func (a *SDKSteps) SetContext(ctx *context.BDDContext) {
	a.bddContext = ctx
}

// RegisterSteps registers agent steps.
func (a *SDKSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" sends a request presentation to the "([^"]*)"$`, a.sendRequestPresentation)
	s.Step(`^"([^"]*)" sends a request presentation with presentation definition to the "([^"]*)"$`,
		a.sendRequestPresentationDefinition)
	s.Step(`^"([^"]*)" sends a propose presentation to the "([^"]*)"$`, a.sendProposePresentation)
	s.Step(`^"([^"]*)" negotiates about the request presentation with a proposal$`, a.negotiateRequestPresentation)
	s.Step(`^"([^"]*)" accepts a request and sends a presentation to the "([^"]*)"$`, a.acceptRequestPresentation)
	s.Step(`^"([^"]*)" accepts a request and sends credentials with BBS to the "([^"]*)" and proof "([^"]*)"$`,
		a.acceptRequestPresentationBBS)
	s.Step(`^"([^"]*)" declines a request presentation$`, a.declineRequestPresentation)
	s.Step(`^"([^"]*)" declines presentation$`, a.declinePresentation)
	s.Step(`^"([^"]*)" declines a propose presentation$`, a.declineProposePresentation)
	s.Step(`^"([^"]*)" receives problem report message \(Present Proof\)$`, a.receiveProblemReport)
	s.Step(`^"([^"]*)" accepts a proposal and sends a request to the Prover$`, a.acceptProposePresentation)
	s.Step(`^"([^"]*)" accepts a presentation with name "([^"]*)"$`, a.acceptPresentation)
	s.Step(`^"([^"]*)" checks that presentation is being stored under "([^"]*)" name$`, a.checkPresentation)
	s.Step(`^"([^"]*)" checks that presentation is being stored under "([^"]*)" name and has "([^"]*)" proof$`,
		a.checkPresentationAndProof)
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
	_, err := a.getPresentation(agent, name)

	return err
}

func (a *SDKSteps) getPresentation(agent, name string) (*verifiable.Presentation, error) {
	if err := a.waitFor(agent, "done"); err != nil {
		return nil, err
	}

	store, err := verifiableStore.New(a.bddContext.AgentCtx[agent])
	if err != nil {
		return nil, err
	}

	ID, err := store.GetPresentationIDByName(name)
	if err != nil {
		return nil, err
	}

	return store.GetPresentation(ID)
}

func (a *SDKSteps) checkPresentationAndProof(agent, name, proof string) error {
	vp, err := a.getPresentation(agent, name)
	if err != nil {
		return err
	}

	for i := range vp.Proofs {
		if vp.Proofs[i]["type"] == proof {
			return nil
		}
	}

	return errors.New("no proof")
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

	_, err = a.clients[agent1].SendRequestPresentation(&presentproof.RequestPresentation{
		WillConfirm: true,
	}, conn.MyDID, conn.TheirDID)

	return err
}

func (a *SDKSteps) sendRequestPresentationDefinition(agent1, agent2 string) error {
	limitDisclosure := presexch.Required

	conn, err := a.getConnection(agent1, agent2)
	if err != nil {
		return err
	}

	ID := uuid.New().String()

	_, err = a.clients[agent1].SendRequestPresentation(&presentproof.RequestPresentation{
		Formats: []protocol.Format{
			{
				Format:   "dif/presentation-exchange/definitions@v1.0",
				AttachID: ID,
			},
		},
		RequestPresentationsAttach: []decorator.Attachment{{
			ID: ID,
			Data: decorator.AttachmentData{
				JSON: map[string]interface{}{
					"presentation_definition": &presexch.PresentationDefinition{
						ID: uuid.New().String(),
						InputDescriptors: []*presexch.InputDescriptor{{
							Schema: []*presexch.Schema{{
								URI: "https://www.w3.org/2018/credentials/examples/v1#UniversityDegreeCredential",
							}},
							ID: uuid.New().String(),
							Constraints: &presexch.Constraints{
								LimitDisclosure: &limitDisclosure,
								Fields: []*presexch.Field{{
									Path:   []string{"$.credentialSubject.degree.degreeSchool"},
									Filter: &presexch.Filter{Type: &strFilterType},
								}},
							},
						}},
					},
				},
			},
		}},
		WillConfirm: true,
	}, conn.MyDID, conn.TheirDID)

	return err
}

func (a *SDKSteps) getActionID(agent string) (string, error) {
	select {
	case e := <-a.actions[agent]:
		err := issuecredential.CheckProperties(e)
		if err != nil {
			return "", fmt.Errorf("check properties: %w", err)
		}

		return e.Properties.All()["piid"].(string), nil
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

	loader, err := bddverifiable.CreateDocumentLoader()
	if err != nil {
		return err
	}

	vp, err := verifiable.ParsePresentation(
		[]byte(fmt.Sprintf(vpStrFromWallet, conn.MyDID, conn.MyDID)),
		verifiable.WithPresJSONLDDocumentLoader(loader),
		verifiable.WithPresDisabledProofCheck())
	if err != nil {
		return fmt.Errorf("failed to decode VP JSON: %w", err)
	}

	jwtClaims, err := vp.JWTClaims([]string{conn.MyDID}, true)
	if err != nil {
		return fmt.Errorf("failed to create JWT claims of VP: %w", err)
	}

	doc, err := a.bddContext.AgentCtx[prover].VDRegistry().Resolve(conn.MyDID)
	if err != nil {
		return err
	}

	pubKey := doc.DIDDocument.VerificationMethod[0]
	km := a.bddContext.AgentCtx[prover].KMS()
	cr := a.bddContext.AgentCtx[prover].Crypto()

	kid, err := localkms.CreateKID(pubKey.Value, kms.ED25519)
	if err != nil {
		return fmt.Errorf("failed to key kid for kms: %w", err)
	}

	vpJWS, err := jwtClaims.MarshalJWS(verifiable.EdDSA, newSigner(km, cr, kid), pubKey.ID)
	if err != nil {
		return fmt.Errorf("failed to sign VP inside JWT: %w", err)
	}

	return a.clients[prover].AcceptRequestPresentation(PIID, &presentproof.Presentation{
		PresentationsAttach: []decorator.Attachment{{
			Data: decorator.AttachmentData{
				Base64: base64.StdEncoding.EncodeToString([]byte(vpJWS)),
			},
		}},
	}, nil)
}

func (a *SDKSteps) acceptRequestPresentationBBS(prover, _, proof string) error { // nolint: funlen
	PIID, err := a.getActionID(prover)
	if err != nil {
		return err
	}

	km := a.bddContext.AgentCtx[prover].KMS()
	cr := a.bddContext.AgentCtx[prover].Crypto()

	kid, pubKey, err := km.CreateAndExportPubKeyBytes(kms.BLS12381G2Type)
	if err != nil {
		return err
	}

	_, didKey := fingerprint.CreateDIDKeyByCode(fingerprint.BLS12381g2PubKeyMultiCodec, pubKey)

	vc := &verifiable.Credential{
		ID: "https://issuer.oidp.uscis.gov/credentials/83627465",
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1",
			"https://w3id.org/security/bbs/v1",
		},
		Types: []string{
			"VerifiableCredential",
			"UniversityDegreeCredential",
		},
		Subject: verifiable.Subject{
			ID: "did:example:b34ca6cd37bbf23",
			CustomFields: map[string]interface{}{
				"name":   "Jayden Doe",
				"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1",
				"degree": map[string]interface{}{
					"degree":       "MIT",
					"degreeSchool": "MIT school",
					"type":         "BachelorDegree",
				},
			},
		},
		Issued: &util.TimeWithTrailingZeroMsec{
			Time: time.Now(),
		},
		Expired: &util.TimeWithTrailingZeroMsec{
			Time: time.Now().AddDate(1, 0, 0),
		},
		Issuer: verifiable.Issuer{
			ID: "did:example:489398593",
		},
		CustomFields: map[string]interface{}{
			"identifier":  "83627465",
			"name":        "Permanent Resident Card",
			"description": "Government of Example Permanent Resident Card.",
		},
	}

	loader, err := bddverifiable.CreateDocumentLoader()
	if err != nil {
		return err
	}

	err = vc.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
		SignatureType:           "BbsBlsSignature2020",
		SignatureRepresentation: verifiable.SignatureProofValue,
		Suite:                   bbsblssignature2020.New(suite.WithSigner(newBBSSigner(km, cr, kid))),
		VerificationMethod:      didKey,
	}, jsonld.WithDocumentLoader(loader))

	if err != nil {
		return fmt.Errorf("failed to key kid for kms: %w", err)
	}

	var signFn func(presentation *verifiable.Presentation) error

	if proof == "default" {
		signFn = nil
	}

	if proof == "BbsBlsSignature2020" {
		signFn = func(presentation *verifiable.Presentation) error {
			presentation.Context = append(presentation.Context, "https://w3id.org/security/bbs/v1")

			return presentation.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
				SignatureType:           "BbsBlsSignature2020",
				SignatureRepresentation: verifiable.SignatureProofValue,
				Suite:                   bbsblssignature2020.New(suite.WithSigner(newBBSSigner(km, cr, kid))),
				VerificationMethod:      didKey,
			}, jsonld.WithDocumentLoader(loader))
		}
	}

	return a.clients[prover].AcceptRequestPresentation(PIID, &presentproof.Presentation{
		PresentationsAttach: []decorator.Attachment{{
			MimeType: "application/ld+json",
			Data: decorator.AttachmentData{
				JSON: vc,
			},
		}},
	}, signFn)
}

func (a *SDKSteps) receiveProblemReport(agent string) error {
	PIID, err := a.getActionID(agent)
	if err != nil {
		return err
	}

	return a.clients[agent].AcceptProblemReport(PIID)
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

	return a.clients[verifier].AcceptProposePresentation(PIID, &presentproof.RequestPresentation{
		WillConfirm: true,
	})
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
	km    kms.KeyManager
	cr    crypto.Crypto
	keyID string
}

func newSigner(km kms.KeyManager, cr crypto.Crypto, keyID string) *signer {
	return &signer{km: km, cr: cr, keyID: keyID}
}

// Sign signs data with signer's keyID found in an internal kms.
func (s *signer) Sign(data []byte) ([]byte, error) {
	kh, err := s.km.Get(s.keyID)
	if err != nil {
		return nil, err
	}

	return s.cr.Sign(data, kh)
}

type bbsSigner struct{ *signer }

func newBBSSigner(km kms.KeyManager, cr crypto.Crypto, keyID string) *bbsSigner {
	return &bbsSigner{&signer{km: km, cr: cr, keyID: keyID}}
}

func (s *bbsSigner) Sign(data []byte) ([]byte, error) {
	kh, err := s.km.Get(s.keyID)
	if err != nil {
		return nil, err
	}

	return s.cr.SignMulti(s.textToLines(string(data)), kh)
}

func (s *bbsSigner) textToLines(txt string) [][]byte {
	lines := strings.Split(txt, "\n")
	linesBytes := make([][]byte, 0, len(lines))

	for i := range lines {
		if strings.TrimSpace(lines[i]) != "" {
			linesBytes = append(linesBytes, []byte(lines[i]))
		}
	}

	return linesBytes
}
