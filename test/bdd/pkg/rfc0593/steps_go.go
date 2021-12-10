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
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/phayes/freeport"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/client/issuecredential/rfc0593"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	protocol "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	arieshttp "github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/http"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/defaults"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	bddcontext "github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
)

// GoSDKSteps are the BDD test steps.
type GoSDKSteps struct {
	context    *bddcontext.BDDContext
	agents     map[string]*context.Provider
	clients    map[string]*issuecredential.Client
	dids       map[string]string
	options    *rfc0593.CredentialSpecOptions
	vcTemplate *verifiable.Credential
}

// NewGoSDKSteps returns a new GoSDKSteps.
func NewGoSDKSteps() *GoSDKSteps {
	return &GoSDKSteps{
		agents:  make(map[string]*context.Provider),
		clients: make(map[string]*issuecredential.Client),
		dids:    make(map[string]string),
	}
}

// SetContext sets the BDD context.
func (s *GoSDKSteps) SetContext(ctx *bddcontext.BDDContext) {
	s.context = ctx
}

// RegisterSteps for this BDD test.
func (s *GoSDKSteps) RegisterSteps(g *godog.Suite) {
	g.Step(`^"([^"]*)" is running and has enabled auto-execution of RFC0593$`, s.setupAgent)
	g.Step(`^"([^"]*)" and "([^"]*)" are connected$`, s.connectAgents)
	g.Step(`^options "([^"]*)" ""([^"]*)"" ""([^"]*)"" ""([^"]*)"" "([^"]*)"$`, s.scenario)
	g.Step(`^"([^"]*)" sends an RFC0593 proposal to the "([^"]*)"$`, s.sendProposal)
	g.Step(`^"([^"]*)" sends an RFC0593 offer to the "([^"]*)"$`, s.sendOffer)
	g.Step(`^"([^"]*)" sends an RFC0593 request to the "([^"]*)"$`, s.sendRequest)
	g.Step(`^"([^"]*)" is issued the verifiable credential in JSONLD format$`, s.verifyCredential)
}

func (s *GoSDKSteps) setupAgent(agent string) error {
	port, err := freeport.GetFreePort()
	if err != nil {
		return fmt.Errorf("failed to obtain a free port: %w", err)
	}

	out, err := arieshttp.NewOutbound(arieshttp.WithOutboundHTTPClient(&http.Client{}))
	if err != nil {
		return fmt.Errorf("failed to init outbound http transport: %w", err)
	}

	internalInboundAddr := fmt.Sprintf("localhost:%d", port)
	externalInboundAddr := fmt.Sprintf("http://%s", internalInboundAddr)

	a, err := aries.New(
		aries.WithStoreProvider(mem.NewProvider()),
		aries.WithProtocolStateStoreProvider(mem.NewProvider()),
		defaults.WithInboundHTTPAddr(internalInboundAddr, externalInboundAddr, "", ""),
		aries.WithOutboundTransports(out),
	)
	if err != nil {
		return fmt.Errorf("failed to init aries framework: %w", err)
	}

	ctx, err := a.Context()
	if err != nil {
		return fmt.Errorf("failed to get framework context: %w", err)
	}

	mw, err := rfc0593.NewMiddleware(ctx)
	if err != nil {
		return fmt.Errorf("failed to init middleware: %w", err)
	}

	err = rfc0593.RegisterMiddleware(mw, ctx)
	if err != nil {
		return fmt.Errorf("failed to register middlware: %w", err)
	}

	err = s.initClient(agent, ctx)
	if err != nil {
		return fmt.Errorf("failed to init clients: %w", err)
	}

	s.agents[agent] = ctx

	return nil
}

func (s *GoSDKSteps) initClient(agent string, ctx *context.Provider) error {
	var err error

	s.clients[agent], err = issuecredential.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to init issuecredential client: %w", err)
	}

	rfc0593Events := make(chan service.DIDCommAction)

	err = s.clients[agent].RegisterActionEvent(rfc0593Events)
	if err != nil {
		return fmt.Errorf("failed to register issuecredential events: %w", err)
	}

	// All issuecredential messages conforming to RFC0593 will be handled automatically.
	// For nonconformant messages, pass a channel instead of `nil` to handle them.
	go rfc0593.AutoExecute(ctx, nil)(rfc0593Events)

	return nil
}

func (s *GoSDKSteps) connectAgents(holder, issuer string) error {
	holderDIDClient, err := didexchangeClient(s.agents[holder])
	if err != nil {
		return fmt.Errorf("'%s': %w", holder, err)
	}

	issuerDIDClient, err := didexchangeClient(s.agents[issuer])
	if err != nil {
		return fmt.Errorf("'%s': %w", issuer, err)
	}

	holderOOBClient, err := outofband.New(s.agents[holder])
	if err != nil {
		return fmt.Errorf("'%s' failed to init their oob client: %w", holder, err)
	}

	issuerOOBClient, err := outofband.New(s.agents[issuer])
	if err != nil {
		return fmt.Errorf("'%s' failed to init their oob client: %w", issuer, err)
	}

	invitation, err := issuerOOBClient.CreateInvitation(nil, outofband.WithLabel(issuer))
	if err != nil {
		return fmt.Errorf("'%s' failed to create an oob invitation: %w", issuer, err)
	}

	_, err = holderOOBClient.AcceptInvitation(invitation, holder)
	if err != nil {
		return fmt.Errorf("'%s' failed to accept the oob invitation: %w", holder, err)
	}

	err = s.verifyConnectionStates(holder, issuer, holderDIDClient, issuerDIDClient)
	if err != nil {
		return fmt.Errorf("failed to verify connection state: %w", err)
	}

	return nil
}

func (s *GoSDKSteps) scenario(proofPurpose, created, domain, challenge, proofType string) error {
	s.options = &rfc0593.CredentialSpecOptions{
		ProofPurpose: proofPurpose,
		Created:      created,
		Domain:       domain,
		Challenge:    challenge,
		ProofType:    proofType,
	}

	return nil
}

func (s *GoSDKSteps) sendProposal(holder, issuer string) error {
	s.vcTemplate = newVCTemplate()

	raw, err := json.Marshal(s.vcTemplate)
	if err != nil {
		return fmt.Errorf("failed to marshal vc template: %w", err)
	}

	attachID := uuid.New().String()

	_, err = s.clients[holder].SendProposal(
		&issuecredential.ProposeCredential{
			Formats: []protocol.Format{{
				AttachID: attachID,
				Format:   rfc0593.ProofVCDetailFormat,
			}},
			Attachments: []decorator.GenericAttachment{{
				ID: attachID,
				Data: decorator.AttachmentData{
					JSON: &rfc0593.CredentialSpec{
						Template: raw,
						Options:  s.options,
					},
				},
			}},
		},
		&connection.Record{
			MyDID:    s.dids[holder],
			TheirDID: s.dids[issuer],
		},
	)
	if err != nil {
		return fmt.Errorf("'%s' failed to send the proposal: %w", holder, err)
	}

	return nil
}

func (s *GoSDKSteps) sendOffer(issuer, holder string) error {
	s.vcTemplate = newVCTemplate()

	raw, err := json.Marshal(s.vcTemplate)
	if err != nil {
		return fmt.Errorf("failed to marshal vc template: %w", err)
	}

	attachID := uuid.New().String()

	_, err = s.clients[issuer].SendOffer(
		&issuecredential.OfferCredential{
			Formats: []protocol.Format{{
				AttachID: attachID,
				Format:   rfc0593.ProofVCDetailFormat,
			}},
			Attachments: []decorator.GenericAttachment{{
				ID: attachID,
				Data: decorator.AttachmentData{
					JSON: &rfc0593.CredentialSpec{
						Template: raw,
						Options:  s.options,
					},
				},
			}},
		},
		&connection.Record{
			MyDID:    s.dids[issuer],
			TheirDID: s.dids[holder],
		},
	)
	if err != nil {
		return fmt.Errorf("'%s' failed to send the offer: %w", issuer, err)
	}

	return nil
}

func (s *GoSDKSteps) sendRequest(holder, issuer string) error {
	s.vcTemplate = newVCTemplate()

	raw, err := json.Marshal(s.vcTemplate)
	if err != nil {
		return fmt.Errorf("failed to marshal vc template: %w", err)
	}

	attachID := uuid.New().String()

	_, err = s.clients[holder].SendRequest(
		&issuecredential.RequestCredential{
			Formats: []protocol.Format{{
				AttachID: attachID,
				Format:   rfc0593.ProofVCDetailFormat,
			}},
			Attachments: []decorator.GenericAttachment{{
				ID: attachID,
				Data: decorator.AttachmentData{
					JSON: &rfc0593.CredentialSpec{
						Template: raw,
						Options:  s.options,
					},
				},
			}},
		},
		&connection.Record{
			MyDID:    s.dids[holder],
			TheirDID: s.dids[issuer],
		},
	)
	if err != nil {
		return fmt.Errorf("'%s' failed to send the offer: %w", holder, err)
	}

	return nil
}

func (s *GoSDKSteps) verifyCredential(holder string) error { // nolint:funlen,gocyclo
	var (
		vc  *verifiable.Credential
		err error
	)

	err = retry(func() error {
		vc, err = s.agents[holder].VerifiableStore().GetCredential(s.vcTemplate.ID)

		return err
	})
	if err != nil {
		return fmt.Errorf("'%s' failed to fetch their vc: %w", holder, err)
	}

	if !reflect.DeepEqual(vc.Context, s.vcTemplate.Context) {
		return fmt.Errorf("expected context [%+v] but got [%+v]", s.vcTemplate.Context, vc.Context)
	}

	if !reflect.DeepEqual(vc.Types, s.vcTemplate.Types) {
		return fmt.Errorf("expected types [%+v] but got [%+v]", s.vcTemplate.Types, vc.Types)
	}

	if !reflect.DeepEqual(vc.Issuer, s.vcTemplate.Issuer) {
		return fmt.Errorf("expected issuer [%+v] but got [%+v]", s.vcTemplate.Issuer, vc.Issuer)
	}

	if len(vc.Proofs) == 0 {
		return fmt.Errorf("no proof was attached to the credential: %+v", vc)
	}

	if !reflect.DeepEqual(vc.Proofs[0]["type"], s.options.ProofType) {
		return fmt.Errorf("expected proofType %s but got %s", s.options.ProofType, vc.Proofs[0]["type"])
	}

	if !reflect.DeepEqual(vc.Proofs[0]["proofPurpose"], s.options.ProofPurpose) {
		return fmt.Errorf("expected proofPurpose %s but got %s", s.options.ProofPurpose, vc.Proofs[0]["proofPurpose"])
	}

	if !reflect.DeepEqual(vc.Proofs[0]["domain"], s.options.Domain) {
		return fmt.Errorf("expected domain %s but got %s", s.options.Domain, vc.Proofs[0]["domain"])
	}

	if !reflect.DeepEqual(vc.Proofs[0]["challenge"], s.options.Challenge) {
		return fmt.Errorf("expected challenge %s but got %s", s.options.Challenge, vc.Proofs[0]["challenge"])
	}

	expected, err := toMap(s.vcTemplate.Subject)
	if err != nil {
		return fmt.Errorf("failed to convert expected vc subject to map: %w", err)
	}

	actual, err := toMap(vc.Subject)
	if err != nil {
		return fmt.Errorf("failed to convert actual vc subject to map: %w", err)
	}

	if !reflect.DeepEqual(expected, actual) {
		return fmt.Errorf("expected subject [%+v] but got [%+v]", expected, actual)
	}

	return nil
}

func (s *GoSDKSteps) verifyConnectionStates(holder, issuer string,
	holderDIDClient, issuerDIDClient *didexchange.Client) error {
	err := retry(func() error {
		return s.checkConnection(holder, issuer, holderDIDClient)
	})
	if err != nil {
		return fmt.Errorf("failed to verify connection '%s' -> '%s': %w", holder, issuer, err)
	}

	err = retry(func() error {
		return s.checkConnection(issuer, holder, issuerDIDClient)
	})
	if err != nil {
		return fmt.Errorf("failed to verify connection '%s' -> '%s': %w", issuer, holder, err)
	}

	return nil
}

func (s *GoSDKSteps) checkConnection(agentA, agentB string, client *didexchange.Client) error {
	connections, err := client.QueryConnections(&didexchange.QueryConnectionsParams{})
	if err != nil {
		return fmt.Errorf("'%s' failed to fetch their connection record: %w", agentA, err)
	}

	var conn *didexchange.Connection

	for i := range connections {
		if connections[i].TheirLabel == agentB {
			conn = connections[i]

			break
		}
	}

	if conn == nil {
		return fmt.Errorf("'%s' does not have any connection with '%s'", agentA, agentB)
	}

	if conn.State != "completed" {
		return fmt.Errorf(
			"'%s' has connection record in state '%s' but expected 'completed'",
			agentA, conn.State,
		)
	}

	s.dids[agentA] = conn.MyDID
	s.dids[agentB] = conn.TheirDID

	return nil
}

func retry(f func() error) error {
	const (
		delay      = time.Second
		maxRetries = 10
	)

	return backoff.Retry(f, backoff.WithMaxRetries(backoff.NewConstantBackOff(delay), maxRetries))
}

func didexchangeClient(ctx *context.Provider) (*didexchange.Client, error) {
	client, err := didexchange.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to init didexchange client: %w", err)
	}

	events := make(chan service.DIDCommAction)

	err = client.RegisterActionEvent(events)
	if err != nil {
		return nil, fmt.Errorf("failed to register didexchange events: %w", err)
	}

	go service.AutoExecuteActionEvent(events)

	return client, nil
}

func newVCTemplate() *verifiable.Credential {
	return &verifiable.Credential{
		Context: []string{verifiable.ContextURI, "https://w3id.org/security/bbs/v1"},
		Types:   []string{verifiable.VCType},
		ID:      uuid.New().URN(),
		Subject: []verifiable.Subject{{
			ID: uuid.New().URN(),
			CustomFields: map[string]interface{}{
				"firstName": "John",
				"lastName":  "Doe",
			},
		}},
		Issuer: verifiable.Issuer{
			ID: uuid.New().URN(),
		},
		Issued: util.NewTime(time.Now()),
	}
}

func toMap(v interface{}) ([]map[string]interface{}, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal failed: %w", err)
	}

	m := make([]map[string]interface{}, 0)

	err = json.Unmarshal(raw, &m)
	if err != nil {
		return nil, fmt.Errorf("unmarshal failed: %w", err)
	}

	return m, nil
}
