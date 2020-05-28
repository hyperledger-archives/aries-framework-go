/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package redeemableroutes

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cucumber/godog"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	introClient "github.com/hyperledger/aries-framework-go/pkg/client/introduce"
	routeClient "github.com/hyperledger/aries-framework-go/pkg/client/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	agentSteps "github.com/hyperledger/aries-framework-go/test/bdd/agent"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	bddroute "github.com/hyperledger/aries-framework-go/test/bdd/pkg/mediator"
	oobSteps "github.com/hyperledger/aries-framework-go/test/bdd/pkg/outofband"
)

const timeout = 2 * time.Second

// BDDSteps for this feature.
type BDDSteps struct {
	context        *context.BDDContext
	agentSdk       *agentSteps.SDKSteps
	oobSdk         *oobSteps.SDKSteps
	routeSdk       *bddroute.SDKSteps
	proposals      map[string]*introClient.Recipient
	goalCode       string
	redeemableCode string
	redeemableOpts *mediator.Options
	introClients   map[string]*introClient.Client
	introEvents    map[string]chan service.DIDCommAction
	introApprovals map[string]chan interface{}
}

// NewBDDSteps this feature's test steps.
func NewBDDSteps() *BDDSteps {
	return &BDDSteps{
		agentSdk:       agentSteps.NewSDKSteps(),
		oobSdk:         oobSteps.NewOutOfBandSDKSteps(),
		routeSdk:       bddroute.NewRouteSDKSteps(),
		proposals:      make(map[string]*introClient.Recipient),
		introClients:   make(map[string]*introClient.Client),
		introEvents:    make(map[string]chan service.DIDCommAction),
		introApprovals: make(map[string]chan interface{}),
	}
}

// RegisterSteps registers agent steps
func (b *BDDSteps) RegisterSteps(s *godog.Suite) {
	s.Step(
		`^"([^"]*)" is connected to "([^"]*)" with transport "([^"]*)" on "([^"]*)" port "([^"]*)"$`,
		b.createIntroduceeAndConnect)
	s.Step(
		`^"([^"]*)" prepares an introduction proposal to "([^"]*)" for "([^"]*)"$`,
		b.alicePreparesProposalToBobForRouter)
	s.Step(
		`^"([^"]*)" prepares an introduction proposal to "([^"]*)" for "([^"]*)" with the goal code "([^"]*)"$`,
		b.alicePreparesProposalToRouterForBob)
	s.Step(`^"([^"]*)" sends these proposals to "([^"]*)" and "([^"]*)"$`, b.sendProposals)
	s.Step(`^"([^"]*)" approves$`, b.bobApprovesIntroduction)
	s.Step(
		`^"([^"]*)" approves and responds with serviceEndpoint "([^"]*)" and routingKey "([^"]*)"`,
		b.routerApprovesIntroduction)
	s.Step(
		`^"([^"]*)" connects with "([^"]*)" and sends the embedded route registration request$`,
		b.bobConnectsWithRouterAndRequestsRoute)
	s.Step(
		`^"([^"]*)" confirms redeemable code and approves`, b.routerConfirmsCodeAndApprovesRequest)
	s.Step(`^"([^"]*)" is granted serviceEndpoint "([^"]*)" and routingKey "([^"]*)"`, b.bobConfirmsGrant)
}

// SetContext for these BDD test steps.
func (b *BDDSteps) SetContext(c *context.BDDContext) {
	b.context = c
	b.agentSdk.SetContext(c)
	b.oobSdk.SetContext(c)
	b.routeSdk.SetContext(c)
}

func (b *BDDSteps) createIntroduceeAndConnect(introducer, introducee, protocolScheme, host, port string) error {
	err := b.agentSdk.CreateAgent(introducee, host, port, protocolScheme)
	if err != nil {
		return fmt.Errorf("failed to create router %s : %w", introducee, err)
	}

	err = b.routeSdk.CreateRouteClient(introducee)
	if err != nil {
		return fmt.Errorf("%s failed to create a routing client : %w", introducee, err)
	}

	err = b.oobSdk.ConnectAll(introducer + "," + introducee)
	if err != nil {
		return fmt.Errorf("failed to connect %s to %s : %w", introducer, introducee, err)
	}

	return nil
}

func (b *BDDSteps) alicePreparesProposalToBobForRouter(alice, bob, router string) error {
	err := b.createIntroduceClients(alice, bob, router)
	if err != nil {
		return err
	}

	conn, err := b.getConnection(alice, bob)
	if err != nil {
		return err
	}

	b.proposals[bob] = &introClient.Recipient{
		To:       &introduce.To{Name: router},
		MyDID:    conn.MyDID,
		TheirDID: conn.TheirDID,
	}

	return nil
}

func (b *BDDSteps) alicePreparesProposalToRouterForBob(alice, router, bob, goalCode string) error {
	b.goalCode = goalCode

	conn, err := b.getConnection(alice, router)
	if err != nil {
		return err
	}

	b.proposals[router] = &introClient.Recipient{
		To:       &introduce.To{Name: bob},
		Goal:     "test",
		GoalCode: goalCode,
		MyDID:    conn.MyDID,
		TheirDID: conn.TheirDID,
	}

	return nil
}

func (b *BDDSteps) sendProposals(alice, bob, router string) error {
	err := b.introClients[alice].SendProposal(
		b.proposals[bob],
		b.proposals[router],
	)
	if err != nil {
		return fmt.Errorf("%s failed to send proposals to %s and %s : %w", alice, bob, router, err)
	}

	return nil
}

func (b *BDDSteps) bobApprovesIntroduction(bob string) error {
	b.introApprovals[bob] <- &service.Empty{}

	return nil
}

func (b *BDDSteps) routerApprovesIntroduction(router, serviceEndpoint, routingKey string) error {
	select {
	case event := <-b.introEvents[router]:
		proposal := &introduce.Proposal{}

		err := event.Message.Decode(proposal)
		if err != nil {
			return fmt.Errorf("%s failed to decode introduce proposal : %w", router, err)
		}

		if proposal.GoalCode != b.goalCode {
			return fmt.Errorf(
				"%s expected goal-code %s but got %s in the introduce proposal",
				router, b.goalCode, proposal.GoalCode)
		}
	case <-time.After(timeout):
		return fmt.Errorf("%s timed out waiting for proposal for introduction", router)
	}

	routeRequest := routeClient.NewRequest()
	b.redeemableCode = routeRequest.ID
	b.redeemableOpts = &mediator.Options{
		ServiceEndpoint: serviceEndpoint,
		RoutingKeys:     []string{routingKey},
	}

	bits, err := json.Marshal(routeRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal route-request : %w", err)
	}

	req, err := b.context.OutOfBandClients[router].CreateRequest(
		[]*decorator.Attachment{{
			Description: "please redeem your route code",
			Data: decorator.AttachmentData{
				Base64: base64.StdEncoding.EncodeToString(bits),
			},
		}},
		outofband.WithLabel(router),
	)
	if err != nil {
		return fmt.Errorf("%s failed to create an oob request : %w", router, err)
	}

	b.introApprovals[router] <- introClient.WithOOBRequest(
		req,
		&decorator.Attachment{
			Description: "pre-approved routing keys and service endpoints",
			Data: decorator.AttachmentData{
				JSON: map[string]interface{}{
					"routingKeys":     []string{routingKey},
					"serviceEndpoint": serviceEndpoint,
				},
			},
		},
	)

	return nil
}

func (b *BDDSteps) bobConnectsWithRouterAndRequestsRoute(bob, router string) error {
	// bob approves oob request received via the introducer
	b.oobSdk.ApproveOOBRequest(bob, &outofband.EventOptions{Label: bob})

	err := b.oobSdk.ApproveDIDExchangeRequest(router)
	if err != nil {
		return fmt.Errorf("%s failed to approve didexchange request : %w", router, err)
	}

	err = b.oobSdk.ConfirmConnections(router, bob, "completed")
	if err != nil {
		return fmt.Errorf("failed to confirm connection status between %s and %s : %w", router, bob, err)
	}

	return nil
}

func (b *BDDSteps) routerConfirmsCodeAndApprovesRequest(router string) error {
	event, err := b.routeSdk.GetEventReceived(b.redeemableCode, timeout)
	if err != nil {
		return err
	}

	request := &routeClient.Request{}

	err = event.Message.Decode(request)
	if err != nil {
		return err
	}

	if request.ID != b.redeemableCode {
		return fmt.Errorf("request received does not contain the redeemable routing code %s", b.redeemableCode)
	}

	b.routeSdk.ApproveRequest(router, b.redeemableOpts)

	return nil
}

func (b *BDDSteps) bobConfirmsGrant(bob, serviceEndpoint, routingKey string) error {
	config, err := b.routeSdk.GetRoutingConfig(bob, timeout)
	if err != nil {
		return err
	}

	if b.redeemableOpts.ServiceEndpoint != config.Endpoint() {
		return fmt.Errorf(
			"routing config mismatch: %s expected serviceEndpoint %s but got %s",
			bob, b.redeemableOpts.ServiceEndpoint, config.Endpoint())
	}

	for i, k := range b.redeemableOpts.RoutingKeys {
		if config.Keys()[i] != k {
			return fmt.Errorf(
				"routing config mismatch: %s expected routingKeys %+v but got %+v",
				bob, b.redeemableOpts.RoutingKeys, config.Keys())
		}
	}

	return nil
}

func (b *BDDSteps) createIntroduceClients(agents ...string) error {
	for _, agent := range agents {
		client, err := introClient.New(b.context.AgentCtx[agent])
		if err != nil {
			return fmt.Errorf("failed to create introduce client for %s : %w", agent, err)
		}

		actions := make(chan service.DIDCommAction)

		err = client.RegisterActionEvent(actions)
		if err != nil {
			return fmt.Errorf("failed to register %s for introduce action events : %w", agent, err)
		}

		b.introClients[agent] = client
		b.introEvents[agent] = make(chan service.DIDCommAction)
		b.introApprovals[agent] = make(chan interface{})

		go listenForIntroduceEvents(b.introApprovals[agent], actions, b.introEvents[agent])
	}

	return nil
}

func listenForIntroduceEvents(approvals chan interface{}, events, listen chan service.DIDCommAction) {
	for event := range events {
		go func() { listen <- event }()
		event.Continue(<-approvals)
	}
}

func (b *BDDSteps) getConnection(agentA, agentB string) (*didexchange.Connection, error) {
	connections, err := b.context.DIDExchangeClients[agentA].QueryConnections(&didexchange.QueryConnectionsParams{})
	if err != nil {
		return nil, err
	}

	for i := range connections {
		if connections[i].TheirLabel == agentB {
			return connections[i], nil
		}
	}

	return nil, fmt.Errorf("no connection between %s and %s", agentA, agentB)
}
