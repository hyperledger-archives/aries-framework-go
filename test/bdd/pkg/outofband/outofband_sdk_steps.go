/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"fmt"
	"strings"

	"github.com/cucumber/godog"
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	bddDIDExchange "github.com/hyperledger/aries-framework-go/test/bdd/pkg/didexchange"
)

// SDKSteps for the out-of-band protocol.
type SDKSteps struct {
	context            *context.BDDContext
	pendingRequests    map[string]*outofband.Request
	pendingInvitations map[string]*outofband.Invitation
	connectionIDs      map[string]string
	bddDIDExchSDK      *bddDIDExchange.SDKSteps
	nextAction         map[string]chan struct{}
}

// NewOutOfBandSDKSteps returns the out-of-band protocol's BDD steps using the SDK binding.
func NewOutOfBandSDKSteps() *SDKSteps {
	return &SDKSteps{
		pendingRequests:    make(map[string]*outofband.Request),
		pendingInvitations: make(map[string]*outofband.Invitation),
		connectionIDs:      make(map[string]string),
		bddDIDExchSDK:      bddDIDExchange.NewDIDExchangeSDKSteps(),
		nextAction:         make(map[string]chan struct{}),
	}
}

// SetContext is called before every scenario is run with a fresh new context
func (sdk *SDKSteps) SetContext(ctx *context.BDDContext) {
	sdk.context = ctx
	sdk.bddDIDExchSDK.SetContext(ctx)
}

// RegisterSteps registers the BDD steps on the suite.
func (sdk *SDKSteps) RegisterSteps(suite *godog.Suite) {
	suite.Step(
		`^"([^"]*)" constructs an out-of-band request with no attachments`, sdk.constructOOBRequestWithNoAttachments)
	suite.Step(`^"([^"]*)" constructs an out-of-band invitation`, sdk.constructOOBInvitation)
	suite.Step(
		`^"([^"]*)" sends the request to "([^"]*)" through an out-of-band channel`, sdk.sendRequestThruOOBChannel)
	suite.Step(
		`^"([^"]*)" sends the invitation to "([^"]*)" through an out-of-band channel`, sdk.sendInvitationThruOOBChannel)
	suite.Step(`^"([^"]*)" accepts the request and connects with "([^"]*)"`, sdk.acceptRequestAndConnect)
	suite.Step(`^"([^"]*)" accepts the invitation and connects with "([^"]*)"`, sdk.acceptInvitationAndConnect)
	suite.Step(`^"([^"]*)" and "([^"]*)" confirm their connection is "([^"]*)"`, sdk.confirmConnections)
}

func (sdk *SDKSteps) constructOOBRequestWithNoAttachments(agentID string) error {
	err := sdk.registerClients(agentID)
	if err != nil {
		return fmt.Errorf("failed to register outofband client : %w", err)
	}

	req, err := sdk.newRequest(agentID)
	if err != nil {
		return fmt.Errorf("failed to create an out-of-bound request : %w", err)
	}

	sdk.pendingRequests[agentID] = req

	return nil
}

func (sdk *SDKSteps) constructOOBInvitation(agentID string) error {
	err := sdk.registerClients(agentID)
	if err != nil {
		return fmt.Errorf("failed to register outofband client : %w", err)
	}

	inv, err := sdk.newInvitation(agentID)
	if err != nil {
		return err
	}

	sdk.pendingInvitations[agentID] = inv

	return nil
}

// sends a the sender's pending request to the receiver and returns the sender and receiver's new connection IDs.
func (sdk *SDKSteps) sendRequestThruOOBChannel(senderID, receiverID string) error {
	err := sdk.registerClients([]string{senderID, receiverID}...)
	if err != nil {
		return fmt.Errorf("failed to register framework clients : %w", err)
	}

	req, found := sdk.pendingRequests[senderID]
	if !found {
		return fmt.Errorf("no request found for %s", senderID)
	}

	delete(sdk.pendingRequests, senderID)

	sdk.pendingRequests[receiverID] = req

	return nil
}

func (sdk *SDKSteps) sendInvitationThruOOBChannel(sender, receiver string) error {
	err := sdk.registerClients([]string{sender, receiver}...)
	if err != nil {
		return fmt.Errorf("failed to register framework clients : %w", err)
	}

	inv, found := sdk.pendingInvitations[sender]
	if !found {
		return fmt.Errorf("no invitation found for %s", sender)
	}

	sdk.pendingInvitations[receiver] = inv

	return nil
}

func (sdk *SDKSteps) acceptRequestAndConnect(receiverID, senderID string) error {
	request, found := sdk.pendingRequests[receiverID]
	if !found {
		return fmt.Errorf("no pending requests found for %s", receiverID)
	}

	return sdk.acceptAndConnect(receiverID, senderID, func(r *outofband.Client) error {
		var err error

		sdk.connectionIDs[receiverID], err = r.AcceptRequest(request)
		if err != nil {
			return fmt.Errorf("%s failed to accept out-of-band request : %w", receiverID, err)
		}

		return nil
	})
}

func (sdk *SDKSteps) acceptInvitationAndConnect(receiverID, senderID string) error {
	invitation, found := sdk.pendingInvitations[receiverID]
	if !found {
		return fmt.Errorf("no pending invitations found for %s", receiverID)
	}

	return sdk.acceptAndConnect(receiverID, senderID, func(r *outofband.Client) error {
		var err error

		sdk.connectionIDs[receiverID], err = r.AcceptInvitation(invitation)
		if err != nil {
			return fmt.Errorf("%s failed to accept out-of-band invitation : %w", receiverID, err)
		}

		return nil
	})
}

func (sdk *SDKSteps) acceptAndConnect(
	receiverID, senderID string, accept func(receiver *outofband.Client) error) error {
	receiver, found := sdk.context.OutOfBandClients[receiverID]
	if !found {
		return fmt.Errorf("no registered outofband client for %s", receiverID)
	}

	err := sdk.bddDIDExchSDK.RegisterPostMsgEvent(strings.Join([]string{senderID, receiverID}, ","), "completed")
	if err != nil {
		return fmt.Errorf("failed to register agents for didexchange post msg events : %w", err)
	}

	err = accept(receiver)
	if err != nil {
		return err
	}

	err = sdk.bddDIDExchSDK.ApproveRequest(receiverID)
	if err != nil {
		return fmt.Errorf("failed to approve invitation for %s : %w", senderID, err)
	}

	err = sdk.bddDIDExchSDK.ApproveRequest(senderID)
	if err != nil {
		return fmt.Errorf("failed to approve invitation for %s : %w", senderID, err)
	}

	return nil
}

func (sdk *SDKSteps) confirmConnections(senderID, receiverID, status string) error {
	err := sdk.bddDIDExchSDK.WaitForPostEvent(strings.Join([]string{senderID, receiverID}, ","), status)
	if err != nil {
		return fmt.Errorf("failed to wait for post events : %w", err)
	}

	err = sdk.bddDIDExchSDK.ValidateConnection(senderID, status)
	if err != nil {
		return fmt.Errorf("failed to validate connection status for %s : %w", senderID, err)
	}

	err = sdk.bddDIDExchSDK.ValidateConnection(receiverID, status)
	if err != nil {
		return fmt.Errorf("failed to validate connection status for %s : %w", receiverID, err)
	}

	return nil
}

func (sdk *SDKSteps) registerClients(agentIDs ...string) error {
	for _, agent := range agentIDs {
		if _, exists := sdk.context.OutOfBandClients[agent]; !exists {
			client, err := outofband.New(sdk.context.AgentCtx[agent])
			if err != nil {
				return fmt.Errorf("failed to create new outofband client : %w", err)
			}

			sdk.context.OutOfBandClients[agent] = client
		}

		if _, exists := sdk.context.DIDExchangeClients[agent]; !exists {
			err := sdk.bddDIDExchSDK.CreateDIDExchangeClient(agent)
			if err != nil {
				return fmt.Errorf("failed to create new didexchange client : %w", err)
			}
		}
	}

	return nil
}

func (sdk *SDKSteps) newRequest(agentID string) (*outofband.Request, error) {
	agent, found := sdk.context.OutOfBandClients[agentID]
	if !found {
		return nil, fmt.Errorf("no agent for %s was found", agentID)
	}

	req, err := agent.CreateRequest([]*decorator.Attachment{{
		ID:          uuid.New().String(),
		Description: "dummy",
		MimeType:    "text/plain",
		Data: decorator.AttachmentData{
			JSON: map[string]interface{}{},
		},
	}})
	if err != nil {
		return nil, fmt.Errorf("failed to create request for %s : %w", agentID, err)
	}

	return req, nil
}

func (sdk *SDKSteps) newInvitation(agentID string) (*outofband.Invitation, error) {
	agent, found := sdk.context.OutOfBandClients[agentID]
	if !found {
		return nil, fmt.Errorf("no agent for %s was found", agentID)
	}

	inv, err := agent.CreateInvitation(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create invitation for %s : %w", agentID, err)
	}

	return inv, nil
}

// CreateClients creates out-of-band clients for the given agents.
// 'agents' is a comma-separated string of agent identifiers.
// The out-of-band clients are registered in the BDD context under their respective identifier.
func (sdk *SDKSteps) CreateClients(agents string) error {
	for _, agent := range strings.Split(agents, ",") {
		client, err := outofband.New(sdk.context.AgentCtx[agent])
		if err != nil {
			return fmt.Errorf("failed to create new oob client for %s : %w", agent, err)
		}

		actions := make(chan service.DIDCommAction)

		err = client.RegisterActionEvent(actions)
		if err != nil {
			return fmt.Errorf("failed to register %s to listen for oob action events : %w", agent, err)
		}

		sdk.context.OutOfBandClients[agent] = client
		sdk.nextAction[agent] = make(chan struct{})

		go sdk.autoExecuteActionEvent(agent, actions)
	}

	return nil
}

func (sdk *SDKSteps) autoExecuteActionEvent(agentID string, ch <-chan service.DIDCommAction) {
	for e := range ch {
		// waits for the signal to approve this event
		<-sdk.nextAction[agentID]
		e.Continue(&service.Empty{})
	}
}

// ApproveRequest approves request
func (sdk *SDKSteps) ApproveRequest(agentID string) {
	// sends the signal which automatically handles events
	sdk.nextAction[agentID] <- struct{}{}
}

// CreateRequestWithDID creates an out-of-band request message and sets its 'service' to a single
// entry containing a public DID registered in the BDD context.
// The request is registered internally.
func (sdk *SDKSteps) CreateRequestWithDID(agent string) error {
	did, found := sdk.context.PublicDIDDocs[agent]
	if !found {
		return fmt.Errorf("no public did found for %s", agent)
	}

	client, found := sdk.context.OutOfBandClients[agent]
	if !found {
		return fmt.Errorf("no oob client found for %s", agent)
	}

	req, err := client.CreateRequest(
		[]*decorator.Attachment{{
			ID:          uuid.New().String(),
			Description: "bdd test",
			Data: decorator.AttachmentData{
				JSON: map[string]interface{}{},
			},
		}},
		outofband.WithLabel(agent),
		outofband.WithServices(did.ID),
	)
	if err != nil {
		return fmt.Errorf("failed to create oob request for %s : %w", agent, err)
	}

	sdk.pendingRequests[agent] = req

	return nil
}

// ReceiveRequest makes 'to' accept a pre-registered out-of-band request created by 'from'.
func (sdk *SDKSteps) ReceiveRequest(to, from string) error {
	req, found := sdk.pendingRequests[from]
	if !found {
		return fmt.Errorf("%s does not have a pending request", from)
	}

	receiver, found := sdk.context.OutOfBandClients[to]
	if !found {
		return fmt.Errorf("%s does not have a registered oob client", to)
	}

	connID, err := receiver.AcceptRequest(req)
	if err != nil {
		return fmt.Errorf("%s failed to accept request from %s : %w", to, from, err)
	}

	sdk.connectionIDs[to] = connID

	return nil
}
