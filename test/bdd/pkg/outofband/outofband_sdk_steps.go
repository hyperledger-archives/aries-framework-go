/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/google/uuid"

	didexClient "github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofbandv2"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	oobv2 "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofbandv2"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	bddDIDExchange "github.com/hyperledger/aries-framework-go/test/bdd/pkg/didexchange"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/didresolver"
	bddIssueCred "github.com/hyperledger/aries-framework-go/test/bdd/pkg/issuecredential"
)

// SDKSteps for the out-of-band protocol.
type SDKSteps struct {
	context            *context.BDDContext
	pendingInvitations map[string]*outofband.Invitation
	pendingV2Invites   map[string]*oobv2.Invitation
	connectionIDs      map[string]string
	bddDIDExchSDK      *bddDIDExchange.SDKSteps
	bddIssueCredSDK    *bddIssueCred.SDKSteps
	nextAction         map[string]chan interface{}
	credName           string
	accept             string
}

// NewOutOfBandSDKSteps returns the out-of-band protocol's BDD steps using the SDK binding.
func NewOutOfBandSDKSteps() *SDKSteps {
	return &SDKSteps{
		pendingInvitations: make(map[string]*outofband.Invitation),
		pendingV2Invites:   make(map[string]*oobv2.Invitation),
		connectionIDs:      make(map[string]string),
		bddDIDExchSDK:      bddDIDExchange.NewDIDExchangeSDKSteps(),
		bddIssueCredSDK:    bddIssueCred.NewIssueCredentialSDKSteps(),
		nextAction:         make(map[string]chan interface{}),
	}
}

// SetContext is called before every scenario is run with a fresh new context.
func (sdk *SDKSteps) SetContext(ctx *context.BDDContext) {
	sdk.context = ctx
	sdk.bddDIDExchSDK = bddDIDExchange.NewDIDExchangeSDKSteps()
	sdk.bddDIDExchSDK.SetContext(ctx)
	sdk.bddIssueCredSDK = bddIssueCred.NewIssueCredentialSDKSteps()
	sdk.bddIssueCredSDK.SetContext(ctx)
}

func (sdk *SDKSteps) scenario(accept string) error {
	sdk.accept = accept

	return nil
}

// RegisterSteps registers the BDD steps on the suite.
func (sdk *SDKSteps) RegisterSteps(suite *godog.Suite) {
	suite.Step(`^"([^"]*)" creates an out-of-band invitation$`, sdk.createOOBInvitation)
	suite.Step(`^options ""([^"]*)""$`, sdk.scenario)
	suite.Step(
		`^"([^"]*)" sends the invitation to "([^"]*)" through an out-of-band channel$`, sdk.sendInvitationThruOOBChannel)
	suite.Step(`^"([^"]*)" accepts the invitation and connects with "([^"]*)"$`, sdk.acceptInvitationAndConnect)
	suite.Step(`^"([^"]*)" and "([^"]*)" confirm their connection is "([^"]*)"$`, sdk.ConfirmConnections)
	suite.Step(`^"([^"]*)" creates an out-of-band invitation with a public DID$`, sdk.createOOBInvitationWithPubDID)
	suite.Step(`^"([^"]*)" connects with "([^"]*)" using the invitation$`, sdk.connectAndConfirmConnection)
	suite.Step(`^"([^"]*)" creates another out-of-band invitation with the same public DID$`, sdk.CreateInvitationWithDID)
	suite.Step(`^"([^"]*)" accepts the invitation from "([^"]*)" and both agents opt to reuse their connections$`,
		sdk.acceptInvitationAndConnectWithReuse)
	suite.Step(`^"([^"]*)" and "([^"]*)" confirm they reused their connections$`, sdk.confirmConnectionReuse)
	suite.Step(`^"([^"]*)" creates an out-of-band invitation with an attached offer-credential message$`,
		sdk.createOOBInvitationWithOfferCredential)
	suite.Step(`^"([^"]*)" accepts the offer-credential message from "([^"]*)"$`, sdk.acceptCredentialOffer)
	suite.Step(`^"([^"]*)" is issued the credential$`, sdk.confirmCredentialReceived)
	suite.Step(
		`^"([^"]*)" creates another out-of-band invitation with the same public DID and an attached `+
			`offer-credential message$`, sdk.createOOBInvitationReusePubDIDAndOfferCredential)
	suite.Step(`^"([^"]*)" creates an out-of-band-v2 invitation with embedded present proof v3 request`+
		` as target service$`, sdk.createOOBV2WithPresentProof)
	suite.Step(`^"([^"]*)" sends the request to "([^"]*)" and he accepts it by processing both OOBv2 and the `+
		`embedded present proof v3 request$`, sdk.acceptOOBV2Invitation)
}

func (sdk *SDKSteps) createOOBInvitation(agentID string) error {
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

func (sdk *SDKSteps) createOOBInvitationWithPubDID(agentID string) error {
	err := sdk.registerClients(agentID)
	if err != nil {
		return fmt.Errorf("'%s' failed to create an OOB client: %w", agentID, err)
	}

	err = didresolver.CreateDIDDocument(sdk.context, agentID, "")
	if err != nil {
		return fmt.Errorf("'%s' failed to create a public DID: %w", agentID, err)
	}

	err = sdk.bddDIDExchSDK.WaitForPublicDID(agentID, 10)
	if err != nil {
		return fmt.Errorf("'%s' timed out waiting for their public DID to be ready: %w", agentID, err)
	}

	err = sdk.CreateInvitationWithDID(agentID)
	if err != nil {
		return fmt.Errorf("'%s' failed to create invitation with public DID: %w", agentID, err)
	}

	return nil
}

func (sdk *SDKSteps) createOOBInvitationWithOfferCredential(agent string) error {
	err := sdk.registerClients(agent)
	if err != nil {
		return fmt.Errorf("'%s' failed to register oob client: %w", agent, err)
	}

	inv, err := sdk.newInvitation(agent, &issuecredential.OfferCredentialV2{
		Type:    issuecredential.OfferCredentialMsgTypeV2,
		Comment: "test",
	})
	if err != nil {
		return fmt.Errorf("'%s' failed to create invitation: %w", agent, err)
	}

	sdk.pendingInvitations[agent] = inv

	return nil
}

func (sdk *SDKSteps) createOOBInvitationReusePubDIDAndOfferCredential(agent string) error {
	err := sdk.registerClients(agent)
	if err != nil {
		return fmt.Errorf("'%s' failed to create an OOB client: %w", agent, err)
	}

	did, found := sdk.context.PublicDIDDocs[agent]
	if !found {
		return fmt.Errorf("no public did found for %s", agent)
	}

	client, found := sdk.context.OutOfBandClients[agent]
	if !found {
		return fmt.Errorf("no oob client found for %s", agent)
	}

	inv, err := client.CreateInvitation(
		[]interface{}{did.ID},
		outofband.WithLabel(agent),
		outofband.WithAttachments(&decorator.Attachment{
			ID:       uuid.New().String(),
			MimeType: "application/json",
			Data: decorator.AttachmentData{
				JSON: &issuecredential.OfferCredentialV2{
					Type:    issuecredential.OfferCredentialMsgTypeV2,
					Comment: "test",
				},
			},
		}),
	)
	if err != nil {
		return fmt.Errorf("failed to create oob invitation for %s : %w", agent, err)
	}

	sdk.pendingInvitations[agent] = inv

	return nil
}

func (sdk *SDKSteps) acceptCredentialOffer(holder, issuer string) error {
	err := sdk.bddIssueCredSDK.AcceptOffer(holder)
	if err != nil {
		return fmt.Errorf("'%s' failed to accept credential offer: %w", holder, err)
	}

	err = sdk.bddIssueCredSDK.AcceptRequest(issuer)
	if err != nil {
		return fmt.Errorf("'%s' failed to accept the request for credential: %w", issuer, err)
	}

	sdk.credName = uuid.New().String()

	err = sdk.bddIssueCredSDK.AcceptCredential(holder, sdk.credName, false)
	if err != nil {
		return fmt.Errorf("'%s' failed to accept the credential: %w", holder, err)
	}

	return nil
}

func (sdk *SDKSteps) confirmCredentialReceived(holder string) error {
	err := sdk.bddIssueCredSDK.CheckCredential(holder, sdk.credName)
	if err != nil {
		return fmt.Errorf(
			"'%s' failed to confirm they are holding a credential with name '%s': %w",
			holder, sdk.credName, err,
		)
	}

	return nil
}

func (sdk *SDKSteps) sendInvitationThruOOBChannel(sender, receiver string) error {
	err := sdk.registerClients(sender, receiver)
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

func (sdk *SDKSteps) connectAndConfirmConnection(receiver, sender string) error {
	err := sdk.registerClients(receiver, sender)
	if err != nil {
		return fmt.Errorf("'%s' and '%s' failed to create an OOB client: %w", receiver, sender, err)
	}

	err = sdk.sendInvitationThruOOBChannel(sender, receiver)
	if err != nil {
		return fmt.Errorf("'%s' failed to send invitation to '%s': %w", sender, receiver, err)
	}

	err = sdk.acceptInvitationAndConnect(receiver, sender)
	if err != nil {
		return fmt.Errorf("'%s' and '%s' failed to connect: %w", receiver, sender, err)
	}

	err = sdk.ConfirmConnections(sender, receiver, "completed")
	if err != nil {
		return fmt.Errorf(
			"failed to confirm status 'completed' for connection b/w '%s' and '%s': %w",
			receiver, sender, err,
		)
	}

	return nil
}

func (sdk *SDKSteps) acceptInvitationAndConnect(receiverID, senderID string) error {
	invitation, found := sdk.pendingInvitations[receiverID]
	if !found {
		return fmt.Errorf("no pending invitations found for %s", receiverID)
	}

	return sdk.acceptAndConnect(receiverID, senderID, func(client *outofband.Client) error {
		var err error

		sdk.connectionIDs[receiverID], err = client.AcceptInvitation(invitation, receiverID)
		if err != nil {
			return fmt.Errorf("%s failed to accept out-of-band invitation : %w", receiverID, err)
		}

		return nil
	})
}

func (sdk *SDKSteps) acceptInvitationAndConnectWithReuse(receiver, sender string) error {
	invitation, found := sdk.pendingInvitations[receiver]
	if !found {
		return fmt.Errorf("no pending invitations found for %s", receiver)
	}

	var pubDID string

	for i := range invitation.Services {
		if s, ok := invitation.Services[i].(string); ok {
			pubDID = s

			break
		}
	}

	if pubDID == "" {
		return fmt.Errorf("no public DID in the invitation from '%s'", sender)
	}

	var err error

	sdk.connectionIDs[receiver], err = sdk.context.OutOfBandClients[receiver].AcceptInvitation(
		invitation,
		receiver,
		outofband.ReuseConnection(pubDID),
	)
	if err != nil {
		return fmt.Errorf("%s failed to accept out-of-band invitation : %w", receiver, err)
	}

	sdk.ApproveHandshakeReuse(sender, nil)

	return nil
}

func (sdk *SDKSteps) acceptAndConnect( // nolint:gocyclo
	receiverID, senderID string, accept func(receiver *outofband.Client) error) error {
	receiver, found := sdk.context.OutOfBandClients[receiverID]
	if !found {
		return fmt.Errorf("no registered outofband client for %s", receiverID)
	}

	err := sdk.bddDIDExchSDK.RegisterPostMsgEvent(strings.Join([]string{senderID, receiverID}, ","), "completed")
	if err != nil {
		return fmt.Errorf("failed to register agents for didexchange post msg events : %w", err)
	}

	states := make(chan service.StateMsg)

	err = sdk.context.DIDExchangeClients[senderID].RegisterMsgEvent(states)
	if err != nil {
		return err
	}

	err = accept(receiver)
	if err != nil {
		return fmt.Errorf("failed to accept invite: %w", err)
	}

	var event service.StateMsg

	select {
	case event = <-states:
		err = sdk.context.DIDExchangeClients[senderID].UnregisterMsgEvent(states)
		if err != nil {
			return err
		}
	case <-time.After(time.Second):
		return fmt.Errorf("'%s' timed out waiting for state events", senderID)
	}

	conn, err := sdk.context.DIDExchangeClients[senderID].GetConnection(event.Properties.All()["connectionID"].(string))
	if err != nil {
		return err
	}

	if strings.TrimSpace(conn.TheirLabel) == "" {
		return errors.New("their label is empty")
	}

	err = sdk.bddDIDExchSDK.ApproveRequest(senderID)
	if err != nil {
		return fmt.Errorf("failed to approve invitation for %s : %w", senderID, err)
	}

	return nil
}

// ConfirmConnections confirms the connection between the sender and receiver is at the given status.
func (sdk *SDKSteps) ConfirmConnections(senderID, receiverID, status string) error {
	err := sdk.bddDIDExchSDK.WaitForPostEvent(strings.Join([]string{senderID, receiverID}, ","), status)
	if err != nil {
		return fmt.Errorf("failed to wait for post events : %w", err)
	}

	connSender, err := sdk.GetConnection(senderID, receiverID)
	if err != nil {
		return err
	}

	if connSender.State != status {
		return fmt.Errorf(
			"%s's connection with %s is in state %s but expected %s",
			senderID, receiverID, connSender.State, status,
		)
	}

	connReceiver, err := sdk.GetConnection(receiverID, senderID)
	if err != nil {
		return err
	}

	if connReceiver.State != status {
		return fmt.Errorf(
			"%s's connection with %s is in state %s but expected %s",
			receiverID, senderID, connSender.State, status,
		)
	}

	return nil
}

func (sdk *SDKSteps) confirmConnectionReuse(alice, bob string) error {
	err := sdk.verifyConnectionsCount(alice, bob, 1)
	if err != nil {
		return err
	}

	return sdk.verifyConnectionsCount(bob, alice, 1)
}

func (sdk *SDKSteps) verifyConnectionsCount(agentA, agentB string, expected int) error {
	agentAClient, err := didexClient.New(sdk.context.AgentCtx[agentA])
	if err != nil {
		return fmt.Errorf("failed to create didexchange client for %s: %w", agentA, err)
	}

	records, err := agentAClient.QueryConnections(&didexClient.QueryConnectionsParams{})
	if err != nil {
		return fmt.Errorf("failed to fetch %s'sconnection records: %w", agentA, err)
	}

	count := 0

	for i := range records {
		r := records[i]

		if r.TheirLabel == agentB {
			count++
		}
	}

	if count != expected {
		return fmt.Errorf("'%s' expected %d connection record with '%s' but has %d", agentA, expected, agentB, count)
	}

	return nil
}

// GetConnection returns connection between agents.
func (sdk *SDKSteps) GetConnection(from, to string) (*didexClient.Connection, error) {
	connections, err := sdk.context.DIDExchangeClients[from].QueryConnections(&didexClient.QueryConnectionsParams{})
	if err != nil {
		return nil, fmt.Errorf("%s failed to fetch their connections : %w", from, err)
	}

	for _, c := range connections {
		if c.TheirLabel == to {
			return c, nil
		}
	}

	return nil, fmt.Errorf("no connection %s -> %s", from, to)
}

func (sdk *SDKSteps) registerClients(agentIDs ...string) error {
	for _, agent := range agentIDs {
		err := sdk.CreateClients(agent)
		if err != nil {
			return fmt.Errorf("'%s' failed to create an outofband client: %w", agent, err)
		}

		err = sdk.bddDIDExchSDK.CreateDIDExchangeClient(agent)
		if err != nil {
			return fmt.Errorf("'%s' failed to create new didexchange client: %w", agent, err)
		}

		err = sdk.bddIssueCredSDK.CreateClient(agent)
		if err != nil {
			return fmt.Errorf("'%s' failed to create new issuecredential client: %w", agent, err)
		}
	}

	return nil
}

func (sdk *SDKSteps) newInvitation(agentID string, attachments ...interface{}) (*outofband.Invitation, error) {
	agent, found := sdk.context.OutOfBandClients[agentID]
	if !found {
		return nil, fmt.Errorf("no agent for %s was found", agentID)
	}

	var attachDecorators []*decorator.Attachment

	for i := range attachments {
		attachDecorators = append(attachDecorators, &decorator.Attachment{
			ID: uuid.New().String(),
			Data: decorator.AttachmentData{
				JSON: attachments[i],
			},
		})
	}

	opts := []outofband.MessageOption{
		outofband.WithLabel(agentID),
		outofband.WithAttachments(attachDecorators...),
	}

	if sdk.accept != "" {
		opts = append(opts, outofband.WithAccept(sdk.accept))
	}

	inv, err := agent.CreateInvitation(
		nil,
		opts...,
	)
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
		if _, exists := sdk.context.OutOfBandClients[agent]; exists {
			continue
		}

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
		sdk.nextAction[agent] = make(chan interface{})

		go sdk.autoExecuteActionEvent(agent, actions)
	}

	return nil
}

// CreateOOBV2Clients creates out-of-band v2 clients for the given agents.
// 'agents' is a comma-separated string of agent identifiers.
// The out-of-band clients are registered in the BDD context under their respective identifier.
func (sdk *SDKSteps) CreateOOBV2Clients(agents string) error {
	for _, agent := range strings.Split(agents, ",") {
		if _, exists := sdk.context.OutOfBandV2Clients[agent]; exists {
			continue
		}

		clientV2, err := outofbandv2.New(sdk.context.AgentCtx[agent])
		if err != nil {
			return fmt.Errorf("failed to create new oobv2 client for %s : %w", agent, err)
		}

		sdk.context.OutOfBandV2Clients[agent] = clientV2
	}

	return nil
}

func (sdk *SDKSteps) autoExecuteActionEvent(agentID string, ch <-chan service.DIDCommAction) {
	for e := range ch {
		// waits for the signal to approve this event
		e.Continue(<-sdk.nextAction[agentID])
	}
}

// ApproveOOBInvitation approves an out-of-band request for this agent.
func (sdk *SDKSteps) ApproveOOBInvitation(agentID string, args interface{}) {
	// sends the signal which automatically handles events
	sdk.nextAction[agentID] <- args
}

// ApproveHandshakeReuse makes the given agent approve a handshake-reuse message.
func (sdk *SDKSteps) ApproveHandshakeReuse(agentID string, args interface{}) {
	sdk.nextAction[agentID] <- args
}

// ApproveDIDExchangeRequest approves a didexchange request for this agent.
func (sdk *SDKSteps) ApproveDIDExchangeRequest(agentID string) error {
	return sdk.bddDIDExchSDK.ApproveRequest(agentID)
}

// CreateInvitationWithDID creates an out-of-band request message and sets its 'service' to a single
// entry containing a public DID registered in the BDD context.
// The request is registered internally.
func (sdk *SDKSteps) CreateInvitationWithDID(agent string) error {
	did, found := sdk.context.PublicDIDDocs[agent]
	if !found {
		return fmt.Errorf("no public did found for %s", agent)
	}

	client, found := sdk.context.OutOfBandClients[agent]
	if !found {
		return fmt.Errorf("no oob client found for %s", agent)
	}

	mtps := sdk.context.AgentCtx[agent].MediaTypeProfiles()
	didCommV2 := false

	for _, mtp := range mtps {
		switch mtp {
		case transport.MediaTypeDIDCommV2Profile, transport.MediaTypeAIP2RFC0587Profile:
			didCommV2 = true
		}

		if didCommV2 {
			break
		}
	}

	if !didCommV2 && len(mtps) == 0 {
		mtps = []string{transport.MediaTypeAIP2RFC0019Profile}
	}

	inv, err := client.CreateInvitation(
		[]interface{}{did.ID},
		outofband.WithLabel(agent),
		outofband.WithAccept(mtps...),
	)
	if err != nil {
		return fmt.Errorf("failed to create oob invitation for %s : %w", agent, err)
	}

	sdk.pendingInvitations[agent] = inv

	return nil
}

// ReceiveInvitation makes 'to' accept a pre-registered out-of-band invitation created by 'from'.
func (sdk *SDKSteps) ReceiveInvitation(to, from string) error {
	inv, found := sdk.pendingInvitations[from]
	if !found {
		return fmt.Errorf("%s does not have a pending request", from)
	}

	receiver, found := sdk.context.OutOfBandClients[to]
	if !found {
		return fmt.Errorf("%s does not have a registered oob client", to)
	}

	connID, err := receiver.AcceptInvitation(inv, to)
	if err != nil {
		return fmt.Errorf("%s failed to accept invitation from %s : %w", to, from, err)
	}

	sdk.connectionIDs[to] = connID

	return nil
}

// ConnectAll connects all agents to each other.
// 'agents' is a comma-separated string of agent identifiers.
func (sdk *SDKSteps) ConnectAll(agents string) error {
	err := sdk.CreateClients(agents)
	if err != nil {
		return err
	}

	err = sdk.bddDIDExchSDK.CreateDIDExchangeClient(agents)
	if err != nil {
		return err
	}

	all := strings.Split(agents, ",")

	for i := 0; i < len(all)-1; i++ {
		inviter := all[i]

		err = sdk.createOOBInvitation(inviter)
		if err != nil {
			return err
		}

		for j := i + 1; j < len(all); j++ {
			invitee := all[j]

			// send outofband invitation to invitee
			err = sdk.sendInvitationThruOOBChannel(inviter, invitee)
			if err != nil {
				return err
			}

			// invitee accepts outofband invitation
			err = sdk.acceptInvitationAndConnect(invitee, inviter)
			if err != nil {
				return err
			}

			err = sdk.ConfirmConnections(inviter, invitee, "completed")
			if err != nil {
				return err
			}
		}
	}

	return nil
}

const (
	vpStr = `
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
      "expirationDate": "2025-01-01T19:23:24Z",
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
	ppfGoal     = "present-proof/3.0/request-presentation"
	ppfGoalCode = "https://didcomm.org/present-proof/3.0/request-presentation"
)

func (sdk *SDKSteps) createOOBV2WithPresentProof(agent1 string) error {
	err := sdk.CreateOOBV2Clients(agent1)
	if err != nil {
		return fmt.Errorf("send OOBV2 failed to register %s client: %w", agent1, err)
	}

	oobv2Client1, ok := sdk.context.OutOfBandV2Clients[agent1]
	if !ok {
		return fmt.Errorf("missing oobv2 client for %s", agent1)
	}

	agentDIDDoc, ok := sdk.context.PublicDIDDocs[agent1]
	if !ok {
		return fmt.Errorf("oobv2: missing DID Doc for %s", agent1)
	}

	ppfv3Req := service.NewDIDCommMsgMap(presentproof.PresentationV3{
		Type: presentproof.RequestPresentationMsgTypeV3,
		Attachments: []decorator.AttachmentV2{{
			Data: decorator.AttachmentData{
				Base64: base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(vpStr, agentDIDDoc.ID, agentDIDDoc.ID))),
			},
		}},
	})

	ppfv3Attachment := []*decorator.AttachmentV2{{
		ID:          uuid.New().String(),
		Description: "PresentProof V3 propose presentation request",
		FileName:    "presentproofv3.json",
		MediaType:   "application/json",
		LastModTime: time.Time{},
		Data: decorator.AttachmentData{
			JSON: ppfv3Req,
		},
	}}

	inv, err := oobv2Client1.CreateInvitation(
		outofbandv2.WithGoal(ppfGoal, ppfGoalCode),
		outofbandv2.WithAttachments(ppfv3Attachment...),
		outofbandv2.WithFrom(agentDIDDoc.ID),
	)
	if err != nil {
		return fmt.Errorf("failed to create invitation: %w", err)
	}

	sdk.pendingV2Invites[agent1] = inv

	return nil
}

func (sdk *SDKSteps) acceptOOBV2Invitation(agent1, agent2 string) error {
	err := sdk.CreateOOBV2Clients(agent2)
	if err != nil {
		return fmt.Errorf("send OOBV2 failed to register %s client: %w", agent2, err)
	}

	oobv2Client2, ok := sdk.context.OutOfBandV2Clients[agent2]
	if !ok {
		return fmt.Errorf("missing oobv2 client for %s", agent2)
	}

	inv := sdk.pendingV2Invites[agent1]

	connID, err := oobv2Client2.AcceptInvitation(inv)
	if err != nil {
		return fmt.Errorf("failed to accept oobv2 invitation for %s : %w", agent1, err)
	}

	sdk.context.SaveConnectionID(agent2, agent1, connID)

	return nil
}
