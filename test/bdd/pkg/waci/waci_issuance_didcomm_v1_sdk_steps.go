/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package waci

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/cucumber/godog"
	"github.com/google/uuid"

	didexClient "github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	issuecredentialclient "github.com/hyperledger/aries-framework-go/pkg/client/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/doc/cm"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	bddDIDExchange "github.com/hyperledger/aries-framework-go/test/bdd/pkg/didexchange"
)

// TODO (#3143) Refactor these tests to reduce code duplication between the V1 and V2 tests.

var (
	//nolint: gochecknoglobals // logger
	loggerDIDCommV1Tests = log.New("aries-framework-go/waci-issuance-didcomm-v1")
	//nolint: gochecknoglobals // logger
	loggerDIDCommV2Tests = log.New("aries-framework-go/waci-issuance-didcomm-v2")
)

const timeBetweenGetConnectionRetries = time.Millisecond * 10

// IssuanceSDKDIDCommV1Steps contains steps for WACI issuance tests using the SDK binding with DIDComm V1.
type IssuanceSDKDIDCommV1Steps struct {
	context                            *context.BDDContext
	nextAction                         map[string]chan interface{}
	bddDIDExchSDK                      *bddDIDExchange.SDKSteps
	connectionIDs                      map[string]string
	pendingInvitations                 map[string]*outofband.Invitation
	issueCredentialClients             map[string]*issuecredentialclient.Client
	issueCredentialActions             map[string]chan service.DIDCommAction
	issueCredentialEvents              map[string]chan service.StateMsg
	credentialManifestReceivedByHolder *cm.CredentialManifest
}

// NewIssuanceDIDCommV1SDKSteps returns the WACI issuance's BDD steps using the SDK binding with DIDComm V1.
func NewIssuanceDIDCommV1SDKSteps() *IssuanceSDKDIDCommV1Steps {
	return &IssuanceSDKDIDCommV1Steps{
		connectionIDs:          make(map[string]string),
		bddDIDExchSDK:          bddDIDExchange.NewDIDExchangeSDKSteps(),
		nextAction:             make(map[string]chan interface{}),
		pendingInvitations:     make(map[string]*outofband.Invitation),
		issueCredentialClients: make(map[string]*issuecredentialclient.Client),
		issueCredentialActions: make(map[string]chan service.DIDCommAction),
		issueCredentialEvents:  make(map[string]chan service.StateMsg),
	}
}

// SetContext is called before every scenario is run with a fresh context.
func (i *IssuanceSDKDIDCommV1Steps) SetContext(ctx *context.BDDContext) {
	i.context = ctx
	i.bddDIDExchSDK = bddDIDExchange.NewDIDExchangeSDKSteps()
	i.bddDIDExchSDK.SetContext(ctx)
}

// RegisterSteps registers the BDD test steps on the suite.
// Note that VC proofs are not checked in this test suite.
func (i *IssuanceSDKDIDCommV1Steps) RegisterSteps(suite *godog.Suite) {
	suite.Step(`^"([^"]*)" creates an out-of-band-v1 invitation with streamlined-vc goal-code$`,
		i.createOOBV1WithStreamlinedVCGoalCode)
	suite.Step(`^"([^"]*)" sends the out-of-band-v1 invitation to "([^"]*)" and they accept it$`,
		i.acceptOOBV1Invitation)
	suite.Step(`^"([^"]*)" sends proposal credential V2 to the "([^"]*)" \(WACI, DIDComm V1\)$`,
		i.sendsProposalV2)
	suite.Step(`^"([^"]*)" accepts a proposal V2 and sends an offer to the Holder \(WACI, DIDComm V1\)$`,
		i.acceptProposalV2)
	suite.Step(`^"([^"]*)" accepts the offer and sends a Credential Application to the Issuer \(DIDComm V1\)$`,
		i.acceptOffer)
	suite.Step(`^"([^"]*)" accepts the Credential Application and sends a credential to the Holder \(DIDComm V1\)$`,
		i.acceptCredentialApplication)
	suite.Step(`^"([^"]*)" accepts the credential \(DIDComm V1\)$`, i.acceptCredential)
	suite.Step(`^Holder checks that the expected credential was received in a Credential `+
		`Fulfillment attachment \(DIDComm V1\)$`, i.checkCredential)
}

func (i *IssuanceSDKDIDCommV1Steps) createOOBV1WithStreamlinedVCGoalCode(issuerName string) error {
	err := i.registerClients(issuerName)
	if err != nil {
		return fmt.Errorf("failed to register outofband client: %w", err)
	}

	inv, err := i.newInvitation(issuerName)
	if err != nil {
		return err
	}

	i.pendingInvitations[issuerName] = inv

	return nil
}

//nolint:gocyclo // To be refactored in #3143
func (i *IssuanceSDKDIDCommV1Steps) acceptOOBV1Invitation(issuerName, holderName string) error {
	err := i.registerClients(holderName)
	if err != nil {
		return fmt.Errorf("failed to register framework clients: %w", err)
	}

	holderOOBV1Client, err := outofband.New(i.context.AgentCtx[holderName])
	if err != nil {
		return fmt.Errorf("failed to create an OOB V2 client for %s: %w", issuerName, err)
	}

	states := make(chan service.StateMsg)

	err = i.context.DIDExchangeClients[issuerName].RegisterMsgEvent(states)
	if err != nil {
		return err
	}

	i.connectionIDs[holderName], err =
		holderOOBV1Client.AcceptInvitation(i.pendingInvitations[issuerName], holderName)
	if err != nil {
		return fmt.Errorf("%s failed to accept out-of-band invitation: %w", holderName, err)
	}

	var event service.StateMsg

	select {
	case event = <-states:
		err = i.context.DIDExchangeClients[issuerName].UnregisterMsgEvent(states)
		if err != nil {
			return err
		}
	case <-time.After(time.Second):
		return fmt.Errorf("'%s' timed out waiting for state events", issuerName)
	}

	conn, err := i.context.DIDExchangeClients[issuerName].GetConnection(event.Properties.All()["connectionID"].(string))
	if err != nil {
		return err
	}

	if strings.TrimSpace(conn.TheirLabel) == "" {
		return errors.New("their label is empty")
	}

	err = i.bddDIDExchSDK.ApproveRequest(issuerName)
	if err != nil {
		return fmt.Errorf("failed to approve invitation for %s: %w", issuerName, err)
	}

	return nil
}

func (i *IssuanceSDKDIDCommV1Steps) sendsProposalV2(holderName, issuerName string) error {
	proposeCredentialMsg := issuecredentialclient.ProposeCredential{
		Type:         issuecredential.ProposeCredentialMsgTypeV2,
		ID:           uuid.New().String(),
		InvitationID: i.pendingInvitations[issuerName].ID,
	}

	connection, err := i.getConnection(holderName, issuerName)
	if err != nil {
		return err
	}

	piid, err := i.issueCredentialClients[holderName].SendProposal(&proposeCredentialMsg, connection.Record)
	if err != nil {
		return fmt.Errorf("failed to send proposal: %w", err)
	}

	if piid == "" {
		return errors.New("piid is empty")
	}

	return nil
}

func (i *IssuanceSDKDIDCommV1Steps) acceptProposalV2(issuerName string) error {
	piid, invitationID, err := i.getActionIDAndInvitationID(issuerName)
	if err != nil {
		return err
	}

	if i.pendingInvitations[issuerName].ID != invitationID {
		return fmt.Errorf("expected the Propose Credential's invitation ID to match the "+
			"original invitation ID (%s) but got %s instead", i.pendingInvitations[issuerName].ID, invitationID)
	}

	offerCredential, err := generateOfferCredentialV2Msg()
	if err != nil {
		return err
	}

	err = i.issueCredentialClients[issuerName].AcceptProposal(piid, offerCredential)
	if err != nil {
		return err
	}

	return nil
}

func (i *IssuanceSDKDIDCommV1Steps) acceptOffer(holderName string) error {
	piid, attachmentsFromOfferMsg, err := i.getActionIDAndAttachments(holderName, "offers~attach")
	if err != nil {
		return err
	}

	err = i.checkAttachments(attachmentsFromOfferMsg)
	if err != nil {
		return err
	}

	requestCredential, err := generateRequestCredentialMsgV2(i.credentialManifestReceivedByHolder)
	if err != nil {
		return err
	}

	err = i.issueCredentialClients[holderName].AcceptOffer(piid, requestCredential)
	if err != nil {
		return err
	}

	return nil
}

func (i *IssuanceSDKDIDCommV1Steps) acceptCredentialApplication(issuerName string) error {
	piid, attachmentsFromApplicationMsg, err := i.getActionIDAndAttachments(issuerName, "requests~attach")
	if err != nil {
		return err
	}

	// In a real flow, the issuer would want to check the proofs in the VC sent from the Holder.
	credentialApplicationBytes, err := getCredentialApplicationFromAttachment(&attachmentsFromApplicationMsg[0])
	if err != nil {
		return err
	}

	credentialManifest, err := generateCredentialManifest()
	if err != nil {
		return err
	}

	_, err = cm.UnmarshalAndValidateAgainstCredentialManifest(credentialApplicationBytes, credentialManifest)
	if err != nil {
		return err
	}

	issueCredentialMsg, err := generateIssueCredentialMsgV2()
	if err != nil {
		return err
	}

	err = i.issueCredentialClients[issuerName].AcceptRequest(piid, issueCredentialMsg)
	if err != nil {
		return err
	}

	return nil
}

func (i *IssuanceSDKDIDCommV1Steps) acceptCredential(holderName string) error {
	piid, err := i.getActionID(holderName)
	if err != nil {
		return err
	}

	err = i.issueCredentialClients[holderName].AcceptCredential(piid, issuecredentialclient.AcceptBySkippingStorage())
	if err != nil {
		return err
	}

	return nil
}

func (i *IssuanceSDKDIDCommV1Steps) checkCredential() error {
	credentialFulfillmentAttachment, err := i.getCredentialFulfillmentAttachment()
	if err != nil {
		return err
	}

	vc, err := getVCFromCredentialFulfillmentAttachment(&credentialFulfillmentAttachment)
	if err != nil {
		return err
	}

	if vc.ID != expectedVCID {
		return fmt.Errorf("expected VC ID to be %s but got %s instead", expectedVCID, vc.ID)
	}

	// TODO #3144 - Remove this time.Sleep call once the listener handler error issue is resolved.
	loggerDIDCommV1Tests.Infof("Waiting one second for Aries agents to finish internal operations. " +
		"(TODO #3144 - remove the need for this delay)")
	time.Sleep(time.Second)

	return nil
}

func (i *IssuanceSDKDIDCommV1Steps) getCredentialFulfillmentAttachment() (decorator.GenericAttachment, error) {
	for {
		select {
		case msg := <-i.issueCredentialEvents["Holder"]:
			if msg.StateID == "done" {
				attachment, err := getAttachmentFromDIDCommMsgV2(msg.Msg)
				if err != nil {
					return decorator.GenericAttachment{}, err
				}

				return attachment, nil
			}
		case <-time.After(timeoutDuration):
			return decorator.GenericAttachment{}, errors.New("timeout")
		}
	}
}

func (i *IssuanceSDKDIDCommV1Steps) getActionID(agent string) (string, error) {
	select {
	case action := <-i.issueCredentialActions[agent]:
		err := checkProperties(action)
		if err != nil {
			return "", fmt.Errorf("check properties: %w", err)
		}

		return action.Properties.All()["piid"].(string), nil
	case <-time.After(timeoutDuration):
		return "", errors.New("timeout")
	}
}

func (i *IssuanceSDKDIDCommV1Steps) checkAttachments(attachmentsFromOfferMsg []decorator.GenericAttachment) error {
	credentialManifest, err := getCredentialManifestFromAttachment(&attachmentsFromOfferMsg[0])
	if err != nil {
		return err
	}

	i.credentialManifestReceivedByHolder = credentialManifest

	expectedCredentialManifestID := "dcc75a16-19f5-4273-84ce-4da69ee2b7fe"

	if credentialManifest.ID != expectedCredentialManifestID {
		return fmt.Errorf("expected credential manifest ID to be %s, but got %s instead",
			expectedCredentialManifestID, credentialManifest.ID)
	}

	// The Credential Fulfillment we receive from the issuer acts as a preview for the credentials we eventually
	// wish to receive.
	credentialFulfillment, err := getCredentialFulfillmentFromAttachment(&attachmentsFromOfferMsg[1])
	if err != nil {
		return err
	}

	if credentialFulfillment.ManifestID != expectedCredentialManifestID {
		return fmt.Errorf("expected credential fulfillment's manifest ID to be %s, but got %s instead",
			expectedCredentialManifestID, credentialFulfillment.ManifestID)
	}

	documentLoader, err := createDocumentLoader()
	if err != nil {
		return err
	}

	// These VCs are only previews - they lack proofs.
	vcs, err := credentialFulfillment.ResolveDescriptorMaps(attachmentsFromOfferMsg[1].Data.JSON,
		verifiable.WithJSONLDDocumentLoader(documentLoader))
	if err != nil {
		return err
	}

	if len(vcs) != 1 {
		return fmt.Errorf("received %d VCs, but expected only one", len(vcs))
	}

	if vcs[0].ID != expectedVCID {
		return fmt.Errorf("expected VC ID to be %s but got %s instead", expectedVCID, vcs[0].ID)
	}

	return nil
}

func (i *IssuanceSDKDIDCommV1Steps) getActionIDAndAttachments(agent,
	fieldName string) (string, []decorator.GenericAttachment, error) {
	select {
	case action := <-i.issueCredentialActions[agent]:
		err := checkProperties(action)
		if err != nil {
			return "", nil, fmt.Errorf("check properties: %w", err)
		}

		var attachments []decorator.GenericAttachment

		attachments, err = getAttachmentsV2(action, fieldName)
		if err != nil {
			return "", nil, err
		}

		return action.Properties.All()["piid"].(string), attachments, nil
	case <-time.After(timeoutDuration):
		return "", nil, errors.New("timeout")
	}
}

func (i *IssuanceSDKDIDCommV1Steps) getActionIDAndInvitationID(agent string) (string, string, error) {
	select {
	case action := <-i.issueCredentialActions[agent]:
		err := checkProperties(action)
		if err != nil {
			return "", "", fmt.Errorf("check properties: %w", err)
		}

		invitationID, err := getInvitationID(action)
		if err != nil {
			return "", "", err
		}

		return action.Properties.All()["piid"].(string), invitationID, nil
	case <-time.After(timeoutDuration):
		return "", "", errors.New("timeout")
	}
}

func (i *IssuanceSDKDIDCommV1Steps) getConnection(from, to string) (*didexClient.Connection, error) {
	var foundConnection *didexClient.Connection

	// It can take some time before the DID actually gets saved from a previous step,
	// so we retry if record is found but the "to" DID is missing.
	maxRetries := 9
	attemptCount := 0

	err := backoff.Retry(func() error {
		attemptCount++

		connections, err := i.context.DIDExchangeClients[from].QueryConnections(&didexClient.QueryConnectionsParams{})
		if err != nil {
			return backoff.Permanent(fmt.Errorf("%s failed to fetch their connections: %w", from, err))
		}

		for _, connection := range connections {
			if connection.TheirLabel == to {
				if connection.TheirDID == "" {
					errMsg := fmt.Sprintf(`[from=%s,to=%s] connection record is missing the "to" DID. `+
						`Attempt: %d. Max attempts before giving up: %d`,
						from, to, attemptCount, maxRetries+1)

					loggerDIDCommV1Tests.Infof(errMsg)

					return errors.New(errMsg)
				}
				foundConnection = connection

				return nil
			}
		}

		return backoff.Permanent(fmt.Errorf("no connection %s -> %s", from, to))
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(timeBetweenGetConnectionRetries), uint64(maxRetries)))
	if err != nil {
		return nil, err
	}

	return foundConnection, nil
}

func (i *IssuanceSDKDIDCommV1Steps) registerClients(agentIDs ...string) error {
	for _, agent := range agentIDs {
		err := i.createClients(agent)
		if err != nil {
			return fmt.Errorf("'%s' failed to create an outofband client: %w", agent, err)
		}

		err = i.bddDIDExchSDK.CreateDIDExchangeClient(agent)
		if err != nil {
			return fmt.Errorf("'%s' failed to create new didexchange client: %w", agent, err)
		}

		err = i.createIssueCredentialClient(agent)
		if err != nil {
			return fmt.Errorf("'%s' failed to create new issuecredential client: %w", agent, err)
		}
	}

	return nil
}

func (i *IssuanceSDKDIDCommV1Steps) createIssueCredentialClient(agentID string) error {
	if i.issueCredentialClients[agentID] != nil {
		return nil
	}

	const stateMsgChanSize = 12

	client, err := issuecredentialclient.New(i.context.AgentCtx[agentID])
	if err != nil {
		return err
	}

	i.issueCredentialClients[agentID] = client
	i.issueCredentialActions[agentID] = make(chan service.DIDCommAction, 1)
	i.issueCredentialEvents[agentID] = make(chan service.StateMsg, stateMsgChanSize)

	if err := client.RegisterMsgEvent(i.issueCredentialEvents[agentID]); err != nil {
		return err
	}

	return client.RegisterActionEvent(i.issueCredentialActions[agentID])
}

func (i *IssuanceSDKDIDCommV1Steps) createClients(agents string) error {
	for _, agent := range strings.Split(agents, ",") {
		if _, exists := i.context.OutOfBandClients[agent]; exists {
			continue
		}

		client, err := outofband.New(i.context.AgentCtx[agent])
		if err != nil {
			return fmt.Errorf("failed to create new oob client for %s: %w", agent, err)
		}

		actions := make(chan service.DIDCommAction)

		err = client.RegisterActionEvent(actions)
		if err != nil {
			return fmt.Errorf("failed to register %s to listen for oob action events: %w", agent, err)
		}

		i.context.OutOfBandClients[agent] = client
		i.nextAction[agent] = make(chan interface{})

		go i.autoExecuteActionEvent(agent, actions)
	}

	return nil
}

func (i *IssuanceSDKDIDCommV1Steps) newInvitation(agentID string,
	attachments ...interface{}) (*outofband.Invitation, error) {
	agent, found := i.context.OutOfBandClients[agentID]
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
		outofband.WithAccept("didcomm/v2"),
	}

	inv, err := agent.CreateInvitation(
		nil,
		opts...,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create invitation for %s: %w", agentID, err)
	}

	return inv, nil
}

func (i *IssuanceSDKDIDCommV1Steps) autoExecuteActionEvent(agentID string, ch <-chan service.DIDCommAction) {
	for e := range ch {
		// waits for the signal to approve this event
		e.Continue(<-i.nextAction[agentID])
	}
}

func getAttachmentFromDIDCommMsgV2(didCommMsg service.DIDCommMsg) (decorator.GenericAttachment, error) {
	var didCommMsgAsMap map[string]interface{}

	err := didCommMsg.Decode(&didCommMsgAsMap)
	if err != nil {
		return decorator.GenericAttachment{}, err
	}

	attachmentsRaw, ok := didCommMsgAsMap["credentials~attach"]
	if !ok {
		return decorator.GenericAttachment{}, errors.New("missing attachments from DIDComm message map")
	}

	attachments, ok := attachmentsRaw.([]interface{})
	if !ok {
		return decorator.GenericAttachment{}, errors.New("attachments were not an array of interfaces as expected")
	}

	attachmentRaw := attachments[0]

	attachmentBytes, err := json.Marshal(attachmentRaw)
	if err != nil {
		return decorator.GenericAttachment{}, err
	}

	var attachment decorator.GenericAttachment

	err = json.Unmarshal(attachmentBytes, &attachment)
	if err != nil {
		return decorator.GenericAttachment{}, err
	}

	return attachment, nil
}

func generateIssueCredentialMsgV2() (*issuecredentialclient.IssueCredential, error) {
	cxt := []string{
		"https://www.w3.org/2018/credentials/v1",
		cm.CredentialFulfillmentPresentationContext,
	}

	types := []string{
		"VerifiablePresentation",
		"CredentialFulfillment",
	}

	var credentialFulfillment cm.CredentialFulfillment

	err := json.Unmarshal(credentialFulfillmentDriversLicense, &credentialFulfillment)
	if err != nil {
		return nil, err
	}

	documentLoader, err := createDocumentLoader()
	if err != nil {
		return nil, err
	}

	verifiableCredential, err := verifiable.ParseCredential(vcDriversLicense,
		verifiable.WithJSONLDDocumentLoader(documentLoader), verifiable.WithDisabledProofCheck())
	if err != nil {
		return nil, err
	}

	verifiableCredentials := []*verifiable.Credential{verifiableCredential}

	proof := generateCredentialFulfillmentProof()

	attachmentData := map[string]interface{}{
		"@context":               cxt,
		"type":                   types,
		"credential_fulfillment": credentialFulfillment,
		"verifiableCredential":   verifiableCredentials,
		"proof":                  proof,
	}

	issueCredentialAttachment := decorator.GenericAttachment{
		ID:        uuid.New().String(),
		MediaType: "application/json",
		Format:    cm.CredentialFulfillmentAttachmentFormat,
		Data:      decorator.AttachmentData{JSON: attachmentData},
	}

	attachments := []decorator.GenericAttachment{issueCredentialAttachment}

	issueCredentialMsg := issuecredentialclient.IssueCredential{
		Type:        issuecredential.IssueCredentialMsgTypeV2,
		ID:          uuid.New().String(),
		Attachments: attachments,
	}

	return &issueCredentialMsg, nil
}

func generateRequestCredentialMsgV2(credentialManifest *cm.CredentialManifest) (
	*issuecredentialclient.RequestCredential, error) {
	credentialApplicationAttachment, err := generateCredentialApplicationAttachment(credentialManifest)
	if err != nil {
		return nil, err
	}

	attachments := []decorator.GenericAttachment{*credentialApplicationAttachment}

	requestCredential := issuecredentialclient.RequestCredential{
		Type:        issuecredential.RequestCredentialMsgTypeV2,
		ID:          uuid.New().String(),
		Attachments: attachments,
	}

	return &requestCredential, nil
}

func getAttachmentsV2(action service.DIDCommAction, fieldName string) ([]decorator.GenericAttachment, error) {
	var didCommMsgAsMap map[string]interface{}

	err := action.Message.Decode(&didCommMsgAsMap)
	if err != nil {
		return nil, err
	}

	attachmentsRaw, ok := didCommMsgAsMap[fieldName]
	if !ok {
		return nil, errors.New("missing attachments from DIDComm message map")
	}

	attachmentsAsArrayOfInterfaces, ok := attachmentsRaw.([]interface{})
	if !ok {
		return nil, errors.New("attachments were not an array of interfaces as expected")
	}

	attachmentsBytes, err := json.Marshal(attachmentsAsArrayOfInterfaces)
	if err != nil {
		return nil, err
	}

	var attachments []decorator.GenericAttachment

	err = json.Unmarshal(attachmentsBytes, &attachments)
	if err != nil {
		return nil, err
	}

	return attachments, nil
}

func generateOfferCredentialV2Msg() (*issuecredentialclient.OfferCredential, error) {
	credentialManifestAttachment, err := generateCredentialManifestAttachment()
	if err != nil {
		return nil, err
	}

	// A Credential Fulfillment attachment is sent here as a preview of the VC so the Holder can see what
	// the credential will look like.
	credentialFulfillmentAttachment, err := generateCredentialFulfillmentAttachmentWithoutProof()
	if err != nil {
		return nil, err
	}

	attachments := []decorator.GenericAttachment{*credentialManifestAttachment, *credentialFulfillmentAttachment}

	offerCredential := issuecredentialclient.OfferCredential{
		Type:        issuecredential.OfferCredentialMsgTypeV2,
		ID:          uuid.New().String(),
		Attachments: attachments,
	}

	return &offerCredential, nil
}

func getInvitationID(action service.DIDCommAction) (string, error) {
	var didCommMsgAsMap map[string]interface{}

	err := action.Message.Decode(&didCommMsgAsMap)
	if err != nil {
		return "", err
	}

	invitationID, ok := didCommMsgAsMap["invitationID"]
	if !ok {
		return "", errors.New("missing ID from DIDComm message map")
	}

	return invitationID.(string), nil
}
