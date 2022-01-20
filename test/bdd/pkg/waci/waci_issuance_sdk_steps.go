/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package waci

import (
	_ "embed" //nolint // This is needed to use go:embed
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cucumber/godog"
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	didexClient "github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	issuecredentialclient "github.com/hyperledger/aries-framework-go/pkg/client/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofbandv2"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	oobv2 "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofbandv2"
	"github.com/hyperledger/aries-framework-go/pkg/doc/cm"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
)

var (
	//go:embed offer_credential_attachments.json
	offerCredentialAttachments []byte //nolint:gochecknoglobals
	//go:embed request_credential_attachments.json
	requestCredentialAttachments []byte //nolint:gochecknoglobals
	//go:embed issue_credential_attachments.json
	issueCredentialAttachments []byte //nolint:gochecknoglobals
)

const (
	waciIssuanceGoalCode = "streamlined-vc"
	stateMsgChanSize     = 12
	timeoutDuration      = time.Second * 5
)

// IssuanceSDKSteps contains steps for WACI issuance tests using the SDK binding.
type IssuanceSDKSteps struct {
	context                       *context.BDDContext
	oobV2InviteFromIssuerToHolder *oobv2.Invitation
	issueCredentialClients        map[string]*issuecredentialclient.Client
	actions                       map[string]chan service.DIDCommAction
	holderEvent                   chan service.StateMsg
}

// NewIssuanceSDKSteps returns the WACI issuance's BDD steps using the SDK binding.
func NewIssuanceSDKSteps() *IssuanceSDKSteps {
	return &IssuanceSDKSteps{
		issueCredentialClients: make(map[string]*issuecredentialclient.Client),
		actions:                make(map[string]chan service.DIDCommAction),
		holderEvent:            make(chan service.StateMsg, stateMsgChanSize),
	}
}

// SetContext is called before every scenario is run with a fresh context.
func (i *IssuanceSDKSteps) SetContext(ctx *context.BDDContext) {
	i.context = ctx
}

// RegisterSteps registers the BDD test steps on the suite.
func (i *IssuanceSDKSteps) RegisterSteps(suite *godog.Suite) {
	suite.Step(`^"([^"]*)" creates an out-of-band-v2 invitation with streamlined-vc goal-code$`,
		i.createOOBV2WithStreamlinedVCGoalCode)
	suite.Step(`^"([^"]*)" sends the request to "([^"]*)" and they accept it$`, i.acceptOOBV2Invitation)
	suite.Step(`^"([^"]*)" sends proposal credential V3 to the "([^"]*)" \(WACI\)$`, i.sendsProposalV3)
	suite.Step(`^"([^"]*)" accepts a proposal V3 and sends an offer to the Holder \(WACI\)$`, i.acceptProposalV3)
	suite.Step(`^"([^"]*)" accepts the offer and sends a Credential Application to the Issuer$`, i.acceptOffer)
	suite.Step(`^"([^"]*)" accepts the Credential Application and sends a credential to the Holder$`,
		i.acceptCredentialApplication)
	suite.Step(`^"([^"]*)" accepts the credential$`, i.acceptCredential)
	suite.Step(`^Holder checks that the expected credential was received in a Credential `+
		`Fulfillment attachment$`, i.checkCredential)
}

func (i *IssuanceSDKSteps) createOOBV2WithStreamlinedVCGoalCode(issuerName string) error {
	issuerOOBV2Client, err := outofbandv2.New(i.context.AgentCtx[issuerName])
	if err != nil {
		return fmt.Errorf("failed to create an OOB V2 client for %s: %w", issuerName, err)
	}

	issuerDIDDoc, ok := i.context.PublicDIDDocs[issuerName]
	if !ok {
		return fmt.Errorf("DID document for %s is unexpectedly missing from the context", issuerName)
	}

	invitation, err := issuerOOBV2Client.CreateInvitation(
		outofbandv2.WithGoal("", waciIssuanceGoalCode),
		outofbandv2.WithAccept("didcomm/v2"),
		outofbandv2.WithFrom(issuerDIDDoc.ID),
		outofbandv2.WithLabel(issuerName),
	)
	if err != nil {
		return fmt.Errorf("failed to create oob invitation for %s: %w", issuerName, err)
	}

	i.oobV2InviteFromIssuerToHolder = invitation

	i.context.OutOfBandV2Clients[issuerName] = issuerOOBV2Client

	return nil
}

func (i *IssuanceSDKSteps) acceptOOBV2Invitation(issuerName, holderName string) error {
	holderOOBV2Client, err := outofbandv2.New(i.context.AgentCtx[holderName])
	if err != nil {
		return fmt.Errorf("failed to create an OOB V2 client for %s: %w", issuerName, err)
	}

	_, err = holderOOBV2Client.AcceptInvitation(i.oobV2InviteFromIssuerToHolder)
	if err != nil {
		return fmt.Errorf("failed to accept OOBV2 invitation from %s to %s : %w", issuerName, holderName, err)
	}

	return nil
}

func (i *IssuanceSDKSteps) sendsProposalV3(holderName, issuerName string) error {
	err := i.createIssueCredentialClients(holderName, issuerName)
	if err != nil {
		return err
	}

	i.createActions(holderName, issuerName)

	err = i.registerActionsAndEvents(holderName, issuerName)
	if err != nil {
		return err
	}

	i.context.DIDExchangeClients[holderName], err = didexClient.New(i.context.AgentCtx[holderName])
	if err != nil {
		return err
	}

	proposeCredentialMsg := issuecredentialclient.ProposeCredential{
		Type:         issuecredential.ProposeCredentialMsgTypeV3,
		ID:           uuid.New().String(),
		InvitationID: i.oobV2InviteFromIssuerToHolder.ID,
	}

	connection, err := i.GetConnection(holderName, issuerName)
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

func (i *IssuanceSDKSteps) acceptProposalV3(issuerName string) error {
	piid, parentThreadID, err := i.getActionIDAndParentThreadID(issuerName)
	if err != nil {
		return err
	}

	if i.oobV2InviteFromIssuerToHolder.ID != parentThreadID {
		return fmt.Errorf("expected message parent thread ID to match the original invitation ID "+
			"(%s) but got %s instead", i.oobV2InviteFromIssuerToHolder.ID, parentThreadID)
	}

	var attachments []decorator.GenericAttachment

	err = json.Unmarshal(offerCredentialAttachments, &attachments)
	if err != nil {
		return err
	}

	offerCredential := issuecredentialclient.OfferCredential{
		Type:        issuecredential.OfferCredentialMsgTypeV3,
		ID:          uuid.New().String(),
		Attachments: attachments,
	}

	err = i.issueCredentialClients[issuerName].AcceptProposal(piid, &offerCredential)
	if err != nil {
		return err
	}

	return nil
}

func (i *IssuanceSDKSteps) acceptOffer(holderName string) error {
	piid, attachmentsFromOfferMsg, err := i.getActionIDAndAttachments(holderName)
	if err != nil {
		return err
	}

	err = i.checkAttachments(attachmentsFromOfferMsg)
	if err != nil {
		return err
	}

	var attachments []decorator.GenericAttachment

	err = json.Unmarshal(requestCredentialAttachments, &attachments)
	if err != nil {
		return err
	}

	requestCredential := issuecredentialclient.RequestCredential{
		Type:        issuecredential.RequestCredentialMsgTypeV3,
		ID:          uuid.New().String(),
		Attachments: attachments,
	}

	err = i.issueCredentialClients[holderName].AcceptOffer(piid, &requestCredential)
	if err != nil {
		return err
	}

	return nil
}

func (i *IssuanceSDKSteps) acceptCredentialApplication(issuerName string) error {
	piid, attachmentsFromApplicationMsg, err := i.getActionIDAndAttachments(issuerName)
	if err != nil {
		return err
	}

	credentialApplicationBytes, err := getCredentialApplicationFromAttachment(&attachmentsFromApplicationMsg[0])
	if err != nil {
		return err
	}

	credentialManifest, err := getExampleCredentialManifest()
	if err != nil {
		return err
	}

	_, err = cm.UnmarshalAndValidateAgainstCredentialManifest(credentialApplicationBytes, credentialManifest)
	if err != nil {
		return err
	}

	var attachments []decorator.GenericAttachment

	err = json.Unmarshal(issueCredentialAttachments, &attachments)
	if err != nil {
		return err
	}

	issueCredential := issuecredentialclient.IssueCredential{
		Type:        issuecredential.RequestCredentialMsgTypeV3,
		ID:          uuid.New().String(),
		Attachments: attachments,
	}

	err = i.issueCredentialClients[issuerName].AcceptRequest(piid, &issueCredential)
	if err != nil {
		return err
	}

	return nil
}

func (i *IssuanceSDKSteps) acceptCredential(holderName string) error {
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

func (i *IssuanceSDKSteps) checkCredential() error {
	credentialFulfillmentAttachment, err := i.getCredentialFulfillmentAttachment()
	if err != nil {
		return err
	}

	vc, err := getVCFromCredentialFulfillmentAttachment(&credentialFulfillmentAttachment)
	if err != nil {
		return err
	}

	expectedVCID := "https://eu.com/claims/DriversLicense"

	if vc.ID != expectedVCID {
		return fmt.Errorf("expected VC ID to be %s but got %s instead", expectedVCID, vc.ID)
	}

	return nil
}

func (i *IssuanceSDKSteps) createIssueCredentialClients(holderName, issuerName string) error {
	issueCredentialClientHolder, err := issuecredentialclient.New(i.context.AgentCtx[holderName])
	if err != nil {
		return err
	}

	issueCredentialClientIssuer, err := issuecredentialclient.New(i.context.AgentCtx[issuerName])
	if err != nil {
		return err
	}

	i.issueCredentialClients[holderName] = issueCredentialClientHolder
	i.issueCredentialClients[issuerName] = issueCredentialClientIssuer

	return nil
}

func (i *IssuanceSDKSteps) createActions(holderName, issuerName string) {
	i.actions[issuerName] = make(chan service.DIDCommAction, 1)
	i.actions[holderName] = make(chan service.DIDCommAction, 1)
}

func (i *IssuanceSDKSteps) registerActionsAndEvents(holderName, issuerName string) error {
	err := i.issueCredentialClients[holderName].RegisterActionEvent(i.actions[holderName])
	if err != nil {
		return err
	}

	err = i.issueCredentialClients[issuerName].RegisterActionEvent(i.actions[issuerName])
	if err != nil {
		return err
	}

	err = i.issueCredentialClients[holderName].RegisterMsgEvent(i.holderEvent)
	if err != nil {
		return err
	}

	return err
}

func (i *IssuanceSDKSteps) getActionID(agent string) (string, error) {
	select {
	case action := <-i.actions[agent]:
		err := checkProperties(action)
		if err != nil {
			return "", fmt.Errorf("check properties: %w", err)
		}

		return action.Properties.All()["piid"].(string), nil
	case <-time.After(timeoutDuration):
		return "", errors.New("timeout")
	}
}

func (i *IssuanceSDKSteps) getActionIDAndParentThreadID(agent string) (string, string, error) {
	select {
	case action := <-i.actions[agent]:
		err := checkProperties(action)
		if err != nil {
			return "", "", fmt.Errorf("check properties: %w", err)
		}

		parentThreadID, err := getParentThreadID(action)
		if err != nil {
			return "", "", err
		}

		return action.Properties.All()["piid"].(string), parentThreadID, nil
	case <-time.After(timeoutDuration):
		return "", "", errors.New("timeout")
	}
}

func (i *IssuanceSDKSteps) getActionIDAndAttachments(agent string) (string, []decorator.GenericAttachment, error) {
	select {
	case action := <-i.actions[agent]:
		err := checkProperties(action)
		if err != nil {
			return "", nil, fmt.Errorf("check properties: %w", err)
		}

		var attachments []decorator.GenericAttachment

		attachments, err = getAttachments(action)
		if err != nil {
			return "", nil, err
		}

		return action.Properties.All()["piid"].(string), attachments, nil
	case <-time.After(timeoutDuration):
		return "", nil, errors.New("timeout")
	}
}

func (i *IssuanceSDKSteps) checkAttachments(attachmentsFromOfferMsg []decorator.GenericAttachment) error {
	credentialManifest, err := getCredentialManifestFromAttachment(&attachmentsFromOfferMsg[0])
	if err != nil {
		return err
	}

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

	expectedVCID := "https://eu.com/claims/DriversLicense"

	if vcs[0].ID != expectedVCID {
		return fmt.Errorf("expected VC ID to be %s but got %s instead", expectedVCID, vcs[0].ID)
	}

	return nil
}

func getCredentialManifestFromAttachment(attachment *decorator.GenericAttachment) (*cm.CredentialManifest, error) {
	attachmentAsMap, ok := attachment.Data.JSON.(map[string]interface{})
	if !ok {
		return nil, errors.New("couldn't assert attachment as a map")
	}

	credentialManifestRaw, ok := attachmentAsMap["credential_manifest"]
	if !ok {
		return nil, errors.New("credential_manifest object missing from attachment")
	}

	credentialManifestBytes, err := json.Marshal(credentialManifestRaw)
	if err != nil {
		return nil, err
	}

	var credentialManifest cm.CredentialManifest

	// This unmarshal call also triggers the credential manifest validation code, which ensures that the
	// credential manifest is valid under the spec.
	err = json.Unmarshal(credentialManifestBytes, &credentialManifest)
	if err != nil {
		return nil, err
	}

	return &credentialManifest, nil
}

func getCredentialFulfillmentFromAttachment(attachment *decorator.GenericAttachment) (*cm.CredentialFulfillment,
	error) {
	attachmentAsMap, ok := attachment.Data.JSON.(map[string]interface{})
	if !ok {
		return nil, errors.New("couldn't assert attachment as a map")
	}

	credentialFulfillmentRaw, ok := attachmentAsMap["credential_fulfillment"]
	if !ok {
		return nil, errors.New("credential_fulfillment object missing from attachment")
	}

	credentialFulfillmentBytes, err := json.Marshal(credentialFulfillmentRaw)
	if err != nil {
		return nil, err
	}

	var credentialFulfillment cm.CredentialFulfillment

	// This unmarshal call also triggers the credential fulfillment validation code, which ensures that the
	// credential fulfillment object is valid under the spec.
	err = json.Unmarshal(credentialFulfillmentBytes, &credentialFulfillment)
	if err != nil {
		return nil, err
	}

	return &credentialFulfillment, nil
}

func getCredentialApplicationFromAttachment(attachment *decorator.GenericAttachment) ([]byte, error) {
	attachmentAsMap, ok := attachment.Data.JSON.(map[string]interface{})
	if !ok {
		return nil, errors.New("couldn't assert attachment as a map")
	}

	credentialApplicationRaw, ok := attachmentAsMap["credential_application"]
	if !ok {
		return nil, errors.New("credential_application object missing from attachment")
	}

	credentialApplicationBytes, err := json.Marshal(credentialApplicationRaw)
	if err != nil {
		return nil, err
	}

	return credentialApplicationBytes, nil
}

func getExampleCredentialManifest() (*cm.CredentialManifest, error) {
	var attachments []decorator.GenericAttachment

	err := json.Unmarshal(offerCredentialAttachments, &attachments)
	if err != nil {
		return nil, err
	}

	credentialManifest, err := getCredentialManifestFromAttachment(&attachments[0])
	if err != nil {
		return nil, err
	}

	return credentialManifest, nil
}

func getVCFromCredentialFulfillmentAttachment(credentialFulfillmentAttachment *decorator.GenericAttachment) (
	verifiable.Credential, error) {
	attachmentRaw := credentialFulfillmentAttachment.Data.JSON

	attachmentAsMap, ok := attachmentRaw.(map[string]interface{})
	if !ok {
		return verifiable.Credential{}, errors.New("couldn't assert attachment as a map")
	}

	credentialFulfillmentRaw, ok := attachmentAsMap["credential_fulfillment"]
	if !ok {
		return verifiable.Credential{}, errors.New("credential_fulfillment object missing from attachment")
	}

	credentialFulfillmentBytes, err := json.Marshal(credentialFulfillmentRaw)
	if err != nil {
		return verifiable.Credential{}, err
	}

	var credentialFulfillment cm.CredentialFulfillment

	err = json.Unmarshal(credentialFulfillmentBytes, &credentialFulfillment)
	if err != nil {
		return verifiable.Credential{}, err
	}

	documentLoader, err := createDocumentLoader()
	if err != nil {
		return verifiable.Credential{}, err
	}

	vcs, err := credentialFulfillment.ResolveDescriptorMaps(credentialFulfillmentAttachment.Data.JSON,
		verifiable.WithDisabledProofCheck(), verifiable.WithJSONLDDocumentLoader(documentLoader))
	if err != nil {
		return verifiable.Credential{}, err
	}

	if len(vcs) != 1 {
		return verifiable.Credential{}, fmt.Errorf("received %d VCs, but expected only one", len(vcs))
	}

	return vcs[0], nil
}

type docLoaderProvider struct {
	ContextStore        ldstore.ContextStore
	RemoteProviderStore ldstore.RemoteProviderStore
}

func (p *docLoaderProvider) JSONLDContextStore() ldstore.ContextStore {
	return p.ContextStore
}

func (p *docLoaderProvider) JSONLDRemoteProviderStore() ldstore.RemoteProviderStore {
	return p.RemoteProviderStore
}

func createDocumentLoader() (*ld.DocumentLoader, error) {
	contextStore, err := ldstore.NewContextStore(mem.NewProvider())
	if err != nil {
		return nil, err
	}

	remoteProviderStore, err := ldstore.NewRemoteProviderStore(mem.NewProvider())
	if err != nil {
		return nil, err
	}

	p := &docLoaderProvider{
		ContextStore:        contextStore,
		RemoteProviderStore: remoteProviderStore,
	}

	loader, err := ld.NewDocumentLoader(p)
	if err != nil {
		return nil, err
	}

	return loader, nil
}

func (i *IssuanceSDKSteps) getCredentialFulfillmentAttachment() (decorator.GenericAttachment, error) {
	for {
		select {
		case msg := <-i.holderEvent:
			if msg.StateID == "done" {
				attachment, err := getAttachmentFromDIDCommMsg(msg.Msg)
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

func getAttachmentFromDIDCommMsg(didCommMsg service.DIDCommMsg) (decorator.GenericAttachment, error) {
	var didCommMsgAsMap map[string]interface{}

	err := didCommMsg.Decode(&didCommMsgAsMap)
	if err != nil {
		return decorator.GenericAttachment{}, err
	}

	attachmentsRaw, ok := didCommMsgAsMap["attachments"]
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

// GetConnection return the connection between agents.
func (i *IssuanceSDKSteps) GetConnection(from, to string) (*didexClient.Connection, error) {
	connections, err := i.context.DIDExchangeClients[from].QueryConnections(&didexClient.QueryConnectionsParams{})
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

type prop interface {
	MyDID() string
	TheirDID() string
}

func checkProperties(action service.DIDCommAction) error {
	properties, ok := action.Properties.(prop)
	if !ok {
		return errors.New("no properties")
	}

	if properties.MyDID() == "" {
		return errors.New("myDID is empty")
	}

	if properties.TheirDID() == "" {
		return errors.New("theirDID is empty")
	}

	return nil
}

func getParentThreadID(action service.DIDCommAction) (string, error) {
	var didCommMsgAsMap map[string]interface{}

	err := action.Message.Decode(&didCommMsgAsMap)
	if err != nil {
		return "", err
	}

	msgParentThreadID, ok := didCommMsgAsMap["pthid"]
	if !ok {
		return "", errors.New("missing ID from DIDComm message map")
	}

	return msgParentThreadID.(string), nil
}

func getAttachments(action service.DIDCommAction) ([]decorator.GenericAttachment, error) {
	var didCommMsgAsMap map[string]interface{}

	err := action.Message.Decode(&didCommMsgAsMap)
	if err != nil {
		return nil, err
	}

	attachmentsRaw, ok := didCommMsgAsMap["attachments"]
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
