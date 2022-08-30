/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package waci

import (
	_ "embed" // nolint // This is needed to use go:embed
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cucumber/godog"
	"github.com/google/uuid"

	didexClient "github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	issuecredentialclient "github.com/hyperledger/aries-framework-go/pkg/client/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofbandv2"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	oobv2 "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofbandv2"
	"github.com/hyperledger/aries-framework-go/pkg/doc/cm"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	bddverifiable "github.com/hyperledger/aries-framework-go/test/bdd/pkg/verifiable"
)

var (
	//go:embed testdata/credential_manifest_drivers_license.json
	credentialManifestDriversLicense []byte //nolint:gochecknoglobals
	//go:embed testdata/credential_response_drivers_license.json
	credentialResponseDriversLicense []byte //nolint:gochecknoglobals
	//go:embed testdata/vc_drivers_license_without_proof.json
	vcDriversLicenseWithoutProof []byte //nolint:gochecknoglobals
	//go:embed testdata/vc_drivers_license.json
	vcDriversLicense []byte //nolint:gochecknoglobals
	//go:embed testdata/vc_prc.json
	vcPRC []byte //nolint:gochecknoglobals
	//go:embed testdata/credential_application_drivers_license.json
	credentialApplicationDriversLicense []byte //nolint:gochecknoglobals
	//go:embed testdata/presentation_submission_prc.json
	presentationSubmissionPRC []byte //nolint:gochecknoglobals
)

const (
	waciIssuanceGoalCode = "streamlined-vc"
	stateMsgChanSize     = 12
	timeoutDuration      = time.Second * 5
)

// IssuanceSDKDIDCommV2Steps contains steps for WACI issuance tests using the SDK binding with DIDComm V2.
type IssuanceSDKDIDCommV2Steps struct {
	context                            *context.BDDContext
	oobV2InviteFromIssuerToHolder      *oobv2.Invitation
	issueCredentialClients             map[string]*issuecredentialclient.Client
	actions                            map[string]chan service.DIDCommAction
	holderEvent                        chan service.StateMsg
	credentialManifestReceivedByHolder *cm.CredentialManifest
}

// NewIssuanceDIDCommV2SDKSteps returns the WACI issuance's BDD steps using the SDK binding with DIDComm V2.
func NewIssuanceDIDCommV2SDKSteps() *IssuanceSDKDIDCommV2Steps {
	return &IssuanceSDKDIDCommV2Steps{
		issueCredentialClients: make(map[string]*issuecredentialclient.Client),
		actions:                make(map[string]chan service.DIDCommAction),
		holderEvent:            make(chan service.StateMsg, stateMsgChanSize),
	}
}

// SetContext is called before every scenario is run with a fresh context.
func (i *IssuanceSDKDIDCommV2Steps) SetContext(ctx *context.BDDContext) {
	i.context = ctx
}

// RegisterSteps registers the BDD test steps on the suite.
// Note that VC proofs are not checked in this test suite.
func (i *IssuanceSDKDIDCommV2Steps) RegisterSteps(suite *godog.Suite) {
	suite.Step(`^"([^"]*)" creates an out-of-band-v2 invitation with streamlined-vc goal_code$`,
		i.createOOBV2WithStreamlinedVCGoalCode)
	suite.Step(`^"([^"]*)" sends the request to "([^"]*)" and they accept it$`, i.acceptOOBV2Invitation)
	suite.Step(`^"([^"]*)" sends proposal credential V3 to the "([^"]*)" \(WACI\)$`, i.sendsProposalV3)
	suite.Step(`^"([^"]*)" accepts a proposal V3 and sends an offer to the Holder \(WACI\)$`, i.acceptProposalV3)
	suite.Step(`^"([^"]*)" accepts the offer and sends a Credential Application to the Issuer$`, i.acceptOffer)
	suite.Step(`^"([^"]*)" accepts the Credential Application and sends a credential to the Holder$`,
		i.acceptCredentialApplication)
	suite.Step(`^"([^"]*)" accepts the credential$`, i.acceptCredential)
	suite.Step(`^Holder checks that the expected credential was received in a Credential `+
		`Response attachment$`, i.checkCredential)
}

func (i *IssuanceSDKDIDCommV2Steps) createOOBV2WithStreamlinedVCGoalCode(issuerName string) error {
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

func (i *IssuanceSDKDIDCommV2Steps) acceptOOBV2Invitation(issuerName, holderName string) error {
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

func (i *IssuanceSDKDIDCommV2Steps) sendsProposalV3(holderName, issuerName string) error {
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

func (i *IssuanceSDKDIDCommV2Steps) acceptProposalV3(issuerName string) error {
	piid, parentThreadID, err := i.getActionIDAndParentThreadID(issuerName)
	if err != nil {
		return err
	}

	if i.oobV2InviteFromIssuerToHolder.ID != parentThreadID {
		return fmt.Errorf("expected message parent thread ID to match the original invitation ID "+
			"(%s) but got %s instead", i.oobV2InviteFromIssuerToHolder.ID, parentThreadID)
	}

	offerCredential, err := generateOfferCredentialMsgV3()
	if err != nil {
		return err
	}

	err = i.issueCredentialClients[issuerName].AcceptProposal(piid, offerCredential)
	if err != nil {
		return err
	}

	return nil
}

func (i *IssuanceSDKDIDCommV2Steps) acceptOffer(holderName string) error {
	piid, attachmentsFromOfferMsg, err := i.getActionIDAndAttachments(holderName)
	if err != nil {
		return err
	}

	err = i.checkAttachments(attachmentsFromOfferMsg)
	if err != nil {
		return err
	}

	requestCredential, err := generateRequestCredentialMsgV3(i.credentialManifestReceivedByHolder)
	if err != nil {
		return err
	}

	err = i.issueCredentialClients[holderName].AcceptOffer(piid, requestCredential)
	if err != nil {
		return err
	}

	return nil
}

func (i *IssuanceSDKDIDCommV2Steps) acceptCredentialApplication(issuerName string) error {
	piid, attachmentsFromApplicationMsg, err := i.getActionIDAndAttachments(issuerName)
	if err != nil {
		return err
	}

	credentialManifest, err := generateCredentialManifest()
	if err != nil {
		return err
	}

	attachmentAsMap, ok := attachmentsFromApplicationMsg[0].Data.JSON.(map[string]interface{})
	if !ok {
		return errors.New("couldn't assert attachment data as a map")
	}

	credentialApplicationBytes, err := json.MarshalIndent(attachmentAsMap, "", "	")
	if err != nil {
		return fmt.Errorf("failed to marshal credential_application object: %w", err)
	}

	documentLoader, err := bddverifiable.CreateDocumentLoader()
	if err != nil {
		return err
	}

	application, err := verifiable.ParsePresentation(credentialApplicationBytes,
		verifiable.WithPresJSONLDDocumentLoader(documentLoader),
		verifiable.WithPresDisabledProofCheck())
	if err != nil {
		return fmt.Errorf("failed to decode credential application presentation: %w", err)
	}

	// Here, the issuer validates the Credential Application against its Credential Manifest.
	// In a real flow, the issuer would want to check the proofs as well.
	err = cm.ValidateCredentialApplication(application, credentialManifest, documentLoader,
		presexch.WithCredentialOptions(verifiable.WithJSONLDDocumentLoader(documentLoader),
			verifiable.WithDisabledProofCheck()))
	if err != nil {
		return err
	}

	issueCredentialMsg, err := generateIssueCredentialMsgV3()
	if err != nil {
		return err
	}

	err = i.issueCredentialClients[issuerName].AcceptRequest(piid, issueCredentialMsg)
	if err != nil {
		return err
	}

	return nil
}

func (i *IssuanceSDKDIDCommV2Steps) acceptCredential(holderName string) error {
	piid, err := getActionID(i.actions[holderName])
	if err != nil {
		return err
	}

	err = i.issueCredentialClients[holderName].AcceptCredential(piid, issuecredentialclient.AcceptBySkippingStorage())
	if err != nil {
		return err
	}

	return nil
}

func (i *IssuanceSDKDIDCommV2Steps) checkCredential() error {
	credentialResponseAttachment, err := i.getCredentialResponseAttachment()
	if err != nil {
		return err
	}

	vc, err := getVCFromCredentialResponseAttachment(&credentialResponseAttachment)
	if err != nil {
		return err
	}

	if vc.ID != expectedVCID {
		return fmt.Errorf("expected VC ID to be %s but got %s instead", expectedVCID, vc.ID)
	}

	// TODO #3144 - Remove this time.Sleep call once the listener handler error issue is resolved.
	loggerDIDCommV2Tests.Infof("Waiting one second for Aries agents to finish internal operations. " +
		"(TODO #3144 - remove the need for this delay)")
	time.Sleep(time.Second)

	return nil
}

func (i *IssuanceSDKDIDCommV2Steps) createIssueCredentialClients(holderName, issuerName string) error {
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

func (i *IssuanceSDKDIDCommV2Steps) createActions(holderName, issuerName string) {
	i.actions[issuerName] = make(chan service.DIDCommAction, 1)
	i.actions[holderName] = make(chan service.DIDCommAction, 1)
}

func (i *IssuanceSDKDIDCommV2Steps) registerActionsAndEvents(holderName, issuerName string) error {
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

func (i *IssuanceSDKDIDCommV2Steps) getActionIDAndParentThreadID(agent string) (string, string, error) {
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

func (i *IssuanceSDKDIDCommV2Steps) getActionIDAndAttachments(agent string) (string,
	[]decorator.GenericAttachment, error) {
	select {
	case action := <-i.actions[agent]:
		err := checkProperties(action)
		if err != nil {
			return "", nil, fmt.Errorf("check properties: %w", err)
		}

		var attachments []decorator.GenericAttachment

		attachments, err = getAttachmentsV3(action)
		if err != nil {
			return "", nil, err
		}

		return action.Properties.All()["piid"].(string), attachments, nil
	case <-time.After(timeoutDuration):
		return "", nil, errors.New("timeout")
	}
}

func (i *IssuanceSDKDIDCommV2Steps) checkAttachments(attachmentsFromOfferMsg []decorator.GenericAttachment) error {
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

	// The Credential Response we receive from the issuer acts as a preview for the credentials we eventually
	// wish to receive.
	credentialResponse, err := getCredentialResponseFromAttachment(&attachmentsFromOfferMsg[1])
	if err != nil {
		return err
	}

	if credentialResponse.ManifestID != expectedCredentialManifestID {
		return fmt.Errorf("expected credential response's manifest ID to be %s, but got %s instead",
			expectedCredentialManifestID, credentialResponse.ManifestID)
	}

	documentLoader, err := bddverifiable.CreateDocumentLoader()
	if err != nil {
		return err
	}

	// These VCs are only previews - they lack proofs.
	vcs, err := credentialResponse.ResolveDescriptorMaps(attachmentsFromOfferMsg[1].Data.JSON,
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

func (i *IssuanceSDKDIDCommV2Steps) getCredentialResponseAttachment() (decorator.GenericAttachment, error) {
	for {
		select {
		case msg := <-i.holderEvent:
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

func (i *IssuanceSDKDIDCommV2Steps) getConnection(from, to string) (*didexClient.Connection, error) {
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

func getAttachmentFromDIDCommMsgV2(didCommMsg service.DIDCommMsg) (decorator.GenericAttachment, error) {
	return getAttachmentFromDIDCommMsg(didCommMsg, "attachments")
}

func generateOfferCredentialMsgV3() (*issuecredentialclient.OfferCredential, error) {
	return generateOfferCredentialMsg(issuecredential.OfferCredentialMsgTypeV3)
}

func generateRequestCredentialMsgV3(credentialManifest *cm.CredentialManifest) (
	*issuecredentialclient.RequestCredential, error) {
	return generateRequestCredentialMsg(credentialManifest, issuecredential.RequestCredentialMsgTypeV3)
}

func generateIssueCredentialMsgV3() (*issuecredentialclient.IssueCredential, error) {
	return generateIssueCredentialMsg(issuecredential.IssueCredentialMsgTypeV3)
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

func getAttachmentsV3(action service.DIDCommAction) ([]decorator.GenericAttachment, error) {
	return getAttachments(action, "attachments")
}
