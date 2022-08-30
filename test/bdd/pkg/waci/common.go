/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package waci

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	issuecredentialclient "github.com/hyperledger/aries-framework-go/pkg/client/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/cm"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	bddverifiable "github.com/hyperledger/aries-framework-go/test/bdd/pkg/verifiable"
)

const expectedVCID = "https://eu.com/claims/DriversLicense"

func getAttachmentFromDIDCommMsg(didCommMsg service.DIDCommMsg,
	attachmentFieldName string) (decorator.GenericAttachment, error) {
	var didCommMsgAsMap map[string]interface{}

	err := didCommMsg.Decode(&didCommMsgAsMap)
	if err != nil {
		return decorator.GenericAttachment{}, err
	}

	attachmentsRaw, ok := didCommMsgAsMap[attachmentFieldName]
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

func getAttachments(action service.DIDCommAction, fieldName string) ([]decorator.GenericAttachment, error) {
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

func getActionID(actionChan <-chan service.DIDCommAction) (string, error) {
	select {
	case action := <-actionChan:
		err := checkProperties(action)
		if err != nil {
			return "", fmt.Errorf("check properties: %w", err)
		}

		return action.Properties.All()["piid"].(string), nil
	case <-time.After(timeoutDuration):
		return "", errors.New("timeout")
	}
}

type property interface {
	MyDID() string
	TheirDID() string
}

func checkProperties(action service.DIDCommAction) error {
	properties, ok := action.Properties.(property)
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

func generateOfferCredentialMsg(msgType string) (*issuecredentialclient.OfferCredential, error) {
	credentialManifestAttachment, err := generateCredentialManifestAttachment()
	if err != nil {
		return nil, err
	}

	// A Credential Response attachment is sent here as a preview of the VC so the Holder can see what
	// the credential will look like.
	credentialResponseAttachment, err := generateCredentialResponseAttachmentWithoutProof()
	if err != nil {
		return nil, err
	}

	attachments := []decorator.GenericAttachment{*credentialManifestAttachment, *credentialResponseAttachment}

	offerCredential := issuecredentialclient.OfferCredential{
		Type:        msgType,
		ID:          uuid.New().String(),
		Attachments: attachments,
	}

	return &offerCredential, nil
}

func generateCredentialManifestAttachment() (*decorator.GenericAttachment, error) {
	credentialManifest, err := generateCredentialManifest()
	if err != nil {
		return nil, err
	}

	options := map[string]string{
		"challenge": "508adef4-b8e0-4edf-a53d-a260371c1423",
		"domain":    "9rf25a28rs96",
	}

	attachmentData := map[string]interface{}{
		"options":             options,
		"credential_manifest": credentialManifest,
	}

	credentialManifestAttachment := decorator.GenericAttachment{
		ID:        uuid.New().String(),
		MediaType: "application/json",
		Format:    cm.CredentialManifestAttachmentFormat,
		Data:      decorator.AttachmentData{JSON: attachmentData},
	}

	return &credentialManifestAttachment, nil
}

func generateCredentialManifest() (*cm.CredentialManifest, error) {
	var credentialManifest cm.CredentialManifest

	err := json.Unmarshal(credentialManifestDriversLicense, &credentialManifest)
	if err != nil {
		return nil, err
	}

	return &credentialManifest, nil
}

func generateCredentialResponseAttachmentWithoutProof() (*decorator.GenericAttachment, error) {
	var credentialResponse cm.CredentialResponse

	err := json.Unmarshal(credentialResponseDriversLicense, &credentialResponse)
	if err != nil {
		return nil, err
	}

	cxt := []string{
		"https://www.w3.org/2018/credentials/v1",
		cm.CredentialResponsePresentationContext,
	}

	types := []string{
		"VerifiablePresentation",
		"CredentialResponse",
	}

	documentLoader, err := bddverifiable.CreateDocumentLoader()
	if err != nil {
		return nil, err
	}

	vcPreview, err := verifiable.ParseCredential(vcDriversLicenseWithoutProof,
		verifiable.WithJSONLDDocumentLoader(documentLoader))
	if err != nil {
		return nil, err
	}

	verifiableCredentials := []*verifiable.Credential{vcPreview}

	attachmentData := map[string]interface{}{
		"@context":             cxt,
		"type":                 types,
		"credential_response":  credentialResponse,
		"verifiableCredential": verifiableCredentials,
	}

	credentialResponseAttachment := decorator.GenericAttachment{
		ID:        uuid.New().String(),
		MediaType: "application/json",
		Format:    cm.CredentialResponseAttachmentFormat,
		Data:      decorator.AttachmentData{JSON: attachmentData},
	}

	return &credentialResponseAttachment, nil
}

func generateRequestCredentialMsg(credentialManifest *cm.CredentialManifest, msgType string) (
	*issuecredentialclient.RequestCredential, error) {
	credentialApplicationAttachment, err := generateCredentialApplicationAttachment(credentialManifest)
	if err != nil {
		return nil, err
	}

	attachments := []decorator.GenericAttachment{*credentialApplicationAttachment}

	requestCredential := issuecredentialclient.RequestCredential{
		Type:        msgType,
		ID:          uuid.New().String(),
		Attachments: attachments,
	}

	return &requestCredential, nil
}

func generateCredentialApplicationAttachment(credentialManifest *cm.CredentialManifest) (*decorator.GenericAttachment,
	error) {
	cxt := []string{
		"https://www.w3.org/2018/credentials/v1",
		cm.CredentialApplicationPresentationContext,
	}

	types := []string{
		"VerifiablePresentation",
		"CredentialApplication",
	}

	credentialApplication, err :=
		cm.UnmarshalAndValidateAgainstCredentialManifest(credentialApplicationDriversLicense, credentialManifest)
	if err != nil {
		return nil, err
	}

	var presentationSubmission presexch.PresentationSubmission

	err = json.Unmarshal(presentationSubmissionPRC, &presentationSubmission)
	if err != nil {
		return nil, err
	}

	documentLoader, err := bddverifiable.CreateDocumentLoader()
	if err != nil {
		return nil, err
	}

	verifiableCredential, err := verifiable.ParseCredential(vcPRC,
		verifiable.WithJSONLDDocumentLoader(documentLoader), verifiable.WithDisabledProofCheck())
	if err != nil {
		return nil, err
	}

	verifiableCredentials := []*verifiable.Credential{verifiableCredential}

	proof := generateCredentialApplicationProof()

	attachmentData := map[string]interface{}{
		"@context":                cxt,
		"type":                    types,
		"credential_application":  credentialApplication,
		"presentation_submission": presentationSubmission,
		"verifiableCredential":    verifiableCredentials,
		"proof":                   proof,
	}

	credentialApplicationAttachment := decorator.GenericAttachment{
		ID:        uuid.New().String(),
		MediaType: "application/json",
		Format:    cm.CredentialApplicationAttachmentFormat,
		Data:      decorator.AttachmentData{JSON: attachmentData},
	}

	return &credentialApplicationAttachment, nil
}

func generateCredentialApplicationProof() map[string]string {
	return map[string]string{
		"type":               "Ed25519Signature2018",
		"verificationMethod": "did:example:123#key-0",
		"created":            "2021-05-14T20:16:29.565377",
		"proofPurpose":       "authentication",
		"challenge":          "3fa85f64-5717-4562-b3fc-2c963f66afa7",
		"jws": "eyJhbGciOiAiRWREU0EiLCAiYjY0IjogZmFsc2UsICJjcml0IjogWyJiNjQiXX0..7M9LwdJR1_SQayHIWVHF5eSSRhbVsr" +
			"jQHKUrfRhRRrlbuKlggm8mm_4EI_kTPeBpalQWiGiyCb_0OWFPtn2wAQ",
	}
}

func generateIssueCredentialMsg(msgType string) (*issuecredentialclient.IssueCredential, error) {
	cxt := []string{
		"https://www.w3.org/2018/credentials/v1",
		cm.CredentialResponsePresentationContext,
	}

	types := []string{
		"VerifiablePresentation",
		"CredentialResponse",
	}

	var credentialResponse cm.CredentialResponse

	err := json.Unmarshal(credentialResponseDriversLicense, &credentialResponse)
	if err != nil {
		return nil, err
	}

	documentLoader, err := bddverifiable.CreateDocumentLoader()
	if err != nil {
		return nil, err
	}

	verifiableCredential, err := verifiable.ParseCredential(vcDriversLicense,
		verifiable.WithJSONLDDocumentLoader(documentLoader), verifiable.WithDisabledProofCheck())
	if err != nil {
		return nil, err
	}

	verifiableCredentials := []*verifiable.Credential{verifiableCredential}

	proof := generateCredentialResponseProof()

	attachmentData := map[string]interface{}{
		"@context":             cxt,
		"type":                 types,
		"credential_response":  credentialResponse,
		"verifiableCredential": verifiableCredentials,
		"proof":                proof,
	}

	issueCredentialAttachment := decorator.GenericAttachment{
		ID:        uuid.New().String(),
		MediaType: "application/json",
		Format:    cm.CredentialResponseAttachmentFormat,
		Data:      decorator.AttachmentData{JSON: attachmentData},
	}

	attachments := []decorator.GenericAttachment{issueCredentialAttachment}

	issueCredentialMsg := issuecredentialclient.IssueCredential{
		Type:        msgType,
		ID:          uuid.New().String(),
		Attachments: attachments,
	}

	return &issueCredentialMsg, nil
}

func generateCredentialResponseProof() map[string]string {
	return map[string]string{
		"type": "Ed25519Signature2018",
		"verificationMethod": "did:orb:EiA3Xmv8A8vUH5lRRZeKakd-cjAxGC2A4aoPDjLysjghow#tMIstfHSzXfBUF" +
			"7O0m2FiBEfTb93_j_4ron47IXPgEo",
		"created":      "2021-06-07T20:02:44.730614315Z",
		"proofPurpose": "authentication",
		"jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19.." +
			"NVum9BeYkhzwslZXm2cDOveQB9njlrCRSrdMZgwV3zZfLRXmZQ1AXdKLLmo4ClTYXFX_TWNyB8aFt9cN6sSvCg",
	}
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

func getCredentialResponseFromAttachment(attachment *decorator.GenericAttachment) (*cm.CredentialResponse,
	error) {
	attachmentAsMap, ok := attachment.Data.JSON.(map[string]interface{})
	if !ok {
		return nil, errors.New("couldn't assert attachment as a map")
	}

	credentialResponseRaw, ok := attachmentAsMap["credential_response"]
	if !ok {
		return nil, errors.New("credential_response object missing from attachment")
	}

	credentialResponseBytes, err := json.Marshal(credentialResponseRaw)
	if err != nil {
		return nil, err
	}

	var credentialResponse cm.CredentialResponse

	// This unmarshal call also triggers the credential response validation code, which ensures that the
	// credential response object is valid under the spec.
	err = json.Unmarshal(credentialResponseBytes, &credentialResponse)
	if err != nil {
		return nil, err
	}

	return &credentialResponse, nil
}

func getVCFromCredentialResponseAttachment(credentialResponseAttachment *decorator.GenericAttachment) (
	verifiable.Credential, error) {
	attachmentRaw := credentialResponseAttachment.Data.JSON

	attachmentAsMap, ok := attachmentRaw.(map[string]interface{})
	if !ok {
		return verifiable.Credential{}, errors.New("couldn't assert attachment as a map")
	}

	credentialResponseRaw, ok := attachmentAsMap["credential_response"]
	if !ok {
		return verifiable.Credential{}, errors.New("credential_response object missing from attachment")
	}

	credentialResponseBytes, err := json.Marshal(credentialResponseRaw)
	if err != nil {
		return verifiable.Credential{}, err
	}

	var credentialResponse cm.CredentialResponse

	err = json.Unmarshal(credentialResponseBytes, &credentialResponse)
	if err != nil {
		return verifiable.Credential{}, err
	}

	documentLoader, err := bddverifiable.CreateDocumentLoader()
	if err != nil {
		return verifiable.Credential{}, err
	}

	vcs, err := credentialResponse.ResolveDescriptorMaps(credentialResponseAttachment.Data.JSON,
		verifiable.WithDisabledProofCheck(), verifiable.WithJSONLDDocumentLoader(documentLoader))
	if err != nil {
		return verifiable.Credential{}, err
	}

	if len(vcs) != 1 {
		return verifiable.Credential{}, fmt.Errorf("received %d VCs, but expected only one", len(vcs))
	}

	return vcs[0], nil
}
