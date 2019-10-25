/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package webhook

// TODO https://github.com/hyperledger/aries-framework-go/issues/583 Webhooks - Package structure for models

// BasicMsg is used for receiving basic messages.
// TODO: This model is not final and was simply copied from ACA-Py for now (see #541).
type BasicMsg struct {
	ConnectionID string `json:"connection_id"`
	MessageID    string `json:"message_id"`
	Content      string `json:"content"`
	State        string `json:"state"`
}

// IssueCredentialMsg is sent when a credential exchange record is updated.
// TODO: This model is not final and was simply copied from ACA-Py for now (see #558).
type IssueCredentialMsg struct {
	CredentialExchangeID      string `json:"credential_exchange_id"`
	ConnectionID              string `json:"connection_id"`
	ThreadID                  string `json:"thread_id"`
	ParentThreadID            string `json:"parent_thread_id"`
	Initiator                 string `json:"initiator"`
	State                     string `json:"state"`
	CredentialDefinitionID    string `json:"credential_definition_id"`
	SchemaID                  string `json:"schema_id"`
	CredentialProposalDict    string `json:"credential_proposal_dict"`
	CredentialOffer           string `json:"credential_offer"`
	CredentialRequest         string `json:"credential_request"`
	CredentialRequestMetadata string `json:"credential_request_metadata"`
	CredentialID              string `json:"credential_id"`
	RawCredential             string `json:"raw_credential"`
	Credential                string `json:"credential"`
	AutoOffer                 string `json:"auto_offer"`
	AutoIssue                 string `json:"auto_issue"`
	ErrorMsg                  string `json:"error_msg"`
}

// PresentProofMsg is sent when a presentation exchange record is updated.
// TODO: This model is not final and was simply copied from ACA-Py for now (see #559).
type PresentProofMsg struct {
	PresentationExchangeID   string `json:"presentation_exchange_id"`
	ConnectionID             string `json:"connection_id"`
	ThreadID                 string `json:"thread_id"`
	Initiator                string `json:"initiator"`
	State                    string `json:"state"`
	PresentationProposalDict string `json:"presentation_proposal_dict"`
	PresentationRequest      string `json:"presentation_request"`
	Presentation             string `json:"presentation"`
	Verified                 string `json:"verified"`
	AutoPresent              string `json:"auto_present"`
	ErrorMsg                 string `json:"error_msg"`
}
