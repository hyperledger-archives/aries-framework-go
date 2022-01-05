/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"

// ProposeCredentialV2 is an optional message sent by the potential Holder to the Issuer
// to initiate the protocol or in response to a offer-credential message when the Holder
// wants some adjustments made to the credential data offered by Issuer.
type ProposeCredentialV2 struct {
	Type string `json:"@type,omitempty"`
	// Comment is an optional field that provides human readable information about this Credential Offer,
	// so the offer can be evaluated by human judgment.
	// TODO: Should follow DIDComm conventions for l10n. [Issue #1300]
	Comment string `json:"comment,omitempty"`
	// CredentialProposal is an optional JSON-LD object that represents
	// the credential data that the Prover wants to receive.
	CredentialProposal PreviewCredential `json:"credential_proposal,omitempty"`
	// Formats contains an entry for each filters~attach array entry, providing the the value of the attachment @id
	// and the verifiable credential format and version of the attachment.
	Formats []Format `json:"formats,omitempty"`
	// FiltersAttach is an array of attachments that further define the credential being proposed.
	// This might be used to clarify which formats or format versions are wanted.
	FiltersAttach []decorator.Attachment `json:"filters~attach,omitempty"`
	// Optional field containing ID of the invitation which initiated this protocol.
	InvitationID string `json:"invitationID,omitempty"`
}

// ProposeCredentialV3 is an optional message sent by the potential Holder to the Issuer
// to initiate the protocol or in response to a offer-credential message when the Holder
// wants some adjustments made to the credential data offered by Issuer.
type ProposeCredentialV3 struct {
	Type string                  `json:"type,omitempty"`
	ID   string                  `json:"id,omitempty"`
	Body ProposeCredentialV3Body `json:"body,omitempty"`
	// Attachments is an array of attachments containing the presentation in the requested format(s).
	// Accepted values for the format attribute of each attachment are provided in the per format Attachment
	// registry immediately below.
	Attachments []decorator.AttachmentV2 `json:"attachments,omitempty"`
	// Optional field containing ID of the invitation which initiated this protocol.
	InvitationID string `json:"pthid,omitempty"`
}

// ProposeCredentialV3Body represents body for ProposeCredentialV3.
type ProposeCredentialV3Body struct {
	GoalCode string `json:"goal_code,omitempty"`
	Comment  string `json:"comment,omitempty"`
	// credentialPreview is an optional JSON-LD object that represents the credential data that Prover wants to receive.
	CredentialPreview interface{} `json:"credential_preview,omitempty"`
}

// Format contains the value of the attachment @id and the verifiable credential format of the attachment.
type Format struct {
	AttachID string `json:"attach_id,omitempty"`
	Format   string `json:"format,omitempty"`
}

// OfferCredentialV2 is a message sent by the Issuer to the potential Holder,
// describing the credential they intend to offer and possibly the price they expect to be paid.
// TODO: Need to add ~payment_request and ~timing.expires_time decorators [Issue #1297].
type OfferCredentialV2 struct {
	Type string `json:"@type,omitempty"`
	// Comment is an optional field that provides human readable information about this Credential Offer,
	// so the offer can be evaluated by human judgment.
	// TODO: Should follow DIDComm conventions for l10n. [Issue #1300].
	Comment string `json:"comment,omitempty"`
	// CredentialPreview is a JSON-LD object that represents the credential data that Issuer is willing to issue.
	CredentialPreview PreviewCredential `json:"credential_preview,omitempty"`
	// Formats contains an entry for each offers~attach array entry, providing the the value
	// of the attachment @id and the verifiable credential format and version of the attachment.
	Formats []Format `json:"formats,omitempty"`
	// OffersAttach is a slice of attachments that further define the credential being offered.
	// This might be used to clarify which formats or format versions will be issued.
	OffersAttach []decorator.Attachment `json:"offers~attach,omitempty"`
}

// OfferCredentialV3 is a message sent by the Issuer to the potential Holder,
// describing the credential they intend to offer and possibly the price they expect to be paid.
type OfferCredentialV3 struct {
	Type string                `json:"type,omitempty"`
	ID   string                `json:"id,omitempty"`
	Body OfferCredentialV3Body `json:"body,omitempty"`
	// Attachments is an array of attachments containing the presentation in the requested format(s).
	// Accepted values for the format attribute of each attachment are provided in the per format Attachment
	// registry immediately below.
	Attachments []decorator.AttachmentV2 `json:"attachments,omitempty"`
}

// OfferCredentialV3Body represents body for OfferCredentialV3.
type OfferCredentialV3Body struct {
	GoalCode      string `json:"goal_code,omitempty"`
	Comment       string `json:"comment,omitempty"`
	ReplacementID string `json:"replacement_id,omitempty"`
	// credentialPreview is an optional JSON-LD object that represents the credential data that Prover wants to receive.
	CredentialPreview interface{} `json:"credential_preview,omitempty"`
}

// RequestCredentialV2 is a message sent by the potential Holder to the Issuer,
// to request the issuance of a credential. Where circumstances do not require
// a preceding Offer Credential message (e.g., there is no cost to issuance
// that the Issuer needs to explain in advance, and there is no need for cryptographic negotiation),
// this message initiates the protocol.
// TODO: Need to add ~payment-receipt decorator [Issue #1298].
type RequestCredentialV2 struct {
	Type string `json:"@type,omitempty"`
	// Comment is an optional field that provides human readable information about this Credential Offer,
	// so the offer can be evaluated by human judgment.
	// TODO: Should follow DIDComm conventions for l10n. [Issue #1300].
	Comment string `json:"comment,omitempty"`
	// Formats contains an entry for each requests~attach array entry, providing the the value
	// of the attachment @id and the verifiable credential format and version of the attachment.
	Formats []Format `json:"formats,omitempty"`
	// RequestsAttach is a slice of attachments defining the requested formats for the credential
	RequestsAttach []decorator.Attachment `json:"requests~attach,omitempty"`
}

// RequestCredentialV3 is a message sent by the potential Holder to the Issuer,
// to request the issuance of a credential. Where circumstances do not require
// a preceding Offer Credential message (e.g., there is no cost to issuance
// that the Issuer needs to explain in advance, and there is no need for cryptographic negotiation),
// this message initiates the protocol.
type RequestCredentialV3 struct {
	Type string                  `json:"type,omitempty"`
	ID   string                  `json:"id,omitempty"`
	Body RequestCredentialV3Body `json:"body,omitempty"`
	// Attachments is an array of attachments containing the presentation in the requested format(s).
	// Accepted values for the format attribute of each attachment are provided in the per format Attachment
	// registry immediately below.
	Attachments []decorator.AttachmentV2 `json:"attachments,omitempty"`
}

// RequestCredentialV3Body represents body for RequestCredentialV3.
type RequestCredentialV3Body struct {
	GoalCode string `json:"goal_code,omitempty"`
	Comment  string `json:"comment,omitempty"`
}

// IssueCredentialV2 contains as attached payload the credentials being issued and is
// sent in response to a valid Invitation Credential message.
// TODO: Need to add ~please-ack decorator [Issue #1299].
type IssueCredentialV2 struct { //nolint: golint
	Type string `json:"@type,omitempty"`
	// Comment is an optional field that provides human readable information about this Credential Offer,
	// so the offer can be evaluated by human judgment.
	// TODO: Should follow DIDComm conventions for l10n. [Issue #1300].
	Comment string `json:"comment,omitempty"`
	// Formats contains an entry for each credentials~attach array entry, providing the value
	// of the attachment @id and the verifiable credential format and version of the attachment.
	Formats []Format `json:"formats,omitempty"`
	// CredentialsAttach is a slice of attachments containing the issued credentials.
	CredentialsAttach []decorator.Attachment `json:"credentials~attach,omitempty"`
	// WebRedirect contains optional web redirect info to be sent to holder for redirect.
	WebRedirect *decorator.WebRedirect `json:"~web-redirect,omitempty"`
}

// IssueCredentialV3 contains as attached payload the credentials being issued and is
// sent in response to a valid Invitation Credential message.
type IssueCredentialV3 struct { //nolint: golint
	Type string                `json:"type,omitempty"`
	ID   string                `json:"id,omitempty"`
	Body IssueCredentialV3Body `json:"body,omitempty"`
	// WebRedirect contains optional web redirect info to be sent to holder for redirect.
	WebRedirect *decorator.WebRedirect `json:"web-redirect,omitempty"`
	// Attachments is an array of attachments containing the presentation in the requested format(s).
	// Accepted values for the format attribute of each attachment are provided in the per format Attachment
	// registry immediately below.
	Attachments []decorator.AttachmentV2 `json:"attachments,omitempty"`
}

// IssueCredentialV3Body represents body for IssueCredentialV3.
type IssueCredentialV3Body struct { //nolint: golint
	GoalCode      string `json:"goal_code,omitempty"`
	ReplacementID string `json:"replacement_id,omitempty"`
	Comment       string `json:"comment,omitempty"`
}

// PreviewCredential is used to construct a preview of the data for the credential that is to be issued.
type PreviewCredential struct {
	Type       string      `json:"@type,omitempty"`
	Attributes []Attribute `json:"attributes,omitempty"`
}

// PreviewCredentialV3 is used to construct a preview of the data for the credential that is to be issued.
type PreviewCredentialV3 struct {
	Type string                `json:"type,omitempty"`
	ID   string                `json:"id,omitempty"`
	Body IssueCredentialV3Body `json:"body,omitempty"`
}

// PreviewCredentialV3Body represents body for PreviewCredentialV3.
type PreviewCredentialV3Body struct {
	Attributes []Attribute `json:"attributes,omitempty"`
}

// Attribute describes an attribute for a Preview Credential.
type Attribute struct {
	Name     string `json:"name,omitempty"`
	MimeType string `json:"mime-type,omitempty"`
	Value    string `json:"value,omitempty"`
}
