/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"

// ProposePresentationV2 is an optional message sent by the prover to the verifier to initiate a proof presentation
// process, or in response to a request-presentation message when the prover wants to propose
// using a different presentation format or request.
type ProposePresentationV2 struct {
	ID   string `json:"@id,omitempty"`
	Type string `json:"@type,omitempty"`
	// Comment is a field that provides some human readable information about the proposed presentation.
	// TODO: Should follow DIDComm conventions for l10n. [Issue #1300]
	Comment string `json:"comment,omitempty"`
	// Formats contains an entry for each proposal~attach array entry, including an optional value of the
	// attachment @id (if attachments are present) and the verifiable presentation format and version of the attachment.
	Formats []Format `json:"formats,omitempty"`
	// ProposalsAttach is an array of attachments that further define the presentation request being proposed.
	// This might be used to clarify which formats or format versions are wanted.
	ProposalsAttach []decorator.Attachment `json:"proposals~attach,omitempty"`
}

// ProposePresentationV3 is an optional message sent by the prover to the verifier to initiate a proof presentation
// process, or in response to a request-presentation message when the prover wants to propose
// using a different presentation format or request.
type ProposePresentationV3 struct {
	ID   string                    `json:"id,omitempty"`
	Type string                    `json:"type,omitempty"`
	Body ProposePresentationV3Body `json:"body,omitempty"`
	// Attachments is an array of attachments that further define the presentation request being proposed.
	// This might be used to clarify which formats or format versions are wanted.
	Attachments []decorator.AttachmentV2 `json:"attachments,omitempty"`
}

// ProposePresentationV3Body represents body for ProposePresentationV3.
type ProposePresentationV3Body struct {
	GoalCode string `json:"goal_code,omitempty"`
	// Comment is a field that provides some human readable information about the proposed presentation.
	// TODO: Should follow DIDComm conventions for l10n. [Issue #1300]
	Comment string `json:"comment,omitempty"`
}

// RequestPresentationV2 describes values that need to be revealed and predicates that need to be fulfilled.
type RequestPresentationV2 struct {
	ID   string `json:"@id,omitempty"`
	Type string `json:"@type,omitempty"`
	// Comment is a field that provides some human readable information about the proposed presentation.
	// TODO: Should follow DIDComm conventions for l10n. [Issue #1300]
	Comment string `json:"comment,omitempty"`
	// WillConfirm is a field that defaults to "false" to indicate that the verifier will or will not
	// send a post-presentation confirmation ack message.
	WillConfirm bool `json:"will_confirm,omitempty"`
	// Formats contains an entry for each request_presentations~attach array entry, providing the the value of the
	// attachment @id and the verifiable presentation request format and version of the attachment.
	Formats []Format `json:"formats,omitempty"`
	// RequestPresentationsAttach is an array of attachments containing the acceptable verifiable presentation requests.
	RequestPresentationsAttach []decorator.Attachment `json:"request_presentations~attach,omitempty"`
}

// RequestPresentationV3 describes values that need to be revealed and predicates that need to be fulfilled.
type RequestPresentationV3 struct {
	ID   string                    `json:"id,omitempty"`
	Type string                    `json:"type,omitempty"`
	Body RequestPresentationV3Body `json:"body,omitempty"`
	// Attachments is an array of attachments containing the acceptable verifiable presentation requests.
	Attachments []decorator.AttachmentV2 `json:"attachments,omitempty"`
}

// RequestPresentationV3Body represents body for RequestPresentationV3.
type RequestPresentationV3Body struct {
	GoalCode string `json:"goal_code,omitempty"`
	// Comment is a field that provides some human readable information about the proposed presentation.
	// TODO: Should follow DIDComm conventions for l10n. [Issue #1300]
	Comment string `json:"comment,omitempty"`
	// WillConfirm is a field that defaults to "false" to indicate that the verifier will or will not
	// send a post-presentation confirmation ack message.
	WillConfirm bool `json:"will_confirm,omitempty"`
}

// PresentationV2 is a response to a RequestPresentationV2 message and contains signed presentations.
// TODO: Add ~please_ack decorator support for the protocol [Issue #2047].
type PresentationV2 struct {
	ID   string `json:"@id,omitempty"`
	Type string `json:"@type,omitempty"`
	// Comment is a field that provides some human readable information about the proposed presentation.
	// TODO: Should follow DIDComm conventions for l10n. [Issue #1300].
	Comment string `json:"comment,omitempty"`
	// Formats contains an entry for each presentations~attach array entry, providing the the value of the attachment
	// @id and the verifiable presentation format and version of the attachment.
	Formats []Format `json:"formats,omitempty"`
	// PresentationsAttach an array of attachments containing the presentation in the requested format(s).
	PresentationsAttach []decorator.Attachment `json:"presentations~attach,omitempty"`
}

// Format contains the value of the attachment @id and the verifiable credential format of the attachment.
type Format struct {
	AttachID string `json:"attach_id,omitempty"`
	Format   string `json:"format,omitempty"`
}

// PresentationV3 is a response to a RequestPresentationV3 message and contains signed presentations.
type PresentationV3 struct {
	Type string             `json:"type,omitempty"`
	Body PresentationV3Body `json:"body,omitempty"`
	// Attachments is an array of attachments that further define the presentation request being proposed.
	// This might be used to clarify which formats or format versions are wanted.
	Attachments []decorator.AttachmentV2 `json:"attachments,omitempty"`
}

// PresentationV3Body represents body for PresentationV3.
type PresentationV3Body struct {
	GoalCode string `json:"goal_code,omitempty"`
	// Comment is a field that provides some human readable information about the proposed presentation.
	// TODO: Should follow DIDComm conventions for l10n. [Issue #1300]
	Comment string `json:"comment,omitempty"`
}
