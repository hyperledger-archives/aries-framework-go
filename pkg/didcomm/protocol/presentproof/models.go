/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"

// ProposePresentation is an optional message sent by the prover to the verifier to initiate a proof presentation
// process, or in response to a request-presentation message when the prover wants to propose
// using a different presentation format or request.
type ProposePresentation struct {
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

// RequestPresentation describes values that need to be revealed and predicates that need to be fulfilled.
type RequestPresentation struct {
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

// Presentation is a response to a RequestPresentation message and contains signed presentations.
// TODO: Add ~please_ack decorator support for the protocol [Issue #2047].
type Presentation struct {
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

// Format contains the the value of the attachment @id and the verifiable credential format of the attachment.
type Format struct {
	AttachID string `json:"attach_id,omitempty"`
	Format   string `json:"format,omitempty"`
}
