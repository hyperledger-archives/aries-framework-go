/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"

// ProposePresentation is an optional message sent by the Prover to the verifier to initiate a proof
// presentation process, or in response to a request-presentation message when the Prover wants to
// propose using a different presentation format.
type ProposePresentation struct {
	Type string `json:"@type,omitempty"`
	// Comment is a field that provides some human readable information about the proposed presentation.
	// TODO: Should follow DIDComm conventions for l10n. [Issue #1300]
	Comment string `json:"comment,omitempty"`
	// PresentationProposal is a JSON-LD object that represents the presentation example that Prover wants to provide.
	PresentationProposal PresentationPreview `json:"presentation_proposal,omitempty"`
}

// RequestPresentation describes values that need to be revealed and predicates that need to be fulfilled.
type RequestPresentation struct {
	Type string `json:"@type,omitempty"`
	// Comment is a field that provides some human readable information about the proposed presentation.
	// TODO: Should follow DIDComm conventions for l10n. [Issue #1300]
	Comment string `json:"comment,omitempty"`
	// RequestPresentations is a slice of attachments defining the acceptable formats for the presentation.
	RequestPresentations []decorator.Attachment `json:"request_presentations~attach,omitempty"`
}

// Presentation is a response to a RequestPresentation message and contains signed presentations.
type Presentation struct {
	Type string `json:"@type,omitempty"`
	// Comment is a field that provides some human readable information about the proposed presentation.
	// TODO: Should follow DIDComm conventions for l10n. [Issue #1300]
	Comment string `json:"comment,omitempty"`
	// Presentations is a slice of attachments containing the presentation in the requested format(s).
	Presentations []decorator.Attachment `json:"presentations~attach,omitempty"`
}

// PresentationPreview is used to construct a preview of the data for the presentation.
type PresentationPreview struct {
	Type       string      `json:"@type,omitempty"`
	Attributes []Attribute `json:"attributes,omitempty"`
	Predicates []Predicate `json:"predicates,omitempty"`
}

// Attribute describes an attribute for the PresentationPreview
type Attribute struct {
	Name      string `json:"name"`
	CredDefID string `json:"cred_def_id"`
	MimeType  string `json:"mime-type,omitempty"`
	Value     string `json:"value"`
	Referent  string `json:"referent"`
}

// Predicate describes a predicate for the PresentationPreview
type Predicate struct {
	Name      string `json:"name"`
	CredDefID string `json:"cred_def_id"`
	Predicate string `json:"predicate"`
	Threshold string `json:"threshold"`
}
