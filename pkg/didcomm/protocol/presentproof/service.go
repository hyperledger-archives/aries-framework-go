/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

const (
	// Name defines the protocol name
	Name = "present-proof"
	// Spec defines the protocol spec
	Spec = "https://didcomm.org/present-proof/1.0/"
	// ProposePresentationMsgType defines the protocol propose-presentation message type.
	ProposePresentationMsgType = Spec + "propose-presentation"
	// RequestPresentationMsgType defines the protocol request-presentation message type.
	RequestPresentationMsgType = Spec + "request-presentation"
	// PresentationMsgType defines the protocol presentation message type.
	PresentationMsgType = Spec + "presentation"
	// AckMsgType defines the protocol ack message type.
	AckMsgType = Spec + "ack"
	// ProblemReportMsgType defines the protocol problem-report message type.
	ProblemReportMsgType = Spec + "problem-report"
	// PresentationPreviewMsgType defines the protocol presentation-preview inner object type.
	PresentationPreviewMsgType = Spec + "presentation-preview"
)
