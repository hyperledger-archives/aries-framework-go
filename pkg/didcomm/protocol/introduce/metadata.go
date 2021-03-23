/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
)

const (
	// protocol instance ID.
	metaPIID         = Introduce + "_pi_id"
	metaSkipProposal = Introduce + "_skip_proposal"
	metaOOBMessage   = Introduce + "_oobmessage"
	metaRecipients   = Introduce + "_recipients"
	metaAttachment   = Introduce + "_attachment"
)

// Opt describes option signature for the Continue function.
type Opt func(m map[string]interface{})

// WithOOBInvitation is used when introducee wants to provide an out-of-band request.
// NOTE: Introducee can provide this request only after receiving ProposalMsgType
// USAGE: event.Continue(WithOOBInvitation(req)).
func WithOOBInvitation(inv *outofband.Invitation, attachments ...*decorator.Attachment) Opt {
	return func(m map[string]interface{}) {
		m[metaOOBMessage] = service.NewDIDCommMsgMap(inv)
		m[metaAttachment] = attachments
	}
}

// WithPublicOOBInvitation is used when introducer wants to provide public an out-of-band request.
// NOTE: Introducer can provide this request only after receiving RequestMsgType
// USAGE: event.Continue(WithPublicOOBInvitation(req, to)).
func WithPublicOOBInvitation(inv *outofband.Invitation, to *To) Opt {
	return func(m map[string]interface{}) {
		m[metaOOBMessage] = service.NewDIDCommMsgMap(inv)
		m[metaSkipProposal] = true
		m[metaRecipients] = []interface{}{&Recipient{
			To: to,
		}}
	}
}

// WithRecipients is used when the introducer does not have a public invitation
// but he is willing to introduce agents to each other.
// NOTE: Introducer can provide recipients only after receiving RequestMsgType.
// USAGE: event.Continue(WithRecipients(to, recipient)).
func WithRecipients(to *To, recipient *Recipient) Opt {
	return func(m map[string]interface{}) {
		m[metaRecipients] = []interface{}{
			&Recipient{To: to}, recipient,
		}
	}
}

// WrapWithMetadataPIID wraps message with metadata.
// The function is used by the introduce client to define that a few messages are related to each other.
// e.g When two proposals are sent simultaneously piID helps the protocol to determine that messages are related.
func WrapWithMetadataPIID(msgMap ...service.DIDCommMsg) {
	piID := uuid.New().String()

	for _, msg := range msgMap {
		msg.Metadata()[metaPIID] = piID
	}
}

// WrapWithMetadataPublicOOBInvitation wraps message with metadata.
// The function is used by the introduce client to define skip proposal.
// It also saves invitation and will provide it later to the introducee.
func WrapWithMetadataPublicOOBInvitation(msg service.DIDCommMsgMap, req *outofband.Invitation) {
	msg.Metadata()[metaOOBMessage] = service.NewDIDCommMsgMap(req)
	msg.Metadata()[metaSkipProposal] = true
}

func copyMetadata(from, to service.DIDCommMsg) {
	for k, v := range from.Metadata() {
		to.Metadata()[k] = v
	}
}
