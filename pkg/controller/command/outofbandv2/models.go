/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofbandv2

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofbandv2"
)

// CreateInvitationArgs model
//
// This is used for creating an invitation.
//
type CreateInvitationArgs struct {
	Label string                     `json:"label"`
	Body  outofbandv2.InvitationBody `json:"body"`
	From  string                     `json:"from"`
	// Attachments are intended to provide the possibility to include files, links or even JSON payload to the message.
	Attachments []*decorator.AttachmentV2 `json:"attachments"`
}

// CreateInvitationResponse model
//
// Represents a CreateInvitation response message.
//
type CreateInvitationResponse struct {
	Invitation *outofbandv2.Invitation `json:"invitation"`
}

// AcceptInvitationArgs model
//
// This is used for accepting an invitation.
//
type AcceptInvitationArgs struct {
	Invitation *outofbandv2.Invitation `json:"invitation"`
	MyLabel    string                  `json:"my_label"`
}

// AcceptInvitationResponse model
//
// Represents a AcceptInvitation response message.
//
type AcceptInvitationResponse struct {
	ConnectionID string `json:"connection_id"`
}
