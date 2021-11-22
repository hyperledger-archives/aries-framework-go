/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofbandv2

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofbandv2"
)

// outofbandV2CreateInvitationRequest model
//
// This is used for operation to create an invitation.
//
// swagger:parameters outofbandV2CreateInvitation
type outofbandV2CreateInvitationRequest struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		Label string                     `json:"label"`
		Body  outofbandv2.InvitationBody `json:"body"`
		// Attachments is intended to provide the possibility to include files, links or even JSON payload to the message.
		// required: true
		Attachments []*decorator.AttachmentV2 `json:"attachments"`
	}
}

// outofbandV2CreateInvitationResponse model
//
// Represents a CreateInvitation response message.
//
// swagger:response outofbandV2CreateInvitationResponse
type outofbandV2CreateInvitationResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		Invitation struct{ *outofbandv2.Invitation } `json:"invitation"`
	}
}

// outofbandV2AcceptInvitationRequest model
//
// This is used for operation to accept an invitation.
//
// swagger:parameters outofbandV2AcceptInvitation
type outofbandV2AcceptInvitationRequest struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		Invitation struct{ *outofbandv2.Invitation } `json:"invitation"`
		MyLabel    string                            `json:"my_label"`
	}
}

// outofbandV2AcceptInvitationResponse model
//
// Represents a AcceptInvitation response message.
//
// swagger:response outofbandV2AcceptInvitationResponse
type outofbandV2Response struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}
