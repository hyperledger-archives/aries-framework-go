/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"

// InvitationRequest model
//
// This is used for returning a create invitation response with a single connection invitation as body
//
//
type InvitationRequest struct {

	// the URL of the invitation.
	URL string `json:"invitation_url"`

	// the Invitation of the connection
	Invitation *didexchange.Invitation `json:"invitation"`

	// the ID of the connection
	ID string `json:"connection_id"`
}
