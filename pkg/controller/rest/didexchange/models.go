/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	didexchangeSvc "github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/didexchange"
)

// createInvitationRequest model
//
// This is used for operation to create invitation
//
// swagger:parameters createInvitation
type createInvitationRequest struct { // nolint: unused,deadcode
	// Params for creating invitation
	//
	// in: path
	didexchange.CreateInvitationArgs
}

// createInvitationResponse model
//
// This is used for returning a create invitation response with a single connection invitation as body
//
// swagger:response createInvitationResponse
type createInvitationResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		Invitation    struct{ *didexchangeSvc.Invitation } `json:"invitation"`
		Alias         string                               `json:"alias"`
		InvitationURL string                               `json:"invitation_url"`
	}
}

// receiveInvitationRequest model
//
// This is used for operation to receive connection invitation
//
// swagger:parameters receiveInvitation
type receiveInvitationRequest struct { // nolint: unused,deadcode
	// The Invitation Invitation to receive
	//
	// required: true
	// in: body
	Invitation struct {
		*didexchangeSvc.Invitation
	}
}

// receiveInvitationResponse model
//
// This is used for returning a receive invitation response with a single receive invitation response as body
//
// swagger:response receiveInvitationResponse
type receiveInvitationResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		didexchange.ReceiveInvitationResponse
	}
}

// acceptInvitationRequest model
//
// This is used for operation to accept connection invitation
//
// swagger:parameters acceptInvitation
type acceptInvitationRequest struct { // nolint: unused,deadcode
	// Connection ID
	//
	// in: path
	// required: true
	ID string `json:"id"`

	// Optional Public DID to be used for this request
	Public string `json:"public"`

	// Optional specifies router connections (comma-separated values)
	RouterConnections string `json:"router_connections"`
}

// acceptInvitationResponse model
//
// This is used for returning a accept invitation response for single invitation
//
// swagger:response acceptInvitationResponse
type acceptInvitationResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		didexchange.AcceptInvitationResponse
	}
}

// implicitInvitationRequest model
//
// This is used by invitee to create implicit invitation
//
// swagger:parameters implicitInvitation
type implicitInvitationRequest struct { // nolint: unused,deadcode
	// InviterDID
	InviterDID string `json:"their_did"`

	// Optional inviter label
	InviterLabel string `json:"their_label"`

	// Optional invitee did
	InviteeDID string `json:"my_did"`

	// Optional invitee label
	InviteeLabel string `json:"my_label"`

	// Optional specifies router connections (comma-separated values)
	RouterConnections string `json:"router_connections"`
}

// implicitInvitationResponse model
//
// This is used for returning create implicit invitation response
//
// swagger:response implicitInvitationResponse
type implicitInvitationResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		didexchange.ImplicitInvitationResponse
	}
}

// getConnectionRequest model
//
// This is used for getting specific connection record
//
// swagger:parameters getConnection
type getConnectionRequest struct { // nolint: unused,deadcode
	// The ID of the connection to get
	//
	// in: path
	// required: true
	ID string `json:"id"`
}

// queryConnections model
//
// This is used for querying connections
//
// swagger:parameters queryConnections
type queryConnections struct { // nolint: unused,deadcode
	// Params for querying connections
	//
	// in: path
	// required: true
	didexchangeSvc.QueryConnectionsParams
}

// queryConnectionResponse model
//
// This is used for returning query connection result for single record search
//
// swagger:response queryConnectionResponse
type queryConnectionResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		Result *didexchangeSvc.Connection `json:"result,omitempty"`
	}
}

// queryConnectionsResponse model
//
// This is used for returning query connections results
//
// swagger:response queryConnectionsResponse
type queryConnectionsResponse struct { // nolint: unused,deadcode

	// in: body
	Body struct {
		Results []*didexchangeSvc.Connection `json:"results,omitempty"`
	}
}

// acceptExchangeRequestParams model
//
// This is used for accepting connection request
//
// swagger:parameters acceptRequest
type acceptExchangeRequestParams struct { // nolint: unused,deadcode
	// Connection ID
	//
	// in: path
	// required: true
	ID string `json:"id"`

	// Optional Public DID to be used for this invitation
	// request
	Public string `json:"public"`

	// Optional specifies router connections (comma-separated values)
	RouterConnections string `json:"router_connections"`
}

// acceptExchangeResult model
//
// This is used for returning response for accept exchange request
//
// swagger:response acceptExchangeResponse
type acceptExchangeResult struct { // nolint: unused,deadcode

	// in: body
	Result didexchange.ExchangeResponse
}

// RemoveConnectionRequest model
//
// This is used for removing connection request
//
// swagger:parameters removeConnection
type RemoveConnectionRequest struct {
	// The ID of the connection record to remove
	//
	// in: path
	// required: true
	ID string `json:"id"`
}

// RemoveConnectionResponse model
//
// response of remove connection action
//
// swagger:response removeConnectionResponse
type RemoveConnectionResponse struct {
	// in: body
	Body struct{}
}

// createConnectionResp model
//
// This is used as the response model for save connection api.
//
// swagger:response createConnectionResp
type createConnectionResp struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		// The ID of the connection to get
		//
		ID string `json:"id"`
	}
}

// createConnectionRequest model
//
// Request to create a new connection between two DIDs.
//
// swagger:parameters createConnection
type createConnectionRequest struct { // nolint: unused,deadcode
	// Params for creating a connection.
	//
	// in: body
	// required: true
	Request didexchange.CreateConnectionRequest
}
