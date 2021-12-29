/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connection

// RotateDIDRequest request to rotate MyDID in the connection with the given ID.
type RotateDIDRequest struct {
	ID            string `json:"id"`
	KID           string `json:"kid"`
	NewDID        string `json:"new_did"`
	CreatePeerDID bool   `json:"create_peer_did"`
}

// RotateDIDResponse response from a DID rotation call, with the new DID that the connection was rotated to.
type RotateDIDResponse struct {
	NewDID string `json:"new_did"`
}

// CreateConnectionRequest request to create a didcomm v2 connection.
type CreateConnectionRequest struct {
	MyDID    string `json:"my_did"`
	TheirDID string `json:"their_did"`
}

// IDMessage is either a request or response message, holding connection ID.
// Used for:
// - response from creating a didcomm v2 connection.
// - request to set a connection to didcomm v2.
type IDMessage struct {
	ConnectionID string `json:"id"`
}
