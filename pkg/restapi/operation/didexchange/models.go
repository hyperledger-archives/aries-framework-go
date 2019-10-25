/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

// ConnectionMsg is sent when a pairwise connection record is updated.
type ConnectionMsg struct {
	ConnectionID        string `json:"connection_id"`
	State               string `json:"state"`
	MyDid               string `json:"myDid"`
	TheirDid            string `json:"theirDid"`
	TheirLabel          string `json:"theirLabel"`
	TheirRole           string `json:"theirRole"`
	InboundConnectionID string `json:"inbound_connection_id"`
	Initiator           string `json:"initiator"`
	InvitationKey       string `json:"invitation_key"`
	RequestID           string `json:"request_id"`
	RoutingState        string `json:"routing_state"`
	Accept              string `json:"accept"`
	ErrorMsg            string `json:"error_msg"`
	InvitationMode      string `json:"invitation_mode"`
	Alias               string `json:"alias"`
}
