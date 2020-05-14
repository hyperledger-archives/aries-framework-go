/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mediator

// Request route request message.
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0211-route-coordination#route-request
type Request struct {
	Type string `json:"@type,omitempty"`
	ID   string `json:"@id,omitempty"`
}

// Grant route grant message.
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0211-route-coordination#route-grant
type Grant struct {
	Type        string   `json:"@type,omitempty"`
	ID          string   `json:"@id,omitempty"`
	Endpoint    string   `json:"endpoint,omitempty"`
	RoutingKeys []string `json:"routing_keys,omitempty"`
}

// KeylistUpdate route keylist update message.
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0211-route-coordination#keylist-update
type KeylistUpdate struct {
	Type    string   `json:"@type,omitempty"`
	ID      string   `json:"@id,omitempty"`
	Updates []Update `json:"updates,omitempty"`
}

// Update route key update message.
type Update struct {
	RecipientKey string `json:"recipient_key,omitempty"`
	Action       string `json:"action,omitempty"`
}

// KeylistUpdateResponse route keylist update response message.
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0211-route-coordination#keylist-update-response
type KeylistUpdateResponse struct {
	Type    string           `json:"@type,omitempty"`
	ID      string           `json:"@id,omitempty"`
	Updated []UpdateResponse `json:"updated,omitempty"`
}

// UpdateResponse route key update response message.
type UpdateResponse struct {
	RecipientKey string `json:"recipient_key,omitempty"`
	Action       string `json:"action,omitempty"`
	Result       string `json:"result,omitempty"`
}
