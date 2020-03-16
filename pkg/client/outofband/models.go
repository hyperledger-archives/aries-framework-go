/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"

// Request embeds the sender's request.
type Request struct {
	ID       string                  `json:"@id"`
	Type     string                  `json:"@type"`
	Label    string                  `json:"label,omitempty"`
	Goal     string                  `json:"goal,omitempty"`
	GoalCode string                  `json:"goal-code,omitempty"`
	Requests []*decorator.Attachment `json:"request~attach"`
	Service  []interface{}           `json:"service"` // Service is an array of either DIDs or 'service' block entries.
}
