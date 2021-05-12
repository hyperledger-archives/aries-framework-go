// +build ACAPyInterop

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"

// Invitation is this protocol's `invitation` message.
type Invitation struct {
	ID        string                  `json:"@id"`
	Type      string                  `json:"@type"`
	Label     string                  `json:"label,omitempty"`
	Goal      string                  `json:"goal,omitempty"`
	GoalCode  string                  `json:"goal_code,omitempty"`
	Services  []interface{}           `json:"service"`
	Accept    []string                `json:"accept,omitempty"`
	Protocols []string                `json:"handshake_protocols,omitempty"`
	Requests  []*decorator.Attachment `json:"request~attach,omitempty"`
}
