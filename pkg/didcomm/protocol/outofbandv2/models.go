/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofbandv2

import "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"

// Invitation is this protocol's `invitation` message.
type Invitation struct {
	ID       string                    `json:"id"`
	Type     string                    `json:"type"`
	Label    string                    `json:"label,omitempty"`
	From     string                    `json:"from"`
	Body     *InvitationBody           `json:"body"`
	Requests []*decorator.AttachmentV2 `json:"attachments,omitempty"`
}

// InvitationBody contains invitation's goal and accept headers.
type InvitationBody struct {
	Goal     string   `json:"goal,omitempty"`
	GoalCode string   `json:"goal-code,omitempty"`
	Accept   []string `json:"accept,omitempty"`
}
