/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

import "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"

// acknowledgement status constants.
// Refer https://github.com/hyperledger/aries-rfcs/blob/main/features/0015-acks/README.md#ack-status.
const (
	AckStatusOK      = "OK"
	AckStatusFAIL    = "FAIL"
	AckStatusPENDING = "PENDING"
)

// Ack acknowledgement struct.
type Ack struct {
	Type        string            `json:"@type,omitempty"`
	ID          string            `json:"@id,omitempty"`
	Status      string            `json:"status,omitempty"`
	Thread      *decorator.Thread `json:"~thread,omitempty"`
	WebRedirect interface{}       `json:"~web-redirect,omitempty"`
}

// AckV2 acknowledgement struct.
type AckV2 struct {
	ID          string      `json:"id,omitempty"`
	Type        string      `json:"type,omitempty"`
	WebRedirect interface{} `json:"web-redirect,omitempty"`
	Body        AckV2Body   `json:"body,omitempty"`
}

// AckV2Body represents body for AckV2.
type AckV2Body struct {
	Status string `json:"status,omitempty"`
}
