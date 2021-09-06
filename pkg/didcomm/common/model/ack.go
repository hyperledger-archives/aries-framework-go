/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

import "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"

// Ack acknowledgement struct.
type Ack struct {
	Type   string            `json:"@type,omitempty"`
	ID     string            `json:"@id,omitempty"`
	Status string            `json:"status,omitempty"`
	Thread *decorator.Thread `json:"~thread,omitempty"`
}

// AckV2 acknowledgement struct.
type AckV2 struct {
	ID   string    `json:"id,omitempty"`
	Type string    `json:"type,omitempty"`
	Body AckV2Body `json:"body,omitempty"`
}

// AckV2Body represents body for AckV2.
type AckV2Body struct {
	Status string `json:"status,omitempty"`
}
