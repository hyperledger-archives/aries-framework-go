/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

import "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"

// Ack acknowledgement struct
type Ack struct {
	Type   string            `json:"@type,omitempty"`
	ID     string            `json:"@id,omitempty"`
	Status string            `json:"status,omitempty"`
	Thread *decorator.Thread `json:"~thread,omitempty"`
}
