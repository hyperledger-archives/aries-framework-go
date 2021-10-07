/*
Copyright Scoir Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package messagepickup

import (
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
)

// StatusRequest sent by the recipient to the message_holder to request a status message./0212-pickup#statusrequest
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0212-pickup#statusrequest
type StatusRequest struct {
	Type   string            `json:"@type,omitempty"`
	ID     string            `json:"@id,omitempty"`
	Thread *decorator.Thread `json:"~thread,omitempty"`
}

// Status details about pending messages
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0212-pickup#status
type Status struct {
	Type              string            `json:"@type,omitempty"`
	ID                string            `json:"@id,omitempty"`
	MessageCount      int               `json:"message_count"`
	DurationWaited    int               `json:"duration_waited,omitempty"`
	LastAddedTime     time.Time         `json:"last_added_time,omitempty"`
	LastDeliveredTime time.Time         `json:"last_delivered_time,omitempty"`
	LastRemovedTime   time.Time         `json:"last_removed_time,omitempty"`
	TotalSize         int               `json:"total_size,omitempty"`
	Thread            *decorator.Thread `json:"~thread,omitempty"`
}

// BatchPickup a request to have multiple waiting messages sent inside a batch message.
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0212-pickup#batch-pickup
type BatchPickup struct {
	Type      string            `json:"@type,omitempty"`
	ID        string            `json:"@id,omitempty"`
	BatchSize int               `json:"batch_size"`
	Thread    *decorator.Thread `json:"~thread,omitempty"`
}

// Batch a message that contains multiple waiting messages.
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0212-pickup#batch
type Batch struct {
	Type     string            `json:"@type,omitempty"`
	ID       string            `json:"@id,omitempty"`
	Messages []*Message        `json:"messages~attach"`
	Thread   *decorator.Thread `json:"~thread,omitempty"`
}

// Message messagepickup wrapper.
type Message struct {
	ID        string    `json:"id"`
	AddedTime time.Time `json:"added_time"`
	Message   []byte    `json:"msg,omitempty"`
}

// Noop message
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0212-pickup#noop
type Noop struct {
	Type string `json:"@type,omitempty"`
	ID   string `json:"@id,omitempty"`
}
