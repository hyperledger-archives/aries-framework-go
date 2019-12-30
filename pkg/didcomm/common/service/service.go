/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
)

// Handler provides protocol service handle api.
type Handler interface {
	// HandleInbound handles inbound messages.
	HandleInbound(msg *DIDCommMsg, myDID string, theirDID string) (string, error)
	// HandleOutbound handles outbound messages.
	HandleOutbound(msg *DIDCommMsg, myDID, theirDID string) error
}

// DIDComm defines service APIs.
type DIDComm interface {
	// service handler
	Handler
	// event service
	Event
}

// Header helper structure which keeps reusable fields
type Header struct {
	ID     string            `json:"@id,omitempty"`
	Thread *decorator.Thread `json:"~thread,omitempty"`
	Type   string            `json:"@type,omitempty"`
}

// MsgID returns message ID
func (h *Header) MsgID() string {
	if h != nil {
		return h.ID
	}

	return ""
}

// MsgThread returns message thread decorator
func (h *Header) MsgThread() *decorator.Thread {
	if h != nil {
		return h.Thread
	}

	return nil
}

// MsgType returns message type
func (h *Header) MsgType() string {
	if h != nil {
		return h.Type
	}

	return ""
}

// ThreadID returns msg ~thread.thid if there is no ~thread.thid returns msg @id
// message is invalid if ~thread.thid exist and @id is absent
func (h *Header) ThreadID() (string, error) {
	// we need to return it only if there is no ~thread.thid
	if h.MsgThread() == nil {
		if len(h.MsgID()) > 0 {
			return h.MsgID(), nil
		}

		return "", ErrInvalidMessage
	}

	// if message has ~thread.thid but @id is absent this is invalid message
	if len(h.MsgThread().ID) > 0 && h.MsgID() == "" {
		return "", ErrInvalidMessage
	}

	if len(h.MsgThread().ID) > 0 {
		return h.MsgThread().ID, nil
	}

	if len(h.MsgID()) > 0 {
		return h.MsgID(), nil
	}

	return "", ErrThreadIDNotFound
}

func (h *Header) clone() *Header {
	if h == nil {
		return nil
	}

	if h.MsgThread() == nil {
		return &Header{
			ID:     h.MsgID(),
			Thread: h.MsgThread(),
			Type:   h.MsgType(),
		}
	}

	return &Header{
		ID: h.MsgID(),
		Thread: &decorator.Thread{
			ID:          h.Thread.ID,
			PID:         h.Thread.PID,
			SenderOrder: h.Thread.SenderOrder,
			// copies ReceivedOrders value
			ReceivedOrders: func() map[string]int {
				if h.Thread.ReceivedOrders == nil {
					return nil
				}

				orders := make(map[string]int, len(h.Thread.ReceivedOrders))

				for k, v := range h.Thread.ReceivedOrders {
					orders[k] = v
				}

				return orders
			}(),
		},
		Type: h.MsgType(),
	}
}

// DIDCommMsg did comm msg
type DIDCommMsg struct {
	*Header
	Payload []byte
}

// NewDIDCommMsg returns DIDCommMsg with Header
func NewDIDCommMsg(payload []byte) (*DIDCommMsg, error) {
	msg := &DIDCommMsg{Payload: payload}

	err := json.Unmarshal(msg.Payload, &msg.Header)
	if err != nil {
		return nil, fmt.Errorf("invalid payload data format: %w", err)
	}

	return msg, nil
}

// Clone creates new DIDCommMsg with the same data
// the cloned message is safe for delivering to the client
// it prevents modifying by the client
func (m *DIDCommMsg) Clone() *DIDCommMsg {
	if m == nil {
		return nil
	}

	return &DIDCommMsg{
		Header:  m.Header.clone(),
		Payload: append(m.Payload[:0:0], m.Payload...),
	}
}
