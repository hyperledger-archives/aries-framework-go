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
	ID     string           `json:"@id"`
	Thread decorator.Thread `json:"~thread"`
	Type   string           `json:"@type"`
}

func (h *Header) clone() *Header {
	if h == nil {
		return nil
	}

	return &Header{
		ID: h.ID,
		Thread: decorator.Thread{
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
		Type: h.Type,
	}
}

// DIDCommMsg did comm msg
type DIDCommMsg struct {
	Header  *Header
	Payload []byte
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

// NewDIDCommMsg returns DIDCommMsg with Header
func NewDIDCommMsg(payload []byte) (*DIDCommMsg, error) {
	msg := &DIDCommMsg{Payload: payload}

	err := json.Unmarshal(msg.Payload, &msg.Header)
	if err != nil {
		return nil, fmt.Errorf("invalid payload data format: %w", err)
	}

	return msg, nil
}

// ThreadID returns msg ~thread.thid if there is no ~thread.thid returns msg @id
// message is invalid if ~thread.thid exist and @id is absent
// NOTE: Header field should be filled before calling ThreadID func
// it can be done by using NewDIDCommMsg([]byte) func or directly set a Header value
func (m *DIDCommMsg) ThreadID() (string, error) {
	if m.Header == nil {
		return "", ErrNoHeader
	}
	// if message has ~thread.thid but @id is absent this is invalid message
	if len(m.Header.Thread.ID) > 0 && m.Header.ID == "" {
		return "", ErrInvalidMessage
	}

	if len(m.Header.Thread.ID) > 0 {
		return m.Header.Thread.ID, nil
	}

	// we need to return it only if there is no ~thread.thid
	if len(m.Header.ID) > 0 {
		return m.Header.ID, nil
	}

	return "", ErrThreadIDNotFound
}
