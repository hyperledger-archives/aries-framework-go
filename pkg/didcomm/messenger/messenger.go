/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package messenger

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// MessengerStore is messenger store name.
const MessengerStore = "messenger_store"

// record is an internal structure and keeps payload about inbound message.
type record struct {
	MyDID          string `json:"my_did,omitempty"`
	TheirDID       string `json:"their_did,omitempty"`
	ThreadID       string `json:"thread_id,omitempty"`
	ParentThreadID string `json:"parent_thread_id,omitempty"`
}

// Provider contains dependencies for the Messenger.
type Provider interface {
	OutboundDispatcher() dispatcher.Outbound
	StorageProvider() storage.Provider
}

// Messenger describes the messenger structure.
type Messenger struct {
	store      storage.Store
	dispatcher dispatcher.Outbound
}

var logger = log.New("aries-framework/pkg/didcomm/messenger")

// NewMessenger returns a new instance of the Messenger.
func NewMessenger(ctx Provider) (*Messenger, error) {
	store, err := ctx.StorageProvider().OpenStore(MessengerStore)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	return &Messenger{
		store:      store,
		dispatcher: ctx.OutboundDispatcher(),
	}, nil
}

// HandleInbound handles all inbound messages.
func (m *Messenger) HandleInbound(msg service.DIDCommMsgMap, ctx service.DIDCommContext) error {
	// an incoming message cannot be without id
	if msg.ID() == "" {
		return errors.New("message-id is absent and can't be processed")
	}

	// get message threadID
	thID, err := msg.ThreadID()
	if err != nil {
		// since we are checking ID above this should never happen
		// even if ~thread decorator is absent the message ID should be returned as a threadID
		return fmt.Errorf("threadID: %w", err)
	}

	// saves message payload
	return m.saveRecord(msg.ID(), record{
		ParentThreadID: msg.ParentThreadID(),
		MyDID:          ctx.MyDID(),
		TheirDID:       ctx.TheirDID(),
		ThreadID:       thID,
	})
}

// Send sends the message by starting a new thread.
// Do not provide a message with ~thread decorator. It will be removed.
// Use ReplyTo function instead. It will keep ~thread decorator automatically.
func (m *Messenger) Send(msg service.DIDCommMsgMap, myDID, theirDID string, opts ...service.Opt) error {
	// fills missing fields
	fillIfMissing(msg, opts...)

	msg.UnsetThread()
	msg.SetThread(msg.ID(), "", opts...)

	return m.dispatcher.SendToDID(msg, myDID, theirDID)
}

// SendToDestination sends the message to given destination by starting a new thread.
// Do not provide a message with ~thread decorator. It will be removed.
// Use ReplyTo function instead. It will keep ~thread decorator automatically.
func (m *Messenger) SendToDestination(msg service.DIDCommMsgMap, sender string,
	destination *service.Destination, opts ...service.Opt) error {
	// fills missing fields
	fillIfMissing(msg, opts...)

	msg.UnsetThread()

	return m.dispatcher.Send(msg, sender, destination)
}

// ReplyTo replies to the message by given msgID.
// The function adds ~thread decorator to the message according to the given msgID.
// Do not provide a message with ~thread decorator. It will be rewritten.
func (m *Messenger) ReplyTo(msgID string, msg service.DIDCommMsgMap, opts ...service.Opt) error {
	// fills missing fields
	fillIfMissing(msg, opts...)

	rec, err := m.getRecord(msgID)
	if err != nil {
		return fmt.Errorf("get record: %w", err)
	}

	msg.UnsetThread()
	// sets thread
	msg.SetThread(rec.ThreadID, rec.ParentThreadID, opts...)

	return m.dispatcher.SendToDID(msg, rec.MyDID, rec.TheirDID)
}

// ReplyToMsg replies to the given message.
// The function adds ~thread decorator to the message according to the given msgID.
// Do not provide a message with ~thread decorator. It will be rewritten.
func (m *Messenger) ReplyToMsg(in, out service.DIDCommMsgMap, myDID, theirDID string, opts ...service.Opt) error {
	// fills missing fields
	fillIfMissing(out, opts...)

	thID, err := in.ThreadID()
	if err != nil {
		return fmt.Errorf("get threadID: %w", err)
	}

	out.UnsetThread()
	// sets thread
	out.SetThread(thID, in.ParentThreadID(), opts...)

	return m.dispatcher.SendToDID(out, myDID, theirDID)
}

// ReplyToNested sends the message by starting a new thread.
// Do not provide a message with ~thread decorator. It will be rewritten.
// The function adds ~thread decorator to the message according to the given threadID.
// NOTE: Given threadID (from opts or from message record) becomes parent threadID.
func (m *Messenger) ReplyToNested(msg service.DIDCommMsgMap, opts *service.NestedReplyOpts) error {
	// fills missing fields
	fillIfMissing(msg, service.WithVersion(opts.V))

	if err := m.fillNestedReplyOption(opts); err != nil {
		return fmt.Errorf("failed to prepare nested reply options: %w", err)
	}

	msg.UnsetThread()
	// sets parent thread id
	msg.SetThread("", opts.ThreadID, service.WithVersion(opts.V))

	return m.dispatcher.SendToDID(msg, opts.MyDID, opts.TheirDID)
}

// fillIfMissing populates message with common fields such as ID.
func fillIfMissing(msg service.DIDCommMsgMap, opts ...service.Opt) {
	// if ID is empty we will create a new one
	if msg.ID() == "" {
		msg.SetID(uuid.New().String(), opts...)
	}
}

// getRecord returns message payload by msgID.
func (m *Messenger) getRecord(msgID string) (*record, error) {
	src, err := m.store.Get(msgID)
	if err != nil {
		return nil, fmt.Errorf("store get: %w", err)
	}

	var r *record
	if err = json.Unmarshal(src, &r); err != nil {
		return nil, fmt.Errorf("unmarshal record: %w", err)
	}

	return r, nil
}

// saveRecord saves incoming message payload.
func (m *Messenger) saveRecord(msgID string, rec record) error {
	src, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal record: %w", err)
	}

	return m.store.Put(msgID, src)
}

// fillNestedReplyOption prefills missing nested reply options from record.
func (m *Messenger) fillNestedReplyOption(opts *service.NestedReplyOpts) error {
	if opts.ThreadID != "" && opts.TheirDID != "" && opts.MyDID != "" {
		return nil
	}

	if opts.MsgID == "" { // nolint: staticcheck
		logger.Debugf("failed to prepare fill nested reply options, missing message ID")
		return nil
	}

	rec, err := m.getRecord(opts.MsgID) // nolint: staticcheck
	if err != nil {
		return err
	}

	if opts.ThreadID == "" {
		opts.ThreadID = rec.ThreadID
	}

	if opts.TheirDID == "" {
		opts.TheirDID = rec.TheirDID
	}

	if opts.MyDID == "" {
		opts.MyDID = rec.MyDID
	}

	return nil
}
