/*
Copyright Scoir Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package messagepickup

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	// MessagePickup defines the protocol name.
	MessagePickup = "messagepickup"
	// Spec defines the protocol spec.
	Spec = "https://didcomm.org/messagepickup/1.0/"
	// StatusMsgType defines the protocol propose-credential message type.
	StatusMsgType = Spec + "status"
	// StatusRequestMsgType defines the protocol propose-credential message type.
	StatusRequestMsgType = Spec + "status-request"
	// BatchPickupMsgType defines the protocol offer-credential message type.
	BatchPickupMsgType = Spec + "batch-pickup"
	// BatchMsgType defines the protocol offer-credential message type.
	BatchMsgType = Spec + "batch"
	// NoopMsgType defines the protocol request-credential message type.
	NoopMsgType = Spec + "noop"
)

const (
	updateTimeout = 50 * time.Second

	// Namespace is namespace of messagepickup store name.
	Namespace = "mailbox"
)

// ErrConnectionNotFound connection not found error.
var (
	ErrConnectionNotFound = errors.New("connection not found")
	logger                = log.New("aries-framework/messagepickup")
)

type provider interface {
	OutboundDispatcher() dispatcher.Outbound
	StorageProvider() storage.Provider
	ProtocolStateStorageProvider() storage.Provider
	InboundMessageHandler() transport.InboundMessageHandler
	Packager() transport.Packager
}

type connections interface {
	GetConnectionRecord(string) (*connection.Record, error)
}

// Service for the messagepickup protocol.
type Service struct {
	service.Action
	service.Message
	connectionLookup connections
	outbound         dispatcher.Outbound
	msgStore         storage.Store
	packager         transport.Packager
	msgHandler       transport.InboundMessageHandler
	batchMap         map[string]chan Batch
	batchMapLock     sync.RWMutex
	statusMap        map[string]chan Status
	statusMapLock    sync.RWMutex
	inboxLock        sync.Mutex
	initialized      bool
}

// New returns the messagepickup service.
func New(prov provider) (*Service, error) {
	svc := Service{}

	err := svc.Initialize(prov)
	if err != nil {
		return nil, err
	}

	return &svc, nil
}

// Initialize initializes the Service. If Initialize succeeds, any further call is a no-op.
func (s *Service) Initialize(p interface{}) error {
	if s.initialized {
		return nil
	}

	prov, ok := p.(provider)
	if !ok {
		return fmt.Errorf("expected provider of type `%T`, got type `%T`", provider(nil), p)
	}

	store, err := prov.StorageProvider().OpenStore(Namespace)
	if err != nil {
		return fmt.Errorf("open mailbox store : %w", err)
	}

	connectionLookup, err := connection.NewLookup(prov)
	if err != nil {
		return err
	}

	s.outbound = prov.OutboundDispatcher()
	s.msgStore = store
	s.connectionLookup = connectionLookup
	s.packager = prov.Packager()
	s.msgHandler = prov.InboundMessageHandler()
	s.batchMap = make(map[string]chan Batch)
	s.statusMap = make(map[string]chan Status)

	s.initialized = true

	return nil
}

// HandleInbound handles inbound message pick up messages.
func (s *Service) HandleInbound(msg service.DIDCommMsg, ctx service.DIDCommContext) (string, error) {
	// perform action asynchronously
	go func() {
		var err error

		switch msg.Type() {
		case StatusMsgType:
			err = s.handleStatus(msg)
		case StatusRequestMsgType:
			err = s.handleStatusRequest(msg, ctx.MyDID(), ctx.TheirDID())
		case BatchPickupMsgType:
			err = s.handleBatchPickup(msg, ctx.MyDID(), ctx.TheirDID())
		case BatchMsgType:
			err = s.handleBatch(msg)
		case NoopMsgType:
			err = s.handleNoop(msg)
		}

		if err != nil {
			logger.Errorf("Error handling message: (%w)\n", err)
		}
	}()

	return msg.ID(), nil
}

// HandleOutbound adherence to dispatcher.ProtocolService.
func (s *Service) HandleOutbound(_ service.DIDCommMsg, _, _ string) (string, error) {
	return "", errors.New("not implemented")
}

// Accept checks whether the service can handle the message type.
func (s *Service) Accept(msgType string) bool {
	switch msgType {
	case BatchPickupMsgType, BatchMsgType, StatusRequestMsgType, StatusMsgType, NoopMsgType:
		return true
	}

	return false
}

// Name of the service.
func (s *Service) Name() string {
	return MessagePickup
}

func (s *Service) handleStatus(msg service.DIDCommMsg) error {
	// unmarshal the payload
	statusMsg := &Status{}

	err := msg.Decode(statusMsg)
	if err != nil {
		return fmt.Errorf("status message unmarshal: %w", err)
	}

	// check if there are any channels registered for the message ID
	statusCh := s.getStatusCh(statusMsg.ID)
	if statusCh != nil {
		// invoke the channel for the incoming message
		statusCh <- *statusMsg
	}

	return nil
}

func (s *Service) handleStatusRequest(msg service.DIDCommMsg, myDID, theirDID string) error {
	s.inboxLock.Lock()
	defer s.inboxLock.Unlock()

	// unmarshal the payload
	request := &StatusRequest{}

	err := msg.Decode(request)
	if err != nil {
		return fmt.Errorf("status request message unmarshal: %w", err)
	}

	logger.Debugf("retrieving stored messages for %s\n", theirDID)

	outbox, err := s.getInbox(theirDID)
	if err != nil {
		return fmt.Errorf("error in status request getting inbox: %w", err)
	}

	resp := &Status{
		Type:              StatusMsgType,
		ID:                msg.ID(),
		MessageCount:      outbox.MessageCount,
		DurationWaited:    int(time.Since(outbox.LastDeliveredTime).Seconds()),
		LastAddedTime:     outbox.LastAddedTime,
		LastDeliveredTime: outbox.LastDeliveredTime,
		LastRemovedTime:   outbox.LastRemovedTime,
		TotalSize:         outbox.TotalSize,
		Thread: &decorator.Thread{
			PID: request.Thread.ID,
		},
	}

	msgBytes, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal batch: %w", err)
	}

	msgMap, err := service.ParseDIDCommMsgMap(msgBytes)
	if err != nil {
		return fmt.Errorf("parse batch into didcomm msg map: %w", err)
	}

	return s.outbound.SendToDID(msgMap, myDID, theirDID)
}

func (s *Service) handleBatchPickup(msg service.DIDCommMsg, myDID, theirDID string) error {
	s.inboxLock.Lock()
	defer s.inboxLock.Unlock()

	// unmarshal the payload
	request := &BatchPickup{}

	err := msg.Decode(request)
	if err != nil {
		return fmt.Errorf("batch pickup message unmarshal : %w", err)
	}

	outbox, err := s.getInbox(theirDID)
	if err != nil {
		return fmt.Errorf("batch pickup get inbox: %w", err)
	}

	msgs, err := outbox.DecodeMessages()
	if err != nil {
		return fmt.Errorf("batch pickup decode : %w", err)
	}

	end := len(msgs)
	if request.BatchSize < end {
		end = request.BatchSize
	}

	outbox.LastDeliveredTime = time.Now()
	outbox.LastRemovedTime = time.Now()

	err = outbox.EncodeMessages(msgs[end:])
	if err != nil {
		return fmt.Errorf("batch pickup encode: %w", err)
	}

	err = s.putInbox(theirDID, outbox)
	if err != nil {
		return fmt.Errorf("batch pick up put inbox: %w", err)
	}

	msgs = msgs[0:end]

	batch := Batch{
		Type:     BatchMsgType,
		ID:       msg.ID(),
		Messages: msgs,
	}

	msgBytes, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("marshal batch: %w", err)
	}

	msgMap, err := service.ParseDIDCommMsgMap(msgBytes)
	if err != nil {
		return fmt.Errorf("parse batch into didcomm msg map: %w", err)
	}

	return s.outbound.SendToDID(msgMap, myDID, theirDID)
}

func (s *Service) handleBatch(msg service.DIDCommMsg) error {
	// unmarshal the payload
	batchMsg := &Batch{}

	err := msg.Decode(batchMsg)
	if err != nil {
		return fmt.Errorf("batch message unmarshal : %w", err)
	}

	// check if there are any channels registered for the message ID
	batchCh := s.getBatchCh(batchMsg.ID)

	if batchCh != nil {
		// invoke the channel for the incoming message
		batchCh <- *batchMsg
	}

	return nil
}

func (s *Service) handleNoop(msg service.DIDCommMsg) error {
	// unmarshal the payload
	request := &Noop{}

	err := msg.Decode(request)
	if err != nil {
		return fmt.Errorf("noop message unmarshal : %w", err)
	}

	return nil
}

type inbox struct {
	DID               string          `json:"DID"`
	MessageCount      int             `json:"message_count"`
	LastAddedTime     time.Time       `json:"last_added_time,omitempty"`
	LastDeliveredTime time.Time       `json:"last_delivered_time,omitempty"`
	LastRemovedTime   time.Time       `json:"last_removed_time,omitempty"`
	TotalSize         int             `json:"total_size,omitempty"`
	Messages          json.RawMessage `json:"messages"`
}

// DecodeMessages Messages.
func (r *inbox) DecodeMessages() ([]*Message, error) {
	var out []*Message

	var err error

	if r.Messages != nil {
		err = json.Unmarshal(r.Messages, &out)
	}

	return out, err
}

// EncodeMessages Messages.
func (r *inbox) EncodeMessages(msg []*Message) error {
	d, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("unable to marshal: %w", err)
	}

	r.Messages = d
	r.MessageCount = len(msg)
	r.TotalSize = len(d)

	return nil
}

// AddMessage add message to inbox.
func (s *Service) AddMessage(message []byte, theirDID string) error {
	s.inboxLock.Lock()
	defer s.inboxLock.Unlock()

	outbox, err := s.createInbox(theirDID)
	if err != nil {
		return fmt.Errorf("unable to pull messages: %w", err)
	}

	msgs, err := outbox.DecodeMessages()
	if err != nil {
		return fmt.Errorf("unable to decode messages: %w", err)
	}

	m := Message{
		ID:        uuid.New().String(),
		AddedTime: time.Now(),
		Message:   message,
	}

	msgs = append(msgs, &m)

	outbox.LastDeliveredTime = time.Now()
	outbox.LastRemovedTime = outbox.LastDeliveredTime

	err = outbox.EncodeMessages(msgs)
	if err != nil {
		return fmt.Errorf("unable to encode messages: %w", err)
	}

	err = s.putInbox(theirDID, outbox)
	if err != nil {
		return fmt.Errorf("unable to put messages: %w", err)
	}

	return nil
}

func (s *Service) createInbox(theirDID string) (*inbox, error) {
	msgs, err := s.getInbox(theirDID)
	if err != nil && errors.Is(err, storage.ErrDataNotFound) {
		msgs = &inbox{DID: theirDID}

		msgBytes, e := json.Marshal(msgs)
		if e != nil {
			return nil, e
		}

		e = s.msgStore.Put(theirDID, msgBytes)
		if e != nil {
			return nil, e
		}

		return msgs, nil
	}

	return msgs, err
}

func (s *Service) getInbox(theirDID string) (*inbox, error) {
	msgs := &inbox{DID: theirDID}

	b, err := s.msgStore.Get(theirDID)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(b, msgs)
	if err != nil {
		return nil, err
	}

	return msgs, nil
}

func (s *Service) putInbox(theirDID string, o *inbox) error {
	b, err := json.Marshal(o)
	if err != nil {
		return err
	}

	return s.msgStore.Put(theirDID, b)
}

// StatusRequest request a status message.
func (s *Service) StatusRequest(connectionID string) (*Status, error) {
	// get the connection record for the ID to fetch DID information
	conn, err := s.getConnection(connectionID)
	if err != nil {
		return nil, err
	}

	// generate message ID
	msgID := uuid.New().String()

	// register chan for callback processing
	statusCh := make(chan Status)
	s.setStatusCh(msgID, statusCh)

	defer s.setStatusCh(msgID, nil)

	// create request message
	req := &StatusRequest{
		Type: StatusRequestMsgType,
		ID:   msgID,
		Thread: &decorator.Thread{
			PID: uuid.New().String(),
		},
	}

	// send message to the router
	if err := s.outbound.SendToDID(req, conn.MyDID, conn.TheirDID); err != nil {
		return nil, fmt.Errorf("send route request: %w", err)
	}

	// callback processing (to make this function look like a sync function)
	var sts *Status
	select {
	case s := <-statusCh:
		sts = &s
		// TODO https://github.com/hyperledger/aries-framework-go/issues/1134 configure this timeout at decorator level
	case <-time.After(updateTimeout):
		return nil, errors.New("timeout waiting for status request")
	}

	return sts, nil
}

// BatchPickup a request to have multiple waiting messages sent inside a batch message.
func (s *Service) BatchPickup(connectionID string, size int) (int, error) {
	// get the connection record for the ID to fetch DID information
	conn, err := s.getConnection(connectionID)
	if err != nil {
		return -1, err
	}

	// generate message ID
	msgID := uuid.New().String()

	// register chan for callback processing
	batchCh := make(chan Batch)
	s.setBatchCh(msgID, batchCh)

	defer s.setBatchCh(msgID, nil)

	// create request message
	req := &BatchPickup{
		Type:      BatchPickupMsgType,
		ID:        msgID,
		BatchSize: size,
	}

	msgBytes, err := json.Marshal(req)
	if err != nil {
		return -1, fmt.Errorf("marshal req: %w", err)
	}

	msgMap, err := service.ParseDIDCommMsgMap(msgBytes)
	if err != nil {
		return -1, fmt.Errorf("parse req into didcomm msg map: %w", err)
	}

	// send message to the router
	if err := s.outbound.SendToDID(msgMap, conn.MyDID, conn.TheirDID); err != nil {
		return -1, fmt.Errorf("send batch pickup request: %w", err)
	}

	// callback processing (to make this function look like a sync function)
	var processed int
	select {
	case batchResp := <-batchCh:
		for _, msg := range batchResp.Messages {
			err := s.handle(msg)
			if err != nil {
				logger.Errorf("error handling batch message %s: %w", msg.ID, err)

				continue
			}
			processed++
		}
	// TODO https://github.com/hyperledger/aries-framework-go/issues/1134 configure this timeout at decorator level
	case <-time.After(updateTimeout):
		return -1, errors.New("timeout waiting for batch")
	}

	return processed, nil
}

// Noop a noop message.
func (s *Service) Noop(connectionID string) error {
	// get the connection record for the ID to fetch DID information
	conn, err := s.getConnection(connectionID)
	if err != nil {
		return err
	}

	noop := &Noop{ID: uuid.New().String(), Type: NoopMsgType}

	msgBytes, err := json.Marshal(noop)
	if err != nil {
		return fmt.Errorf("marshal noop: %w", err)
	}

	msgMap, err := service.ParseDIDCommMsgMap(msgBytes)
	if err != nil {
		return fmt.Errorf("parse noop into didcomm msg map: %w", err)
	}

	if err := s.outbound.SendToDID(msgMap, conn.MyDID, conn.TheirDID); err != nil {
		return fmt.Errorf("send noop request: %w", err)
	}

	return nil
}

func (s *Service) getConnection(routerConnID string) (*connection.Record, error) {
	conn, err := s.connectionLookup.GetConnectionRecord(routerConnID)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return nil, ErrConnectionNotFound
		}

		return nil, fmt.Errorf("fetch connection record from store : %w", err)
	}

	return conn, nil
}

func (s *Service) getBatchCh(msgID string) chan Batch {
	s.batchMapLock.RLock()
	defer s.batchMapLock.RUnlock()

	return s.batchMap[msgID]
}

func (s *Service) setBatchCh(msgID string, batchCh chan Batch) {
	s.batchMapLock.Lock()
	defer s.batchMapLock.Unlock()

	if batchCh == nil {
		delete(s.batchMap, msgID)
	} else {
		s.batchMap[msgID] = batchCh
	}
}

func (s *Service) getStatusCh(msgID string) chan Status {
	s.statusMapLock.RLock()
	defer s.statusMapLock.RUnlock()

	return s.statusMap[msgID]
}

func (s *Service) setStatusCh(msgID string, statusCh chan Status) {
	s.statusMapLock.Lock()
	defer s.statusMapLock.Unlock()

	if statusCh == nil {
		delete(s.statusMap, msgID)
	} else {
		s.statusMap[msgID] = statusCh
	}
}

func (s *Service) handle(msg *Message) error {
	unpackMsg, err := s.packager.UnpackMessage(msg.Message)
	if err != nil {
		return fmt.Errorf("failed to unpack msg: %w", err)
	}

	trans := &decorator.Transport{}
	err = json.Unmarshal(unpackMsg.Message, trans)

	if err != nil {
		return fmt.Errorf("unmarshal transport decorator : %w", err)
	}

	messageHandler := s.msgHandler

	err = messageHandler(unpackMsg)
	if err != nil {
		return fmt.Errorf("incoming msg processing failed: %w", err)
	}

	return nil
}
