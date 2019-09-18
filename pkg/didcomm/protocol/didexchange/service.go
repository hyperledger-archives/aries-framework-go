/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/common/metadata"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/event"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// TODO https://github.com/hyperledger/aries-framework-go/issues/104
var logger = log.New("aries-framework/didexchange")

// didCommChMessage type to correlate actionEvent message(go channel) with callback message(internal go channel).
type didCommChMessage struct {
	ID              string
	DIDCommCallback event.DIDCommCallback
}

const (
	// DIDExchange did exchange protocol
	DIDExchange = "didexchange"
	// DIDExchangeSpec defines the did-exchange spec
	DIDExchangeSpec = metadata.AriesCommunityDID + ";spec/didexchange/1.0/"
	// ConnectionInvite defines the did-exchange invite message type.
	ConnectionInvite = DIDExchangeSpec + "invitation"
	// ConnectionRequest defines the did-exchange request message type.
	ConnectionRequest = DIDExchangeSpec + "request"
	// ConnectionResponse defines the did-exchange response message type.
	ConnectionResponse = DIDExchangeSpec + "response"
	// ConnectionAck defines the did-exchange ack message type.
	ConnectionAck = DIDExchangeSpec + "ack"
)

// message type to store data for eventing. This is retrieved during callback.
type message struct {
	Msg           dispatcher.DIDCommMsg
	ThreadID      string
	NextStateName string
}

// provider contains dependencies for the DID exchange protocol and is typically created by using aries.Context()
type provider interface {
	OutboundTransport() transport.OutboundTransport
}

// Service for DID exchange protocol
type Service struct {
	outboundTransport transport.OutboundTransport
	store             storage.Store
	callbackChannel   chan didCommChMessage
	actionEvent       chan<- event.DIDCommEvent
	statusEvents      []chan<- dispatcher.DIDCommMsg
	lock              sync.RWMutex
	statusEventLock   sync.RWMutex
	execute           bool
}

// New return didexchange service
func New(store storage.Store, prov provider) *Service {
	svc := &Service{
		// TODO Outbound dispatcher - https://github.com/hyperledger/aries-framework-go/issues/259
		outboundTransport: prov.OutboundTransport(),
		store:             store,
		// TODO channel size - https://github.com/hyperledger/aries-framework-go/issues/246
		callbackChannel: make(chan didCommChMessage, 10),
		// set execute to false. Consumers have to enable this by setting either RegisterEvent() or
		// RegisterAutoExecute()
		execute: false,
	}

	svc.startInternalListener()

	return svc
}

// Handle didexchange msg
func (s *Service) Handle(msg dispatcher.DIDCommMsg) error {
	// throw error if there are no action events are registered or auto execute set (if it's not outbound)
	s.lock.RLock()
	execute := s.execute
	s.lock.RUnlock()

	if !msg.Outbound && !execute {
		return errors.New("no clients are registered to handle the message")
	}

	thid, err := threadID(msg.Payload)
	if err != nil {
		return err
	}
	current, err := s.currentState(thid)
	if err != nil {
		return err
	}
	next, err := stateFromMsgType(msg.Type)
	if err != nil {
		return err
	}
	if !current.CanTransitionTo(next) {
		return fmt.Errorf("invalid state transition: %s -> %s", current.Name(), next.Name())
	}

	eventsTriggered := false
	if !msg.Outbound {
		// trigger the actionEvent if the message type is registered (if it's not outbound)
		eventsTriggered, err = s.sendEvent(msg, thid, next)
		if err != nil {
			return fmt.Errorf("send events failed: %w", err)
		}
	}

	// if no events are trigger continue the execution
	if !eventsTriggered {
		return s.handle(&message{Msg: msg, ThreadID: thid, NextStateName: next.Name()})
	}

	return nil
}

// RegisterEvent on DID Exchange protocol messages. The events are triggered for incoming ConnectionRequest,
// ConnectionResponse or ConnectionAck message types. The consumer need to invoke the callback to resume processing.
// Only one channel can be registered for the action events. If called multiple times, the events will be sent to the
// last channel. This works in conjunction with RegisterAutoExecute(). If this function is called after
// RegisterAutoExecute(), the service will not execute the processing automatically and it'll wait for the callback. If
// both are not set, then service will not handle the messages and throw an error.
func (s *Service) RegisterEvent(ch chan<- event.DIDCommEvent) error {
	s.lock.Lock()
	s.actionEvent = ch
	s.execute = true
	s.lock.Unlock()

	return nil
}

// UnregisterEvent on DID Exchange protocol messages. Refer RegisterEvent().
func (s *Service) UnregisterEvent() error {
	return s.disableExecute()
}

// RegisterMsg on DID Exchange protocol messages. The events are triggered for incoming ConnectionRequest,
// ConnectionResponse or ConnectionAck message types. The Callback is set to nil in the actionEvent message and service
// won't be expecting any response from the consumers.
func (s *Service) RegisterMsg(ch chan<- dispatcher.DIDCommMsg) error {
	s.statusEventLock.Lock()
	s.statusEvents = append(s.statusEvents, ch)
	s.statusEventLock.Unlock()

	return nil
}

// UnregisterMsg on DID Exchange protocol messages. Refer RegisterMsg().
func (s *Service) UnregisterMsg(ch chan<- dispatcher.DIDCommMsg) error {
	s.statusEventLock.Lock()
	for i := 0; i < len(s.statusEvents); i++ {
		if s.statusEvents[i] == ch {
			s.statusEvents = append(s.statusEvents[:i], s.statusEvents[i+1:]...)
			i--
		}
	}
	s.statusEventLock.Unlock()

	return nil
}

// RegisterAutoExecute on DID Exchange protocol messages. When this function is called, the service will auto execute
// the workflow. This works in conjunction with RegisterEvent(). If this function is called after
// RegisterEvent(), the service will execute the processing automatically and no action events will be triggered.
// If both are not set, then service will not handle the messages and throw an error.
func (s *Service) RegisterAutoExecute() error {
	s.lock.Lock()
	s.execute = true
	s.lock.Unlock()

	return nil
}

// UnregisterAutoExecute on DID Exchange protocol messages. Refer RegisterAutoExecute().
func (s *Service) UnregisterAutoExecute() error {
	return s.disableExecute()
}

func (s *Service) disableExecute() error {
	s.lock.Lock()
	s.actionEvent = nil
	s.execute = false
	s.lock.Unlock()

	return nil
}

func (s *Service) handle(msg *message) error {
	next, err := stateFromName(msg.NextStateName)
	if err != nil {
		return fmt.Errorf("invalid state name: %w", err)
	}

	followup, err := next.Execute(msg.Msg)
	if err != nil {
		return fmt.Errorf("failed to execute state %s %w", next.Name(), err)
	}
	err = s.update(msg.ThreadID, next)
	if err != nil {
		return fmt.Errorf("failed to persist state %s %w", next.Name(), err)
	}
	for ; !isNoOp(followup); followup = next {
		next, err = followup.Execute(msg.Msg)
		if err != nil {
			return fmt.Errorf("failed to execute state %s %w", followup.Name(), err)
		}
		err = s.update(msg.ThreadID, followup)
		if err != nil {
			return fmt.Errorf("failed to persist state %s %w", followup.Name(), err)
		}
	}
	// TODO call post-transition listeners -  Issue: https://github.com/hyperledger/aries-framework-go/issues/140
	return nil
}

// sendEvent triggeres the status events and action events. Returns true if action events are triggered. The events are
// triggered for ConnectionRequest, ConnectionResponse or ConnectionAck message types.
func (s *Service) sendEvent(msg dispatcher.DIDCommMsg, threadID string, nextState state) (bool, error) {
	// trigger the status events
	s.statusEventLock.RLock()
	statusEvents := s.statusEvents
	s.statusEventLock.RUnlock()

	for _, handler := range statusEvents {
		handler <- msg
	}

	s.lock.RLock()
	aEvent := s.actionEvent
	s.lock.RUnlock()

	// invoke events for ConnectionRequest, ConnectionResponse or ConnectionAck and if action events are registered
	if aEvent == nil || msg.Type != ConnectionRequest &&
		msg.Type != ConnectionResponse && msg.Type != ConnectionAck {
		return false, nil
	}

	jsonDoc, err := json.Marshal(&message{
		Msg:           msg,
		ThreadID:      threadID,
		NextStateName: nextState.Name(),
	})

	if err != nil {
		return false, fmt.Errorf("JSON marshalling of document failed: %w", err)
	}

	// save the incoming message in the store (to retrieve later when callback events are fired)
	id := generateRandomID()
	err = s.store.Put(id, jsonDoc)
	if err != nil {
		return false, fmt.Errorf("JSON marshalling of document failed: %w", err)
	}

	// create the message for the channel
	didCommEvent := event.DIDCommEvent{
		Message: msg,
		Callback: func(didCommCallback event.DIDCommCallback) {
			s.processCallback(id, didCommCallback)
		},
	}

	// trigger the registered action events
	s.lock.RLock()
	aEvent = s.actionEvent
	s.lock.RUnlock()
	if aEvent == nil {
		return false, nil
	}
	// TODO: it can be panic if the channel was closed
	aEvent <- didCommEvent
	return true, nil
}

// startInternalListener listens to messages in gochannel for callback messages from clients.
func (s *Service) startInternalListener() {
	go func() {
		for msg := range s.callbackChannel {
			// TODO handle error in callback - https://github.com/hyperledger/aries-framework-go/issues/242
			s.process(msg.ID, msg.DIDCommCallback)
		}
	}()
}

func (s *Service) processCallback(id string, didCommCallback event.DIDCommCallback) {
	// pass the callback data to internal channel. This is created to unblock consumer go routine and wrap the callback
	// channel internally.
	s.callbackChannel <- didCommChMessage{ID: id, DIDCommCallback: didCommCallback}
}

// processCallback processes the callback events.
func (s *Service) process(id string, didCommCallback event.DIDCommCallback) error {
	if didCommCallback.Err != nil {
		// TODO https://github.com/hyperledger/aries-framework-go/issues/242 Service callback processing error handling
		return nil
	}

	// fetch the record
	jsonDoc, err := s.store.Get(id)
	if err != nil {
		return fmt.Errorf("document for the id doesn't exists in the database: %w", didCommCallback.Err)
	}

	document := &message{}
	err = json.Unmarshal(jsonDoc, document)
	if err != nil {
		return fmt.Errorf("JSON marshalling failed: %w", didCommCallback.Err)
	}

	// continue the processing
	err = s.handle(document)
	if err != nil {
		return fmt.Errorf("processing of the message failed: %w", err)
	}
	return nil
}

func isNoOp(s state) bool {
	_, ok := s.(*noOp)
	return ok
}

func threadID(payload []byte) (string, error) {
	msg := struct {
		ID     string           `json:"@id"`
		Thread decorator.Thread `json:"~thread,omitempty"`
	}{}
	err := json.Unmarshal(payload, &msg)
	if err != nil {
		return "", fmt.Errorf("cannot unmarshal @id and ~thread: error=%s", err)
	}
	thid := msg.ID
	if len(msg.Thread.ID) > 0 {
		thid = msg.Thread.ID
	}
	return thid, nil
}

func (s *Service) currentState(thid string) (state, error) {
	name, err := s.store.Get(thid)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return &null{}, nil
		}
		return nil, fmt.Errorf("cannot fetch state from store: thid=%s err=%s", thid, err)
	}
	return stateFromName(string(name))
}

func (s *Service) update(thid string, state state) error {
	err := s.store.Put(thid, []byte(state.Name()))
	if err != nil {
		return fmt.Errorf("failed to write to store: %s", err)
	}
	return nil
}

// Accept msg checks the msg type
func (s *Service) Accept(msgType string) bool {
	return msgType == ConnectionInvite ||
		msgType == ConnectionRequest ||
		msgType == ConnectionResponse ||
		msgType == ConnectionAck
}

// Name return service name
func (s *Service) Name() string {
	return DIDExchange
}

// Connection return connection
func (s *Service) Connection(id string) {
	// TODO add Connection logic

}

// Connections return all connections
func (s *Service) Connections() {
	// TODO add Connections logic

}

// TODO all these 'destination' parameters should be a complex type that provides the recipientKeys,
//      routingKeys, and serviceEndpoint. The recipientKeys should be fed into the wallet.Pack() function.
//      The routingKeys are used to create the encryption envelopes. Finally, the whole structure is sent
//      to the serviceEndpoint.

// SendExchangeRequest sends exchange request
func (s *Service) SendExchangeRequest(exchangeRequest *Request, destination string) error {
	if exchangeRequest == nil {
		return errors.New("exchangeRequest cannot be nil")
	}

	exchangeRequest.Type = ConnectionRequest

	// ignore response data as it is not used in this communication mode as defined in the spec
	_, err := s.marshalAndSend(exchangeRequest, "Error Marshalling Exchange Request", destination)
	return err
}

// SendExchangeResponse sends exchange response
func (s *Service) SendExchangeResponse(exchangeResponse *Response, destination string) error {
	if exchangeResponse == nil {
		return errors.New("exchangeResponse cannot be nil")
	}

	exchangeResponse.Type = ConnectionResponse

	// ignore response data as it is not used in this communication mode as defined in the spec
	_, err := s.marshalAndSend(exchangeResponse, "Error Marshalling Exchange Response", destination)
	return err
}

func (s *Service) marshalAndSend(data interface{}, errorMsg, destination string) (string, error) {
	// TODO need access to the wallet in order to first pack() the msg before sending
	jsonString, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("%s : %w", errorMsg, err)
	}
	// TODO an outboundtransport implementation should be selected based on the destination's URL.
	return s.outboundTransport.Send(string(jsonString), destination)
}

func generateRandomID() string {
	return uuid.New().String()
}

func encodedExchangeInvitation(inviteMessage *Invitation) (string, error) {
	inviteMessage.Type = ConnectionInvite

	invitationJSON, err := json.Marshal(inviteMessage)
	if err != nil {
		return "", fmt.Errorf("JSON Marshal Error : %w", err)
	}

	return base64.URLEncoding.EncodeToString(invitationJSON), nil
}

// GenerateInviteWithPublicDID generates the DID exchange invitation string with public DID
func GenerateInviteWithPublicDID(invite *Invitation) (string, error) {
	if invite.ID == "" || invite.DID == "" {
		return "", errors.New("ID and DID are mandatory")
	}

	return encodedExchangeInvitation(invite)
}

// GenerateInviteWithKeyAndEndpoint generates the DID exchange invitation string with recipient key and endpoint
func GenerateInviteWithKeyAndEndpoint(invite *Invitation) (string, error) {
	if invite.ID == "" || invite.ServiceEndpoint == "" || len(invite.RecipientKeys) == 0 {
		return "", errors.New("ID, Service Endpoint and Recipient Key are mandatory")
	}

	return encodedExchangeInvitation(invite)
}
