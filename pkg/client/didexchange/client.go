/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange/persistence"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

// provider contains dependencies for the DID exchange protocol and is typically created by using aries.Context()
type provider interface {
	Service(id string) (interface{}, error)
	CryptoWallet() wallet.Crypto
	InboundTransportEndpoint() string
	StorageProvider() storage.Provider
}

// Client enable access to didexchange api
// TODO add support for Accept Exchange Request & Accept Invitation
//  using events & callback (#198 & #238)
type Client struct {
	didexchangeSvc           dispatcher.DIDCommService
	wallet                   wallet.Crypto
	inboundTransportEndpoint string
	actionCh                 chan dispatcher.DIDCommAction
	msgCh                    chan dispatcher.StateMsg
	actionEvent              chan<- dispatcher.DIDCommAction
	actionEventlock          sync.RWMutex
	msgEvents                []chan<- dispatcher.StateMsg
	msgEventsLock            sync.RWMutex
	recorder                 *persistence.ConnectionRecorder
}

// New return new instance of didexchange client
func New(ctx provider) (*Client, error) {
	svc, err := ctx.Service(didexchange.DIDExchange)
	if err != nil {
		return nil, err
	}

	didexchangeSvc, ok := svc.(dispatcher.DIDCommService)
	if !ok {
		return nil, errors.New("cast service to DIDExchange Service failed")
	}

	store, err := ctx.StorageProvider().GetStoreHandle()
	if err != nil {
		return nil, err
	}

	c := &Client{
		didexchangeSvc:           didexchangeSvc,
		wallet:                   ctx.CryptoWallet(),
		inboundTransportEndpoint: ctx.InboundTransportEndpoint(),
		// TODO channel size - https://github.com/hyperledger/aries-framework-go/issues/246
		actionCh: make(chan dispatcher.DIDCommAction, 10),
		msgCh:    make(chan dispatcher.StateMsg, 10),
		recorder: persistence.NewConnectionRecorder(store),
	}

	// start listening for action/message events
	err = c.startServiceEventListener()
	if err != nil {
		return nil, fmt.Errorf("service event listener startup failed: %w", err)
	}

	return c, nil
}

// CreateInvitation create invitation
func (c *Client) CreateInvitation(label string) (*didexchange.Invitation, error) {
	verKey, err := c.wallet.CreateEncryptionKey()
	if err != nil {
		return nil, fmt.Errorf("failed CreateSigningKey: %w", err)
	}

	invitation := &didexchange.Invitation{
		ID:              uuid.New().String(),
		Label:           label,
		RecipientKeys:   []string{verKey},
		ServiceEndpoint: c.inboundTransportEndpoint,
		Type:            didexchange.ConnectionInvite,
	}

	err = c.recorder.SaveInvitation(verKey, invitation)
	if err != nil {
		return nil, fmt.Errorf("failed to save invitation: %w", err)
	}

	return invitation, nil
}

// HandleInvitation handle incoming invitation
func (c *Client) HandleInvitation(invitation *didexchange.Invitation) error {
	payload, err := json.Marshal(invitation)
	if err != nil {
		return fmt.Errorf("failed marshal invitation: %w", err)
	}
	if err = c.didexchangeSvc.Handle(dispatcher.DIDCommMsg{Type: invitation.Type, Payload: payload}); err != nil {
		return fmt.Errorf("failed from didexchange service handle: %w", err)
	}
	return nil
}

// QueryConnections queries connections matching given parameters
func (c *Client) QueryConnections(request *QueryConnectionsParams) ([]*QueryConnectionResult, error) {
	// TODO sample response, to be implemented as part of #226
	return []*QueryConnectionResult{
		{ConnectionID: uuid.New().String(), CreatedTime: time.Now()},
		{ConnectionID: uuid.New().String(), CreatedTime: time.Now()},
	}, nil
}

// QueryConnectionByID fetches single connection record for given id
func (c *Client) QueryConnectionByID(id string) (*QueryConnectionResult, error) {
	// TODO sample response, to be implemented as part of #226
	return &QueryConnectionResult{
		ConnectionID: uuid.New().String(), CreatedTime: time.Now(),
	}, nil
}

// RemoveConnection removes connection record for given id
func (c *Client) RemoveConnection(id string) error {
	// TODO sample response, to be implemented as part of #226
	return nil
}

// startServiceEventListener listens to action and message events from DID Exchange service.
func (c *Client) startServiceEventListener() error {
	err := c.didexchangeSvc.RegisterActionEvent(c.actionCh)
	if err != nil {
		return fmt.Errorf("didexchange action event registration failed: %w", err)
	}

	// register the message event channel
	err = c.didexchangeSvc.RegisterMsgEvent(c.msgCh)
	if err != nil {
		return fmt.Errorf("didexchange message event registration failed: %w", err)
	}

	// listen for action event and message events
	go func() {
		for {
			select {
			case e := <-c.actionCh:
				// assigned to var as lint fails with : Using a reference for the variable on range scope (scopelint)
				msg := e
				c.handleActionEvent(&msg)
			case e := <-c.msgCh:
				// assigned to var as lint fails with : Using a reference for the variable on range scope (scopelint)
				msg := e
				c.handleMessageEvent(&msg)
			}
		}
	}()

	return nil
}

// RegisterActionEvent on DID Exchange protocol messages. The events are triggered for incoming exchangeRequest,
// exchangeResponse and exchangeAck message types. The consumer need to invoke the callback to resume processing.
// Only one channel can be registered for the action events. The function will throw error if a channel is already
// registered. The AutoExecuteActionEvent() function can be used to automatically trigger callback function for the
// event.
func (c *Client) RegisterActionEvent(ch chan<- dispatcher.DIDCommAction) error {
	c.actionEventlock.Lock()
	defer c.actionEventlock.Unlock()

	if c.actionEvent != nil {
		return errors.New("channel is already registered for the action event")
	}

	c.actionEvent = ch

	return nil
}

// UnregisterActionEvent on DID Exchange protocol messages. Refer RegisterActionEvent().
func (c *Client) UnregisterActionEvent(ch chan<- dispatcher.DIDCommAction) error {
	c.actionEventlock.Lock()
	defer c.actionEventlock.Unlock()

	if c.actionEvent != ch {
		return errors.New("invalid channel passed to unregister the action event")
	}

	c.actionEvent = nil

	return nil
}

// RegisterMsgEvent on DID Exchange protocol messages. The message events are triggered for state transitions. Client
// will not expect any callback on these events unlike Action events.
func (c *Client) RegisterMsgEvent(ch chan<- dispatcher.StateMsg) error {
	c.msgEventsLock.Lock()
	c.msgEvents = append(c.msgEvents, ch)
	c.msgEventsLock.Unlock()

	return nil
}

// UnregisterMsgEvent on DID Exchange protocol messages.
func (c *Client) UnregisterMsgEvent(ch chan<- dispatcher.StateMsg) error {
	c.msgEventsLock.Lock()
	for i := 0; i < len(c.msgEvents); i++ {
		if c.msgEvents[i] == ch {
			c.msgEvents = append(c.msgEvents[:i], c.msgEvents[i+1:]...)
			i--
		}
	}
	c.msgEventsLock.Unlock()

	return nil
}

func (c *Client) handleActionEvent(msg *dispatcher.DIDCommAction) {
	c.actionEventlock.RLock()
	aEvent := c.actionEvent
	c.actionEventlock.RLock()

	aEvent <- *msg
}

func (c *Client) handleMessageEvent(msg *dispatcher.StateMsg) {
	c.msgEventsLock.RLock()
	statusEvents := c.msgEvents
	c.msgEventsLock.RUnlock()

	for _, handler := range statusEvents {
		handler <- *msg
	}
}

// AutoExecuteActionEvent is a utility function to execute events automatically. The function requires a channel to be
// passed-in to listen for dispatcher.DIDCommAction and triggers the callback. This is a blocking function and use
// this function with a goroutine.
//
// Usage:
//  c := didexchange.New(....)
//	actionCh := make(chan dispatcher.DIDCommAction)
//	err = c.RegisterActionEvent(actionCh)
//	go didexchange.AutoExecuteActionEvent(actionCh)
func AutoExecuteActionEvent(ch chan dispatcher.DIDCommAction) error {
	// wrap utility from client package
	return didexchange.AutoExecuteActionEvent(ch)
}
