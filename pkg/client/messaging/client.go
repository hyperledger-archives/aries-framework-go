/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package messaging

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	// errors.
	errMsgDestinationMissing = "missing message destination"
)

var logger = log.New("aries-framework/client/messaging")

// provider contains dependencies for the message client and is typically created by using aries.Context().
type provider interface {
	VDRegistry() vdr.Registry
	Messenger() service.Messenger
	ProtocolStateStorageProvider() storage.Provider
	StorageProvider() storage.Provider
	KMS() kms.KeyManager
}

// MessageHandler maintains registered message services
// and it allows dynamic registration of message services.
type MessageHandler interface {
	// Services returns list of available message services in this message handler
	Services() []dispatcher.MessageService
	// Register registers given message services to this message handler
	Register(msgSvcs ...dispatcher.MessageService) error
	// Unregister unregisters message service with given name from this message handler
	Unregister(name string) error
}

// Notifier represents a notification dispatcher.
type Notifier interface {
	Notify(topic string, message []byte) error
}

type sendMsgOpts struct {
	// Connection ID of the message destination
	// This parameter takes precedence over all the other destination parameters.
	connectionID string

	// DID of the destination.
	// This parameter takes precedence over `ServiceEndpoint` destination parameter.
	theirDID string

	// Destination is service endpoint destination.
	// This param can be used to send messages outside connection.
	destination *service.Destination

	// Message type of the response for the message sent.
	// If provided then messenger will wait for the response of this type after sending message.
	responseMsgType string

	// context for await reply operation.
	waitForResponseCtx context.Context
}

// SendMessageOpions is the options for choosing message destinations.
type SendMessageOpions func(opts *sendMsgOpts)

// SendByConnectionID option to choose message destination by connection ID.
func SendByConnectionID(connectionID string) SendMessageOpions {
	return func(opts *sendMsgOpts) {
		opts.connectionID = connectionID
	}
}

// SendByTheirDID option to choose message destination by connection ID.
func SendByTheirDID(theirDID string) SendMessageOpions {
	return func(opts *sendMsgOpts) {
		opts.theirDID = theirDID
	}
}

// SendByDestination option to set message destination.
func SendByDestination(destination *service.Destination) SendMessageOpions {
	return func(opts *sendMsgOpts) {
		opts.destination = destination
	}
}

// WaitForResponse option to set message response type.
// Message reply will wait for the response of this message type and matching thread ID.
func WaitForResponse(ctx context.Context, responseType string) SendMessageOpions {
	return func(opts *sendMsgOpts) {
		opts.waitForResponseCtx = ctx
		opts.responseMsgType = responseType
	}
}

// messageDispatcher is message dispatch action which returns id of the message sent or error if it fails.
type messageDispatcher func() error

// Client enable access to messaging features.
type Client struct {
	ctx              provider
	msgRegistrar     MessageHandler
	notifier         Notifier
	connectionLookup *connection.Lookup
}

// New return new instance of message client.
func New(ctx provider, registrar MessageHandler, notifier Notifier) (*Client, error) {
	connectionLookup, err := connection.NewLookup(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize connection lookup : %w", err)
	}

	c := &Client{
		ctx:              ctx,
		msgRegistrar:     registrar,
		connectionLookup: connectionLookup,
		notifier:         notifier,
	}

	return c, nil
}

// RegisterService registers new message service to message handler registrar.
func (c *Client) RegisterService(name, msgType string, purpose ...string) error {
	return c.msgRegistrar.Register(newMessageService(name, msgType, purpose, c.notifier))
}

// UnregisterService unregisters given message service handler registrar.
func (c *Client) UnregisterService(name string) error {
	return c.msgRegistrar.Unregister(name)
}

// Services returns list of registered service names.
func (c *Client) Services() []string {
	names := []string{}
	for _, svc := range c.msgRegistrar.Services() {
		names = append(names, svc.Name())
	}

	return names
}

// Send sends new message based on destination options provided.
func (c *Client) Send(msg json.RawMessage, opts ...SendMessageOpions) (json.RawMessage, error) {
	sendOpts := &sendMsgOpts{}

	for _, opt := range opts {
		opt(sendOpts)
	}

	var action messageDispatcher

	didCommMsg, err := prepareMessage(msg)
	if err != nil {
		return nil, err
	}

	switch {
	case sendOpts.connectionID != "":
		action, err = c.sendToConnection(didCommMsg, sendOpts.connectionID)
	case sendOpts.theirDID != "":
		action, err = c.sendToTheirDID(didCommMsg, sendOpts.theirDID)
	case sendOpts.destination != nil:
		action, err = c.sendToDestination(didCommMsg, sendOpts.destination)
	default:
		return nil, fmt.Errorf(errMsgDestinationMissing)
	}

	if err != nil {
		return nil, err
	}

	return c.sendAndWaitForReply(sendOpts.waitForResponseCtx, action, didCommMsg.ID(), sendOpts.responseMsgType)
}

// Reply sends reply to existing message.
func (c *Client) Reply(ctx context.Context, msg json.RawMessage, msgID string, startNewThread bool,
	waitForResponse string) (json.RawMessage, error) {
	var action messageDispatcher

	didCommMsg, err := prepareMessage(msg)
	if err != nil {
		return nil, err
	}

	if startNewThread {
		action = func() error {
			return c.ctx.Messenger().ReplyToNested(didCommMsg, &service.NestedReplyOpts{MsgID: msgID})
		}

		return c.sendAndWaitForReply(ctx, action, didCommMsg.ID(), waitForResponse)
	}

	action = func() error {
		return c.ctx.Messenger().ReplyTo(msgID, didCommMsg) // nolint: staticcheck
	}

	return c.sendAndWaitForReply(ctx, action, "", waitForResponse)
}

func (c *Client) sendToConnection(msg service.DIDCommMsgMap, connectionID string) (messageDispatcher, error) {
	conn, err := c.connectionLookup.GetConnectionRecord(connectionID)
	if err != nil {
		return nil, err
	}

	return func() error {
		return c.ctx.Messenger().Send(msg, conn.MyDID, conn.TheirDID)
	}, nil
}

func (c *Client) sendToTheirDID(msg service.DIDCommMsgMap, theirDID string) (messageDispatcher, error) {
	conn, err := c.connectionLookup.GetConnectionRecordByTheirDID(theirDID)
	if err == nil {
		return func() error {
			return c.ctx.Messenger().Send(msg, conn.MyDID, conn.TheirDID)
		}, nil
	} else if !errors.Is(err, storage.ErrDataNotFound) {
		return nil, err
	}

	dest, err := service.GetDestination(theirDID, c.ctx.VDRegistry())
	if err != nil {
		return nil, err
	}

	return c.sendToDestination(msg, dest)
}

func (c *Client) sendToDestination(msg service.DIDCommMsgMap, dest *service.Destination) (messageDispatcher, error) {
	_, sigPubKey, err := c.ctx.KMS().CreateAndExportPubKeyBytes(kms.ED25519Type)
	if err != nil {
		return nil, err
	}

	didKey, _ := fingerprint.CreateDIDKey(sigPubKey)

	return func() error {
		return c.ctx.Messenger().SendToDestination(msg, didKey, dest)
	}, nil
}

func (c *Client) sendAndWaitForReply(ctx context.Context, action messageDispatcher, thID string,
	replyType string) (json.RawMessage, error) {
	var notificationCh chan NotificationPayload

	if replyType != "" {
		topic := uuid.New().String()
		notificationCh = make(chan NotificationPayload)

		err := c.msgRegistrar.Register(newMessageService(topic, replyType, nil,
			NewNotifier(notificationCh, func(topic string, msgBytes []byte) bool {
				var message struct {
					Message service.DIDCommMsgMap `json:"message"`
				}

				err := json.Unmarshal(msgBytes, &message)
				if err != nil {
					logger.Debugf("failed to unmarshal incoming message reply: %s", err)
					return false
				}

				msgThID, err := message.Message.ThreadID()
				if err != nil {
					logger.Debugf("failed to read incoming message reply thread ID: %s", err)
					return false
				}

				return thID == "" || thID == msgThID
			})))
		if err != nil {
			return nil, err
		}

		defer func() {
			e := c.msgRegistrar.Unregister(topic)
			if e != nil {
				logger.Warnf("Failed to unregister wait for reply notifier: %w", e)
			}
		}()
	}

	err := action()
	if err != nil {
		return nil, err
	}

	if notificationCh != nil {
		return waitForResponse(ctx, notificationCh)
	}

	return json.RawMessage{}, nil
}

func waitForResponse(ctx context.Context, notificationCh chan NotificationPayload) (json.RawMessage, error) {
	select {
	case payload := <-notificationCh:
		return json.RawMessage(payload.Raw), nil

	case <-ctx.Done():
		return nil, fmt.Errorf("failed to get reply, context deadline exceeded")
	}
}

func prepareMessage(msg json.RawMessage) (service.DIDCommMsgMap, error) {
	didCommMsg, err := service.ParseDIDCommMsgMap(msg)
	if err != nil {
		return nil, err
	}

	if didCommMsg.ID() == "" {
		didCommMsg.SetID(uuid.New().String())
	}

	return didCommMsg, nil
}
