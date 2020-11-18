/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package messaging

import (
	"encoding/json"
	"fmt"

	"github.com/btcsuite/btcutil/base58"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
)

const (
	// states.
	stateNameCompleted = "completed"

	// errors.
	errMsgConnectionMatchingDIDNotFound = "unable to find connection matching DID"
	errMsgDestinationMissing            = "missing message destination"
)

// errConnForDIDNotFound when matching connection ID not found.
var errConnForDIDNotFound = fmt.Errorf(errMsgConnectionMatchingDIDNotFound)

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
func (c *Client) Send(msg json.RawMessage, opts ...SendMessageOpions) error {
	sendOpts := &sendMsgOpts{}

	for _, opt := range opts {
		opt(sendOpts)
	}

	if sendOpts.connectionID != "" {
		conn, err := c.connectionLookup.GetConnectionRecord(sendOpts.connectionID)
		if err != nil {
			return err
		}

		return c.sendToConnection(msg, conn)
	}

	if sendOpts.theirDID != "" {
		conn, err := c.getConnectionByTheirDID(sendOpts.theirDID)

		if err != nil && err != errConnForDIDNotFound {
			return err
		}

		if conn != nil {
			return c.sendToConnection(msg, conn)
		}
	}

	return c.sendToDestination(msg, sendOpts)
}

// Reply sends reply to existing message.
func (c *Client) Reply(msg json.RawMessage, msgID string, startNewThread bool) error {
	didCommMsg, err := service.ParseDIDCommMsgMap(msg)
	if err != nil {
		return err
	}

	if startNewThread {
		return c.ctx.Messenger().ReplyToNested(didCommMsg, &service.NestedReplyOpts{MsgID: msgID})
	}

	return c.ctx.Messenger().ReplyTo(msgID, didCommMsg)
}

func (c *Client) getConnectionByTheirDID(theirDID string) (*connection.Record, error) {
	records, err := c.connectionLookup.QueryConnectionRecords()
	if err != nil {
		return nil, err
	}

	for _, record := range records {
		if record.State == stateNameCompleted && record.TheirDID == theirDID {
			return record, nil
		}
	}

	return nil, errConnForDIDNotFound
}

func (c *Client) sendToConnection(msg json.RawMessage, conn *connection.Record) error {
	didCommMsg, err := service.ParseDIDCommMsgMap(msg)
	if err != nil {
		return err
	}

	err = c.ctx.Messenger().Send(didCommMsg, conn.MyDID, conn.TheirDID)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) sendToDestination(msg json.RawMessage, rqst *sendMsgOpts) error {
	var dest *service.Destination

	// prepare destination
	if rqst.theirDID != "" {
		var err error

		dest, err = service.GetDestination(rqst.theirDID, c.ctx.VDRegistry())
		if err != nil {
			return err
		}
	} else if rqst.destination != nil {
		dest = rqst.destination
	}

	if dest == nil {
		return fmt.Errorf(errMsgDestinationMissing)
	}

	_, sigPubKey, err := c.ctx.KMS().CreateAndExportPubKeyBytes(kms.ED25519Type)
	if err != nil {
		return err
	}

	didCommMsg, err := service.ParseDIDCommMsgMap(msg)
	if err != nil {
		return err
	}

	return c.ctx.Messenger().SendToDestination(didCommMsg, base58.Encode(sigPubKey), dest)
}
