/*
Copyright Scoir Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package messagepickup

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/messagepickup"
)

type provider interface {
	Service(id string) (interface{}, error)
}

// Client enable access to message pickup api.
type Client struct {
	service.Event
	messagepickupSvc protocolService
}

type protocolService interface {
	// DIDComm service
	service.DIDComm

	StatusRequest(connectionID string) (*messagepickup.Status, error)

	BatchPickup(connectionID string, size int) (int, error)

	Noop(connectionID string) error
}

// New return new instance of messagepickup client.
func New(ctx provider) (*Client, error) {
	svc, err := ctx.Service(messagepickup.MessagePickup)
	if err != nil {
		return nil, fmt.Errorf("failed to create msg pickup service: %w", err)
	}

	messagepickupSvc, ok := svc.(protocolService)
	if !ok {
		return nil, errors.New("cast service to message pickup service failed")
	}

	return &Client{
		Event:            messagepickupSvc,
		messagepickupSvc: messagepickupSvc,
	}, nil
}

// StatusRequest request a status message.
func (r *Client) StatusRequest(connectionID string) (*messagepickup.Status, error) {
	sts, err := r.messagepickupSvc.StatusRequest(connectionID)
	if err != nil {
		return nil, fmt.Errorf("message pickup client - status request: %w", err)
	}

	return sts, nil
}

// BatchPickup request to have multiple waiting messages sent inside a batch message
// to the DID.
func (r *Client) BatchPickup(connectionID string, size int) (int, error) {
	count, err := r.messagepickupSvc.BatchPickup(connectionID, size)
	if err != nil {
		return -1, fmt.Errorf("message pickup client - batch pickup: %w", err)
	}

	return count, nil
}

// Noop a message to reestablish a connection when there is no other reason to message the mediator.
func (r *Client) Noop(connectionID string) error {
	return r.messagepickupSvc.Noop(connectionID)
}
