/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package route

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/route"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
)

// ErrConnectionNotFound is returned when connection not found
var ErrConnectionNotFound = errors.New("connection not found")

// provider contains dependencies for the route protocol and is typically created by using aries.Context()
type provider interface {
	Service(id string) (interface{}, error)
	StorageProvider() storage.Provider
	TransientStorageProvider() storage.Provider
}

// Client enable access to route api
type Client struct {
	connectionLookup *connection.Lookup
	routeSvc         protocolService
}

// protocolService defines DID Exchange service.
type protocolService interface {
	// DIDComm service
	service.Handler

	// SendRequest send route request
	SendRequest(myDID, theirDID string) (string, error)
}

// New return new instance of route client
func New(ctx provider) (*Client, error) {
	svc, err := ctx.Service(route.Coordination)
	if err != nil {
		return nil, err
	}

	routeSvc, ok := svc.(protocolService)
	if !ok {
		return nil, errors.New("cast service to route service failed")
	}

	connectionLookup, err := connection.NewLookup(ctx)
	if err != nil {
		return nil, err
	}

	return &Client{
		routeSvc:         routeSvc,
		connectionLookup: connectionLookup,
	}, nil
}

// SendRequest send route request
func (c *Client) SendRequest(connectionID string) (string, error) {
	conn, err := c.connectionLookup.GetConnectionRecord(connectionID)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return "", ErrConnectionNotFound
		}

		return "", fmt.Errorf("cannot fetch state from store: connectionid=%s err=%s", connectionID, err)
	}

	reqID, err := c.routeSvc.SendRequest(conn.MyDID, conn.TheirDID)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}

	return reqID, nil
}
