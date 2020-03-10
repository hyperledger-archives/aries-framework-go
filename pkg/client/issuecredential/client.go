/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
)

// Provider contains dependencies for the issuecredential protocol and is typically created by using aries.Context()
type Provider interface {
	Service(id string) (interface{}, error)
}

// ProtocolService defines the issuecredential service.
type ProtocolService interface {
	service.DIDComm
	Actions() ([]issuecredential.Action, error)
	ActionContinue(piID string, opt issuecredential.Opt) error
	ActionStop(piID string, err error) error
}

// Client enable access to issuecredential API
type Client struct {
	service.Event
	service ProtocolService
}

// New return new instance of the issuecredential client
func New(ctx Provider) (*Client, error) {
	raw, err := ctx.Service(issuecredential.Name)
	if err != nil {
		return nil, err
	}

	svc, ok := raw.(ProtocolService)
	if !ok {
		return nil, errors.New("cast service to issuecredential service failed")
	}

	return &Client{
		Event:   svc,
		service: svc,
	}, nil
}
