/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connection

import "github.com/hyperledger/aries-framework-go/pkg/didcomm/didrotate"

type provider interface {
	DIDRotator() *didrotate.DIDRotator
}

// Client is a connection management SDK client.
type Client struct {
	didRotator *didrotate.DIDRotator
}

// New creates connection Client.
func New(prov provider) *Client {
	return &Client{
		didRotator: prov.DIDRotator(),
	}
}

// RotateDID rotates the DID of the given connection to the given new DID, using the signing KID for the key in the old
// DID doc to sign the DID rotation.
func (c *Client) RotateDID(connectionID, signingKID, newDID string) error {
	return c.didRotator.RotateConnectionDID(connectionID, signingKID, newDID)
}
