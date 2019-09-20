/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

// Wallet interface
type Wallet interface {
	Crypto
	Pack
	DIDCreator
}

// Crypto interface
type Crypto interface {

	// CreateKey create a new public/private signing keypair.
	//
	// Returns:
	//
	// string: verKey
	//
	// error: error
	CreateKey() (string, error)

	// SignMessage sign a message using the private key associated with a given verification key.
	//
	// Args:
	//
	// message: The message to sign
	//
	// fromVerKey: Sign using the private key related to this verification key
	//
	// Returns:
	//
	// []byte: The signature
	//
	// error: error
	SignMessage(message []byte, fromVerKey string) ([]byte, error)

	// DecryptMessage decrypt message
	//
	// Args:
	//
	// encMessage: The encrypted message content
	//
	// toVerKey:The verification key of the recipient.
	//
	// []byte: Decrypted message content
	//
	// string: The sender verification key
	//
	// error: error
	DecryptMessage(encMessage []byte, toVerKey string) ([]byte, string, error)
}

// Pack provide methods to pack and unpack msg
type Pack interface {
	// PackMessage Pack a message for one or more recipients.
	//
	// Args:
	//
	// envelope: The message to pack
	//
	// Returns:
	//
	// []byte: The packed message
	//
	// error: error
	PackMessage(envelope *Envelope) ([]byte, error)

	// UnpackMessage Unpack a message.
	//
	// Args:
	//
	// encMessage: The encrypted message
	//
	// Returns:
	//
	// envelope: unpack message
	//
	// error: error
	UnpackMessage(encMessage []byte) (*Envelope, error)
}

// DIDCreator provide method to create DID document
type DIDCreator interface {
	// Creates new DID document.
	//
	// Args:
	//
	// method: DID method
	//
	// opts: options to create DID
	//
	// Returns:
	//
	// did: DID document
	//
	// error: error
	CreateDID(method string, opts ...DocOpts) (*did.Doc, error)
}

// Envelope contain msg,FromVerKey and ToVerKeys
type Envelope struct {
	Message    []byte
	FromVerKey string
	// TODO add key type - issue #272
	ToVerKeys []string
}

// createDIDOpts holds the options for creating DID
type createDIDOpts struct {
	serviceType string
}

// DocOpts is a create DID option
type DocOpts func(opts *createDIDOpts)

// WithServiceType service type of DID document to be created
func WithServiceType(serviceType string) DocOpts {
	return func(opts *createDIDOpts) {
		opts.serviceType = serviceType
	}
}

// ErrKeyNotFound is returned when key not found
var ErrKeyNotFound = errors.New("key not found")
