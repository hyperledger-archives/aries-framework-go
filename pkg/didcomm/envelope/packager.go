/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package envelope

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
)

// PackerProvider contains dependencies for the base packager and is typically created by using aries.Context()
type PackerProvider interface {
	Packer() Packer
}

// BasePackager is the basic implementation of Packager
type BasePackager struct {
	packer Packer
}

// New return new instance of KMS implementation
func New(ctx PackerProvider) (*BasePackager, error) {
	crypter := ctx.Packer()

	return &BasePackager{packer: crypter}, nil
}

// PackMessage Pack a message for one or more recipients.
func (p *BasePackager) PackMessage(envelope *Envelope) ([]byte, error) {
	if envelope == nil {
		return nil, errors.New("envelope argument is nil")
	}

	var recipients [][]byte

	for _, verKey := range envelope.ToVerKeys {
		// TODO It is possible to have different key schemes in an interop situation
		// there is no guarantee that each recipient is using the same key types
		// for now this package uses Ed25519 signing keys. Other key schemes should have their own
		// packer implementations.
		// decode base58 ver key
		verKeyBytes := base58.Decode(verKey)
		// create 32 byte key
		recipients = append(recipients, verKeyBytes)
	}
	// encrypt message
	bytes, err := p.packer.Pack(envelope.Message, base58.Decode(envelope.FromVerKey), recipients)
	if err != nil {
		return nil, fmt.Errorf("failed from encrypt: %w", err)
	}

	return bytes, nil
}

// UnpackMessage Unpack a message.
func (p *BasePackager) UnpackMessage(encMessage []byte) (*Envelope, error) {
	bytes, err := p.packer.Unpack(encMessage)
	if err != nil {
		return nil, fmt.Errorf("failed from decrypt: %w", err)
	}
	// TODO extract fromVerKey and toVerKey from packer.Unpack() call above and set them here
	return &Envelope{Message: bytes}, nil
}
