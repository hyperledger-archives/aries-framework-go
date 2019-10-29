/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package envelope

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcutil/base58"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/crypto"
)

// Provider contains dependencies for the base packager and is typically created by using aries.Context()
type Provider interface {
	Crypter() crypto.Crypter
}

// BasePackager is the basic implementation of Packager
type BasePackager struct {
	crypter crypto.Crypter
}

// New return new instance of KMS implementation
func New(ctx Provider) (*BasePackager, error) {
	crypter := ctx.Crypter()

	return &BasePackager{crypter: crypter}, nil
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
		// for now this package uses Curve25519 encryption keys. Other key schemes should have their own
		// crypter implementations.
		// decode base58 ver key
		verKeyBytes := base58.Decode(verKey)
		// create 32 byte key
		recipients = append(recipients, verKeyBytes)
	}
	// encrypt message
	bytes, err := p.crypter.Encrypt(envelope.Message, base58.Decode(envelope.FromVerKey), recipients)
	if err != nil {
		return nil, fmt.Errorf("failed from encrypt: %w", err)
	}
	return bytes, nil
}

// UnpackMessage Unpack a message.
func (p *BasePackager) UnpackMessage(encMessage []byte) (*Envelope, error) {
	bytes, err := p.crypter.Decrypt(encMessage)
	if err != nil {
		return nil, fmt.Errorf("failed from decrypt: %w", err)
	}
	// TODO extract fromVerKey and toVerKey from crypter.Decrypt() call above and set them here
	return &Envelope{Message: bytes}, nil
}
