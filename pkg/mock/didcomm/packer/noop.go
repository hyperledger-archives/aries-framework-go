/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package packer

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/btcsuite/btcutil/base58"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
)

type envelope struct {
	Header    string `json:"protected,omitempty"`
	Sender    string `json:"spk,omitempty"`
	Recipient string `json:"kid,omitempty"`
	Message   string `json:"msg,omitempty"`
}

type header struct {
	Type string `json:"typ,omitempty"`
}

// Packer encodes messages using the NO-OP format - sending them as-is, with only a header to indicate message format.
type Packer struct{}

// encodingType is the `typ` string identifier in a message that identifies the format as being legacy.
const encodingType string = "NOOP"

// New will create a Packer that transmits messages IN PLAINTEXT.
// Never use this in production.
func New(ctx packer.Provider) *Packer {
	return &Packer{}
}

// Pack will wrap the payload in a bit of JSON and send it as plaintext. Will fail on non-string payloads.
func (p *Packer) Pack(payload, sender []byte, recipientPubKeys [][]byte) ([]byte, error) {
	head := header{
		Type: encodingType,
	}

	headerBytes, err := json.Marshal(&head)
	if err != nil {
		return nil, err
	}

	headerB64 := base64.URLEncoding.EncodeToString(headerBytes)

	if len(recipientPubKeys) == 0 {
		return nil, fmt.Errorf("no recipients")
	}

	message := envelope{
		Header:    headerB64,
		Sender:    base58.Encode(sender),
		Recipient: base58.Encode(recipientPubKeys[0]),
		Message:   string(payload),
	}

	msgBytes, err := json.Marshal(&message)

	return msgBytes, err
}

// Unpack will decode the envelope using the NOOP format.
func (p *Packer) Unpack(message []byte) (*transport.Envelope, error) {
	var env envelope

	err := json.Unmarshal(message, &env)
	if err != nil {
		return nil, err
	}

	headerBytes, err := base64.URLEncoding.DecodeString(env.Header)
	if err != nil {
		return nil, err
	}

	var head header

	err = json.Unmarshal(headerBytes, &head)
	if err != nil {
		return nil, err
	}

	return &transport.Envelope{
		Message: []byte(env.Message),
		FromKey: base58.Decode(env.Sender),
		ToKey:   base58.Decode(env.Recipient),
	}, nil
}

// EncodingType returns the type of the encoding, as found in the header `Typ` field.
func (p *Packer) EncodingType() string {
	return encodingType
}
