/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package packer

import (
	"encoding/base64"
	"encoding/json"

	"github.com/btcsuite/btcutil/base58"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
)

type envelope struct {
	Header  string `json:"protected,omitempty"`
	Sender  string `json:"spk,omitempty"`
	Message string `json:"msg,omitempty"`
}

type header struct {
	Type string `json:"typ,omitempty"`
}

// Packer encodes messages using the NO-OP format - sending them as-is, with only a header to indicate message format.
type Packer struct{}

// encodingType is the `typ` string identifier in a message that identifies the format as being legacy
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

	message := envelope{
		Header:  headerB64,
		Sender:  base58.Encode(sender),
		Message: string(payload),
	}

	msgBytes, err := json.Marshal(&message)

	return msgBytes, err
}

// Unpack will decode the envelope using the NOOP format.
func (p *Packer) Unpack(message []byte) ([]byte, []byte, error) {
	var env envelope

	err := json.Unmarshal(message, &env)
	if err != nil {
		return nil, nil, err
	}

	headerBytes, err := base64.URLEncoding.DecodeString(env.Header)
	if err != nil {
		return nil, nil, err
	}

	var head header

	err = json.Unmarshal(headerBytes, &head)
	if err != nil {
		return nil, nil, err
	}

	return []byte(env.Message), base58.Decode(env.Sender), nil
}

// EncodingType returns the type of the encoding, as found in the header `Typ` field
func (p *Packer) EncodingType() string {
	return encodingType
}
