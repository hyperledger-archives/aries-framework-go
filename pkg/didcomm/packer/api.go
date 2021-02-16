/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package packer

import (
	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// Provider interface for Packer ctx.
type Provider interface {
	KMS() kms.KeyManager
	Crypto() cryptoapi.Crypto
	StorageProvider() storage.Provider
}

// Creator method to create new Packer service.
type Creator func(prov Provider) (Packer, error)

// Packer is an Aries envelope packer/unpacker to support
// secure DIDComm exchange of envelopes between Aries agents.
type Packer interface {
	// Pack a payload in an Aries compliant format using the sender keypair
	// and a list of recipients public keys
	// returns:
	// 		[]byte containing the encrypted envelope
	//		error if encryption failed
	// TODO add key type of recipients and sender keys to be validated by the implementation - Issue #272
	Pack(payload []byte, senderKey []byte, recipients [][]byte) ([]byte, error)
	// Unpack an envelope in an Aries compliant format.
	// 		The recipient's key will be the one found in KMS that matches one of the list of recipients in the envelope
	//
	// returns:
	// 		Envelope containing the message, decryption key, and sender key
	//		error if decryption failed
	// TODO add key type of recipients keys to be validated by the implementation - Issue #272
	Unpack(envelope []byte) (*transport.Envelope, error)

	// Encoding returns the type of the encoding, as found in the header `Typ` field
	EncodingType() string
}
