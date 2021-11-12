/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package packer

import (
	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	// EnvelopeEncodingTypeV2 is the default JWE `typ` protected header value as per:
	// https://identity.foundation/didcomm-messaging/spec/#didcomm-encrypted-message
	// and
	//nolint:lll
	// https://github.com/hyperledger/aries-rfcs/blob/master/features/0044-didcomm-file-and-mime-types/README.md#detecting-didcomm-versions
	// for DIDComm compliance.
	EnvelopeEncodingTypeV2 = "application/didcomm-encrypted+json"

	// ContentEncodingTypeV1 is the old `cty` protected header value, added to maintain backward compatibility as per:
	// https://github.com/hyperledger/aries-rfcs/tree/master/features/0587-encryption-envelope-v2#didcomm-v2-transition.
	ContentEncodingTypeV1 = "application/json;flavor=didcomm-msg"
	// ContentEncodingTypeV2 is the default JWE `cty` protected header.
	ContentEncodingTypeV2 = "application/didcomm-plain+json"
)

// Provider interface for Packer ctx.
type Provider interface {
	KMS() kms.KeyManager
	Crypto() cryptoapi.Crypto
	StorageProvider() storage.Provider
	VDRegistry() vdrapi.Registry
}

// Creator method to create new Packer service.
type Creator func(prov Provider) (Packer, error)

// Packer is an Aries envelope packer/unpacker to support
// secure DIDComm exchange of envelopes between Aries agents.
type Packer interface {
	// Pack a payload of type ContentType in an Aries compliant format using the sender keypair
	// and a list of recipients public keys
	// returns:
	// 		[]byte containing the encrypted envelope
	//		error if encryption failed
	Pack(contentType string, payload []byte, senderKey []byte, recipients [][]byte) ([]byte, error)
	// Unpack an envelope in an Aries compliant format.
	// 		The recipient's key will be the one found in KMS that matches one of the list of recipients in the envelope
	//
	// returns:
	// 		Envelope containing the message, decryption key, and sender key
	//		error if decryption failed
	Unpack(envelope []byte) (*transport.Envelope, error)

	// EncodingType returns the type of the encoding, as found in the protected header 'typ' field
	EncodingType() string
}
