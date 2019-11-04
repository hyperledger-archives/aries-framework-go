/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package envelope

import "github.com/hyperledger/aries-framework-go/pkg/kms"

// KMSProvider interface for Packer ctx
type KMSProvider interface {
	KMS() kms.KeyManager
}

// Creator method to create new Packer service
type Creator func(prov KMSProvider) (Packer, error)

// Packer is an Aries envelope packer/unpacker to support
// secure DIDComm exchange of envelopes between Aries agents
// TODO create a higher-level packer that switches implementations based on the algorithm - Issue #273
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
	// 		[]byte containing the decrypted payload
	//		error if decryption failed
	// TODO add key type of recipients keys to be validated by the implementation - Issue #272
	Unpack(envelope []byte) ([]byte, error)
}
