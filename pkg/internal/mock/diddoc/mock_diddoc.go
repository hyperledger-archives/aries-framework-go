/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package mockdiddoc

import (
	"github.com/btcsuite/btcutil/base58"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

// GetMockDIDDoc creates a mock DID Doc for testing.
func GetMockDIDDoc() *did.Doc {
	return &did.Doc{
		Context: []string{"https://w3id.org/did/v1"},
		ID:      "did:peer:123456789abcdefghi#inbox",
		Service: []did.Service{
			{
				ServiceEndpoint: "https://localhost:8090",
				Type:            "did-communication",
				Priority:        0,
				RecipientKeys:   []string{"did:example:123456789abcdefghi#keys-2"},
				RoutingKeys:     []string{"76HmFbj8sds7jjdnZ4hMVcQgtUYZpEN1HEmPnCrH2Bby"},
			},
			{
				ServiceEndpoint: "https://localhost:8090",
				Type:            "did-communication",
				Priority:        1,
				RecipientKeys:   []string{"did:example:123456789abcdefghi#keys-1"},
			},
		},
		PublicKey: []did.PublicKey{
			{
				ID:         "did:example:123456789abcdefghi#keys-1",
				Controller: "did:example:123456789abcdefghi",
				Type:       "Secp256k1VerificationKey2018",
				Value:      base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"),
			},
			{
				ID:         "did:example:123456789abcdefghi#keys-2",
				Controller: "did:example:123456789abcdefghi",
				Type:       "Ed25519VerificationKey2018",
				Value:      base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"),
			},
			{
				ID:         "did:example:123456789abcdefghw#key2",
				Controller: "did:example:123456789abcdefghw",
				Type:       "RsaVerificationKey2018",
				Value:      base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"),
			},
		},
	}
}
