/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package mockdiddoc

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
)

// GetMockDIDDoc creates a mock DID Doc for testing.
func GetMockDIDDoc(t *testing.T) *did.Doc {
	t.Helper()

	return &did.Doc{
		Context: []string{"https://w3id.org/did/v1"},
		ID:      "did:peer:123456789abcdefghi",
		Service: []did.Service{
			{
				ServiceEndpoint: "https://localhost:8090",
				Type:            "did-communication",
				Priority:        0,
				RecipientKeys:   []string{MockDIDKey(t)},
				RoutingKeys:     []string{MockDIDKey(t)},
			},
		},
		VerificationMethod: []did.VerificationMethod{
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

// MockDIDKey returns a new did:key DID for testing purposes.
func MockDIDKey(t *testing.T) string {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	d, _ := fingerprint.CreateDIDKey(pub)

	return d
}
