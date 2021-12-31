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

// GetLegacyInteropMockDIDDoc creates a mock did doc for testing legacy interop didcomm.
func GetLegacyInteropMockDIDDoc(t *testing.T, id string, ed25519PubKey []byte) *did.Doc {
	t.Helper()

	peerDID := "did:peer:" + id

	pubKeyBase58 := base58.Encode(ed25519PubKey)

	return &did.Doc{
		Context: []string{"https://w3id.org/did/v1"},
		ID:      peerDID,
		Service: []did.Service{
			{
				ServiceEndpoint: "https://localhost:8090",
				Type:            "did-communication",
				Priority:        0,
				RecipientKeys:   []string{pubKeyBase58},
			},
			{
				ServiceEndpoint: "https://localhost:8090",
				Type:            "IndyAgent",
				Priority:        0,
				RecipientKeys:   []string{pubKeyBase58},
			},
		},
		VerificationMethod: []did.VerificationMethod{
			{
				ID:         peerDID + "#keys-1",
				Controller: peerDID,
				Type:       "Ed25519VerificationKey2018",
				Value:      ed25519PubKey,
			},
		},
	}
}

// GetMockDIDDocWithKeyAgreements creates mock DID doc with KeyAgreements.
func GetMockDIDDocWithKeyAgreements(t *testing.T) *did.Doc {
	didDoc := GetMockDIDDoc(t)

	didDoc.KeyAgreement = []did.Verification{
		{
			VerificationMethod: did.VerificationMethod{
				ID:         "did:example:123456789abcdefghi#keys3",
				Controller: "did:example:123456789abcdefghi",
				Type:       "X25519KeyAgreementKey2019",
				Value:      base58.Decode("JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr"),
			},
		},
		{
			VerificationMethod: did.VerificationMethod{
				ID:         "#keys4",
				Controller: "did:example:123456789abcdefghi",
				Type:       "X25519KeyAgreementKey2019",
				Value:      base58.Decode("JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr"),
			},
		},
	}

	return didDoc
}

// GetMockDIDDocWithDIDCommV2Bloc using a DIDComm V2 service bloc.
func GetMockDIDDocWithDIDCommV2Bloc(t *testing.T, id string) *did.Doc {
	t.Helper()

	peerDID := "did:peer:" + id

	return &did.Doc{
		Context: []string{"https://www.w3.org/ns/did/v1"},
		ID:      peerDID,
		Service: []did.Service{
			{
				ServiceEndpoint: "https://localhost:8090",
				Type:            "DIDCommMessaging",
				Priority:        0,
				RecipientKeys:   []string{MockDIDKey(t)},
				RoutingKeys:     []string{MockDIDKey(t)},
			},
		},
		VerificationMethod: []did.VerificationMethod{
			{
				ID:         peerDID + "#key-1",
				Controller: peerDID,
				Type:       "Secp256k1VerificationKey2018",
				Value:      base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"),
			},
			{
				ID:         peerDID + "#key-2",
				Controller: peerDID,
				Type:       "Ed25519VerificationKey2018",
				Value:      base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"),
			},
			{
				ID:         peerDID + "#key-3",
				Controller: "did:example:123456789abcdefghw",
				Type:       "RsaVerificationKey2018",
				Value:      base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"),
			},
		},
		KeyAgreement: []did.Verification{
			{
				Relationship: did.KeyAgreement,
				Embedded:     true,
				VerificationMethod: did.VerificationMethod{
					ID:         peerDID + "#key-4",
					Controller: peerDID,
					Type:       "X25519KeyAgreementKey2019",
					Value:      base58.Decode("JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr"),
				},
			},
		},
	}
}

// GetMockIndyDoc creates a mock DID Doc for testing.
func GetMockIndyDoc(t *testing.T) *did.Doc {
	t.Helper()

	return &did.Doc{
		Context: []string{"https://w3id.org/did/v1"},
		ID:      "did:sov:AyRHrP7u6rF1dKViGf5shA",
		VerificationMethod: []did.VerificationMethod{
			{
				ID:         "did:sov:AyRHrP7u6rF1dKViGf5shA#1",
				Type:       "Ed25519VerificationKey2018",
				Controller: "did:sov:AyRHrP7u6rF1dKViGf5shA",
				Value:      base58.Decode("6SFxbqdqGKtVVmLvXDnq9JP4ziZCG2fJzETpMYHt1VNx"),
			},
		},
		Service: []did.Service{
			{
				ID:              "did:sov:AyRHrP7u6rF1dKViGf5shA;indy",
				Type:            "IndyAgent",
				Priority:        0,
				RecipientKeys:   []string{"6SFxbqdqGKtVVmLvXDnq9JP4ziZCG2fJzETpMYHt1VNx"},
				ServiceEndpoint: "https://localhost:8090",
			},
		},
		Authentication: []did.Verification{
			{
				VerificationMethod: did.VerificationMethod{
					ID:         "did:sov:AyRHrP7u6rF1dKViGf5shA#1",
					Type:       "Ed25519VerificationKey2018",
					Controller: "did:sov:AyRHrP7u6rF1dKViGf5shA",
					Value:      base58.Decode("6SFxbqdqGKtVVmLvXDnq9JP4ziZCG2fJzETpMYHt1VNx"),
				},
				Relationship: 1,
				Embedded:     false,
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
