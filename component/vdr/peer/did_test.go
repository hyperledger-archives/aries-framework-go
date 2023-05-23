/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/models/did"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mock/storage"
)

func TestComputeDID(t *testing.T) {
	storedDoc := genesisDoc()
	require.NotNil(t, storedDoc)
	peerDID, err := computeDidMethod1(storedDoc)
	require.NoError(t, err)
	require.Len(t, peerDID, 57)
	require.Equal(t, "did:peer:1zQmZdT2jawCX5T1RKUB7ro83gQuiKbuHwuHi8G1NypB8BTr", peerDID)
}

func TestComputeDIDError(t *testing.T) {
	storedDoc := &did.Doc{ID: "did:peer:11"}
	_, err := computeDidMethod1(storedDoc)
	require.Error(t, err)
	assert.Equal(t, err.Error(), "the genesis version must include public keys and authentication")
}

func TestValidateDid(t *testing.T) {
	peerDoc, err := peerDidDoc()
	require.NoError(t, err)
	require.NotNil(t, peerDoc)
	err = validateDID(peerDoc)
	require.NoError(t, err)
}

func TestValidateDIDError(t *testing.T) {
	peerDoc := invalidPeerDIDDoc()
	require.NotNil(t, peerDoc)
	err := validateDID(peerDoc)
	require.Error(t, err)
	require.Contains(t, err.Error(), "did doesnt follow matching regex")
}

func TestValidateErrorHashString(t *testing.T) {
	peerDoc := &did.Doc{ID: "did:peer:1zQmVP6iorWky5rP9f6qxCyhRJ4tkEkvXWkbCpVXnbzFu4ay"}
	err := validateDID(peerDoc)
	require.Error(t, err)
	require.Contains(t, err.Error(), "multiHash of the doc doesnt match the computed multiHash")
}

func TestValidateDIDRegex(t *testing.T) {
	did1 := &did.Doc{ID: "did:peer:22"}
	err := validateDID(did1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "did doesnt follow matching regex")

	did2 := &did.Doc{ID: "did:sidetree:22"}
	err = validateDID(did2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "did doesnt follow matching regex")

	did3 := &did.Doc{ID: "did:peer:1-*&$*|||"}
	err = validateDID(did3)
	require.Error(t, err)
	require.Contains(t, err.Error(), "did doesnt follow matching regex")
}

func TestNewDoc(t *testing.T) {
	t.Run("New() success", func(t *testing.T) {
		publicKey := did.VerificationMethod{
			ID:         "did:example:123456789abcdefghi#keys-1",
			Type:       "Secp256k1VerificationKey2018",
			Controller: "did:example:123456789abcdefghi",
			Value:      []byte("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"),
		}

		doc, err := NewDoc(
			[]did.VerificationMethod{publicKey},
			did.WithAuthentication([]did.Verification{{VerificationMethod: publicKey}}))
		require.NoError(t, err)
		require.NotNil(t, doc)

		// validate function validates the DID as well
		err = validateDID(doc)
		require.NoError(t, err)
	})

	t.Run("New() without keys failure", func(t *testing.T) {
		_, err := NewDoc([]did.VerificationMethod{})
		require.EqualError(t, err, "the did:peer genesis version must include public keys and authentication")
	})

	t.Run("New() without authentication key failure", func(t *testing.T) {
		_, err := NewDoc([]did.VerificationMethod{})
		require.EqualError(t, err, "the did:peer genesis version must include public keys and authentication")
	})
}

func TestNewDocWithKeyAgreementVM(t *testing.T) {
	sProvider := storage.NewMockStoreProvider()
	km := newKMS(t, sProvider)

	t.Run("New Doc using default Ed25519 and X25519 keys (raw key bytes/non JWK)", func(t *testing.T) {
		ed25519VM, x25519VM := getSigningAndKeyAgreementKey(t, false, km)

		ed25519VM.ID = "did:peer:xyz#keys-1"
		x25519VM.VerificationMethod.ID = "did:peer:xyz#keys-1"
		ed25519VM.Controller = "did:peer:xyz"
		x25519VM.VerificationMethod.Controller = "did:peer:xyz"

		doc, err := NewDoc(
			[]did.VerificationMethod{ed25519VM},
			did.WithAuthentication([]did.Verification{{VerificationMethod: ed25519VM}}),
			did.WithKeyAgreement([]did.Verification{x25519VM}))
		require.NoError(t, err)
		require.NotNil(t, doc)

		// validate function validates the DID as well
		err = validateDID(doc)
		require.NoError(t, err)
	})

	t.Run("New Doc using P-256 keys (JWK)", func(t *testing.T) {
		p256Sign, p256Enc := getSigningAndKeyAgreementKey(t, true, km)

		doc, err := NewDoc(
			[]did.VerificationMethod{p256Sign},
			did.WithAuthentication([]did.Verification{{VerificationMethod: p256Sign}}),
			did.WithKeyAgreement([]did.Verification{p256Enc}))
		require.NoError(t, err)
		require.NotNil(t, doc)

		// validate function validates the DID as well
		err = validateDID(doc)
		require.NoError(t, err)
	})
}

func TestNewDocError(t *testing.T) {
	doc, err := NewDoc(nil, nil)
	require.Error(t, err)
	require.Equal(t, "the did:peer genesis version must include public keys and authentication", err.Error())
	require.Nil(t, doc)
}

// genesisDoc creates the doc without an id.
func genesisDoc() *did.Doc {
	//nolint:lll
	pk := []did.VerificationMethod{
		{
			ID:         "did:example:123456789abcdefghi#keys-1",
			Type:       "Secp256k1VerificationKey2018",
			Controller: "did:example:123456789abcdefghi",
			Value:      []byte(`"publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"`),
		},
		{
			ID:         "did:example:123456789abcdefghw#key2",
			Type:       "RsaVerificationKey2018",
			Controller: "did:example:123456789abcdefghw",
			Value:      []byte(`"publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAryQICCl6NZ5gDKrnSztO\n3Hy8PEUcuyvg/ikC+VcIo2SFFSf18a3IMYldIugqqqZCs4/4uVW3sbdLs/6PfgdX\n7O9D22ZiFWHPYA2k2N744MNiCD1UE+tJyllUhSblK48bn+v1oZHCM0nYQ2NqUkvS\nj+hwUU3RiWl7x3D2s9wSdNt7XUtW05a/FXehsPSiJfKvHJJnGOX0BgTvkLnkAOTd\nOrUZ/wK69Dzu4IvrN4vs9Nes8vbwPa/ddZEzGR0cQMt0JBkhk9kU/qwqUseP1QRJ\n5I1jR4g8aYPL/ke9K35PxZWuDp3U0UPAZ3PjFAh+5T+fc7gzCs9dPzSHloruU+gl\nFQIDAQAB\n-----END PUBLIC KEY-----"`),
		},
	}
	auth := []did.Verification{
		{
			VerificationMethod: did.VerificationMethod{
				ID:         "did:example:123456789abcdefghs#key3",
				Type:       "RsaVerificationKey2018",
				Controller: "did:example:123456789abcdefghs",
				Value:      []byte(`"publicKeyHex": "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71"`),
			},
		},
	}

	doc := &did.Doc{
		Context:            []string{"https://w3id.org/did/v1", "https://w3id.org/did/v2"},
		VerificationMethod: pk,
		Authentication:     auth,
		Created:            &time.Time{},
	}

	return &did.Doc{
		Context: doc.Context, VerificationMethod: doc.VerificationMethod, Authentication: doc.Authentication,
		Created: doc.Created,
	}
}

func peerDidDoc() (*did.Doc, error) {
	doc := genesisDoc()

	id, err := computeDidMethod1(doc)
	if err != nil {
		return nil, err
	}

	doc.ID = id

	return doc, nil
}

func invalidPeerDIDDoc() *did.Doc {
	doc := genesisDoc()
	doc.ID = "did:peer:11-"

	return doc
}
