/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/internal/mock/diddoc"
	mockvdri "github.com/hyperledger/aries-framework-go/pkg/internal/mock/vdri"
)

func TestGetDestinationFromDID(t *testing.T) {
	doc := createDIDDoc()

	t.Run("successfully getting destination from public DID", func(t *testing.T) {
		vdr := mockvdri.MockVDRIRegistry{ResolveValue: doc}
		destination, err := GetDestination(doc.ID, &vdr)
		require.NoError(t, err)
		require.NotNil(t, destination)
	})

	t.Run("test public key not found", func(t *testing.T) {
		doc.PublicKey = nil
		vdr := mockvdri.MockVDRIRegistry{ResolveValue: doc}
		destination, err := GetDestination(doc.ID, &vdr)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing keys")
		require.Nil(t, destination)
	})

	t.Run("test service not found", func(t *testing.T) {
		doc2 := createDIDDoc()
		doc2.Service = nil
		vdr := mockvdri.MockVDRIRegistry{ResolveValue: doc2}
		destination, err := GetDestination(doc2.ID, &vdr)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing DID doc service")
		require.Nil(t, destination)
	})

	t.Run("test did document not found", func(t *testing.T) {
		vdr := mockvdri.MockVDRIRegistry{ResolveErr: errors.New("resolver error")}
		destination, err := GetDestination(doc.ID, &vdr)
		require.Error(t, err)
		require.Contains(t, err.Error(), "resolver error")
		require.Nil(t, destination)
	})
}

func TestPrepareDestination(t *testing.T) {
	ed25519KeyType := "Ed25519VerificationKey2018"
	didCommServiceType := "did-communication"

	t.Run("successfully prepared destination", func(t *testing.T) {
		dest, err := CreateDestination(mockdiddoc.GetMockDIDDoc())
		require.NoError(t, err)
		require.NotNil(t, dest)
		require.Equal(t, dest.ServiceEndpoint, "https://localhost:8090")
		require.Equal(t, []string{"76HmFbj8sds7jjdnZ4hMVcQgtUYZpEN1HEmPnCrH2Bby"}, dest.RoutingKeys)
	})

	t.Run("error while getting service", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc()
		didDoc.Service = nil

		dest, err := CreateDestination(didDoc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing DID doc service")
		require.Nil(t, dest)
	})

	t.Run("error while getting recipient keys from did doc", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc()
		didDoc.Service[0].RecipientKeys = []string{}

		recipientKeys, ok := did.LookupRecipientKeys(didDoc, didCommServiceType, ed25519KeyType)
		require.False(t, ok)
		require.Nil(t, recipientKeys)
	})
}

func createDIDDoc() *did.Doc {
	pubKey, _ := generateKeyPair()
	return createDIDDocWithKey(pubKey)
}

func generateKeyPair() (string, []byte) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	return base58.Encode(pubKey[:]), privKey
}

func createDIDDocWithKey(pub string) *did.Doc {
	const (
		didFormat    = "did:%s:%s"
		didPKID      = "%s#keys-%d"
		didServiceID = "%s#endpoint-%d"
		method       = "test"
	)

	id := fmt.Sprintf(didFormat, method, pub[:16])
	pubKeyID := fmt.Sprintf(didPKID, id, 1)
	pubKey := did.PublicKey{
		ID:         pubKeyID,
		Type:       "Ed25519VerificationKey2018",
		Controller: id,
		Value:      []byte(pub),
	}
	services := []did.Service{
		{
			ID:              fmt.Sprintf(didServiceID, id, 1),
			Type:            "did-communication",
			ServiceEndpoint: "http://localhost:58416",
			Priority:        0,
			RecipientKeys:   []string{pubKeyID},
		},
	}
	createdTime := time.Now()
	didDoc := &did.Doc{
		Context:   []string{did.Context},
		ID:        id,
		PublicKey: []did.PublicKey{pubKey},
		Service:   services,
		Created:   &createdTime,
		Updated:   &createdTime,
	}

	return didDoc
}
