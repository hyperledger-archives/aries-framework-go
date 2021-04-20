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
	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/mock/diddoc"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
)

func TestGetDestinationFromDID(t *testing.T) {
	doc := createDIDDoc()

	t.Run("successfully getting destination from public DID", func(t *testing.T) {
		vdr := mockvdr.MockVDRegistry{ResolveValue: doc}
		destination, err := GetDestination(doc.ID, &vdr)
		require.NoError(t, err)
		require.NotNil(t, destination)
	})

	t.Run("test service not found", func(t *testing.T) {
		doc2 := createDIDDoc()
		doc2.Service = nil
		vdr := mockvdr.MockVDRegistry{ResolveValue: doc2}
		destination, err := GetDestination(doc2.ID, &vdr)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing DID doc service")
		require.Nil(t, destination)
	})

	t.Run("fails if no service of type did-communication is found", func(t *testing.T) {
		diddoc := createDIDDoc()
		for i := range diddoc.Service {
			diddoc.Service[i].Type = "invalid"
		}
		vdr := &mockvdr.MockVDRegistry{ResolveValue: diddoc}
		_, err := GetDestination(diddoc.ID, vdr)
		require.Error(t, err)
	})

	t.Run("fails if the service endpoint is missing", func(t *testing.T) {
		diddoc := createDIDDoc()
		for i := range diddoc.Service {
			diddoc.Service[i].ServiceEndpoint = ""
		}
		vdr := &mockvdr.MockVDRegistry{ResolveValue: diddoc}
		_, err := GetDestination(diddoc.ID, vdr)
		require.Error(t, err)
	})

	t.Run("fails it there are no recipient keys", func(t *testing.T) {
		diddoc := createDIDDoc()
		for i := range diddoc.Service {
			diddoc.Service[i].RecipientKeys = nil
		}
		vdr := &mockvdr.MockVDRegistry{ResolveValue: diddoc}
		_, err := GetDestination(diddoc.ID, vdr)
		require.Error(t, err)
	})

	t.Run("test did document not found", func(t *testing.T) {
		vdr := mockvdr.MockVDRegistry{ResolveErr: errors.New("resolver error")}
		destination, err := GetDestination(doc.ID, &vdr)
		require.Error(t, err)
		require.Contains(t, err.Error(), "resolver error")
		require.Nil(t, destination)
	})
}

func TestPrepareDestination(t *testing.T) {
	t.Run("successfully prepared destination", func(t *testing.T) {
		doc := mockdiddoc.GetMockDIDDoc(t)
		dest, err := CreateDestination(doc)
		require.NoError(t, err)
		require.NotNil(t, dest)
		require.Equal(t, dest.ServiceEndpoint, "https://localhost:8090")
		require.Equal(t, doc.Service[0].RoutingKeys, dest.RoutingKeys)
	})

	t.Run("error while getting service", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc(t)
		didDoc.Service = nil

		dest, err := CreateDestination(didDoc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing DID doc service")
		require.Nil(t, dest)
	})

	t.Run("error while getting recipient keys from did doc", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc(t)
		didDoc.Service[0].RecipientKeys = []string{}

		recipientKeys, ok := did.LookupDIDCommRecipientKeys(didDoc)
		require.False(t, ok)
		require.Nil(t, recipientKeys)
	})
}

func TestCreateDestinationFromLegacyDoc(t *testing.T) {
	t.Run("successfully prepared destination", func(t *testing.T) {
		doc := mockdiddoc.GetMockIndyDoc(t)
		dest, err := CreateDestination(doc)
		require.NoError(t, err)
		require.NotNil(t, dest)
		require.Equal(t, dest.ServiceEndpoint, "https://localhost:8090")
		require.Equal(t, doc.Service[0].RoutingKeys, dest.RoutingKeys)
	})

	t.Run("error while getting service", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockIndyDoc(t)
		didDoc.Service = nil

		dest, err := createDestinationFromIndy(didDoc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing DID doc service")
		require.Nil(t, dest)
	})

	t.Run("missing service endpoint", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockIndyDoc(t)
		didDoc.Service = []did.Service{{
			Type: legacyDIDCommServiceType,
		}}

		dest, err := createDestinationFromIndy(didDoc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no service endpoint")
		require.Nil(t, dest)
	})

	t.Run("missing recipient keys", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockIndyDoc(t)
		didDoc.Service = []did.Service{{
			Type:            legacyDIDCommServiceType,
			ServiceEndpoint: "localhost:8080",
		}}

		dest, err := createDestinationFromIndy(didDoc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no recipient keys")
		require.Nil(t, dest)
	})
}

func TestLookupIndyKeys(t *testing.T) {
	t.Run("lookup recipient keys", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockIndyDoc(t)

		recipientKeys := lookupIndyRecipientKeys(didDoc, didDoc.Service[0].RecipientKeys)
		require.NotNil(t, recipientKeys)
		require.Len(t, recipientKeys, 1)

		pk, err := fingerprint.PubKeyFromDIDKey(recipientKeys[0])
		require.NoError(t, err)
		require.ElementsMatch(t, didDoc.VerificationMethod[0].Value, pk)
	})

	t.Run("no keys to lookup", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockIndyDoc(t)

		recipientKeys := lookupIndyRecipientKeys(didDoc, nil)
		require.Nil(t, recipientKeys)
	})

	t.Run("skip key that isn't found in verificationmethod list", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockIndyDoc(t)

		didDoc.Service[0].RecipientKeys = []string{"bad key"}

		recipientKeys := lookupIndyRecipientKeys(didDoc, didDoc.Service[0].RecipientKeys)
		require.Len(t, recipientKeys, 0)
	})

	t.Run("skip keys that aren't of handled type", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockIndyDoc(t)

		didDoc.VerificationMethod[0].Type = "bad type"

		recipientKeys := lookupIndyRecipientKeys(didDoc, didDoc.Service[0].RecipientKeys)
		require.Len(t, recipientKeys, 0)
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
	pubKey := did.VerificationMethod{
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
		Context:            []string{did.ContextV1},
		ID:                 id,
		VerificationMethod: []did.VerificationMethod{pubKey},
		Service:            services,
		Created:            &createdTime,
		Updated:            &createdTime,
	}

	return didDoc
}
