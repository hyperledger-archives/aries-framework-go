/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/mock/diddoc"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
)

func TestGetDestinationFromDID(t *testing.T) {
	doc := createDIDDoc()

	t.Run("successfully getting destination from public DID", func(t *testing.T) {
		vdr := mockvdr.MockVDRegistry{ResolveValue: doc}
		destination, err := GetDestination(doc.ID, &vdr)
		require.NoError(t, err)
		require.NotNil(t, destination)
	})

	t.Run("successfully getting destination from public DID with DIDComm V2 service block", func(t *testing.T) {
		doc2 := mockdiddoc.GetMockDIDDocWithDIDCommV2Bloc(t, "alicedid")
		vdr := mockvdr.MockVDRegistry{ResolveValue: doc2}
		destination, err := GetDestination(doc.ID, &vdr)
		require.NoError(t, err)
		require.NotNil(t, destination)
	})

	t.Run("successfully getting destination from public DID with DIDComm V2 service block using relative key "+
		"Agreement ID", func(t *testing.T) {
		doc2 := mockdiddoc.GetMockDIDDocWithDIDCommV2Bloc(t, "alicedid")
		prefixID := strings.Index(doc2.KeyAgreement[0].VerificationMethod.ID, "#")
		doc2.KeyAgreement[0].VerificationMethod.ID = doc2.KeyAgreement[0].VerificationMethod.ID[prefixID:]
		vdr := mockvdr.MockVDRegistry{ResolveValue: doc2}
		destination, err := GetDestination(doc.ID, &vdr)
		require.NoError(t, err)
		require.NotNil(t, destination)
	})

	t.Run("error getting destination from public DID with DIDComm V2 service block using empty key "+
		"Agreements", func(t *testing.T) {
		doc2 := mockdiddoc.GetMockDIDDocWithDIDCommV2Bloc(t, "alicedid")
		doc2.KeyAgreement = nil
		vdr := mockvdr.MockVDRegistry{ResolveValue: doc2}
		destination, err := GetDestination(doc.ID, &vdr)
		require.EqualError(t, err, fmt.Sprintf("create destination: no keyAgreements in diddoc for didcomm v2 "+
			"service bloc. DIDDoc: %+v", doc2))
		require.Nil(t, destination)
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
			diddoc.Service[i].ServiceEndpoint = model.NewDIDCommV1Endpoint("")
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
		doc := mockdiddoc.GetMockDIDDoc(t, false)
		dest, err := CreateDestination(doc)
		require.NoError(t, err)
		require.NotNil(t, dest)
		uri, err := dest.ServiceEndpoint.URI()
		require.NoError(t, err)
		require.Equal(t, uri, "https://localhost:8090")
		require.EqualValues(t, doc.Service[0].RoutingKeys, dest.RoutingKeys)
	})

	t.Run("successfully prepared legacy destination", func(t *testing.T) {
		doc := mockdiddoc.GetMockIndyDoc(t)
		dest, err := CreateDestination(doc)
		require.NoError(t, err)
		require.NotNil(t, dest)
		uri, err := dest.ServiceEndpoint.URI()
		require.NoError(t, err)
		require.Equal(t, uri, "https://localhost:8090")
		require.Equal(t, doc.Service[0].RoutingKeys, dest.RoutingKeys)
	})

	t.Run("error with destination having recipientKeys not did:keys", func(t *testing.T) {
		doc := mockdiddoc.GetMockDIDDoc(t, false)
		doc.Service[0].RecipientKeys = []string{"badKey"}
		dest, err := CreateDestination(doc)

		require.EqualError(t, err, "create destination: recipient key 1:[badKey] of didComm '' not a did:key")
		require.Nil(t, dest)
	})

	t.Run("error while getting service", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc(t, false)
		didDoc.Service = nil

		dest, err := CreateDestination(didDoc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing DID doc service")
		require.Nil(t, dest)
	})

	t.Run("error while getting recipient keys from did doc", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc(t, false)
		didDoc.Service[0].RecipientKeys = []string{}

		recipientKeys, ok := did.LookupDIDCommRecipientKeys(didDoc)
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
			ServiceEndpoint: model.NewDIDCommV1Endpoint("http://localhost:58416"),
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
