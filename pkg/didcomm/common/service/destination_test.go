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
}

func TestB58ToDIDKeys(t *testing.T) {
	t.Run("convert recipient keys in did doc", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockIndyDoc(t)

		recipientKeys := convertAnyB58Keys(didDoc.Service[0].RecipientKeys)
		require.NotNil(t, recipientKeys)
		require.Len(t, recipientKeys, 1)

		pk, err := fingerprint.PubKeyFromDIDKey(recipientKeys[0])
		require.NoError(t, err)
		require.ElementsMatch(t, didDoc.VerificationMethod[0].Value, pk)
	})

	t.Run("no keys given", func(t *testing.T) {
		recipientKeys := convertAnyB58Keys(nil)
		require.Nil(t, recipientKeys)
	})

	t.Run("some keys are converted", func(t *testing.T) {
		inKeys := []string{
			"6SFxbqdqGKtVVmLvXDnq9JP4ziZCG2fJzETpMYHt1VNx",
			"#key1",
			"6oDmCnt5w4h2hEQ12hwvD8w5JdvMDPYMzKNv5yPVomFu",
			"did:key:z6MkjtX1C5tGbsNxcGBdCnkfzPw4pHq3fuufgFNkBpFtviAL",
			"QEaG6QrDbx7dQ7U5Bm1Bqvx3psrGEqSieZACZ1LyU62",
			"/path#fragment",
			"9onu2hZrqtcoiVTkBStZ4N8iLYd24bmuHUvx9w3jb9av",
			"GTcPhsGS3XdkWL5mS8sxsTLzwPfSBCYVY93QeT95U6NQ",
			"?query=value",
			"FFPJcCWHGchhuiE5hV1BTRaiBzXpZfgYdsSPFHu6DSAC",
			"",
			"@!~unexpected data~!@",
		}
		expectedKeys := []string{
			"did:key:z6MkjtX1C5tGbsNxcGBdCnkfzPw4pHq3fuufgFNkBpFtviAL",
			"#key1",
			"did:key:z6MkkFUoo38XGcBVojEhiGum4EV58DCCdGnigLHqvFMWiz3H",
			"did:key:z6MkjtX1C5tGbsNxcGBdCnkfzPw4pHq3fuufgFNkBpFtviAL",
			"did:key:z6MkerVcrLfHZ9SajtxAkkir2wUwsQ9hg85oQfU62pyMtgsQ",
			"/path#fragment",
			"did:key:z6MkoG3wcwpJBS7GpzJSs1rPuTgiA7tsUV2FyVqszD1kWNNJ",
			"did:key:z6MkuusSJ7WsP58DcpvU7hqoiYtzkxwHb5nrE9xLUj76PK9n",
			"?query=value",
			"did:key:z6MktheMCSkicACB2D4nP3y2JX8i1ZofyYvuKtMK5Zs78ewa",
			"",
			"@!~unexpected data~!@",
		}

		outKeys := convertAnyB58Keys(inKeys)

		require.Equal(t, len(expectedKeys), len(outKeys))

		for i := range outKeys {
			require.Equal(t, expectedKeys[i], outKeys[i])

			// if we expect the key to be converted, check if it's converted correctly
			if inKeys[i] != expectedKeys[i] {
				pk, err := fingerprint.PubKeyFromDIDKey(outKeys[i])
				require.NoError(t, err)

				pkb58 := base58.Encode(pk)
				require.Equal(t, inKeys[i], pkb58)
			}
		}
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
