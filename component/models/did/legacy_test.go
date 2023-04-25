/*
Copyright Avast Software. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/models/did/endpoint"
)

func TestToLegacyRawDoc(t *testing.T) {
	doc, err := ParseDocument([]byte(validDocV011))
	require.NoError(t, err)
	require.NotEmpty(t, doc)

	legacyRawDoc, err := doc.ToLegacyRawDoc()
	require.NoError(t, err)

	rawDoc := &rawDoc{}
	err = mapstructure.Decode(legacyRawDoc, rawDoc)
	require.NoError(t, err)
	require.NotEmpty(t, rawDoc)

	require.Equal(t, rawDoc.ID, doc.ID)

	require.Equal(t, rawDoc.Context, ContextV1Old)

	require.Equal(t, rawDoc.PublicKey[0]["type"], doc.VerificationMethod[0].Type)
	require.Equal(t, rawDoc.PublicKey[0]["publicKeyBase58"], base58.Encode(doc.VerificationMethod[0].Value))
	require.Equal(t, rawDoc.PublicKey[1]["type"], doc.VerificationMethod[1].Type)
	require.Equal(t, rawDoc.PublicKey[1]["publicKeyBase58"], base58.Encode(doc.VerificationMethod[1].Value))

	require.Equal(t, rawDoc.Authentication[0].(map[string]string)["publicKey"], doc.Authentication[0].VerificationMethod.ID) //nolint: lll
	require.Equal(t, rawDoc.Authentication[0].(map[string]string)["type"], doc.Authentication[0].VerificationMethod.Type)
	require.Equal(t, rawDoc.Authentication[1].(map[string]string)["publicKey"], doc.Authentication[1].VerificationMethod.ID) //nolint: lll
	require.Equal(t, rawDoc.Authentication[1].(map[string]string)["type"], doc.Authentication[1].VerificationMethod.Type)

	require.Equal(t, rawDoc.PublicKey[0]["id"], doc.VerificationMethod[0].ID)
	require.Equal(t, rawDoc.Service[0]["id"], doc.Service[0].ID)
	uri, err := doc.Service[0].ServiceEndpoint.URI()
	require.NoError(t, err)
	require.Equal(t, rawDoc.Service[0]["serviceEndpoint"], uri)
}

func TestPopulateRawServicesLegacy(t *testing.T) {
	services := []Service{
		{
			ID:              "did:example:123456789abcdefghi",
			Type:            "IndyAgent",
			Priority:        0,
			RecipientKeys:   []string{"key1"},
			RoutingKeys:     []string{"key2"},
			ServiceEndpoint: endpoint.NewDIDCommV1Endpoint("https://agent.example.com/"),
			Properties:      map[string]interface{}{},
		},
		{
			ID:                       "did:example:123456789abcdefghi#indy",
			Type:                     "IndyAgent",
			Priority:                 0,
			relativeURL:              true,
			RecipientKeys:            []string{"did:example:123456789abcdefghi#key1"},
			RoutingKeys:              []string{"did:example:123456789abcdefghi#key2"},
			ServiceEndpoint:          endpoint.NewDIDCommV1Endpoint("https://agent.example.com/"),
			Properties:               map[string]interface{}{},
			recipientKeysRelativeURL: map[string]bool{"did:example:123456789abcdefghi#key1": true},
			routingKeysRelativeURL:   map[string]bool{"did:example:123456789abcdefghi#key2": true},
		},
	}

	rMap := populateRawServicesLegacy(services, "did:example:123456789abcdefghi", "")
	require.NotEmpty(t, rMap)

	// check without relative URI
	require.Equal(t, rMap[0]["id"], "did:example:123456789abcdefghi")
	require.Equal(t, rMap[0]["type"], "IndyAgent")
	require.Equal(t, rMap[0]["recipientKeys"], []string{"key1"})
	require.Equal(t, rMap[0]["routingKeys"], []string{"key2"})
	require.Equal(t, rMap[0]["serviceEndpoint"], "https://agent.example.com/")

	// check with relative URI
	require.Equal(t, rMap[1]["id"], "#indy")
	require.Equal(t, rMap[1]["type"], "IndyAgent")
	require.Equal(t, rMap[1]["recipientKeys"], []string{"#key1"})
	require.Equal(t, rMap[1]["routingKeys"], []string{"#key2"})
	require.Equal(t, rMap[1]["serviceEndpoint"], "https://agent.example.com/")
}
