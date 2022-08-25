/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package legacyconnection

import (
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

//nolint:gochecknoglobals
var (
	//go:embed testdata/valid_conn_data.jsonld
	validConnectionData string
)

// nolint:lll
func TestJSONConversion(t *testing.T) {
	con, err := parseLegacyJSONBytes([]byte(validConnectionData))
	require.NoError(t, err)
	require.NotEmpty(t, con)

	require.Equal(t, con.DID, "did:example:21tDAKCERh95uGgKbJNHYp")
	require.Equal(t, con.DIDDoc.ID, "did:example:21tDAKCERh95uGgKbJNHYp")
	require.Contains(t, con.DIDDoc.Context, "https://w3id.org/did/v0.11")
	require.Equal(t, con.DIDDoc.AlsoKnownAs[0], "did:example:123")
	require.Equal(t, con.DIDDoc.VerificationMethod[0].Type, "Secp256k1VerificationKey2018")
	require.Equal(t, base58.Encode(con.DIDDoc.VerificationMethod[0].Value), "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV")
	require.Equal(t, con.DIDDoc.Authentication[0].VerificationMethod.Type, "Secp256k1VerificationKey2018")
	require.Equal(t, base58.Encode(con.DIDDoc.Authentication[0].VerificationMethod.Value), "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV")
	require.Equal(t, con.DIDDoc.Service[0].Type, "IndyAgent")
	uri, err := con.DIDDoc.Service[0].ServiceEndpoint.URI()
	require.NoError(t, err)
	require.Contains(t, uri, "https://agent.example.com/")
	require.Equal(t, con.DIDDoc.Service[0].RecipientKeys, []string{"did:example:123456789abcdefghi#key2"})
	require.Equal(t, con.DIDDoc.Service[0].RoutingKeys, []string{"did:example:123456789abcdefghi#key2"})

	conBytes, err := con.toLegacyJSONBytes()
	require.NoError(t, err)
	require.NotEmpty(t, conBytes)

	rawString := string(conBytes)

	require.Contains(t, rawString, "\"DID\":\"did:example:21tDAKCERh95uGgKbJNHYp\"")
	require.Contains(t, rawString, "\"@context\":\"https://w3id.org/did/v1\"")
	require.Contains(t, rawString, "\"controller\":\"did:example:123456789abcdefghi\",\"id\":\"did:example:123456789abcdefghi#keys-1\",\"publicKeyBase58\":\"H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV\",\"type\":\"Secp256k1VerificationKey2018\"")
	require.Contains(t, rawString, "\"authentication\":[{\"publicKey\":\"did:example:123456789abcdefghi#keys-1\",\"type\":\"Secp256k1VerificationKey2018\"},{\"publicKey\":\"did:example:123456789abcdefghs#key3\",\"type\":\"RsaVerificationKey2018\"}]")
	require.Contains(t, rawString, "\"service\":[{\"id\":\"did:example:123456789abcdefghi#did-communication\",\"priority\":0,\"recipientKeys\":[\"did:example:123456789abcdefghi#key2\"],\"routingKeys\":[\"did:example:123456789abcdefghi#key2\"],\"serviceEndpoint\":\"https://agent.example.com/\",\"type\":\"IndyAgent\"}]")
}

func TestToLegacyJSONBytes(t *testing.T) {
	con := &Connection{
		DID: "did:example:21tDAKCERh95uGgKbJNHYp",
	}

	// Empty DIDDoc data
	legacyDoc, err := con.toLegacyJSONBytes()
	require.ErrorContains(t, err, "DIDDoc field cannot be empty")
	require.Empty(t, legacyDoc)

	// Success

	con.DIDDoc = &did.Doc{
		Context: "https://w3id.org/did/v0.11",
		ID:      "did:example:21tDAKCERh95uGgKbJNHYp",
	}
	legacyDoc, err = con.toLegacyJSONBytes()

	require.NoError(t, err)
	require.NotEmpty(t, legacyDoc)
	require.Contains(t, string(legacyDoc), "\"DID\":\"did:example:21tDAKCERh95uGgKbJNHYp\"")
	require.Contains(t, string(legacyDoc), "\"@context\":\"https://w3id.org/did/v1\"")
}

func TestParseJSONBytes(t *testing.T) {
	// Nil payload
	conRaw, err := parseLegacyJSONBytes(nil)
	require.ErrorContains(t, err, "JSON umarshalling of connection data bytes failed")
	require.Empty(t, conRaw)

	// Empty payload
	conRaw, err = parseLegacyJSONBytes([]byte{})
	require.ErrorContains(t, err, "JSON umarshalling of connection data bytes failed")
	require.Empty(t, conRaw)

	// Empty DIDDoc
	docBytes, err := json.Marshal(Connection{
		DID: "did:example:21tDAKCERh95uGgKbJNHYp",
	})
	require.NoError(t, err)
	require.NotEmpty(t, docBytes)

	conRaw, err = parseLegacyJSONBytes(docBytes)
	require.ErrorContains(t, err, "connection DIDDoc field is missed")
	require.Empty(t, conRaw)

	// Success
	con, err := parseLegacyJSONBytes([]byte(validConnectionData))
	require.NoError(t, err)
	require.NotEmpty(t, con)
}
