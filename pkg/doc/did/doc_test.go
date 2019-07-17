/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"

	"github.com/stretchr/testify/require"
)

var pemPK = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAryQICCl6NZ5gDKrnSztO
3Hy8PEUcuyvg/ikC+VcIo2SFFSf18a3IMYldIugqqqZCs4/4uVW3sbdLs/6PfgdX
7O9D22ZiFWHPYA2k2N744MNiCD1UE+tJyllUhSblK48bn+v1oZHCM0nYQ2NqUkvS
j+hwUU3RiWl7x3D2s9wSdNt7XUtW05a/FXehsPSiJfKvHJJnGOX0BgTvkLnkAOTd
OrUZ/wK69Dzu4IvrN4vs9Nes8vbwPa/ddZEzGR0cQMt0JBkhk9kU/qwqUseP1QRJ
5I1jR4g8aYPL/ke9K35PxZWuDp3U0UPAZ3PjFAh+5T+fc7gzCs9dPzSHloruU+gl
FQIDAQAB
-----END PUBLIC KEY-----`

var validDoc = `{
  "@context": ["https://w3id.org/did/v1","https://w3id.org/did/v2"],
  "id": "did:example:21tDAKCERh95uGgKbJNHYp",
  "publicKey": [
    {
      "id": "did:example:123456789abcdefghi#keys-1",
      "type": "Secp256k1VerificationKey2018",
      "controller": "did:example:123456789abcdefghi",
      "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
    },
    {
      "id": "did:example:123456789abcdefghw#key2",
      "type": "RsaVerificationKey2018",
      "controller": "did:example:123456789abcdefghw",
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAryQICCl6NZ5gDKrnSztO\n3Hy8PEUcuyvg/ikC+VcIo2SFFSf18a3IMYldIugqqqZCs4/4uVW3sbdLs/6PfgdX\n7O9D22ZiFWHPYA2k2N744MNiCD1UE+tJyllUhSblK48bn+v1oZHCM0nYQ2NqUkvS\nj+hwUU3RiWl7x3D2s9wSdNt7XUtW05a/FXehsPSiJfKvHJJnGOX0BgTvkLnkAOTd\nOrUZ/wK69Dzu4IvrN4vs9Nes8vbwPa/ddZEzGR0cQMt0JBkhk9kU/qwqUseP1QRJ\n5I1jR4g8aYPL/ke9K35PxZWuDp3U0UPAZ3PjFAh+5T+fc7gzCs9dPzSHloruU+gl\nFQIDAQAB\n-----END PUBLIC KEY-----"
    }
  ],
  "authentication": [
    "did:example:123456789abcdefghi#keys-1",
    {
      "id": "did:example:123456789abcdefghs#key3",
      "type": "RsaVerificationKey2018",
      "controller": "did:example:123456789abcdefghs",
      "publicKeyHex": "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71"
    }
  ],
  "service": [
    {
      "id": "did:example:123456789abcdefghi#inbox",
      "type": "SocialWebInboxService",
      "serviceEndpoint": "https://social.example.com/83hfh37dj",
      "spamCost": {
        "amount": "0.50",
        "currency": "USD"
      }
    }
  ],
  "created": "2002-10-10T17:00:00Z",
  "proof": {
    "type": "LinkedDataSignature2015",
    "created": "2016-02-08T16:02:20Z",
    "creator": "did:example:8uQhQMGzWxR8vw5P3UWH1ja#keys-1",
    "signatureValue": "QNB13Y7Q9...1tzjn4w=="
  }
}`

func TestValid(t *testing.T) {

	doc, err := FromBytes([]byte(validDoc))
	require.NoError(t, err)
	require.NotNil(t, doc)
	require.Equal(t, "https://w3id.org/did/v1", doc.Context[0])

	// test doc id
	require.Equal(t, doc.ID, "did:example:21tDAKCERh95uGgKbJNHYp")

	hexDecodeValue, err := hex.DecodeString("02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71")
	block, _ := pem.Decode([]byte(pemPK))
	require.NotNil(t, block)

	// test authentication
	require.NoError(t, err)
	require.Equal(t, []VerificationMethod{{PublicKey: PublicKey{ID: "did:example:123456789abcdefghi#keys-1", Controller: "did:example:123456789abcdefghi",
		Type: "Secp256k1VerificationKey2018", Value: base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV")}}, {PublicKey: PublicKey{ID: "did:example:123456789abcdefghs#key3",
		Controller: "did:example:123456789abcdefghs", Type: "RsaVerificationKey2018", Value: hexDecodeValue}}}, doc.Authentication)

	// test public key
	require.Equal(t, []PublicKey{{ID: "did:example:123456789abcdefghi#keys-1", Controller: "did:example:123456789abcdefghi",
		Type: "Secp256k1VerificationKey2018", Value: base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV")}, {ID: "did:example:123456789abcdefghw#key2",
		Controller: "did:example:123456789abcdefghw", Type: "RsaVerificationKey2018", Value: block.Bytes}}, doc.PublicKey)

	// test service
	require.Equal(t, []Service{{ID: "did:example:123456789abcdefghi#inbox", Type: "SocialWebInboxService",
		ServiceEndpoint: "https://social.example.com/83hfh37dj", Properties: map[string]interface{}{"spamCost": map[string]interface{}{"amount": "0.50", "currency": "USD"}}}}, doc.Service)

	// test proof
	timeValue, err := time.Parse(time.RFC3339, "2016-02-08T16:02:20Z")
	require.NoError(t, err)
	require.Equal(t, Proof{Type: "LinkedDataSignature2015", Created: timeValue, Creator: "did:example:8uQhQMGzWxR8vw5P3UWH1ja#keys-1", SignatureValue: "QNB13Y7Q9...1tzjn4w==", Domain: "", Nonce: ""}, doc.Proof)

	// test created
	timeValue, err = time.Parse(time.RFC3339, "2002-10-10T17:00:00Z")
	require.NoError(t, err)
	require.Equal(t, timeValue, doc.Created)

	// test updated
	require.Empty(t, doc.Updated)
}

func TestPopulateAuthentications(t *testing.T) {
	t.Run("test key not exist", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDoc), &raw))
		raw.Authentication[0] = "did:example:123456789abcdefghs#key4"
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		_, err = FromBytes(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "authentication key did:example:123456789abcdefghs#key4 not exist in did doc public key")

	})
	t.Run("test value not valid", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDoc), &raw))
		raw.Authentication[0] = 1
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		_, err = FromBytes(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "authentication value is not map[string]interface{}")

	})
}

func TestPublicKeys(t *testing.T) {
	t.Run("test failed to decode PEM block", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDoc), &raw))
		raw.PublicKey[1][jsonldPublicKeyPem] = "wrongData"
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		_, err = FromBytes(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to decode PEM block containing public key")

	})

	t.Run("test public key encoding not supported", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDoc), &raw))
		delete(raw.PublicKey[1], jsonldPublicKeyPem)
		raw.PublicKey[1]["publicKeyMultibase"] = "wrongData"
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		_, err = FromBytes(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "public key encoding not supported")
	})
}

func TestFromBytes(t *testing.T) {
	// test error from Unmarshal
	_, err := FromBytes([]byte("wrongData"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to unmarshal did doc bytes")
}
