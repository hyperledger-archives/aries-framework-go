/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
)

const pemPK = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAryQICCl6NZ5gDKrnSztO
3Hy8PEUcuyvg/ikC+VcIo2SFFSf18a3IMYldIugqqqZCs4/4uVW3sbdLs/6PfgdX
7O9D22ZiFWHPYA2k2N744MNiCD1UE+tJyllUhSblK48bn+v1oZHCM0nYQ2NqUkvS
j+hwUU3RiWl7x3D2s9wSdNt7XUtW05a/FXehsPSiJfKvHJJnGOX0BgTvkLnkAOTd
OrUZ/wK69Dzu4IvrN4vs9Nes8vbwPa/ddZEzGR0cQMt0JBkhk9kU/qwqUseP1QRJ
5I1jR4g8aYPL/ke9K35PxZWuDp3U0UPAZ3PjFAh+5T+fc7gzCs9dPzSHloruU+gl
FQIDAQAB
-----END PUBLIC KEY-----`

//nolint:lll
const validDoc = `{
  "@context": ["https://w3id.org/did/v1"],
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
    },
    {
      "id": "did:example:123456789abcdefghi#did-communication",
      "type": "did-communication",
      "serviceEndpoint": "https://agent.example.com/",
      "priority" : 0,
      "recipientKeys" : ["did:example:123456789abcdefghi#key2"],
      "routingKeys" : ["did:example:123456789abcdefghi#key2"]
    }
  ],
  "created": "2002-10-10T17:00:00Z"
}`

//nolint:lll
const validDocV011 = `{
  "@context": ["https://w3id.org/did/v0.11"],
  "id": "did:example:21tDAKCERh95uGgKbJNHYp",
  "publicKey": [
    {
      "id": "did:example:123456789abcdefghi#keys-1",
      "type": "Secp256k1VerificationKey2018",
      "owner": "did:example:123456789abcdefghi",
      "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
    },
    {
      "id": "did:example:123456789abcdefghw#key2",
      "type": "RsaVerificationKey2018",
      "owner": "did:example:123456789abcdefghw",
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAryQICCl6NZ5gDKrnSztO\n3Hy8PEUcuyvg/ikC+VcIo2SFFSf18a3IMYldIugqqqZCs4/4uVW3sbdLs/6PfgdX\n7O9D22ZiFWHPYA2k2N744MNiCD1UE+tJyllUhSblK48bn+v1oZHCM0nYQ2NqUkvS\nj+hwUU3RiWl7x3D2s9wSdNt7XUtW05a/FXehsPSiJfKvHJJnGOX0BgTvkLnkAOTd\nOrUZ/wK69Dzu4IvrN4vs9Nes8vbwPa/ddZEzGR0cQMt0JBkhk9kU/qwqUseP1QRJ\n5I1jR4g8aYPL/ke9K35PxZWuDp3U0UPAZ3PjFAh+5T+fc7gzCs9dPzSHloruU+gl\nFQIDAQAB\n-----END PUBLIC KEY-----"
    }
  ],
  "authentication": [
    {
      "type": "Secp256k1VerificationKey2018",
      "publicKey": "did:example:123456789abcdefghi#keys-1"
    },
    {
      "id": "did:example:123456789abcdefghs#key3",
      "type": "RsaVerificationKey2018",
      "owner": "did:example:123456789abcdefghs",
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
    },
    {
      "id": "did:example:123456789abcdefghi#did-communication",
      "type": "did-communication",
      "serviceEndpoint": "https://agent.example.com/",
      "priority" : 0,
      "recipientKeys" : ["did:example:123456789abcdefghi#key2"],
      "routingKeys" : ["did:example:123456789abcdefghi#key2"]
    }
  ],
  "created": "2002-10-10T17:00:00Z"
}`

const did = "did:method:abc"
const creator = did + "#key-1"
const keyType = "Ed25519VerificationKey2018"
const signatureType = "Ed25519Signature2018"

func TestParseOfNull(t *testing.T) {
	doc, err := ParseDocument([]byte("null"))
	require.Error(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "document payload is not provided")
}

func TestValid(t *testing.T) {
	// use single value string type context
	singleCtxValidDoc := strings.ReplaceAll(validDoc, `"@context": ["https://w3id.org/did/v1"]`,
		`"@context": "https://w3id.org/did/v1"`)
	singleCtxValidDocV011 := strings.ReplaceAll(validDocV011, `"@context": ["https://w3id.org/did/v0.11"]`,
		`"@context": "https://w3id.org/did/v0.11"`)

	docs := []string{validDoc, validDocV011, singleCtxValidDoc, singleCtxValidDocV011}
	for _, d := range docs {
		doc, err := ParseDocument([]byte(d))
		require.NoError(t, err)
		require.NotNil(t, doc)
		require.Contains(t, doc.Context[0], "https://w3id.org/did/v")

		// test doc id
		require.Equal(t, doc.ID, "did:example:21tDAKCERh95uGgKbJNHYp")

		hexDecodeValue, err := hex.DecodeString("02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71")
		block, _ := pem.Decode([]byte(pemPK))
		require.NotNil(t, block)
		require.NoError(t, err)

		// test authentication
		eAuthentication := []VerificationMethod{
			{PublicKey: PublicKey{
				ID:         "did:example:123456789abcdefghi#keys-1",
				Controller: "did:example:123456789abcdefghi",
				Type:       "Secp256k1VerificationKey2018",
				Value:      base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV")}},
			{PublicKey: PublicKey{
				ID:         "did:example:123456789abcdefghs#key3",
				Controller: "did:example:123456789abcdefghs",
				Type:       "RsaVerificationKey2018",
				Value:      hexDecodeValue}}}
		require.Equal(t, eAuthentication, doc.Authentication)

		// test public key
		ePubKey := []PublicKey{
			{ID: "did:example:123456789abcdefghi#keys-1",
				Controller: "did:example:123456789abcdefghi",
				Type:       "Secp256k1VerificationKey2018",
				Value:      base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV")},
			{ID: "did:example:123456789abcdefghw#key2",
				Controller: "did:example:123456789abcdefghw",
				Type:       "RsaVerificationKey2018",
				Value:      block.Bytes}}
		require.Equal(t, ePubKey, doc.PublicKey)

		// test services
		eServices := []Service{
			{ID: "did:example:123456789abcdefghi#inbox",
				Type:            "SocialWebInboxService",
				ServiceEndpoint: "https://social.example.com/83hfh37dj",
				Properties:      map[string]interface{}{"spamCost": map[string]interface{}{"amount": "0.50", "currency": "USD"}},
			},
			{ID: "did:example:123456789abcdefghi#did-communication",
				Type:            "did-communication",
				Priority:        0,
				RecipientKeys:   []string{"did:example:123456789abcdefghi#key2"},
				RoutingKeys:     []string{"did:example:123456789abcdefghi#key2"},
				ServiceEndpoint: "https://agent.example.com/",
				Properties:      map[string]interface{}{},
			},
		}
		require.EqualValues(t, eServices, doc.Service)
	}
}

func TestValidWithProof(t *testing.T) {
	docs := []string{validDocWithProof, validDocV011WithProof}
	for _, d := range docs {
		doc, err := ParseDocument([]byte(d))
		require.NoError(t, err)
		require.NotNil(t, doc)

		// test proof
		created, err := time.Parse(time.RFC3339, "2019-09-23T14:16:59.484733-04:00")
		require.NoError(t, err)

		const encProofValue = "6mdES87erjP5r1qCSRW__otj-A_Rj0YgRO7XU_0Amhwdfa7AAmtGUSFGflR_fZqPYrY9ceLRVQCJ49s0q7-LBA"
		proofValue, err := base64.RawURLEncoding.DecodeString(encProofValue)
		require.NoError(t, err)

		nonce, err := base64.RawURLEncoding.DecodeString("")
		require.NoError(t, err)

		eProof := Proof{Type: "Ed25519Signature2018",
			Created:    &created,
			Creator:    "did:method:abc#key-1",
			ProofValue: proofValue,
			Domain:     "",
			Nonce:      nonce}
		require.Equal(t, []Proof{eProof}, doc.Proof)

		byteDoc, err := doc.JSONBytes()
		require.NoError(t, err)
		require.NotNil(t, byteDoc)

		// test invalid created
		docWithInvalid := docWithInvalidCreatedInProof
		if d == validDocV011WithProof {
			docWithInvalid = docV011WithInvalidCreatedInProof
		}

		invalidDoc, err := ParseDocument([]byte(docWithInvalid))
		require.NotNil(t, err)
		require.Nil(t, invalidDoc)
		require.Contains(t, err.Error(), "populate proofs failed")
	}
}

func TestInvalidEncodingInProof(t *testing.T) {
	proofKey := []string{jsonldProofValue, jsonldSignatureValue}
	for _, v := range proofKey {
		c := Context
		if v == jsonldSignatureValue {
			c = contextV011
		}
		// invalid encoding in nonce
		rawProofs := []interface{}{map[string]interface{}{
			"created": "2011-09-23T20:21:34Z",
			"creator": "did:method:abc#key-1",
			v:         "6mdES87erjP5r1qCSRW__otj-A_Rj0YgRO7XU_0Amhwdfa7AAmtGUSFGflR_fZqPYrY9ceLRVQCJ49s0q7-LBA",
			"nonce":   "Invalid\x01",
			"type":    "Ed25519Signature2018",
		}}
		doc, err := populateProofs(c, rawProofs)
		require.NotNil(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "illegal base64 data")

		// invalid encoding in proof value
		rawProofs = []interface{}{map[string]interface{}{
			"created": "2011-09-23T20:21:34Z",
			"creator": "did:method:abc#key-1",
			v:         "Invalid\x01",
			"type":    "Ed25519Signature2018",
		}}

		doc, err = populateProofs(c, rawProofs)
		require.NotNil(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "illegal base64 data")
	}
}

func TestPopulateAuthentications(t *testing.T) {
	t.Run("test key not exist", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDoc), &raw))
		raw.Authentication[0] = "did:example:123456789abcdefghs#key4"
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		_, err = ParseDocument(bytes)
		require.Error(t, err)

		expected := "authentication key did:example:123456789abcdefghs#key4 not exist in did doc public key"
		require.Contains(t, err.Error(), expected)
	})

	t.Run("test key not exist v0.11", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDocV011), &raw))
		m := make(map[string]string)
		m[jsonldPublicKey] = "did:example:123456789abcdefghs#key4"
		m["type"] = "key"
		raw.Authentication[0] = m
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		_, err = ParseDocument(bytes)
		require.Error(t, err)

		expected := "authentication key did:example:123456789abcdefghs#key4 not exist in did doc public key"
		require.Contains(t, err.Error(), expected)
	})
}

func TestPublicKeys(t *testing.T) {
	t.Run("test failed to decode PEM block", func(t *testing.T) {
		docs := []string{validDoc, validDocV011}
		for _, d := range docs {
			raw := &rawDoc{}
			require.NoError(t, json.Unmarshal([]byte(d), &raw))
			raw.PublicKey[1][jsonldPublicKeyPem] = "wrongData"
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			_, err = ParseDocument(bytes)
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to decode PEM block containing public key")
		}
	})

	t.Run("test public key encoding not supported", func(t *testing.T) {
		docs := []string{validDoc, validDocV011}
		for _, d := range docs {
			raw := &rawDoc{}
			require.NoError(t, json.Unmarshal([]byte(d), &raw))
			delete(raw.PublicKey[1], jsonldPublicKeyPem)
			raw.PublicKey[1]["publicKeyMultibase"] = "wrongData"
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			_, err = ParseDocument(bytes)
			require.Error(t, err)
			require.Contains(t, err.Error(), "public key encoding not supported")
		}
	})
}

func TestParseDocument(t *testing.T) {
	// test error from Unmarshal
	_, err := ParseDocument([]byte("wrongData"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "JSON marshalling of did doc bytes bytes failed")
}

func TestValidateDidDocContext(t *testing.T) {
	t.Run("test did doc with empty context", func(t *testing.T) {
		docs := []string{validDoc, validDocV011}
		for _, d := range docs {
			raw := &rawDoc{}
			require.NoError(t, json.Unmarshal([]byte(d), &raw))
			raw.Context = nil
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			err = validate(bytes, raw.schemaLoader())
			require.Error(t, err)
			require.Contains(t, err.Error(), "@context is required")
		}
	})

	t.Run("test did doc with invalid context", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDoc), &raw))
		raw.Context = []string{"https://w3id.org/did/v2", "https://w3id.org/did/v1"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, raw.schemaLoader())
		require.Error(t, err)
		require.Contains(t, err.Error(), "Does not match pattern '^https://")
	})
}

func TestValidateDidDocID(t *testing.T) {
	t.Run("test did doc with empty id", func(t *testing.T) {
		docs := []string{validDoc, validDocV011}
		for _, d := range docs {
			raw := &rawDoc{}
			require.NoError(t, json.Unmarshal([]byte(d), &raw))
			raw.ID = ""
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			err = validate(bytes, raw.schemaLoader())
			require.Error(t, err)
			require.Contains(t, err.Error(), "id is required")
		}
	})
}

func TestValidateDidDocPublicKey(t *testing.T) {
	t.Run("test did doc with empty public key", func(t *testing.T) {
		docs := []string{validDoc, validDocV011}
		for _, d := range docs {
			raw := &rawDoc{}
			require.NoError(t, json.Unmarshal([]byte(d), &raw))
			raw.PublicKey = nil
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			err = validate(bytes, raw.schemaLoader())
			require.NoError(t, err)
		}
	})

	t.Run("test did doc public key without id", func(t *testing.T) {
		docs := []string{validDoc, validDocV011}
		for _, d := range docs {
			raw := &rawDoc{}
			require.NoError(t, json.Unmarshal([]byte(d), &raw))
			delete(raw.PublicKey[0], jsonldID)
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			err = validate(bytes, raw.schemaLoader())
			require.Error(t, err)
			require.Contains(t, err.Error(), "id is required")
		}
	})

	t.Run("test did doc public key without type", func(t *testing.T) {
		docs := []string{validDoc, validDocV011}
		for _, d := range docs {
			raw := &rawDoc{}
			require.NoError(t, json.Unmarshal([]byte(d), &raw))
			delete(raw.PublicKey[0], jsonldType)
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			err = validate(bytes, raw.schemaLoader())
			require.Error(t, err)
			require.Contains(t, err.Error(), "type is required")
		}
	})

	t.Run("test did doc public key without controller", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDoc), &raw))
		delete(raw.PublicKey[0], jsonldController)
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, raw.schemaLoader())
		require.Error(t, err)
		require.Contains(t, err.Error(), "controller is required")
	})

	t.Run("test did doc public key without controller v0.11", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDocV011), &raw))
		delete(raw.PublicKey[0], jsonldOwner)
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, raw.schemaLoader())
		require.NoError(t, err)
	})
}

func TestValidateDidDocAuthentication(t *testing.T) {
	t.Run("test did doc with empty auth", func(t *testing.T) {
		docs := []string{validDoc, validDocV011}
		for _, d := range docs {
			raw := &rawDoc{}
			require.NoError(t, json.Unmarshal([]byte(d), &raw))
			raw.Authentication = nil
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			err = validate(bytes, raw.schemaLoader())
			require.NoError(t, err)
		}
	})

	t.Run("test did doc with invalid auth type", func(t *testing.T) {
		docs := []string{validDoc, validDocV011}
		for _, d := range docs {
			raw := &rawDoc{}
			require.NoError(t, json.Unmarshal([]byte(d), &raw))
			raw.Authentication[0] = 1
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			err = validate(bytes, raw.schemaLoader())
			require.Error(t, err)
			require.Contains(t, err.Error(), "Invalid type. Expected: object, given: integer")
		}
	})

	t.Run("test did doc auth public key without id", func(t *testing.T) {
		docs := []string{validDoc, validDocV011}
		for _, d := range docs {
			raw := &rawDoc{}
			require.NoError(t, json.Unmarshal([]byte(d), &raw))
			pk, ok := raw.Authentication[1].(map[string]interface{})
			require.True(t, ok)
			delete(pk, jsonldID)
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			err = validate(bytes, raw.schemaLoader())
			require.Error(t, err)
			require.Contains(t, err.Error(), "id is required")
		}
	})

	t.Run("test did doc auth public key without type", func(t *testing.T) {
		docs := []string{validDoc, validDocV011}
		for _, d := range docs {
			raw := &rawDoc{}
			require.NoError(t, json.Unmarshal([]byte(d), &raw))
			pk, ok := raw.Authentication[1].(map[string]interface{})
			require.True(t, ok)
			delete(pk, jsonldType)
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			err = validate(bytes, raw.schemaLoader())
			require.Error(t, err)
			require.Contains(t, err.Error(), "type is required")
		}
	})

	t.Run("test did doc auth public key without controller", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDoc), &raw))
		pk, ok := raw.Authentication[1].(map[string]interface{})
		require.True(t, ok)
		delete(pk, jsonldController)
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, raw.schemaLoader())
		require.Error(t, err)
		require.Contains(t, err.Error(), "controller is required")
	})

	t.Run("test did doc auth public key without controller v0.11", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDocV011), &raw))
		pk, ok := raw.Authentication[1].(map[string]interface{})
		require.True(t, ok)
		delete(pk, jsonldOwner)
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, raw.schemaLoader())
		require.NoError(t, err)
	})
}

func TestValidateDidDocService(t *testing.T) {
	t.Run("test did doc with empty service", func(t *testing.T) {
		docs := []string{validDoc, validDocV011}
		for _, d := range docs {
			raw := &rawDoc{}
			require.NoError(t, json.Unmarshal([]byte(d), &raw))
			raw.Service = nil
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			err = validate(bytes, raw.schemaLoader())
			require.NoError(t, err)
		}
	})

	t.Run("test did doc service without id", func(t *testing.T) {
		docs := []string{validDoc, validDocV011}
		for _, d := range docs {
			raw := &rawDoc{}
			require.NoError(t, json.Unmarshal([]byte(d), &raw))
			delete(raw.Service[0], jsonldID)
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			err = validate(bytes, raw.schemaLoader())
			require.Error(t, err)
			require.Contains(t, err.Error(), "id is required")
		}
	})

	t.Run("test did doc service without type", func(t *testing.T) {
		docs := []string{validDoc, validDocV011}
		for _, d := range docs {
			raw := &rawDoc{}
			require.NoError(t, json.Unmarshal([]byte(d), &raw))
			delete(raw.Service[0], jsonldType)
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			err = validate(bytes, raw.schemaLoader())
			require.Error(t, err)
			require.Contains(t, err.Error(), "type is required")
		}
	})

	t.Run("test did doc service without serviceEndpoint", func(t *testing.T) {
		docs := []string{validDoc, validDocV011}
		for _, d := range docs {
			raw := &rawDoc{}
			require.NoError(t, json.Unmarshal([]byte(d), &raw))
			delete(raw.Service[0], jsonldServicePoint)
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			err = validate(bytes, raw.schemaLoader())
			require.Error(t, err)
			require.Contains(t, err.Error(), "serviceEndpoint is required")
		}
	})
}

func TestValidateDidDocCreated(t *testing.T) {
	t.Run("test did doc with empty created", func(t *testing.T) {
		docs := []string{validDoc, validDocV011}
		for _, d := range docs {
			raw := &rawDoc{}
			require.NoError(t, json.Unmarshal([]byte(d), &raw))
			raw.Created = nil
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			err = validate(bytes, raw.schemaLoader())
			require.NoError(t, err)
		}
	})
	t.Run("test did doc with wrong format created", func(t *testing.T) {
		docs := []string{docWithInvalidCreated, docV011WithInvalidCreated}
		for _, d := range docs {
			doc, err := ParseDocument([]byte(d))
			require.Error(t, err)
			require.Nil(t, doc)
			require.Contains(t, err.Error(), "cannot parse")
		}
	})
}

func TestValidateDidDocUpdated(t *testing.T) {
	t.Run("test did doc with empty updated", func(t *testing.T) {
		docs := []string{validDoc, validDocV011}
		for _, d := range docs {
			raw := &rawDoc{}
			require.NoError(t, json.Unmarshal([]byte(d), &raw))
			raw.Updated = nil
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			err = validate(bytes, raw.schemaLoader())
			require.NoError(t, err)
		}
	})
	t.Run("test did doc with wrong format updated", func(t *testing.T) {
		docs := []string{docWithInvalidUpdated, docV011WithInvalidUpdated}
		for _, d := range docs {
			doc, err := ParseDocument([]byte(d))
			require.Error(t, err)
			require.Nil(t, doc)
			require.Contains(t, err.Error(), "cannot parse")
		}
	})
}

func TestValidateDidDocProof(t *testing.T) {
	t.Run("test did doc with empty proof", func(t *testing.T) {
		docs := []string{validDocWithProof, validDocV011WithProof}
		for _, d := range docs {
			raw := &rawDoc{}
			require.NoError(t, json.Unmarshal([]byte(d), &raw))
			raw.Proof = nil
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			err = validate(bytes, raw.schemaLoader())
			require.NoError(t, err)
		}
	})

	t.Run("test did doc proof without type", func(t *testing.T) {
		docs := []string{validDocWithProof, validDocV011WithProof}
		for _, d := range docs {
			raw := &rawDoc{}
			require.NoError(t, json.Unmarshal([]byte(d), &raw))
			proof, ok := raw.Proof[0].(map[string]interface{})
			require.True(t, ok)
			delete(proof, jsonldType)
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			err = validate(bytes, raw.schemaLoader())
			require.Error(t, err)
			require.Contains(t, err.Error(), "type is required")
		}
	})

	t.Run("test did doc proof without created", func(t *testing.T) {
		docs := []string{validDocWithProof, validDocV011WithProof}
		for _, d := range docs {
			raw := &rawDoc{}
			require.NoError(t, json.Unmarshal([]byte(d), &raw))
			proof, ok := raw.Proof[0].(map[string]interface{})
			require.True(t, ok)
			delete(proof, jsonldCreated)
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			err = validate(bytes, raw.schemaLoader())
			require.Error(t, err)
			require.Contains(t, err.Error(), "created is required")
		}
	})

	t.Run("test did doc proof without creator", func(t *testing.T) {
		docs := []string{validDocWithProof, validDocV011WithProof}
		for _, d := range docs {
			raw := &rawDoc{}
			require.NoError(t, json.Unmarshal([]byte(d), &raw))
			proof, ok := raw.Proof[0].(map[string]interface{})
			require.True(t, ok)
			delete(proof, jsonldCreator)
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			err = validate(bytes, raw.schemaLoader())
			require.Error(t, err)
			require.Contains(t, err.Error(), "creator is required")
		}
	})

	t.Run("test did doc proof without proofValue", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDocWithProof), &raw))
		proof, ok := raw.Proof[0].(map[string]interface{})
		require.True(t, ok)
		delete(proof, jsonldProofValue)
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, raw.schemaLoader())
		require.Error(t, err)
		require.Contains(t, err.Error(), "proofValue is required")
	})

	t.Run("test did doc proof without proofValue v0.11", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDocV011WithProof), &raw))
		proof, ok := raw.Proof[0].(map[string]interface{})
		require.True(t, ok)
		delete(proof, jsonldSignatureValue)
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, raw.schemaLoader())
		require.Error(t, err)
		require.Contains(t, err.Error(), "signatureValue is required")
	})

	t.Run("test did doc proof without domain", func(t *testing.T) {
		docs := []string{validDocWithProof, validDocV011WithProof}
		for _, d := range docs {
			raw := &rawDoc{}
			require.NoError(t, json.Unmarshal([]byte(d), &raw))
			proof, ok := raw.Proof[0].(map[string]interface{})
			require.True(t, ok)
			delete(proof, jsonldDomain)
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			err = validate(bytes, raw.schemaLoader())
			require.NoError(t, err)
		}
	})

	t.Run("test did doc proof without nonce", func(t *testing.T) {
		docs := []string{validDocWithProof, validDocV011WithProof}
		for _, d := range docs {
			raw := &rawDoc{}
			require.NoError(t, json.Unmarshal([]byte(d), &raw))
			proof, ok := raw.Proof[0].(map[string]interface{})
			require.True(t, ok)
			delete(proof, jsonldNonce)
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			err = validate(bytes, raw.schemaLoader())
			require.NoError(t, err)
		}
	})
}

func TestJSONConversion(t *testing.T) {
	docs := []string{validDoc, validDocV011}
	for _, d := range docs {
		// setup -> create Document from json byte data
		doc, err := ParseDocument([]byte(d))
		require.NoError(t, err)
		require.NotEmpty(t, doc)

		// convert Document to json byte data
		byteDoc, err := doc.JSONBytes()
		require.NoError(t, err)
		require.NotEmpty(t, byteDoc)

		// convert json byte data to document
		doc2, err := ParseDocument(byteDoc)
		require.NoError(t, err)
		require.NotEmpty(t, doc2)

		// verify documents created by ParseDocument and JSONBytes function matches
		require.Equal(t, doc, doc2)
	}
}

func TestVerifyProof(t *testing.T) {
	docs := []string{validDoc, validDocV011}
	for _, d := range docs {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}

		signedDoc := createSignedDidDocument(privKey, pubKey)

		suite := ed25519signature2018.New(ed25519signature2018.WithVerifier(&ed25519signature2018.PublicKeyVerifier{}))

		// happy path - valid signed document
		doc, err := ParseDocument(signedDoc)
		require.Nil(t, err)
		require.NotNil(t, doc)
		err = doc.VerifyProof(suite)
		require.NoError(t, err)

		// error - doc with invalid proof value
		doc.Proof[0].ProofValue = []byte("invalid")
		err = doc.VerifyProof(suite)
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "ed25519: invalid signature")

		// error - doc with no proof
		doc, err = ParseDocument([]byte(d))
		require.NoError(t, err)
		require.NotNil(t, doc)
		err = doc.VerifyProof(suite)
		require.Equal(t, ErrProofNotFound, err)
		require.Contains(t, err.Error(), "proof not found")
	}
}

func TestDidKeyResolver_Resolve(t *testing.T) {
	// error - key not found
	keyResolver := didKeyResolver{}
	key, err := keyResolver.Resolve("id")
	require.Equal(t, ErrKeyNotFound, err)
	require.Nil(t, key)

	testKeyVal := []byte("pub key")
	pubKeys := []PublicKey{{
		ID:    "id",
		Value: testKeyVal,
		Type:  keyType,
	}}

	// happy path - key found
	keyResolver = didKeyResolver{PubKeys: pubKeys}
	key, err = keyResolver.Resolve("id")
	require.NoError(t, err)
	require.Equal(t, testKeyVal, key.Value)
}

func TestBuildDoc(t *testing.T) {
	ti := time.Now()
	doc := BuildDoc(WithPublicKey([]PublicKey{{}}), WithService([]Service{{}, {}}),
		WithAuthentication([]VerificationMethod{{}}), WithCreatedTime(ti), WithUpdatedTime(ti))
	require.NotEmpty(t, doc)
	require.Equal(t, 1, len(doc.PublicKey))
	require.Equal(t, 2, len(doc.Service))
	require.Equal(t, 1, len(doc.Authentication))
	require.Equal(t, ti, *doc.Created)
	require.Equal(t, ti, *doc.Updated)
}

func TestParseDID(t *testing.T) {
	t.Run("scheme is always 'did'", func(t *testing.T) {
		did, err := Parse("did:example:123")
		require.NoError(t, err)
		require.Equal(t, "did", did.Scheme)
	})
	t.Run("parse method", func(t *testing.T) {
		did, err := Parse("did:example:123")
		require.NoError(t, err)
		require.Equal(t, "example", did.Method)
	})
	t.Run("parse method-specific-id", func(t *testing.T) {
		id := "123456789abcdefghi"
		did, err := Parse("did:test:" + id)
		require.NoError(t, err)
		require.Equal(t, id, did.MethodSpecificID)
	})
	t.Run("disallow less than 3 parts", func(t *testing.T) {
		_, err := Parse("did:test")
		require.Error(t, err)
		_, err = Parse("did")
		require.Error(t, err)
	})
	t.Run("disallow empty method-specific-id", func(t *testing.T) {
		_, err := Parse("did:test:")
		require.Error(t, err)
	})
	t.Run("allow more than 2 colons in method-specific-id", func(t *testing.T) {
		const id = "a:b:c:d:e:f:g"
		did, err := Parse("did:test:" + id)
		require.NoError(t, err)
		require.Equal(t, id, did.MethodSpecificID)
	})
	t.Run("allow leading colon in method-specific-id", func(t *testing.T) {
		const id = ":a:b:c:d:e:f"
		did, err := Parse("did:test:" + id)
		require.NoError(t, err)
		require.Equal(t, id, did.MethodSpecificID)
	})
	t.Run("disallow trailing colon in method-specific-id", func(t *testing.T) {
		_, err := Parse("did:test:a:b:c:d:e:f:")
		require.Error(t, err)
	})
	t.Run("disallow scheme other than 'did'", func(t *testing.T) {
		_, err := Parse("invalid:test:abcdefg123")
		require.Error(t, err)
	})
}

func Test_DID_String(t *testing.T) {
	const expected = "did:example:123456"
	did, err := Parse(expected)
	require.NoError(t, err)
	require.Equal(t, expected, did.String())
}

func TestDIDSchemas(t *testing.T) {
	t.Run("Test decode public key", func(t *testing.T) {
		tests := []struct {
			name   string
			didStr string
		}{
			{
				name: "DID with JWK & multiple contexts & extra public Key properties",
				didStr: `{
				"authentication": ["#5hgq2bNVTqyns_Nvcc_ybVHnFMx33_dAsfrfpZMTqTA", "#primary", "#recovery",
				"#aBpRoPAbz0yw0evvPM1aEot39hAkG-XHgxFptPYAd6s"],
				"capabilityDelegation": ["#5hgq2bNVTqyns_Nvcc_ybVHnFMx33_dAsfrfpZMTqTA", "#primary", "#recovery",
				"#aBpRoPAbz0yw0evvPM1aEot39hAkG-XHgxFptPYAd6s"],
				"keyAgreement": [{
				"type": "X25519KeyAgreementKey2019",
				"publicKeyBase58": "HFJE99F2iCaxCTKJdNPU8fML3N5jemVXksxcXvozRJu1",
				"id": "#keyAgreement",
				"usage": "signing",
				"controller": "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ"
			}],
				"assertionMethod": ["#5hgq2bNVTqyns_Nvcc_ybVHnFMx33_dAsfrfpZMTqTA", "#primary", "#recovery",
				"#aBpRoPAbz0yw0evvPM1aEot39hAkG-XHgxFptPYAd6s"],
				"@context": ["https://www.w3.org/ns/did/v1", "https://docs.example.com/contexts/sample/sample-v0.1.jsonld"],
				"publicKey": [{
				"id": "#5hgq2bNVTqyns_Nvcc_ybVHnFMx33_dAsfrfpZMTqTA",
				"usage": "signing",
				"publicKeyJwk": {
				"x": "DSE4CfCVKNgxNMDV6dK_DbcwshievbxwHJwOsGoSpaw",
				"kty": "EC",
				"crv": "secp256k1",
				"y": "xzrnm-VHA22nfGrNGGaLL9aPHRN26qyJNli3jByQSfQ",
				"kid": "5hgq2bNVTqyns_Nvcc_ybVHnFMx33_dAsfrfpZMTqTA"
			},
				"type": "EcdsaSecp256k1VerificationKey2019",
				"controller": "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ"
			}, {
				"publicKeyHex": "020d213809f09528d83134c0d5e9d2bf0db730b2189ebdbc701c9c0eb06a12a5ac",
				"type": "EcdsaSecp256k1VerificationKey2019",
				"id": "#primary",
				"usage": "signing",
				"controller": "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ"
			}, {
				"publicKeyHex": "02d5a045f28c14b3d5971b0df9aabd8ee44a3e3af52a1a14a206327991c6e54a80",
				"type": "EcdsaSecp256k1VerificationKey2019",
				"id": "#recovery",
				"usage": "recovery",
				"controller": "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ"
			}, {
				"type": "Ed25519VerificationKey2018",
				"publicKeyBase58": "GUXiqNHCdirb6NKpH6wYG4px3YfMjiCh6dQhU3zxQVQ7",
				"id": "#aBpRoPAbz0yw0evvPM1aEot39hAkG-XHgxFptPYAd6s",
				"usage": "signing",
				"controller": "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ"
			}],
				"capabilityInvocation": ["#5hgq2bNVTqyns_Nvcc_ybVHnFMx33_dAsfrfpZMTqTA", "#primary", "#recovery",
				"#aBpRoPAbz0yw0evvPM1aEot39hAkG-XHgxFptPYAd6s"],
				"id": "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ"
			}`,
			},
			{
				name: "DID with JWK & single context & extra public Key properties",
				didStr: `{
				"authentication": ["#5hgq2bNVTqyns_Nvcc_ybVHnFMx33_dAsfrfpZMTqTA", "#primary", "#recovery",
				"#aBpRoPAbz0yw0evvPM1aEot39hAkG-XHgxFptPYAd6s"],
				"capabilityDelegation": ["#5hgq2bNVTqyns_Nvcc_ybVHnFMx33_dAsfrfpZMTqTA", "#primary", "#recovery",
				"#aBpRoPAbz0yw0evvPM1aEot39hAkG-XHgxFptPYAd6s"],
				"keyAgreement": [{
				"type": "X25519KeyAgreementKey2019",
				"publicKeyBase58": "HFJE99F2iCaxCTKJdNPU8fML3N5jemVXksxcXvozRJu1",
				"id": "#keyAgreement",
				"usage": "signing",
				"controller": "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ"
			}],
				"assertionMethod": ["#5hgq2bNVTqyns_Nvcc_ybVHnFMx33_dAsfrfpZMTqTA", "#primary", "#recovery",
				"#aBpRoPAbz0yw0evvPM1aEot39hAkG-XHgxFptPYAd6s"],
				"@context": "https://w3id.org/did/v1",
				"publicKey": [{
				"id": "#5hgq2bNVTqyns_Nvcc_ybVHnFMx33_dAsfrfpZMTqTA",
				"usage": "signing",
				"publicKeyJwk": {
				"x": "DSE4CfCVKNgxNMDV6dK_DbcwshievbxwHJwOsGoSpaw",
				"kty": "EC",
				"crv": "secp256k1",
				"y": "xzrnm-VHA22nfGrNGGaLL9aPHRN26qyJNli3jByQSfQ",
				"kid": "5hgq2bNVTqyns_Nvcc_ybVHnFMx33_dAsfrfpZMTqTA"
			},
				"type": "EcdsaSecp256k1VerificationKey2019",
				"controller": "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ"
			}, {
				"publicKeyHex": "020d213809f09528d83134c0d5e9d2bf0db730b2189ebdbc701c9c0eb06a12a5ac",
				"type": "EcdsaSecp256k1VerificationKey2019",
				"id": "#primary",
				"usage": "signing",
				"controller": "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ"
			}, {
				"publicKeyHex": "02d5a045f28c14b3d5971b0df9aabd8ee44a3e3af52a1a14a206327991c6e54a80",
				"type": "EcdsaSecp256k1VerificationKey2019",
				"id": "#recovery",
				"usage": "recovery",
				"controller": "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ"
			}, {
				"type": "Ed25519VerificationKey2018",
				"publicKeyBase58": "GUXiqNHCdirb6NKpH6wYG4px3YfMjiCh6dQhU3zxQVQ7",
				"id": "#aBpRoPAbz0yw0evvPM1aEot39hAkG-XHgxFptPYAd6s",
				"usage": "signing",
				"controller": "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ"
			}],
				"capabilityInvocation": ["#5hgq2bNVTqyns_Nvcc_ybVHnFMx33_dAsfrfpZMTqTA", "#primary", "#recovery",
				"#aBpRoPAbz0yw0evvPM1aEot39hAkG-XHgxFptPYAd6s"],
				"id": "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ"
			}`,
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				doc, err := ParseDocument([]byte(tc.didStr))
				require.NoError(t, err)
				require.NotNil(t, doc)
			})
		}
	})
}

func createDidDocumentWithSigningKey(pubKey []byte) *Doc {
	const didContext = "https://w3id.org/did/v1"

	signingKey := PublicKey{
		ID:         creator,
		Type:       keyType,
		Controller: did,
		Value:      pubKey,
	}

	createdTime := time.Now()

	didDoc := &Doc{
		Context:   []string{didContext},
		ID:        did,
		PublicKey: []PublicKey{signingKey},
		Created:   &createdTime,
		Updated:   &createdTime,
	}

	return didDoc
}

func createSignedDidDocument(privKey, pubKey []byte) []byte {
	didDoc := createDidDocumentWithSigningKey(pubKey)

	jsonDoc, err := didDoc.JSONBytes()
	if err != nil {
		panic(err)
	}

	context := &signer.Context{Creator: creator,
		SignatureType: signatureType}

	s := signer.New(ed25519signature2018.New(
		ed25519signature2018.WithSigner(getSigner(privKey))))

	signedDoc, err := s.Sign(context, jsonDoc)
	if err != nil {
		panic(err)
	}

	return signedDoc
}

func getSigner(privKey []byte) *testSigner {
	return &testSigner{privateKey: privKey}
}

type testSigner struct {
	privateKey []byte
}

func (s *testSigner) Sign(doc []byte) ([]byte, error) {
	if l := len(s.privateKey); l != ed25519.PrivateKeySize {
		return nil, errors.New("ed25519: bad private key length")
	}

	return ed25519.Sign(s.privateKey, doc), nil
}

const validDocWithProof = `{
	"@context": ["https://w3id.org/did/v1"],
	"created": "2019-09-23T14:16:59.261024-04:00",
	"id": "did:method:abc",
	"proof": [{
		"created": "2019-09-23T14:16:59.484733-04:00",
		"creator": "did:method:abc#key-1",
		"domain": "",
		"nonce": "",
		"proofValue": "6mdES87erjP5r1qCSRW__otj-A_Rj0YgRO7XU_0Amhwdfa7AAmtGUSFGflR_fZqPYrY9ceLRVQCJ49s0q7-LBA",
		"type": "Ed25519Signature2018"
	}],
	"publicKey": [{
		"controller": "did:method:abc",
		"id": "did:method:abc#key-1",
		"publicKeyBase58": "GY4GunSXBPBfhLCzDL7iGmP5dR3sBDCJZkkaGK8VgYQf",
		"type": "Ed25519VerificationKey2018"
	}],
	"updated": "2019-09-23T14:16:59.261024-04:00"
}`

const validDocV011WithProof = `{
	"@context": ["https://w3id.org/did/v0.11"],
	"created": "2019-09-23T14:16:59.261024-04:00",
	"id": "did:method:abc",
	"proof": [{
		"created": "2019-09-23T14:16:59.484733-04:00",
		"creator": "did:method:abc#key-1",
		"domain": "",
		"nonce": "",
		"signatureValue": "6mdES87erjP5r1qCSRW__otj-A_Rj0YgRO7XU_0Amhwdfa7AAmtGUSFGflR_fZqPYrY9ceLRVQCJ49s0q7-LBA",
		"type": "Ed25519Signature2018"
	}],
	"publicKey": [{
		"owner": "did:method:abc",
		"id": "did:method:abc#key-1",
		"publicKeyBase58": "GY4GunSXBPBfhLCzDL7iGmP5dR3sBDCJZkkaGK8VgYQf",
		"type": "Ed25519VerificationKey2018"
	}],
	"updated": "2019-09-23T14:16:59.261024-04:00"
}`

const docWithInvalidCreatedInProof = `{
	"@context": ["https://w3id.org/did/v1"],
	"created": "2019-09-23T14:16:59.261024-04:00",
	"id": "did:method:abc",
	"proof": [{
		"created": "2019-9-23T14:16:59",
		"creator": "did:method:abc#key-1",
		"domain": "",
		"nonce": "",
		"proofValue": "6mdES87erjP5r1qCSRW__otj-A_Rj0YgRO7XU_0Amhwdfa7AAmtGUSFGflR_fZqPYrY9ceLRVQCJ49s0q7-LBA",
		"type": "Ed25519Signature2018"
	}]
}`

const docV011WithInvalidCreatedInProof = `{
	"@context": ["https://w3id.org/did/v0.11"],
	"created": "2019-09-23T14:16:59.261024-04:00",
	"id": "did:method:abc",
	"proof": [{
		"created": "2019-9-23T14:16:59",
		"creator": "did:method:abc#key-1",
		"domain": "",
		"nonce": "",
		"signatureValue": "6mdES87erjP5r1qCSRW__otj-A_Rj0YgRO7XU_0Amhwdfa7AAmtGUSFGflR_fZqPYrY9ceLRVQCJ49s0q7-LBA",
		"type": "Ed25519Signature2018"
	}]
}`

const docWithInvalidCreated = `{
	"@context": ["https://w3id.org/did/v1"],
	"created": "2019-9-23T14:16:59.261024-04:00",
	"id": "did:method:abc"
}`

const docV011WithInvalidCreated = `{
	"@context": ["https://w3id.org/did/v0.11"],
	"created": "2019-9-23T14:16:59.261024-04:00",
	"id": "did:method:abc"
}`

const docWithInvalidUpdated = `{
	"@context": ["https://w3id.org/did/v1"],
	"created": "2019-09-23T14:16:59.484733-04:00",
	"updated": "2019-9-23T14:16:59.261024-04:00",
	"id": "did:method:abc"
}`

const docV011WithInvalidUpdated = `{
	"@context": ["https://w3id.org/did/v0.11"],
	"created": "2019-09-23T14:16:59.484733-04:00",
	"updated": "2019-9-23T14:16:59.261024-04:00",
	"id": "did:method:abc"
}`
