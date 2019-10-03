/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"
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
    }
  ],
  "created": "2002-10-10T17:00:00Z"
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

	// test service
	eService := []Service{
		{ID: "did:example:123456789abcdefghi#inbox",
			Type:            "SocialWebInboxService",
			ServiceEndpoint: "https://social.example.com/83hfh37dj",
			Properties:      map[string]interface{}{"spamCost": map[string]interface{}{"amount": "0.50", "currency": "USD"}}}}
	require.Equal(t, eService, doc.Service)
}

func TestValidWithProof(t *testing.T) {
	doc, err := FromBytes([]byte(validDocWithProof))
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
	invalidDoc, err := FromBytes([]byte(docWithInvalidCreatedInProof))
	require.NotNil(t, err)
	require.Nil(t, invalidDoc)
	require.Contains(t, err.Error(), "populate proofs failed")
}

func TestInvalidEncodingInProof(t *testing.T) {
	// invalid encoding in nonce
	rawProofs := []interface{}{map[string]interface{}{
		"created":    "2011-09-23T20:21:34Z",
		"creator":    "did:method:abc#key-1",
		"proofValue": "6mdES87erjP5r1qCSRW__otj-A_Rj0YgRO7XU_0Amhwdfa7AAmtGUSFGflR_fZqPYrY9ceLRVQCJ49s0q7-LBA",
		"nonce":      "Invalid\x01",
		"type":       "Ed25519Signature2018",
	}}
	doc, err := populateProofs(rawProofs)
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "illegal base64 data")

	// invalid encoding in proof value
	rawProofs = []interface{}{map[string]interface{}{
		"created":    "2011-09-23T20:21:34Z",
		"creator":    "did:method:abc#key-1",
		"proofValue": "Invalid\x01",
		"type":       "Ed25519Signature2018",
	}}

	doc, err = populateProofs(rawProofs)
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "illegal base64 data")
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

		expected := "authentication key did:example:123456789abcdefghs#key4 not exist in did doc public key"
		require.Contains(t, err.Error(), expected)
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

func TestValidateDidDocContext(t *testing.T) {
	t.Run("test did doc with empty context", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDoc), &raw))
		raw.Context = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "@context is required")
	})

	t.Run("test did doc with invalid context", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDoc), &raw))
		raw.Context = []string{"https://w3id.org/did/v2", "https://w3id.org/did/v1"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Does not match pattern '^https://w3id.org/did/v1$'")
	})
}

func TestValidateDidDocID(t *testing.T) {
	t.Run("test did doc with empty id", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDoc), &raw))
		raw.ID = ""
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "id is required")
	})
}

func TestValidateDidDocPublicKey(t *testing.T) {
	t.Run("test did doc with empty public key", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDoc), &raw))
		raw.PublicKey = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes)
		require.NoError(t, err)
	})

	t.Run("test did doc public key without id", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDoc), &raw))
		delete(raw.PublicKey[0], jsonldID)
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "id is required")
	})

	t.Run("test did doc public key without type", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDoc), &raw))
		delete(raw.PublicKey[0], jsonldType)
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "type is required")
	})

	t.Run("test did doc public key without controller", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDoc), &raw))
		delete(raw.PublicKey[0], jsonldController)
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "controller is required")
	})

	t.Run("test did doc public key with extra key", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDoc), &raw))
		raw.PublicKey[0]["key1"] = ""
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Must have at most 4 properties")
	})
}

func TestValidateDidDocAuthentication(t *testing.T) {
	t.Run("test did doc with empty auth", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDoc), &raw))
		raw.Authentication = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes)
		require.NoError(t, err)
	})

	t.Run("test did doc with invalid auth type", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDoc), &raw))
		raw.Authentication[0] = 1
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Invalid type. Expected: object, given: integer")
	})

	t.Run("test did doc auth public key without id", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDoc), &raw))
		pk, ok := raw.Authentication[1].(map[string]interface{})
		require.True(t, ok)
		delete(pk, jsonldID)
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "id is required")
	})

	t.Run("test did doc auth public key without type", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDoc), &raw))
		pk, ok := raw.Authentication[1].(map[string]interface{})
		require.True(t, ok)
		delete(pk, jsonldType)
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "type is required")
	})

	t.Run("test did doc auth public key without controller", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDoc), &raw))
		pk, ok := raw.Authentication[1].(map[string]interface{})
		require.True(t, ok)
		delete(pk, jsonldController)
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "controller is required")
	})

	t.Run("test did doc auth public key with extra key", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDoc), &raw))
		pk, ok := raw.Authentication[1].(map[string]interface{})
		require.True(t, ok)
		pk["key1"] = ""
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Must have at most 4 properties")
	})
}

func TestValidateDidDocService(t *testing.T) {
	t.Run("test did doc with empty service", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDoc), &raw))
		raw.Service = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes)
		require.NoError(t, err)
	})

	t.Run("test did doc service without id", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDoc), &raw))
		delete(raw.Service[0], jsonldID)
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "id is required")
	})

	t.Run("test did doc service without type", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDoc), &raw))
		delete(raw.Service[0], jsonldType)
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "type is required")
	})

	t.Run("test did doc service without serviceEndpoint", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDoc), &raw))
		delete(raw.Service[0], jsonldServicePoint)
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "serviceEndpoint is required")
	})
}

func TestValidateDidDocCreated(t *testing.T) {
	t.Run("test did doc with empty created", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDoc), &raw))
		raw.Created = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes)
		require.NoError(t, err)
	})
	t.Run("test did doc with wrong format created", func(t *testing.T) {
		doc, err := FromBytes([]byte(docWithInvalidCreated))
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "cannot parse")
	})
}

func TestValidateDidDocUpdated(t *testing.T) {
	t.Run("test did doc with empty updated", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDoc), &raw))
		raw.Updated = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes)
		require.NoError(t, err)
	})
	t.Run("test did doc with wrong format updated", func(t *testing.T) {
		doc, err := FromBytes([]byte(docWithInvalidUpdated))
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "cannot parse")
	})
}

func TestValidateDidDocProof(t *testing.T) {
	t.Run("test did doc with empty proof", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDocWithProof), &raw))
		raw.Proof = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes)
		require.NoError(t, err)
	})

	t.Run("test did doc proof without type", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDocWithProof), &raw))
		proof, ok := raw.Proof[0].(map[string]interface{})
		require.True(t, ok)
		delete(proof, jsonldType)
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "type is required")
	})

	t.Run("test did doc proof without created", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDocWithProof), &raw))
		proof, ok := raw.Proof[0].(map[string]interface{})
		require.True(t, ok)
		delete(proof, jsonldCreated)
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "created is required")
	})

	t.Run("test did doc proof without creator", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDocWithProof), &raw))
		proof, ok := raw.Proof[0].(map[string]interface{})
		require.True(t, ok)
		delete(proof, jsonldCreator)
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "creator is required")
	})

	t.Run("test did doc proof without proofValue", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDocWithProof), &raw))
		proof, ok := raw.Proof[0].(map[string]interface{})
		require.True(t, ok)
		delete(proof, jsonldProofValue)
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "proofValue is required")
	})

	t.Run("test did doc proof without domain", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDocWithProof), &raw))
		proof, ok := raw.Proof[0].(map[string]interface{})
		require.True(t, ok)
		delete(proof, jsonldDomain)
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes)
		require.NoError(t, err)
	})

	t.Run("test did doc proof without nonce", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDocWithProof), &raw))
		proof, ok := raw.Proof[0].(map[string]interface{})
		require.True(t, ok)
		delete(proof, jsonldNonce)
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes)
		require.NoError(t, err)
	})
}

func TestJSONConversion(t *testing.T) {
	// setup -> create Document from json byte data
	doc, err := FromBytes([]byte(validDoc))
	require.NoError(t, err)
	require.NotEmpty(t, doc)

	// convert Document to json byte data
	byteDoc, err := doc.JSONBytes()
	require.NoError(t, err)
	require.NotEmpty(t, byteDoc)

	// convert json byte data to document
	doc2, err := FromBytes(byteDoc)
	require.NoError(t, err)
	require.NotEmpty(t, doc2)

	// verify documents created by FromBytes and JSONBytes function matches
	require.Equal(t, doc, doc2)
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

const docWithInvalidCreated = `{
	"@context": ["https://w3id.org/did/v1"],
	"created": "2019-9-23T14:16:59.261024-04:00",
	"id": "did:method:abc"
}`

const docWithInvalidUpdated = `{
	"@context": ["https://w3id.org/did/v1"],
	"created": "2019-09-23T14:16:59.484733-04:00",
	"updated": "2019-9-23T14:16:59.261024-04:00",
	"id": "did:method:abc"
}`
