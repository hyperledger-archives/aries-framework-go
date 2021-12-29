/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	gojose "github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/internal/ldtestutil"
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

const (
	did           = "did:method:abc"
	creator       = did + "#key-1"
	keyType       = "Ed25519VerificationKey2018"
	signatureType = "Ed25519Signature2018"
)

const (
	missingPubKeyID = "did:example:123456789abcdefghs#key4"
	wrongDataMsg    = "wrongData"
)

//nolint:gochecknoglobals
var (
	//go:embed testdata/valid_doc.jsonld
	validDoc string
	//go:embed testdata/valid_doc_resolution.jsonld
	validDocResolution string
	//go:embed testdata/invalid_doc.jsonld
	invalidDoc string
	//go:embed testdata/valid_doc_v0.11.jsonld
	validDocV011 string
	//go:embed testdata/valid_doc_with_base.jsonld
	validDocWithBase string
)

func TestParseOfNull(t *testing.T) {
	doc, err := ParseDocument([]byte("null"))
	require.Error(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "document payload is not provided")
}

func TestValidWithDocBase(t *testing.T) {
	docs := []string{validDocWithBase}
	for _, d := range docs {
		doc, err := ParseDocument([]byte(d))
		require.NoError(t, err)
		require.NotNil(t, doc)
		require.Contains(t, doc.Context[0], "https://www.w3.org/ns/did/v")

		// test doc id
		require.Equal(t, doc.ID, "did:example:123456789abcdefghi")

		hexDecodeValue, err := hex.DecodeString("02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71")
		block, _ := pem.Decode([]byte(pemPK))
		require.NotNil(t, block)
		require.NoError(t, err)

		// test authentication
		eAuthentication := []Verification{
			{
				VerificationMethod: VerificationMethod{
					ID:          "did:example:123456789abcdefghi#keys-1",
					Type:        "Secp256k1VerificationKey2018",
					Controller:  "did:example:123456789abcdefghi",
					Value:       base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"),
					relativeURL: true,
				},
				Relationship: Authentication,
			},
			{
				VerificationMethod: VerificationMethod{
					ID:          "did:example:123456789abcdefghi#key3",
					Controller:  "did:example:123456789abcdefghi",
					Type:        "RsaVerificationKey2018",
					Value:       hexDecodeValue,
					relativeURL: true,
				},
				Relationship: Authentication, Embedded: true,
			},
		}
		require.Equal(t, eAuthentication, doc.Authentication)

		// test public key
		ePubKey := []VerificationMethod{
			{
				ID:          "did:example:123456789abcdefghi#keys-1",
				Controller:  "did:example:123456789abcdefghi",
				Type:        "Secp256k1VerificationKey2018",
				Value:       base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"),
				relativeURL: true,
			},
			{
				ID:          "did:example:123456789abcdefghi#key2",
				Controller:  "did:example:123456789abcdefghi",
				Type:        "RsaVerificationKey2018",
				Value:       block.Bytes,
				relativeURL: true,
			},
		}
		require.Equal(t, ePubKey, doc.VerificationMethod)

		// test services
		eServices := []Service{
			{
				ID:              "did:example:123456789abcdefghi#inbox",
				Type:            "SocialWebInboxService",
				relativeURL:     true,
				ServiceEndpoint: "https://social.example.com/83hfh37dj",
				Properties:      map[string]interface{}{"spamCost": map[string]interface{}{"amount": "0.50", "currency": "USD"}},
			},
			{
				ID:                       "did:example:123456789abcdefghi#did-communication",
				Type:                     "did-communication",
				Priority:                 0,
				relativeURL:              true,
				RecipientKeys:            []string{"did:example:123456789abcdefghi#key2"},
				RoutingKeys:              []string{"did:example:123456789abcdefghi#key2"},
				ServiceEndpoint:          "https://agent.example.com/",
				Properties:               map[string]interface{}{},
				recipientKeysRelativeURL: map[string]bool{"did:example:123456789abcdefghi#key2": true},
				routingKeysRelativeURL:   map[string]bool{"did:example:123456789abcdefghi#key2": true},
			},
		}
		require.EqualValues(t, eServices, doc.Service)

		// test proof
		require.EqualValues(t, "did:example:123456789abcdefghi#key-5", doc.Proof[0].Creator)
	}
}

func TestDocResolution(t *testing.T) {
	t.Run("test valid doc resolution", func(t *testing.T) {
		d, err := ParseDocumentResolution([]byte(validDocResolution))
		require.NoError(t, err)

		require.Equal(t, 1, len(d.Context))
		require.Equal(t, "https://w3id.org/did-resolution/v1", d.Context[0])
		require.Equal(t, "did:example:21tDAKCERh95uGgKbJNHYp", d.DIDDocument.ID)
		require.Equal(t, true, d.DocumentMetadata.Method.Published)
		require.Equal(t, "did:ex:123333", d.DocumentMetadata.CanonicalID)

		bytes, err := d.JSONBytes()
		require.NoError(t, err)

		d, err = ParseDocumentResolution(bytes)
		require.NoError(t, err)

		require.Equal(t, 1, len(d.Context))
		require.Equal(t, "https://w3id.org/did-resolution/v1", d.Context[0])
		require.Equal(t, "did:example:21tDAKCERh95uGgKbJNHYp", d.DIDDocument.ID)
		require.Equal(t, true, d.DocumentMetadata.Method.Published)
		require.Equal(t, "did:ex:123333", d.DocumentMetadata.CanonicalID)
	})

	t.Run("test did doc not exists", func(t *testing.T) {
		_, err := ParseDocumentResolution([]byte(validDoc))
		require.Error(t, err)
		require.Contains(t, err.Error(), ErrDIDDocumentNotExist.Error())
	})
}

func TestValid(t *testing.T) {
	docs := []string{validDoc}
	for _, d := range docs {
		doc, err := ParseDocument([]byte(d))
		require.NoError(t, err)
		require.NotNil(t, doc)
		require.Contains(t, doc.Context[0], "https://www.w3.org/ns/did/v")

		// test doc id
		require.Equal(t, doc.ID, "did:example:21tDAKCERh95uGgKbJNHYp")

		hexDecodeValue, err := hex.DecodeString("02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71")
		block, _ := pem.Decode([]byte(pemPK))
		require.NotNil(t, block)
		require.NoError(t, err)

		// test authentication
		eAuthentication := []Verification{
			{VerificationMethod: *NewVerificationMethodFromBytes("did:example:123456789abcdefghi#keys-1",
				"Secp256k1VerificationKey2018",
				"did:example:123456789abcdefghi",
				base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV")), Relationship: Authentication},
			{VerificationMethod: VerificationMethod{
				ID:         "did:example:123456789abcdefghs#key3",
				Controller: "did:example:123456789abcdefghs",
				Type:       "RsaVerificationKey2018",
				Value:      hexDecodeValue,
			}, Relationship: Authentication, Embedded: true},
		}
		require.Equal(t, eAuthentication, doc.Authentication)

		// test public key
		ePubKey := []VerificationMethod{
			{
				ID:         "did:example:123456789abcdefghi#keys-1",
				Controller: "did:example:123456789abcdefghi",
				Type:       "Secp256k1VerificationKey2018",
				Value:      base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"),
			},
			{
				ID:         "did:example:123456789abcdefghw#key2",
				Controller: "did:example:123456789abcdefghw",
				Type:       "RsaVerificationKey2018",
				Value:      block.Bytes,
			},
		}
		require.Equal(t, ePubKey, doc.VerificationMethod)

		// test services
		eServices := []Service{
			{
				ID:              "did:example:123456789abcdefghi#inbox",
				Type:            "SocialWebInboxService",
				ServiceEndpoint: "https://social.example.com/83hfh37dj",
				Properties:      map[string]interface{}{"spamCost": map[string]interface{}{"amount": "0.50", "currency": "USD"}},
			},
			{
				ID:                       "did:example:123456789abcdefghi#did-communication",
				Type:                     "did-communication",
				Priority:                 0,
				RecipientKeys:            []string{"did:example:123456789abcdefghi#key2"},
				RoutingKeys:              []string{"did:example:123456789abcdefghi#key2"},
				ServiceEndpoint:          "https://agent.example.com/",
				Properties:               map[string]interface{}{},
				recipientKeysRelativeURL: map[string]bool{"did:example:123456789abcdefghi#key2": false},
				routingKeysRelativeURL:   map[string]bool{"did:example:123456789abcdefghi#key2": false},
			},
		}
		require.EqualValues(t, eServices, doc.Service)
	}
}

func TestInvalid(t *testing.T) {
	doc, err := ParseDocument([]byte(invalidDoc))
	require.Error(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "did document not valid")
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

		eProof := Proof{
			Type:       "Ed25519Signature2018",
			Created:    &created,
			Creator:    "did:method:abc#key-1",
			ProofValue: proofValue,
			Domain:     "",
			Nonce:      nonce,
		}
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
		c := ContextV1
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
		doc, err := populateProofs(c, "", "", rawProofs)
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

		doc, err = populateProofs(c, "", "", rawProofs)
		require.NotNil(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "illegal base64 data")
	}
}

func TestPopulateAuthentications(t *testing.T) {
	t.Run("test key not exist", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDoc), &raw))
		raw.Authentication[0] = missingPubKeyID
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		_, err = ParseDocument(bytes)
		require.Error(t, err)

		expected := fmt.Sprintf("key %s does not exist in did doc verification method", missingPubKeyID)
		require.Contains(t, err.Error(), expected)
	})

	t.Run("test key not exist v0.11", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(validDocV011), &raw))
		m := make(map[string]string)
		m[jsonldPublicKey] = missingPubKeyID
		m["type"] = "key"
		raw.Authentication[0] = m
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		_, err = ParseDocument(bytes)
		require.Error(t, err)

		expected := fmt.Sprintf("key %s does not exist in did doc verification method", missingPubKeyID)
		require.Contains(t, err.Error(), expected)
	})
}

func TestPopulateAssertionMethods(t *testing.T) {
	t.Run("test key does not exist", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(docV011WithVerificationRelationships), &raw))

		raw.AssertionMethod[0] = missingPubKeyID
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)

		_, err = ParseDocument(bytes)
		require.Error(t, err)

		expected := fmt.Sprintf("key %s does not exist in did doc verification method", missingPubKeyID)
		require.Contains(t, err.Error(), expected)
	})
}

func TestPopulateCapabilityDelegations(t *testing.T) {
	t.Run("test key not exist", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(docV011WithVerificationRelationships), &raw))

		raw.CapabilityDelegation[0] = missingPubKeyID
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)

		_, err = ParseDocument(bytes)
		require.Error(t, err)

		expected := fmt.Sprintf("key %s does not exist in did doc verification method", missingPubKeyID)
		require.Contains(t, err.Error(), expected)
	})
}

func TestPopulateCapabilityInvocations(t *testing.T) {
	t.Run("test key not exist", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(docV011WithVerificationRelationships), &raw))

		raw.CapabilityInvocation[0] = missingPubKeyID
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)

		_, err = ParseDocument(bytes)
		require.Error(t, err)

		expected := fmt.Sprintf("key %s does not exist in did doc verification method", missingPubKeyID)
		require.Contains(t, err.Error(), expected)
	})
}

func TestPopulateKeyAgreements(t *testing.T) {
	t.Run("test key not exist", func(t *testing.T) {
		raw := &rawDoc{}
		require.NoError(t, json.Unmarshal([]byte(docV011WithVerificationRelationships), &raw))

		raw.KeyAgreement[0] = missingPubKeyID
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)

		_, err = ParseDocument(bytes)
		require.EqualError(t, err, fmt.Sprintf("populate key agreements failed: key %s does not exist in did doc"+
			" verification method", missingPubKeyID))
	})
}

func TestPublicKeys(t *testing.T) {
	t.Run("test failed to decode PEM block", func(t *testing.T) {
		docs := []string{validDoc, validDocV011}
		for _, d := range docs {
			raw := &rawDoc{}
			require.NoError(t, json.Unmarshal([]byte(d), &raw))

			if len(raw.PublicKey) != 0 {
				raw.PublicKey[1][jsonldPublicKeyPem] = wrongDataMsg
			} else {
				raw.VerificationMethod[1][jsonldPublicKeyPem] = wrongDataMsg
			}

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

			if len(raw.PublicKey) != 0 {
				delete(raw.PublicKey[1], jsonldPublicKeyPem)
				raw.PublicKey[1]["publicKeyMultibase"] = wrongDataMsg
			} else {
				delete(raw.VerificationMethod[1], jsonldPublicKeyPem)
				raw.VerificationMethod[1]["publicKeyMultibase"] = wrongDataMsg
			}

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
	_, err := ParseDocument([]byte(wrongDataMsg))
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
			raw.VerificationMethod = nil
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

			if len(raw.PublicKey) != 0 {
				delete(raw.PublicKey[0], jsonldID)
			} else {
				delete(raw.VerificationMethod[0], jsonldID)
			}

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

			if len(raw.PublicKey) != 0 {
				delete(raw.PublicKey[0], jsonldType)
			} else {
				delete(raw.VerificationMethod[0], jsonldType)
			}

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

		if len(raw.PublicKey) != 0 {
			delete(raw.PublicKey[0], jsonldController)
		} else {
			delete(raw.VerificationMethod[0], jsonldController)
		}

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

func TestRequiresLegacyHandling(t *testing.T) {
	doc := &rawDoc{}

	err := json.Unmarshal([]byte(validDocV011), doc)
	require.NoError(t, err)

	doc.Context = []string{ContextV1Old}

	ret := requiresLegacyHandling(doc)
	require.Equal(t, true, ret)

	doc.Context = []string{ContextV1}

	ret = requiresLegacyHandling(doc)
	require.Equal(t, false, ret)

	doc.Context = []string{contextV011}

	ret = requiresLegacyHandling(doc)
	require.Equal(t, false, ret)
}

func TestJSONConversion(t *testing.T) {
	docs := []string{
		validDoc, validDocV011, validDocWithProofAndJWK, docV011WithVerificationRelationships, validDocWithBase,
	}
	for _, d := range docs {
		// setup -> create Document from json byte data
		doc, err := ParseDocument([]byte(d))
		require.NoError(t, err)
		require.NotEmpty(t, doc)

		// convert Document to json byte data
		byteDoc, err := doc.JSONBytes()
		require.NoError(t, err)
		require.NotEmpty(t, byteDoc)

		if d != validDocWithBase {
			require.NotContains(t, string(byteDoc), "@base")
		} else {
			require.Contains(t, string(byteDoc), "@base")
		}

		// convert json byte data to document
		doc2, err := ParseDocument(byteDoc)
		require.NoError(t, err)
		require.NotEmpty(t, doc2)

		// verify documents created by ParseDocument and JSONBytes function matches
		require.Equal(t, doc, doc2)
	}
}

func TestMarshalJSON(t *testing.T) {
	docs := []string{
		validDoc, validDocV011, validDocWithProofAndJWK, docV011WithVerificationRelationships, validDocWithBase,
	}
	for _, d := range docs {
		// setup -> create Document from json byte data
		doc := &Doc{}
		err := json.Unmarshal([]byte(d), doc)
		require.NoError(t, err)
		require.NotEmpty(t, doc)

		// convert Document to json byte data
		byteDoc, err := json.Marshal(doc)
		require.NoError(t, err)
		require.NotEmpty(t, byteDoc)

		if d != validDocWithBase {
			require.NotContains(t, string(byteDoc), "@base")
		} else {
			require.Contains(t, string(byteDoc), "@base")
		}

		// convert json byte data to document
		doc2, err := ParseDocument(byteDoc)
		require.NoError(t, err)
		require.NotEmpty(t, doc2)

		// verify documents created by ParseDocument and JSONBytes function matches
		require.Equal(t, doc, doc2)
	}
}

func TestUnmarshalJSON(t *testing.T) {
	t.Run("does not panic if parsing fails", func(t *testing.T) {
		d := &Doc{}
		err := d.UnmarshalJSON(nil)

		require.Error(t, err)
	})
}

func TestNewPublicKeyFromJWK(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	j := &jwk.JWK{
		JSONWebKey: gojose.JSONWebKey{
			Key:   pubKey,
			KeyID: "_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A",
		},
	}

	// Success.
	signingKey, err := NewVerificationMethodFromJWK(creator, keyType, did, j)
	require.NoError(t, err)
	require.Equal(t, j, signingKey.JSONWebKey())
	require.Equal(t, []byte(pubKey), signingKey.Value)

	// Error - invalid JWK.
	j = &jwk.JWK{
		JSONWebKey: gojose.JSONWebKey{
			Key:   nil,
			KeyID: "_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A",
		},
	}
	signingKey, err = NewVerificationMethodFromJWK(creator, keyType, did, j)
	require.Error(t, err)
	require.Contains(t, err.Error(), "convert JWK to public key bytes")
	require.Nil(t, signingKey)
}

func TestJSONWebKey(t *testing.T) {
	const didContext = "https://w3id.org/did/v1"

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	j := &jwk.JWK{
		JSONWebKey: gojose.JSONWebKey{
			Key:   pubKey,
			KeyID: "_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A",
		},
	}

	signingKey, err := NewVerificationMethodFromJWK(creator, keyType, did, j)
	require.NoError(t, err)
	require.Equal(t, j, signingKey.JSONWebKey())

	createdTime := time.Now()

	didDoc := &Doc{
		Context:            []string{didContext},
		ID:                 did,
		VerificationMethod: []VerificationMethod{*signingKey},
		Created:            &createdTime,
		Updated:            &createdTime,
	}

	didDocBytes, err := didDoc.JSONBytes()
	require.NoError(t, err)

	parsedDidDoc, err := ParseDocument(didDocBytes)
	require.NoError(t, err)

	parsedDidDocBytes, err := parsedDidDoc.JSONBytes()
	require.NoError(t, err)
	require.Equal(t, didDocBytes, parsedDidDocBytes)
}

func TestVerifyProof(t *testing.T) {
	docs := []string{validDoc, validDocV011}
	for _, d := range docs {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}

		signedDoc := createSignedDidDocument(t, privKey, pubKey)

		s := ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier()))

		// happy path - valid signed document
		doc, err := ParseDocument(signedDoc)
		require.Nil(t, err)
		require.NotNil(t, doc)
		err = doc.VerifyProof([]verifier.SignatureSuite{s}, ldtestutil.WithDocumentLoader(t))
		require.NoError(t, err)

		// error - no suites are passed, verifier is not created
		err = doc.VerifyProof([]verifier.SignatureSuite{}, ldtestutil.WithDocumentLoader(t))
		require.Error(t, err)
		require.Contains(t, err.Error(), "create verifier")

		// error - doc with invalid proof value
		doc.Proof[0].ProofValue = []byte("invalid")
		err = doc.VerifyProof([]verifier.SignatureSuite{s}, ldtestutil.WithDocumentLoader(t))
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "ed25519: invalid signature")

		// error - doc with no proof
		doc, err = ParseDocument([]byte(d))
		require.NoError(t, err)
		require.NotNil(t, doc)
		err = doc.VerifyProof([]verifier.SignatureSuite{s}, ldtestutil.WithDocumentLoader(t))
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
	pubKeys := []VerificationMethod{{
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
	doc := BuildDoc(WithVerificationMethod([]VerificationMethod{{}}), WithService([]Service{{}, {}}),
		WithAuthentication([]Verification{{}}), WithCreatedTime(ti), WithUpdatedTime(ti))
	require.NotEmpty(t, doc)
	require.Equal(t, 1, len(doc.VerificationMethod))
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

func TestParseDIDURL(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectErr string
		result    *DIDURL
	}{
		{
			name:      "success: plain DID without URL components",
			input:     "did:test:abc",
			expectErr: "",
			result: &DIDURL{
				DID: DID{
					Scheme:           "did",
					Method:           "test",
					MethodSpecificID: "abc",
				},
				Queries: map[string][]string{},
			},
		},
		{
			name:      "success: full DID URL with all components",
			input:     "did:test:abc/path/a/b/c?query1=value1&query2=value2&query1=value3#fragment",
			expectErr: "",
			result: &DIDURL{
				DID: DID{
					Scheme:           "did",
					Method:           "test",
					MethodSpecificID: "abc",
				},
				Path: "/path/a/b/c",
				Queries: map[string][]string{
					"query1": {"value1", "value3"},
					"query2": {"value2"},
				},
				Fragment: "fragment",
			},
		},
		{
			name:      "success: DID URL with fragment only",
			input:     "did:test:abc#fragment",
			expectErr: "",
			result: &DIDURL{
				DID: DID{
					Scheme:           "did",
					Method:           "test",
					MethodSpecificID: "abc",
				},
				Queries:  map[string][]string{},
				Fragment: "fragment",
			},
		},
		{
			name:      "fail: error parsing DID",
			input:     "foo",
			expectErr: "invalid did",
		},
		{
			name:      "fail: DID URL doesn't satisfy URL format",
			input:     "did:test:abc/\t",
			expectErr: "failed to parse",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := ParseDIDURL(tc.input)

			if tc.expectErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.expectErr)

				return
			}

			require.Equal(t, tc.result, actual)
		})
	}
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
				"verificationMethod": [{
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
				"verificationMethod": [{
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
				name: "DID with old context, minimal authentication & publicKey properties",
				didStr: `{
        "@context": "https://www.w3.org/2019/did/v1",
        "id": "did:sov:danube:CDEabPCipwE51bg7KF9yXt",
        "service": [{"type": "example","serviceEndpoint": "http://example.com"}],
        "authentication": [{
            "type": "Ed25519SignatureAuthentication2018",
            "publicKey": ["did:sov:danube:CDEabPCipwE51bg7KF9yXt#key-1"]
        }],
        "publicKey": [{
            "id": "did:sov:danube:CDEabPCipwE51bg7KF9yXt#key-1",
            "type": "Ed25519VerificationKey2018",
            "publicKeyBase58": "77QBazin3A2k3aVrHowUn2HDsq6HxxdFtY1LiDrTrL4m"
        }]
    }`,
			},
			{
				name: "DID v0.11 with empty JWK & empty auth key",
				didStr: `{
        "@context": "https://w3id.org/did/v0.11",
        "id": "did:w123:world",
        "assertionMethod": ["did:w123:world#z6MksHh7qHWvybLg5QTPPdG2DgEjjduBDArV9EF9mRiRzMBN", 
		"did:w123:world#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A", 
		"did:w123:world#_TKzHv2jFIyvdTGF1Dsgwngfdg3SH6TpDv0Ta1aOEkw", 
		"did:w123:world#NjQ6Y_ZMj6IUK_XkgCDwtKHlNTUTVjEYOWZtxhp1n-E"],
        "authentication": ["did:w123:world#z6MksHh7qHWvybLg5QTPPdG2DgEjjduBDArV9EF9mRiRzMBN", "", 
		"did:w123:world#_TKzHv2jFIyvdTGF1Dsgwngfdg3SH6TpDv0Ta1aOEkw",  
		"did:w123:world#NjQ6Y_ZMj6IUK_XkgCDwtKHlNTUTVjEYOWZtxhp1n-E"],
        "capabilityDelegation": ["did:w123:world#z6MksHh7qHWvybLg5QTPPdG2DgEjjduBDArV9EF9mRiRzMBN", 
		"did:w123:world#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A", 
		 "did:w123:world#_TKzHv2jFIyvdTGF1Dsgwngfdg3SH6TpDv0Ta1aOEkw", 
		 "did:w123:world#NjQ6Y_ZMj6IUK_XkgCDwtKHlNTUTVjEYOWZtxhp1n-E"],
        "capabilityInvocation": ["did:w123:world#z6MksHh7qHWvybLg5QTPPdG2DgEjjduBDArV9EF9mRiRzMBN", 
		"did:w123:world#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A", 
		 "did:w123:world#_TKzHv2jFIyvdTGF1Dsgwngfdg3SH6TpDv0Ta1aOEkw", 
		 "did:w123:world#NjQ6Y_ZMj6IUK_XkgCDwtKHlNTUTVjEYOWZtxhp1n-E"],
        "keyAgreement": [{
            "id": "did:w123:world#zC5iai1sL93gQxn8LKh1i42fTbpfar65dVx4NYznYfG3Y5",
            "type": "X25519KeyAgreementKey2019",
            "controller": "did:w123:world",
            "publicKeyBase58": "6DrzegWwfw8Xg5MsHX95sVnJaPmtXP214B5X9hkG9oRs"
        }],
        "publicKey": [{
            "id": "did:w123:world#z6MksHh7qHWvybLg5QTPPdG2DgEjjduBDArV9EF9mRiRzMBN",
            "type": "Ed25519VerificationKey2018",
            "controller": "did:w123:world",
            "publicKeyBase58": "DqS5F3GVe3rCxucgi4JBNagjv4dKoHc8TDLDw9kR58Pz"
        }, {
            "id": "did:w123:world#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A",
            "type": "JwsVerificationKey2020",
            "controller": "did:w123:world",
            "publicKeyJwk": {}
        }, {
            "id": "did:w123:world#4SZ-StXrp5Yd4_4rxHVTCYTHyt4zyPfN1fIuYsm6k3A",
            "type": "JwsVerificationKey2020",
            "controller": "did:w123:world",
            "publicKeyJwk": {}
        }, {
            "id": "did:w123:world#_TKzHv2jFIyvdTGF1Dsgwngfdg3SH6TpDv0Ta1aOEkw",
            "type": "JwsVerificationKey2020",
            "controller": "did:w123:world",
            "publicKeyJwk": {}
        }, {
            "id": "did:w123:world#NjQ6Y_ZMj6IUK_XkgCDwtKHlNTUTVjEYOWZtxhp1n-E",
            "type": "JwsVerificationKey2020",
            "controller": "did:w123:world",
            "publicKeyJwk": {}
        }]
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

func TestNewEmbeddedVerificationMethod(t *testing.T) {
	vm := NewEmbeddedVerification(&VerificationMethod{}, Authentication)
	require.NotNil(t, vm)
	require.NotNil(t, vm.VerificationMethod)
	require.True(t, vm.Embedded)
	require.Equal(t, Authentication, vm.Relationship)
}

func TestNewReferencedVerificationMethod(t *testing.T) {
	t.Run("relative URL - true", func(t *testing.T) {
		vm := NewReferencedVerification(&VerificationMethod{}, Authentication)
		require.NotNil(t, vm)
		require.NotNil(t, vm.VerificationMethod)
		require.Equal(t, Authentication, vm.Relationship)
	})
	t.Run("relative URL - false", func(t *testing.T) {
		vm := NewReferencedVerification(&VerificationMethod{}, Authentication)
		require.NotNil(t, vm)
		require.NotNil(t, vm.VerificationMethod)
		require.Equal(t, Authentication, vm.Relationship)
	})
}

// nolint:lll
func TestDoc_VerificationMethods(t *testing.T) {
	didDocStr := `
{
  "@context": "https://w3id.org/did/v1",
  "id": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A",
  "service": [
    {
      "id": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#openid",
      "type": "OpenIdConnectVersion1.0Service",
      "serviceEndpoint": "https://openid.example.com/"
    }
  ],
  "assertionMethod": [
    "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#edv"
  ],
  "authentication": [
    "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#edv",
    {
      "id": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#authentication",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A",
      "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
    }
  ],
  "capabilityDelegation": [
    "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#edv"
  ],
  "capabilityInvocation": [
    "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#edv"
  ],
  "keyAgreement": [
    {
      "id": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#keyAgreement",
      "type": "X25519KeyAgreementKey2019",
      "controller": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A",
      "publicKeyBase58": "ENpfk9K9J6uss5qu6BrAszioE732mYCobmMPSpvB3faM"
    }
  ],
  "publicKey": [
    {
      "id": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#primary",
      "type": "Secp256k1VerificationKey2018",
      "controller": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A",
      "publicKeyHex": "0361f286ada2a6b2c74bc6ed44a71ef59fb9dd15eca9283cbe5608aeb516730f33"
    },
    {
      "id": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#recovery",
      "type": "Secp256k1VerificationKey2018",
      "controller": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A",
      "publicKeyHex": "02c00982681081372cbb941cd2c9745908316e1373ac333479f0deabcad0e9d574"
    },
    {
      "id": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#edv",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A",
      "publicKeyBase58": "atEBuHypSkQx7486xT5FUkoBLqvNcWyNK2Xz9EPjdMy"
    },
    {
      "id": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#key-JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A",
      "publicKeyJwk": {
        "crv": "secp256k1",
        "kid": "JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw",
        "kty": "EC",
        "x": "dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A",
        "y": "36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA"
      }
    }
  ]
}
`

	doc, err := ParseDocument([]byte(didDocStr))
	require.NoError(t, err)

	// Get all verification methods.
	methods := doc.VerificationMethods()
	require.Len(t, methods, 6)
	require.Len(t, methods[AssertionMethod], 1)
	require.Len(t, methods[Authentication], 2)
	require.Len(t, methods[CapabilityInvocation], 1)
	require.Len(t, methods[CapabilityDelegation], 1)
	require.Len(t, methods[KeyAgreement], 1)
	require.Len(t, methods[VerificationRelationshipGeneral], 4)

	// Get verification methods of several relationships.
	methods = doc.VerificationMethods(AssertionMethod, Authentication)
	require.Len(t, methods, 2)
	require.Len(t, methods[AssertionMethod], 1)
	require.Len(t, methods[Authentication], 2)

	// Get verification methods of concrete relationship.
	methods = doc.VerificationMethods(AssertionMethod)
	require.Len(t, methods, 1)
	require.Len(t, methods[AssertionMethod], 1)

	methods = doc.VerificationMethods(Authentication)
	require.Len(t, methods, 1)
	require.Len(t, methods[Authentication], 2)

	methods = doc.VerificationMethods(CapabilityInvocation)
	require.Len(t, methods, 1)
	require.Len(t, methods[CapabilityInvocation], 1)

	methods = doc.VerificationMethods(CapabilityDelegation)
	require.Len(t, methods, 1)
	require.Len(t, methods[CapabilityDelegation], 1)

	methods = doc.VerificationMethods(KeyAgreement)
	require.Len(t, methods, 1)
	require.Len(t, methods[KeyAgreement], 1)

	methods = doc.VerificationMethods(VerificationRelationshipGeneral)
	require.Len(t, methods, 1)
	require.Len(t, methods[VerificationRelationshipGeneral], 4)
}

func TestDoc_SerializeInterop(t *testing.T) {
	doc, err := ParseDocument([]byte(validDoc))
	require.NoError(t, err)

	docJSON, err := doc.JSONBytes()
	require.NoError(t, err)

	docInteropJSON, err := doc.SerializeInterop()
	require.NoError(t, err)

	// in default mode, SerializeInterop should return the regular did doc
	require.Equal(t, docJSON, docInteropJSON)
}

func createDidDocumentWithSigningKey(pubKey []byte) *Doc {
	const (
		didContext      = "https://w3id.org/did/v1"
		securityContext = "https://w3id.org/security/v1"
	)

	signingKey := VerificationMethod{
		ID:         creator,
		Type:       keyType,
		Controller: did,
		Value:      pubKey,
	}

	createdTime := time.Now()

	didDoc := &Doc{
		Context:            []string{didContext, securityContext},
		ID:                 did,
		VerificationMethod: []VerificationMethod{signingKey},
		Created:            &createdTime,
	}

	return didDoc
}

func createSignedDidDocument(t *testing.T, privKey, pubKey []byte) []byte {
	didDoc := createDidDocumentWithSigningKey(pubKey)

	jsonDoc, err := didDoc.JSONBytes()
	require.NoError(t, err)

	context := &signer.Context{
		Creator:       creator,
		SignatureType: signatureType,
	}

	s := signer.New(ed25519signature2018.New(
		suite.WithSigner(getSigner(privKey))))

	signedDoc, err := s.Sign(context, jsonDoc, ldtestutil.WithDocumentLoader(t))
	require.NoError(t, err)

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
	"verificationMethod": [{
		"controller": "did:method:abc",
		"id": "did:method:abc#key-1",
		"publicKeyBase58": "GY4GunSXBPBfhLCzDL7iGmP5dR3sBDCJZkkaGK8VgYQf",
		"type": "Ed25519VerificationKey2018"
	}],
	"updated": "2019-09-23T14:16:59.261024-04:00"
}`

const validDocWithProofAndJWK = `
{
  "@context": [
    "https://w3id.org/did/v1"
  ],
  "created": "2019-09-23T14:16:59.261024-04:00",
  "id": "did:method:abc",
  "proof": [
    {
      "created": "2019-09-23T14:16:59.484733-04:00",
      "creator": "did:method:abc#key-1",
      "domain": "",
      "nonce": "",
      "proofValue": "6mdES87erjP5r1qCSRW__otj-A_Rj0YgRO7XU_0Amhwdfa7AAmtGUSFGflR_fZqPYrY9ceLRVQCJ49s0q7-LBA",
      "type": "Ed25519Signature2018"
    }
  ],
  "verificationMethod": [
    {
      "controller": "did:method:abc",
      "id": "did:method:abc#key-1",
      "publicKeyJwk": {
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "x": "DEfkntM3vCV5WtS-1G9cBMmkNJSPlVdjwSdHmHbirTg"
      },
      "type": "Ed25519VerificationKey2018"
    }
  ],
  "updated": "2019-09-23T14:16:59.261024-04:00"
}
`

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

const docV011WithVerificationRelationships = `{
	"@context": ["https://w3id.org/did/v0.11"],
	"id": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
	"assertionMethod": [
		"did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
	],
	"authentication": [
		"#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
	],
	"capabilityDelegation": [
		"did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
	],
	"capabilityInvocation": [
		"did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
	],
	"keyAgreement": [{
		"id": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#zBzoR5sqFgi6q3iFia8JPNfENCpi7RNSTKF7XNXX96SBY4",
		"type": "X25519KeyAgreementKey2019",
		"controller": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
		"publicKeyBase58": "JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr"
	}],
	"publicKey": [{
		"id": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
		"type": "Ed25519VerificationKey2018",
		"controller": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
		"publicKeyBase58": "B12NYF8RrR3h41TDCTJojY59usg3mbtbjnFs7Eud1Y6u"
	}]
}`
