/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbsblssignatureproof2020_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignatureproof2020"
	sigverifier "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
)

//nolint:lll
const docWithSingleBBSProofJSON = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/citizenship/v1",
    "https://w3c-ccg.github.io/ldp-bbs2020/context/v1"
  ],
  "id": "https://issuer.oidp.uscis.gov/credentials/83627465",
  "type": [
    "VerifiableCredential",
    "PermanentResidentCard"
  ],
  "issuer": "did:example:489398593",
  "identifier": "83627465",
  "name": "Permanent Resident Card",
  "description": "Government of Example Permanent Resident Card.",
  "issuanceDate": "2019-12-03T12:19:52Z",
  "expirationDate": "2029-12-03T12:19:52Z",
  "credentialSubject": {
    "id": "did:example:b34ca6cd37bbf23",
    "type": [
      "PermanentResident",
      "Person"
    ],
    "givenName": "JOHN",
    "familyName": "SMITH",
    "gender": "Male",
    "image": "data:image/png;base64,iVBORw0KGgokJggg==",
    "residentSince": "2015-01-01",
    "lprCategory": "C09",
    "lprNumber": "999-999-999",
    "commuterClassification": "C1",
    "birthCountry": "Bahamas",
    "birthDate": "1958-07-17"
  },
  "proof": {
    "type": "BbsBlsSignature2020",
    "created": "2020-12-06T19:23:10Z",
    "proofPurpose": "assertionMethod",
    "proofValue": "jj3Xd3+KxmbQo85PFDjQJ7dAZlhj8A8W1Um8Vk7Xoiv6+jWRx5d8s0rgPk5dAXy6HwaJ4fQOde/MBb7E4QaGMlfK6y5eEKDUYzoGG0DScWIvaGcSZug6DwvWVXi+214P5MtlKnNwO6gJdemEgj8T/A==",
    "verificationMethod": "did:example:489398593#test"
  }
}
`

//nolint:lll
const docWithManyProofsJSON = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/citizenship/v1",
    "https://w3c-ccg.github.io/ldp-bbs2020/context/v1"
  ],
  "id": "https://issuer.oidp.uscis.gov/credentials/83627465",
  "type": [
    "VerifiableCredential",
    "PermanentResidentCard"
  ],
  "issuer": "did:example:489398593",
  "identifier": "83627465",
  "name": "Permanent Resident Card",
  "description": "Government of Example Permanent Resident Card.",
  "issuanceDate": "2019-12-03T12:19:52Z",
  "expirationDate": "2029-12-03T12:19:52Z",
  "credentialSubject": {
    "id": "did:example:b34ca6cd37bbf23",
    "type": [
      "PermanentResident",
      "Person"
    ],
    "givenName": "JOHN",
    "familyName": "SMITH",
    "gender": "Male",
    "image": "data:image/png;base64,iVBORw0KGgokJggg==",
    "residentSince": "2015-01-01",
    "lprCategory": "C09",
    "lprNumber": "999-999-999",
    "commuterClassification": "C1",
    "birthCountry": "Bahamas",
    "birthDate": "1958-07-17"
  },
  "proof": [
    {
      "type": "BbsBlsSignature2020",
      "created": "2020-12-06T19:23:10Z",
      "proofPurpose": "assertionMethod",
      "proofValue": "jj3Xd3+KxmbQo85PFDjQJ7dAZlhj8A8W1Um8Vk7Xoiv6+jWRx5d8s0rgPk5dAXy6HwaJ4fQOde/MBb7E4QaGMlfK6y5eEKDUYzoGG0DScWIvaGcSZug6DwvWVXi+214P5MtlKnNwO6gJdemEgj8T/A==",
      "verificationMethod": "did:example:489398593#test"
    },
    {
      "created": "2010-01-01T19:23:24Z",
      "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..lrkhpRH4tWl6KzQKHlcyAwSm8qUTXIMSKmD3QASF_uI5QW8NWLxLebXmnQpIM8H7umhLA6dINSYVowcaPdpwBw",
      "proofPurpose": "assertionMethod",
      "type": "Ed25519Signature2018",
      "verificationMethod": "did:example:123456#key1"
    }
  ]
}
`

//nolint
func TestSuite_SelectiveDisclosure(t *testing.T) {

	revealDocJSON := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/citizenship/v1",
    "https://w3c-ccg.github.io/ldp-bbs2020/context/v1"
  ],
  "type": ["VerifiableCredential", "PermanentResidentCard"],
  "credentialSubject": {
    "@explicit": true,
    "type": ["PermanentResident", "Person"],
    "givenName": {},
    "familyName": {},
    "gender": {}
  }
}
`

	pkBase58 := "oqpWYKaZD9M1Kbe94BVXpr8WTdFBNZyKv48cziTiQUeuhm7sBhCABMyYG4kcMrseC68YTFFgyhiNeBKjzdKk9MiRWuLv5H4FFujQsQK2KTAtzU8qTBiZqBHMmnLF4PL7Ytu"
	pubKeyBytes := base58.Decode(pkBase58)
	nonce := []byte("nonce")
	docMap := toMap(t, docWithSingleBBSProofJSON)
	revealDocMap := toMap(t, revealDocJSON)
	withDocLoader := jsonld.WithDocumentLoader(createLDPBBS2020DocumentLoader())

	s := bbsblssignatureproof2020.New()

	const proofField = "proof"

	pubKeyResolver := &testKeyResolver{
		publicKey: &sigverifier.PublicKey{
			Type:  "Bls12381G2Key2020",
			Value: pubKeyBytes,
		},
	}

	t.Run("single BBS+ signature", func(t *testing.T) {
		docWithSelectiveDisclosure, err := s.SelectiveDisclosure(docMap, revealDocMap, nonce,
			pubKeyResolver, withDocLoader)
		require.NoError(t, err)
		require.NotEmpty(t, docWithSelectiveDisclosure)
		require.Contains(t, docWithSelectiveDisclosure, proofField)

		proofs, ok := docWithSelectiveDisclosure[proofField].([]map[string]interface{})
		require.True(t, ok)

		require.Len(t, proofs, 1)
		require.Equal(t, "BbsBlsSignatureProof2020", proofs[0]["type"])
		require.NotEmpty(t, proofs[0]["proofValue"])
	})

	t.Run("several proofs including BBS+ signature", func(t *testing.T) {
		docWithSeveralProofsMap := toMap(t, docWithManyProofsJSON)

		docWithSelectiveDisclosure, err := s.SelectiveDisclosure(docWithSeveralProofsMap, revealDocMap, nonce,
			pubKeyResolver, withDocLoader)
		require.NoError(t, err)
		require.NotEmpty(t, docWithSelectiveDisclosure)
		require.Contains(t, docWithSelectiveDisclosure, proofField)

		proofs, ok := docWithSelectiveDisclosure[proofField].([]map[string]interface{})
		require.True(t, ok)

		require.Len(t, proofs, 2)
		require.Equal(t, "BbsBlsSignatureProof2020", proofs[0]["type"])
		require.NotEmpty(t, proofs[0]["proofValue"])
	})

	t.Run("no proof", func(t *testing.T) {
		docMapWithoutProof := make(map[string]interface{}, len(docMap)-1)

		for k, v := range docMap {
			if k != proofField {
				docMapWithoutProof[k] = v
			}
		}

		docWithSelectiveDisclosure, err := s.SelectiveDisclosure(docMapWithoutProof, revealDocMap, nonce,
			pubKeyResolver, withDocLoader)
		require.Error(t, err)
		require.EqualError(t, err, "document does not have a proof")
		require.Empty(t, docWithSelectiveDisclosure)
	})

	t.Run("invalid proof", func(t *testing.T) {
		docMapWithInvalidProof := make(map[string]interface{}, len(docMap)-1)

		for k, v := range docMap {
			if k != proofField {
				docMapWithInvalidProof[k] = v
			} else {
				docMapWithInvalidProof[k] = "invalid proof"
			}
		}

		docWithSelectiveDisclosure, err := s.SelectiveDisclosure(docMapWithInvalidProof, revealDocMap, nonce,
			pubKeyResolver, withDocLoader)
		require.Error(t, err)
		require.EqualError(t, err, "proof is not map or array of maps")
		require.Empty(t, docWithSelectiveDisclosure)
	})

	t.Run("invalid proof value", func(t *testing.T) {
		docMapWithInvalidProofValue := make(map[string]interface{}, len(docMap))

		for k, v := range docMap {
			if k == proofField {
				proofMap := make(map[string]interface{})

				for k1, v1 := range v.(map[string]interface{}) {
					if k1 == "proofValue" {
						proofMap[k1] = "invalid"
					} else {
						proofMap[k1] = v1
					}
				}

				docMapWithInvalidProofValue[proofField] = proofMap
			} else {
				docMapWithInvalidProofValue[k] = v
			}
		}

		docWithSelectiveDisclosure, err := s.SelectiveDisclosure(docMapWithInvalidProofValue, revealDocMap, nonce,
			pubKeyResolver, withDocLoader)
		require.Error(t, err)
		require.EqualError(t, err, "derive BBS+ proof: parse signature: invalid size of signature")
		require.Empty(t, docWithSelectiveDisclosure)
	})

	t.Run("invalid input BBS+ proof value", func(t *testing.T) {
		docMapWithInvalidProofType := make(map[string]interface{}, len(docMap)-1)

		for k, v := range docMap {
			if k == proofField {
				proofMap := make(map[string]interface{})

				for k1, v1 := range v.(map[string]interface{}) {
					if k1 == "type" {
						proofMap[k1] = "invalid"
					} else {
						proofMap[k1] = v1
					}
				}

				docMapWithInvalidProofType[proofField] = proofMap
			} else {
				docMapWithInvalidProofType[k] = v
			}
		}

		docWithSelectiveDisclosure, err := s.SelectiveDisclosure(docMapWithInvalidProofType, revealDocMap, nonce,
			pubKeyResolver, withDocLoader)
		require.Error(t, err)
		require.EqualError(t, err, "no BbsBlsSignature2020 proof present")
		require.Empty(t, docWithSelectiveDisclosure)
	})

	t.Run("failed to resolve public key", func(t *testing.T) {
		failingPublicKeyResolver := &testKeyResolver{
			err: errors.New("failed to resolve public key"),
		}

		docWithSelectiveDisclosure, err := s.SelectiveDisclosure(docMap, revealDocMap, nonce,
			failingPublicKeyResolver, withDocLoader)
		require.Error(t, err)
		require.EqualError(t, err, "resolve public key of BBS+ signature: failed to resolve public key")
		require.Empty(t, docWithSelectiveDisclosure)
	})
}

func toMap(t *testing.T, doc string) map[string]interface{} {
	var docMap map[string]interface{}
	err := json.Unmarshal([]byte(doc), &docMap)
	require.NoError(t, err)

	return docMap
}
