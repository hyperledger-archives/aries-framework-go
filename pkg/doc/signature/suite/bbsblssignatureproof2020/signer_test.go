/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbsblssignatureproof2020_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignatureproof2020"
	sigverifier "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

// Case 16 (https://github.com/w3c-ccg/vc-http-api/pull/128)
//nolint:lll
const case16VC = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/bbs/v1",
    "https://w3id.org/citizenship/v1"
  ],
  "id": "https://issuer.oidp.uscis.gov/credentials/83627465",
  "type": [
    "VerifiableCredential",
    "PermanentResidentCard"
  ],
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
    "image": "data:image/png;base64,iVBORw0KGgo...kJggg==",
    "residentSince": "2015-01-01",
    "lprCategory": "C09",
    "lprNumber": "999-999-999",
    "commuterClassification": "C1",
    "birthCountry": "Bahamas",
    "birthDate": "1958-07-17"
  },
  "issuer": "did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2",
  "proof": {
    "type": "BbsBlsSignature2020",
    "created": "2021-02-23T19:31:12Z",
    "proofPurpose": "assertionMethod",
    "proofValue": "qPrB+1BLsVSeOo1ci8dMF+iR6aa5Q6iwV/VzXo2dw94ctgnQGxaUgwb8Hd68IiYTVabQXR+ZPuwJA//GOv1OwXRHkHqXg9xPsl8HcaXaoWERanxYClgHCfy4j76Vudr14U5AhT3v8k8f0oZD+zBIUQ==",
    "verificationMethod": "did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2#zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2"
  }
}
`

// Case 18 (https://github.com/w3c-ccg/vc-http-api/pull/128)
//nolint:lll
const case18VC = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1",
    "https://w3id.org/security/bbs/v1"
  ],
  "id": "http://example.gov/credentials/3732",
  "type": [
    "VerifiableCredential",
    "UniversityDegreeCredential"
  ],
  "issuanceDate": "2020-03-10T04:24:12.164Z",
  "credentialSubject": {
    "id": "did:key:z5TcESXuYUE9aZWYwSdrUEGK1HNQFHyTt4aVpaCTVZcDXQmUheFwfNZmRksaAbBneNm5KyE52SdJeRCN1g6PJmF31GsHWwFiqUDujvasK3wTiDr3vvkYwEJHt7H5RGEKYEp1ErtQtcEBgsgY2DA9JZkHj1J9HZ8MRDTguAhoFtR4aTBQhgnkP4SwVbxDYMEZoF2TMYn3s#zUC7LTa4hWtaE9YKyDsMVGiRNqPMN3s4rjBdB3MFi6PcVWReNfR72y3oGW2NhNcaKNVhMobh7aHp8oZB3qdJCs7RebM2xsodrSm8MmePbN25NTGcpjkJMwKbcWfYDX7eHCJjPGM",
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science and Arts"
    }
  },
  "issuer": "did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2",
  "proof": {
    "type": "BbsBlsSignature2020",
    "created": "2021-02-23T19:36:07Z",
    "proofPurpose": "assertionMethod",
    "proofValue": "qSjCNJzoDV3hv3gBPoUNN9m5lj8saDBBxC0iDHuFTXXz4PbbUhecmn/L3rPoGuySNatqC4I8VE22xQy0RAowIxoZCC+B2mZQIAb+/JGlXeAlWgEQc71WipfvsfqSn+KmR/rN1FREOy3rtSltyQ92rA==",
    "verificationMethod": "did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2#zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2"
  }
}
`

//nolint:lll
const docWithManyProofsJSON = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/citizenship/v1",
    "https://w3id.org/security/bbs/v1"
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
    },
    {
	  "created": "2021-01-11T16:04:13.154596+02:00",
	  "proofPurpose": "assertionMethod",
	  "proofValue": "hR-MODvfO20merTlcBbBQcwrv_Hpj5hXRJSmkAt_9RaC9mQ5QMkh0LGeyhzwUPjkYKLW7npcfXpxoH8Qb8YMFfp1Bu7h7oICwkBcBi-C1YUncKFmsBvDtjzOCkBs_QrtH_ZW_dsSzt7oloOHqgzfHQ",
	  "type": "BbsBlsSignature2020",
	  "verificationMethod": "did:example:123456#key2"
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
    "https://w3id.org/security/bbs/v1"
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
	// pkBase58 from did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2
	pkBase58 := "nEP2DEdbRaQ2r5Azeatui9MG6cj7JUHa8GD7khub4egHJREEuvj4Y8YG8w51LnhPEXxVV1ka93HpSLkVzeQuuPE1mH9oCMrqoHXAKGBsuDT1yJvj9cKgxxLCXiRRirCycki"
	pubKeyBytes := base58.Decode(pkBase58)

	nonce, err := base64.StdEncoding.DecodeString("G/hn9Ca9bIWZpJGlhnr/41r8RB0OO0TLChZASr3QJVztdri/JzS8Zf/xWJT5jW78zlM=")
	require.NoError(t, err)

	docMap := toMap(t, case16VC)
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
		// TODO re-enable (#2562).
		t.Skip()
		docWithSeveralProofsMap := toMap(t, docWithManyProofsJSON)

		pubKeyBytes2 := base58.Decode("tPTWWeUm8yT3aR9HtMvo2pLLvAdyV9Z4nJYZ2ZsyoLVpTupVb7NaRJ3tZePF6YsCN1nw7McqJ38tvpmQxKQxrTbyzjiewUDaj5jbD8gVfpfXJL2SfPBw4TGjYPA6zg6Jrxn")

		compositeResolver := &testKeyResolver{
			variants: map[string]*sigverifier.PublicKey{
				"did:example:489398593#test": {
					Type:  "Bls12381G2Key2020",
					Value: pubKeyBytes},
				"did:example:123456#key2": {
					Type:  "Bls12381G2Key2020",
					Value: pubKeyBytes2},
			},
		}

		docWithSelectiveDisclosure, err := s.SelectiveDisclosure(docWithSeveralProofsMap, revealDocMap, nonce,
			compositeResolver, withDocLoader)
		require.NoError(t, err)
		require.NotEmpty(t, docWithSelectiveDisclosure)
		require.Contains(t, docWithSelectiveDisclosure, proofField)

		proofs, ok := docWithSelectiveDisclosure[proofField].([]map[string]interface{})
		require.True(t, ok)

		require.Len(t, proofs, 2)
		require.Equal(t, "BbsBlsSignatureProof2020", proofs[0]["type"])
		require.NotEmpty(t, proofs[0]["proofValue"])
		require.Equal(t, "BbsBlsSignatureProof2020", proofs[1]["type"])
		require.NotEmpty(t, proofs[1]["proofValue"])
	})

	t.Run("malformed input", func(t *testing.T) {
		docMap := make(map[string]interface{})
		docMap["@context"] = "http://localhost/nocontext"
		docMap["bad"] = "example"
		docMap["proof"] = "example"

		_, err := s.SelectiveDisclosure(docMap, revealDocMap, nonce,
			pubKeyResolver, withDocLoader)

		require.Error(t, err)
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
		require.Contains(t, err.Error(), "document does not have a proof")
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
		require.EqualError(t, err, "get BLS proofs: read document proofs: proof is not map or array of maps")
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
		require.EqualError(t, err, "generate signature proof: derive BBS+ proof: parse signature: invalid size of signature") //nolint:lll
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
			err: errors.New("public key not found"),
		}

		docWithSelectiveDisclosure, err := s.SelectiveDisclosure(docMap, revealDocMap, nonce,
			failingPublicKeyResolver, withDocLoader)
		require.Error(t, err)
		require.EqualError(t, err, "generate signature proof: get public key and signature: resolve public key of BBS+ signature: public key not found") //nolint:lll
		require.Empty(t, docWithSelectiveDisclosure)
	})

	t.Run("Case 18 derives into Case 19", func(t *testing.T) {
		const case18RevealDoc = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1",
    "https://w3id.org/security/bbs/v1"
  ],
  "type": ["UniversityDegreeCredential", "VerifiableCredential"],
  "@explicit": true,
  "issuer": {},
  "issuanceDate": {},
  "credentialSubject": {
    "@explicit": true,
    "degree": {}
  }
}
`

		case18DocMap := toMap(t, case18VC)
		case18RevealDocMap := toMap(t, case18RevealDoc)

		case19Nonce, err := base64.StdEncoding.DecodeString("lEixQKDQvRecCifKl789TQj+Ii6YWDLSwn3AxR0VpPJ1QV5htod/0VCchVf1zVM0y2E=")
		require.NoError(t, err)

		docWithSelectiveDisclosure, err := s.SelectiveDisclosure(case18DocMap, case18RevealDocMap, case19Nonce,
			pubKeyResolver, withDocLoader)
		require.NoError(t, err)
		require.NotEmpty(t, docWithSelectiveDisclosure)
		require.Contains(t, docWithSelectiveDisclosure, proofField)

		proofs, ok := docWithSelectiveDisclosure[proofField].([]map[string]interface{})
		require.True(t, ok)

		require.Len(t, proofs, 1)
		require.Equal(t, "BbsBlsSignatureProof2020", proofs[0]["type"])
		require.NotEmpty(t, proofs[0]["proofValue"])

		case18DerivationBytes, err := json.Marshal(docWithSelectiveDisclosure)

		pubKeyFetcher := verifiable.SingleKey(pubKeyBytes,"Bls12381G2Key2020")
		docLoader := createLDPBBS2020DocumentLoader()

		_, err = verifiable.ParseCredential(case18DerivationBytes, verifiable.WithPublicKeyFetcher(pubKeyFetcher),
			verifiable.WithJSONLDDocumentLoader(docLoader))
		require.NoError(t, err)
	})
}

func toMap(t *testing.T, doc string) map[string]interface{} {
	var docMap map[string]interface{}
	err := json.Unmarshal([]byte(doc), &docMap)
	require.NoError(t, err)

	return docMap
}
