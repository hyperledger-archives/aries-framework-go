/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/bbs/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignatureproof2020"
)

//nolint:lll
func TestCredential_GenerateBBSSelectiveDisclosure(t *testing.T) {
	r := require.New(t)

	s := "uBlesrb_p6VIl-DrJ4Kj7DJ2S45uDqq6cJSgwdw_tVXWazl1XnjQxKsIzrY1RqffBqqT1oFTPi5Nwb_3IGMTWvXeGU7xwZOP8K1jybjknN0ADhp3i8JjTDeuUWH_sixv8ydcx4Qpqq-mMOX7nEm7Dg"
	_, err := base64.RawURLEncoding.DecodeString(s)
	r.NoError(err)

	vcJSON := `
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
	 }
	}
	`

	pubKey, privKey, err := bbs12381g2pub.GenerateKeyPair(sha256.New, nil)
	r.NoError(err)

	pubKeyBytes, err := pubKey.Marshal()
	r.NoError(err)

	signedVC := signVCWithBBS(r, privKey, pubKeyBytes, []byte(vcJSON))

	revealJSON := `
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

	var revealDoc map[string]interface{}
	err = json.Unmarshal([]byte(revealJSON), &revealDoc)
	require.NoError(t, err)

	nonce := []byte("nonce")

	vcWithSelectiveDisclosure, err := signedVC.GenerateBBSSelectiveDisclosure(revealDoc, pubKeyBytes, nonce,
		jsonld.WithDocumentLoader(testDocumentLoader))
	r.NoError(err)
	r.NotNil(vcWithSelectiveDisclosure)

	vcSelectiveDisclosureBytes, err := json.Marshal(vcWithSelectiveDisclosure)
	require.NoError(t, err)

	sigSuite := bbsblssignatureproof2020.New(
		suite.WithCompactProof(),
		suite.WithVerifier(bbsblssignatureproof2020.NewG2PublicKeyVerifier(nonce)))

	vcVerified, err := parseTestCredential(vcSelectiveDisclosureBytes,
		WithEmbeddedSignatureSuites(sigSuite),
		WithPublicKeyFetcher(SingleKey(pubKeyBytes, "Bls12381G2Key2020")),
	)
	r.NoError(err)
	r.NotNil(vcVerified)
}

func signVCWithBBS(r *require.Assertions, privKey *bbs12381g2pub.PrivateKey, pubKeyBytes, vcBytes []byte) *Credential {
	bbsSigner, err := newBBSSigner(privKey)
	r.NoError(err)

	sigSuite := bbsblssignature2020.New(
		suite.WithSigner(bbsSigner),
		suite.WithVerifier(bbsblssignature2020.NewG2PublicKeyVerifier()))

	ldpContext := &LinkedDataProofContext{
		SignatureType:           "BbsBlsSignature2020",
		SignatureRepresentation: SignatureProofValue,
		Suite:                   sigSuite,
		VerificationMethod:      "did:example:123456#key1",
	}

	vc, err := parseTestCredential(vcBytes)
	r.NoError(err)
	r.Len(vc.Proofs, 0)

	err = vc.AddLinkedDataProof(ldpContext, jsonld.WithDocumentLoader(createTestJSONLDDocumentLoader()))
	r.NoError(err)

	vcSignedBytes, err := json.Marshal(vc)
	r.NoError(err)
	r.NotEmpty(vcSignedBytes)

	vcVerified, err := parseTestCredential(vcSignedBytes,
		WithEmbeddedSignatureSuites(sigSuite),
		WithPublicKeyFetcher(SingleKey(pubKeyBytes, "Bls12381G2Key2020")),
	)
	r.NoError(err)

	return vcVerified
}
