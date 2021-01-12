/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbsblssignatureproof2020_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignatureproof2020"
	sigverifier "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
)

func TestSuite(t *testing.T) {
	blsVerifier := &testVerifier{}

	blsSuite := bbsblssignatureproof2020.New(suite.WithCompactProof(), suite.WithVerifier(blsVerifier))

	//nolint:lll
	pkBase64 := "h/rkcTKXXzRbOPr9UxSfegCbid2U/cVNXQUaKeGF7UhwrMJFP70uMH0VQ9+3+/2zDPAAjflsdeLkOXW3+ShktLxuPy8UlXSNgKNmkfb+rrj+FRwbs13pv/WsIf+eV66+"
	pkBytes, err := base64.RawStdEncoding.DecodeString(pkBase64)
	require.NoError(t, err)

	blsBBSPublicKey := &sigverifier.PublicKey{
		Type:  "BbsBlsSignature2020",
		Value: pkBytes,
	}

	verifier, err := sigverifier.New(&testKeyResolver{
		publicKey: blsBBSPublicKey,
	}, blsSuite)
	require.NoError(t, err)

	err = verifier.Verify([]byte(vcDoc), jsonld.WithDocumentLoader(createLDPBBS2020DocumentLoader()))
	require.NoError(t, err)

	require.Equal(t, expectedDoc, blsVerifier.doc)
}

func TestSignatureSuite_GetDigest(t *testing.T) {
	digest := bbsblssignatureproof2020.New().GetDigest([]byte("test doc"))
	require.NotNil(t, digest)
	require.Equal(t, []byte("test doc"), digest)
}

func TestSignatureSuite_Accept(t *testing.T) {
	ss := bbsblssignatureproof2020.New()
	accepted := ss.Accept("BbsBlsSignatureProof2020")
	require.True(t, accepted)

	accepted = ss.Accept("RsaSignature2018")
	require.False(t, accepted)
}

//nolint:lll
const vcDoc = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/citizenship/v1",
    "https://w3c-ccg.github.io/ldp-bbs2020/context/v1"
  ],
  "id": "https://issuer.oidp.uscis.gov/credentials/83627465",
  "type": [
    "PermanentResidentCard",
    "VerifiableCredential"
  ],
  "description": "Government of Example Permanent Resident Card.",
  "identifier": "83627465",
  "name": "Permanent Resident Card",
  "credentialSubject": {
    "id": "did:example:b34ca6cd37bbf23",
    "type": [
      "Person",
      "PermanentResident"
    ],
    "familyName": "SMITH",
    "gender": "Male",
    "givenName": "JOHN"
  },
  "expirationDate": "2029-12-03T12:19:52Z",
  "issuanceDate": "2019-12-03T12:19:52Z",
  "issuer": "did:example:489398593",
  "proof": {
    "created": "2020-12-06T19:23:10Z",
    "nonce": "bm9uY2U=",
    "proofPurpose": "assertionMethod",
    "proofValue": "ABkB/wbvj3hl666VoVa0OoBPw/vBqSAJzGCSA/jmyXu3ou2awUn4C9pQA+QNNkbqQwqloyPEqcFxpS7zok6xYA1pUOx5igu1eYBorAv9+kIOCPONGcW2rsXvZOO2hdn4GWT9xc2ir675V61HhqFF0ETZLkNzH+N5NZOUaiXG2gegI2EjVk8M0TaBJ1bUxb5ZZ0qhnLM1AAAAdIj56X6YvHWghzNhFyUt8FbMDSpTk3i4lujEP0M0OHGEm+hNUhJj2r0ZA4lDsD/tBAAAAAJPSSQ/NOVm7iXCoX2STQESM2yWKrDRErWI+mfzn5wmAklSgf0VA5BunaiRNYh57MA6CJ94cagGixys6rCZ42N7p8F4Yp4pUPpJE3EvHhc63YWRK6y3/smRM+Y3OgVJAcPmpYOjTB7owrHLxNRC7+E+AAAACRp7vxsK7oY3WdStSIA5RcrvMl0tUW5r5e8o4HpOvD2ANlZcne08y6wbRHYFtA22J7pbTliW1NJyLYUj18gOYfg0S+w20OYscVAShjYIwpjRvvvvHpCmIiU0/WD9fOOBPXAeFQJogHPCHM+oKO6YlUS4qmXl/No7oHCedyh11Ty/Bi2x8dRLDXPFpLt3D7dZUg96mkJ5LbGQ35soqepPreYv3JWKh75r6wJny7kN2nNQ0/2CYpMTTNqewxz0XSMVQ0X2ztsCKX9+npiqVWDNe77pT3BYyT3ZUWeV2geJfGTXcpyn7+rAdD0GddYIleYXXVSr4I4/tzEYWWKC2xKsGBwRXq64T//cOdbzEt5i60aPVs9QIsecysZ2gIjuoeVEMg==",
    "type": "BbsBlsSignatureProof2020",
    "verificationMethod": "did:example:489398593#test"
  }
}
`

//nolint:lll
const expectedDoc = `_:c14n0 <http://purl.org/dc/terms/created> "2020-12-06T19:23:10Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3c-ccg.github.io/ldp-bbs2020/context/v1#BbsBlsSignature2020> .
_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:c14n0 <https://w3id.org/security#verificationMethod> <did:example:489398593#test> .
<did:example:b34ca6cd37bbf23> <http://schema.org/familyName> "SMITH" .
<did:example:b34ca6cd37bbf23> <http://schema.org/gender> "Male" .
<did:example:b34ca6cd37bbf23> <http://schema.org/givenName> "JOHN" .
<did:example:b34ca6cd37bbf23> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
<did:example:b34ca6cd37bbf23> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResident> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/description> "Government of Example Permanent Resident Card." .
<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/identifier> "83627465" .
<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/name> "Permanent Resident Card" .
<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResidentCard> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:b34ca6cd37bbf23> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#expirationDate> "2029-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuanceDate> "2019-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuer> <did:example:489398593> .
`

type testVerifier struct {
	err error
	doc string
}

func (v *testVerifier) Verify(_ *sigverifier.PublicKey, doc, _ []byte) error {
	v.doc = string(doc)
	return v.err
}

type testKeyResolver struct {
	publicKey *sigverifier.PublicKey
	variants  map[string]*sigverifier.PublicKey
	err       error
}

func (r *testKeyResolver) Resolve(id string) (*sigverifier.PublicKey, error) {
	if r.err != nil {
		return nil, r.err
	}

	if len(r.variants) > 0 {
		return r.variants[id], nil
	}

	return r.publicKey, r.err
}
