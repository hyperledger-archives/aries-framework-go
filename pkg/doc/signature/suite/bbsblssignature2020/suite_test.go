/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbsblssignature2020

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	sigverifier "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
)

func TestSuite(t *testing.T) {
	blsVerifier := &testVerifier{}

	blsSuite := New(suite.WithCompactProof(), suite.WithVerifier(blsVerifier))

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
	digest := New().GetDigest([]byte("test doc"))
	require.NotNil(t, digest)
	require.Equal(t, []byte("test doc"), digest)
}

func TestSignatureSuite_Accept(t *testing.T) {
	ss := New()
	accepted := ss.Accept("BbsBlsSignature2020")
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
    "created": "2020-10-07T16:38:09Z",
    "proofPurpose": "assertionMethod",
    "proofValue": "o/79UazZRsf3y35mZ8kT6hx2M2R1fGgj2puotSqeLiha5MGRmqHLx1JAQsG3JlJeW5n56Gg+xUKaDPfzyimi0V9ECloPIBJY+dIMjQE15PFAk+/wtnde9QY8cZOmTIiI56HuN6DwADIzo3BLwkL2RQ==",
    "verificationMethod": "did:example:489398593#test"
  }
}
`

//nolint:lll
const expectedDoc = `_:c14n0 <http://purl.org/dc/terms/created> "2020-10-07T16:38:09Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3c-ccg.github.io/ldp-bbs2020/context/v1#BbsBlsSignature2020> .
_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:c14n0 <https://w3id.org/security#verificationMethod> <did:example:489398593#test> .
<did:example:b34ca6cd37bbf23> <http://schema.org/birthDate> "1958-07-17"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<did:example:b34ca6cd37bbf23> <http://schema.org/familyName> "SMITH" .
<did:example:b34ca6cd37bbf23> <http://schema.org/gender> "Male" .
<did:example:b34ca6cd37bbf23> <http://schema.org/givenName> "JOHN" .
<did:example:b34ca6cd37bbf23> <http://schema.org/image> <data:image/png;base64,iVBORw0KGgokJggg==> .
<did:example:b34ca6cd37bbf23> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
<did:example:b34ca6cd37bbf23> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResident> .
<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#birthCountry> "Bahamas" .
<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#commuterClassification> "C1" .
<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#lprCategory> "C09" .
<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#lprNumber> "999-999-999" .
<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#residentSince> "2015-01-01"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
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
	err       error
}

func (r *testKeyResolver) Resolve(string) (*sigverifier.PublicKey, error) {
	return r.publicKey, r.err
}
