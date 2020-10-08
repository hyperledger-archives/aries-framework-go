package bbsblssignature2020

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/bls/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	sigverifier "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
)

func TestSuite(t *testing.T) {
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

	//blsVerifier := &blsBBSVerifier{}
	blsVerifier := NewVerifier(bbs12381g2pub.NewBlsG2Pub())

	blsSuite := New(suite.WithCompactProof(), suite.WithVerifier(blsVerifier))

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

	err = verifier.Verify([]byte(vcJSON), jsonld.WithDocumentLoader(createLDPBBS2020DocumentLoader()))
	require.NoError(t, err)
}

//type blsBBSVerifier struct {
//}
//
//// Verify will verify a signature.
//func (v *blsBBSVerifier) Verify(pubKeyValue *sigverifier.PublicKey, doc, signature []byte) error {
//	fmt.Printf("doc: %s\n", string(doc))
//	return nil
//}

type testKeyResolver struct {
	publicKey *sigverifier.PublicKey
	err       error
}

func (r *testKeyResolver) Resolve(string) (*sigverifier.PublicKey, error) {
	return r.publicKey, r.err
}
