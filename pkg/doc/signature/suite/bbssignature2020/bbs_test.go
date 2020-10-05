package bbssignature2020

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/piprate/json-gold/ld"
	"github.com/square/go-jose/v3/json"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
)

func TestBBS(t *testing.T) {
	proofMap := map[string]interface{}{
		"@context":           "https://w3id.org/security/v2",
		"type":               "https://w3c-ccg.github.io/ldp-bbs2020/context/v1#BbsBlsSignature2020",
		"created":            "2020-10-05T15:37:27Z",
		"verificationMethod": "did:example:489398593#test",
		"proofPurpose":       "assertionMethod",
	}

	processor := jsonld.NewProcessor("URDNA2015")

	withDocumentLoader := jsonld.WithDocumentLoader(createLDPBBS2020DocumentLoader())

	proofCanonical, err := processor.GetCanonicalDocument(proofMap, withDocumentLoader)
	require.NoError(t, err)

	printCanonical(t, proofCanonical)

	var vcMap map[string]interface{}

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

	err = json.Unmarshal([]byte(vcJSON), &vcMap)
	require.NoError(t, err)

	vcMapCompacted, err := processor.Compact(vcMap, getSecurityContextMap(), withDocumentLoader)
	require.NoError(t, err)

	vcCanonical, err := processor.GetCanonicalDocument(vcMapCompacted)

	require.NoError(t, err)

	printCanonical(t, vcCanonical)

	statements := append(getStatements(string(proofCanonical)), getStatements(string(vcCanonical))...)
	t.Logf("statements: %v", statements)

	verifyData := append(
		statementsToBytes(getStatements(string(proofCanonical))),
		statementsToBytes(getStatements(string(vcCanonical)))...,
	)
	t.Logf("verify data: %v", verifyData)
}

func TestProofCreation(t *testing.T) {
	proofJSON := `
{
  "@context": "https://w3c-ccg.github.io/ldp-bbs2020/context/v1",
  "type": "BbsBlsSignature2020"
}
`

	proofMap, err := toMap(proofJSON)
	require.NoError(t, err)

	processor := jsonld.NewProcessor("URDNA2015")
	withDocumentLoader := jsonld.WithDocumentLoader(createLDPBBS2020DocumentLoader())

	proofCompacted, err := processor.Compact(proofMap, map[string]interface{}{
		"@context": "https://w3id.org/security/v2",
	}, withDocumentLoader)
	require.NoError(t, err)

	proofStr, err := json.MarshalIndent(proofCompacted, "", "\t")
	require.NoError(t, err)

	t.Logf("proofCompacted: %s", proofStr)
}

func TestPublicKeyB58ToBase64(t *testing.T) {
	pkB58 := "oqpWYKaZD9M1Kbe94BVXpr8WTdFBNZyKv48cziTiQUeuhm7sBhCABMyYG4kcMrseC68YTFFgyhiNeBKjzdKk9MiRWuLv5H4FFujQsQK2KTAtzU8qTBiZqBHMmnLF4PL7Ytu"

	pkBytes := base58.Decode(pkB58)

	t.Logf("pk: %s", string(pkBytes))

	pkBase64 := base64.RawStdEncoding.EncodeToString(pkBytes)
	t.Logf("pkBase64=%s", pkBase64)
}

func createLDPBBS2020DocumentLoader() ld.DocumentLoader {
	loader := ld.NewCachingDocumentLoader(ld.NewRFC7324CachingDocumentLoader(&http.Client{}))

	reader, err := ld.DocumentFromReader(strings.NewReader(ldpBBS2020JSONLD))
	if err != nil {
		panic(err)
	}

	loader.AddDocument("https://w3c-ccg.github.io/ldp-bbs2020/context/v1", reader)

	reader, err = ld.DocumentFromReader(strings.NewReader(securityJSONLD))
	if err != nil {
		panic(err)
	}

	loader.AddDocument("https://w3id.org/security/v2", reader)

	return loader
}

func printCanonical(t *testing.T, proofCanonical []byte) {
	views := strings.Split(string(proofCanonical), "\n")
	for _, v := range views {
		if len(v) > 0 {
			t.Logf("v=%s", v)
		}
	}
}

func statementsToBytes(statements []string) [][]byte {
	sBytes := make([][]byte, len(statements))

	for i := range statements {
		sBytes[i] = []byte(statements[i])
	}

	return sBytes
}

func getStatements(canonical string) []string {
	statements := make([]string, 0)

	views := strings.Split(canonical, "\n")
	for _, v := range views {
		if len(v) > 0 {
			statements = append(statements, v)
		}
	}

	return statements
}

func getSecurityContextMap() map[string]interface{} {
	return map[string]interface{}{
		"@context": "https://w3id.org/security/v2",
	}
}

func toMap(v interface{}) (map[string]interface{}, error) {
	var (
		b   []byte
		err error
	)

	switch cv := v.(type) {
	case []byte:
		b = cv
	case string:
		b = []byte(cv)
	default:
		b, err = json.Marshal(v)
		if err != nil {
			return nil, err
		}
	}

	var m map[string]interface{}

	err = json.Unmarshal(b, &m)
	if err != nil {
		return nil, err
	}

	return m, nil
}
