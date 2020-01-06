/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_compactJSONLD(t *testing.T) {
	t.Run("Extended both basic VC and subject model", func(t *testing.T) {
		jsonldContext := `
{
  "@context": {
    "referenceNumber": "https://example.com/vocab#referenceNumber",
    "favoriteFood": "https://example.com/vocab#favoriteFood",
    "name": "https://example.com/vocab#name"
  }
}
`

		loadsCount := 0
		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			loadsCount++
			res.WriteHeader(http.StatusOK)
			_, err := res.Write([]byte(jsonldContext))
			require.NoError(t, err)
		}))

		defer func() { testServer.Close() }()

		vcJSONTemplate := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "%s"
  ],
  "id": "http://example.com/credentials/4643",
  "type": ["VerifiableCredential", "CustomExt12"],
  "issuer": "https://example.com/issuers/14",
  "issuanceDate": "2018-02-24T05:28:04Z",
  "referenceNumber": 83294847,
  "credentialSubject": {
    "id": "did:example:abcdef1234567",
    "name": "Jane Doe",
    "favoriteFood": "Papaya"
  }
}
`
		vc := fmt.Sprintf(vcJSONTemplate, testServer.URL)

		loader := CachingJSONLDLoader()

		err := compactJSONLD(vc, loader, true)
		require.NoError(t, err)
		require.Equal(t, 1, loadsCount)

		// Use same the loader, make sure that the cache of the JSON-LD schema is used
		// and thus no extra load of the schema is made.
		err = compactJSONLD(vc, loader, true)
		require.NoError(t, err)
		require.Equal(t, 1, loadsCount)
	})

	jsonldContext := `
{
  "@context": {
    "referenceNumber": "https://example.com/vocab#referenceNumber"
  }
}
`

	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(http.StatusOK)
		_, err := res.Write([]byte(jsonldContext))
		require.NoError(t, err)
	}))

	defer func() { testServer.Close() }()

	t.Run("Extended basic VC model, credentialSubject is defined as string (ID only)", func(t *testing.T) {
		// Use a different VC to verify the case when credentialSubject is a string (i.e. ID is defined only).
		vcJSONTemplate := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "%s"
  ],
  "id": "http://example.com/credentials/4643",
  "type": [
    "VerifiableCredential",
    "CustomExt12"
  ],
  "issuer": "https://example.com/issuers/14",
  "issuanceDate": "2018-02-24T05:28:04Z",
  "referenceNumber": 83294847,
  "credentialSubject": "did:example:abcdef1234567"
}
`
		vcJSON := fmt.Sprintf(vcJSONTemplate, testServer.URL)

		err := compactJSONLD(vcJSON, CachingJSONLDLoader(), true)
		require.NoError(t, err)
	})
}

func Test_compactJSONLDWithExtraUndefinedFields(t *testing.T) {
	jsonldContext := `
{
  "@context": {
    "favoriteFood": "https://example.com/vocab#favoriteFood",
    "name": "https://example.com/vocab#name"
  }
}
`

	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(http.StatusOK)
		_, err := res.Write([]byte(jsonldContext))
		require.NoError(t, err)
	}))

	defer func() { testServer.Close() }()

	vcJSONTemplate := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "%s"
  ],
  "id": "http://example.com/credentials/4643",
  "type": ["VerifiableCredential", "CustomExt12"],
  "issuer": "https://example.com/issuers/14",
  "issuanceDate": "2018-02-24T05:28:04Z",
  "referenceNumber": 83294847,
  "credentialSubject": {
    "id": "did:example:abcdef1234567",
    "name": "Jane Doe",
    "favoriteFood": "Papaya"
  }
}
`
	vc := fmt.Sprintf(vcJSONTemplate, testServer.URL)

	err := compactJSONLD(vc, CachingJSONLDLoader(), true)
	require.Error(t, err)
	require.EqualError(t, err, "JSON-LD doc has different structure after compaction")
}

func Test_compactJSONLDWithExtraUndefinedSubjectFields(t *testing.T) {
	jsonldContext := `
{
  "@context": {
    "referenceNumber": "https://example.com/vocab#referenceNumber"
  }
}
`

	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(http.StatusOK)
		_, err := res.Write([]byte(jsonldContext))
		require.NoError(t, err)
	}))

	defer func() { testServer.Close() }()

	t.Run("Extended basic VC model, credentialSubject is defined as object - undefined fields present",
		func(t *testing.T) {
			// Use a different VC to verify the case when credentialSubject is an array.
			vcJSONTemplate := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "%s"
  ],
  "id": "http://example.com/credentials/4643",
  "type": [
    "VerifiableCredential",
    "CustomExt12"
  ],
  "issuer": "https://example.com/issuers/14",
  "issuanceDate": "2018-02-24T05:28:04Z",
  "referenceNumber": 83294847,
  "credentialSubject": [
    {
      "id": "did:example:abcdef1234567",
      "name": "Jane Doe",
      "favoriteFood": "Papaya"
    }
  ]
}
`

			vcJSON := fmt.Sprintf(vcJSONTemplate, testServer.URL)

			err := compactJSONLD(vcJSON, CachingJSONLDLoader(), true)
			require.Error(t, err)
			require.EqualError(t, err, "JSON-LD doc has different structure after compaction")
		})

	t.Run("Extended basic VC model, credentialSubject is defined as array - undefined fields present", func(t *testing.T) {
		// Use a different VC to verify the case when credentialSubject is an array.
		vcJSONTemplate := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "%s"
  ],
  "id": "http://example.com/credentials/4643",
  "type": [
    "VerifiableCredential",
    "CustomExt12"
  ],
  "issuer": "https://example.com/issuers/14",
  "issuanceDate": "2018-02-24T05:28:04Z",
  "referenceNumber": 83294847,
  "credentialSubject": [
    {
      "id": "did:example:abcdef1234567",
      "name": "Jane Doe",
      "favoriteFood": "Papaya"
    }
  ]
}
`

		vcJSON := fmt.Sprintf(vcJSONTemplate, testServer.URL)

		err := compactJSONLD(vcJSON, CachingJSONLDLoader(), true)
		require.Error(t, err)
		require.EqualError(t, err, "JSON-LD doc has different structure after compaction")
	})
}

func Test_compactJSONLD_CornerErrorCases(t *testing.T) {
	t.Run("Invalid JSON input", func(t *testing.T) {
		err := compactJSONLD("not a json", CachingJSONLDLoader(), true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "convert JSON-LD doc to map")
	})

	t.Run("No \"context\" in VC", func(t *testing.T) {
		vcJSONTemplate := `
{
  "id": "http://example.com/credentials/4643",
  "type": [
    "VerifiableCredential",
    "CustomExt12"
  ],
  "issuer": "https://example.com/issuers/14",
  "issuanceDate": "2018-02-24T05:28:04Z",
  "referenceNumber": 83294847,
  "credentialSubject": "did:example:abcdef1234567"
}
`
		err := compactJSONLD(vcJSONTemplate, CachingJSONLDLoader(), true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "extract context from JSON-LD doc")
	})

	t.Run("JSON-LD compact error", func(t *testing.T) {
		vcJSONTemplate := `
{
  "@context": 777,
  "id": "http://example.com/credentials/4643",
  "type": [
    "VerifiableCredential",
    "CustomExt12"
  ],
  "issuer": "https://example.com/issuers/14",
  "issuanceDate": "2018-02-24T05:28:04Z",
  "referenceNumber": 83294847,
  "credentialSubject": "did:example:abcdef1234567"
}
`

		err := compactJSONLD(vcJSONTemplate, CachingJSONLDLoader(), true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "compact JSON-LD document")
	})
}
