/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

//nolint:lll
const validPresentation = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
  "type": "VerifiablePresentation",
  "verifiableCredential": [
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "id": "http://example.edu/credentials/1872",
      "type": [
        "VerifiableCredential",
        "AlumniCredential"
      ],
      "issuer": "https://example.edu/issuers/565049",
      "issuanceDate": "2010-01-01T19:03:24Z",
      "credentialSubject": {
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "alumniOf": {
          "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
          "name": [
            {
              "value": "Example University",
              "lang": "en"
            }
          ]
        }
      },
      "proof": {
        "type": "RsaSignature2018",
        "created": "2017-06-18T21:19:10Z",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "https://example.edu/issuers/keys/1",
        "jws": "eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..TCYt5XsITJX1CxPCT8yAV-TVkIEq_PbChOMqsLfRoPsnsgw5WEuts01mq-pQy7UJiN5mgRxD-WUcX16dUEMGlv50aqzpqh4Qktb3rk-BuQy72IFLOqV0G_zS245-kronKb78cPN25DGlcTwLtjPAYuNzVBAh4vGHSrQyHUdBBPM"
      }
    }
  ],
  "holder": "did:example:ebfeb1f712ebc6f1c276e12ec21",
  "proof": {
    "type": "RsaSignature2018",
    "created": "2018-09-14T21:19:10Z",
    "proofPurpose": "authentication",
    "verificationMethod": "did:example:ebfeb1f712ebc6f1c276e12ec21#keys-1",
    "challenge": "1f44d55f-f161-4938-a659-f8026467f126",
    "domain": "4jt78h47fh47",
    "jws": "eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..kTCYt5XsITJX1CxPCT8yAV-TVIw5WEuts01mq-pQy7UJiN5mgREEMGlv50aqzpqh4Qq_PbChOMqsLfRoPsnsgxD-WUcX16dUOqV0G_zS245-kronKb78cPktb3rk-BuQy72IFLN25DYuNzVBAh4vGHSrQyHUGlcTwLtjPAnKb78"
  },
  "refreshService": {
    "id": "https://example.edu/refresh/3732",
    "type": "ManualRefreshService2018"
  }
}
`

func TestNewPresentation(t *testing.T) {
	t.Run("creates a new Verifiable Presentation from JSON with valid structure", func(t *testing.T) {
		vp, err := NewPresentation([]byte(validPresentation))
		require.NoError(t, err)
		require.NotNil(t, vp)

		// validate @context
		require.Equal(t, vp.Context, []interface{}{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1"})

		// check id
		require.Equal(t, vp.ID, "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5")

		// check type
		require.Equal(t, vp.Type, "VerifiablePresentation")

		// check verifiableCredentials
		require.NotNil(t, vp.Credential)
		require.Len(t, vp.Credential, 1)

		// check holder
		require.Equal(t, vp.Holder, "did:example:ebfeb1f712ebc6f1c276e12ec21")

		// check proof
		require.NotNil(t, vp.Proof)

		// check refreshService
		require.NotNil(t, vp.RefreshService)
		require.Equal(t, vp.RefreshService.ID, "https://example.edu/refresh/3732")
		require.Equal(t, vp.RefreshService.Type, "ManualRefreshService2018")
	})

	t.Run("creates a new Verifiable Presentation from JSON with invalid structure", func(t *testing.T) {
		emptyJSONDoc := "{}"
		_, err := NewPresentation([]byte(emptyJSONDoc))
		require.Error(t, err)
	})

	t.Run("fails to create a new Verifiable Presentation from non-JSON doc", func(t *testing.T) {
		_, err := NewPresentation([]byte("non json"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "JSON unmarshalling of verifiable presentation failed")
	})
}

func TestValidateVP_Context(t *testing.T) {
	t.Run("rejects verifiable presentation with empty context", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Context = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		_, err = NewPresentation(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "@context is required")
	})

	t.Run("rejects verifiable presentation with invalid context", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Context = []interface{}{
			"https://www.w3.org/2018/credentials/v2",
			"https://www.w3.org/2018/credentials/examples/v1"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		_, err = NewPresentation(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Does not match pattern '^https://www.w3.org/2018/credentials/v1$'")
	})
}

func TestValidateVP_ID(t *testing.T) {
	t.Run("rejects verifiable presentation with non-url ID", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.ID = "not valid presentation ID URL"
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		_, err = NewPresentation(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "id: Does not match format 'uri'")
	})
}

func TestValidateVP_Type(t *testing.T) {
	t.Run("accepts verifiable presentation with single VerifiablePresentation type", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Type = "VerifiablePresentation"
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		_, err = NewPresentation(bytes)
		require.NoError(t, err)
	})

	t.Run("accepts verifiable presentation with multiple types where VerifiablePresentation is a first type",
		func(t *testing.T) {
			raw := &rawPresentation{}
			require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
			raw.Type = []string{"VerifiablePresentation", "CredentialManagerPresentation"}
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			_, err = NewPresentation(bytes)
			require.NoError(t, err)
		})

	t.Run("rejects verifiable presentation with no type defined", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Type = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		_, err = NewPresentation(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "type is required")
	})

	t.Run("rejects verifiable presentation where single type is not VerifiablePresentation", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Type = "CredentialManagerPresentation"
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		_, err = NewPresentation(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Does not match pattern '^VerifiablePresentation$'")
	})

	t.Run("rejects verifiable presentation where several types are defined and first one is not VerifiablePresentation", //nolint:lll
		func(t *testing.T) {
			raw := &rawPresentation{}
			require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
			raw.Type = []string{"CredentialManagerPresentation", "VerifiablePresentation"}
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			_, err = NewPresentation(bytes)
			require.Error(t, err)
			require.Contains(t, err.Error(), "Does not match pattern '^VerifiablePresentation$'")
		})
}

func TestValidateVP_VerifiableCredential(t *testing.T) {
	t.Run("rejects verifiable presentation with not defined verifiableCredential", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Credential = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		_, err = NewPresentation(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "verifiableCredential is required")
	})
}

func TestValidateVP_Holder(t *testing.T) {
	t.Run("rejects verifiable presentation with non-url holder", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Holder = "not valid presentation Holder URL"
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		_, err = NewPresentation(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "holder: Does not match format 'uri'")
	})
}

func TestValidateVP_Proof(t *testing.T) {
	t.Run("rejects verifiable presentation with missed embedded proof", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Proof = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		_, err = NewPresentation(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "embedded proof is missing")
	})
}

func TestValidateVP_RefreshService(t *testing.T) {
	t.Run("accepts verifiable presentation with empty refresh service", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.RefreshService = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		_, err = NewPresentation(bytes)
		require.NoError(t, err)
	})

	t.Run("test verifiable presentation with undefined id of refresh service", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.RefreshService = &RefreshService{Type: "ManualRefreshService2018"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		_, err = NewPresentation(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "refreshService: id is required")
	})

	t.Run("test verifiable presentation with undefined type of refresh service", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.RefreshService = &RefreshService{ID: "https://example.edu/refresh/3732"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		_, err = NewPresentation(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "refreshService: type is required")
	})

	t.Run("test verifiable presentation with invalid URL of id of credential schema", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.RefreshService = &RefreshService{ID: "invalid URL", Type: "ManualRefreshService2018"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		_, err = NewPresentation(bytes)

		require.Error(t, err)
		require.Contains(t, err.Error(), "refreshService.id: Does not match format 'uri'")
	})
}

func TestPresentation_Credentials(t *testing.T) {
	t.Run("extracts verifiable credentials from list", func(t *testing.T) {
		vp, err := NewPresentation([]byte(validPresentation))
		require.NoError(t, err)

		credsData, err := vp.Credentials()
		require.NoError(t, err)
		require.Len(t, credsData, 1)

		// Decode the first verifiable credential
		vc, err := NewCredential(credsData[0])
		require.NoError(t, err)

		// check some VC properties to double check that conversion is OK
		require.Equal(t, "http://example.edu/credentials/1872", vc.ID)
		require.Equal(t, []string{"VerifiableCredential", "AlumniCredential"}, vc.Types)
	})

	t.Run("failure handling on extraction of verifiable credentials from list", func(t *testing.T) {
		vp, err := NewPresentation([]byte(validPresentation))
		require.NoError(t, err)

		// really artificial case...
		invalidCredArray := make([]interface{}, 1)
		invalidCredArray[0] = make(chan int)
		vp.Credential = invalidCredArray

		_, err = vp.Credentials()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to marshal credentials from presentation")
	})

	t.Run("extracts verifiable credentials from single credential", func(t *testing.T) {
		vp, err := NewPresentation([]byte(validPresentation))
		require.NoError(t, err)

		// switch from array to single object
		creds, ok := vp.Credential.([]interface{})
		require.True(t, ok)
		require.Len(t, creds, 1)
		vp.Credential = creds[0]

		credsData, err := vp.Credentials()
		require.NoError(t, err)
		require.Len(t, credsData, 1)

		// Decode the first verifiable credential
		vc, err := NewCredential(credsData[0])
		require.NoError(t, err)
		require.NotNil(t, vc)
	})

	t.Run("failure handling on extraction of verifiable credentials from object", func(t *testing.T) {
		vp, err := NewPresentation([]byte(validPresentation))
		require.NoError(t, err)

		// really artificial case...
		invalidCred := make(chan int)
		vp.Credential = invalidCred

		_, err = vp.Credentials()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to marshal credentials from presentation")
	})
}

func TestPresentation_MarshalJSON(t *testing.T) {
	vp, err := NewPresentation([]byte(validPresentation))
	require.NoError(t, err)
	require.NotEmpty(t, vp)

	// convert verifiable credential to json byte data
	vpData, err := vp.MarshalJSON()
	require.NoError(t, err)
	require.NotEmpty(t, vpData)

	// convert json byte data back to verifiable presentation
	vp2, err := NewPresentation(vpData)
	require.NoError(t, err)
	require.NotEmpty(t, vp2)

	// verify that verifiable presentations created by NewPresentation() and MarshalJSON() matches
	require.Equal(t, vp, vp2)
}

func TestWithPresSkippedEmbeddedProofCheck(t *testing.T) {
	vpOpt := WithPresSkippedEmbeddedProofCheck()
	require.NotNil(t, vpOpt)

	opts := &presentationOpts{}
	vpOpt(opts)
	require.True(t, opts.skipEmbeddedProofCheck)
}
