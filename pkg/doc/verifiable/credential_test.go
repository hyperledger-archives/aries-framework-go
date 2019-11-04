/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const singleCredentialSubject = `
{
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science and Arts"
    }
}
`

const multipleCredentialSubjects = `
[{
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "name": "Jayden Doe",
    "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
  }, {
    "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
    "name": "Morgan Doe",
    "spouse": "did:example:ebfeb1f712ebc6f1c276e12ec21"
  }]
`

const issuerAsObject = `
{
    "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
    "name": "Example University"
}
`

func TestNewCredential(t *testing.T) {
	t.Run("test creation of new Verifiable Credential from JSON with valid structure", func(t *testing.T) {
		vc, err := NewCredential([]byte(validCredential))
		require.NoError(t, err)
		require.NotNil(t, vc)

		// validate @context
		require.Equal(t, []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1"}, vc.Context)

		// validate id
		require.Equal(t, "http://example.edu/credentials/1872", vc.ID)

		// validate type
		require.Equal(t, []string{
			"VerifiableCredential",
			"UniversityDegreeCredential"}, vc.Types)

		// validate not null credential subject
		require.NotNil(t, vc.Subject)

		// validate not null credential subject
		require.NotNil(t, vc.Issuer)
		require.Equal(t, "did:example:76e12ec712ebc6f1c221ebfeb1f", vc.Issuer.ID)
		require.Equal(t, "Example University", vc.Issuer.Name)

		// check issued date
		expectedIssued := time.Date(2010, time.January, 1, 19, 23, 24, 0, time.UTC)
		require.Equal(t, &expectedIssued, vc.Issued)

		// check issued date
		expectedExpired := time.Date(2020, time.January, 1, 19, 23, 24, 0, time.UTC)
		require.Equal(t, &expectedExpired, vc.Expired)

		// validate proof
		require.NotNil(t, vc.Proof)

		// check credential status
		require.NotNil(t, vc.Status)
		require.Equal(t, "https://example.edu/status/24", vc.Status.ID)
		require.Equal(t, "CredentialStatusList2017", vc.Status.Type)

		// check refresh service
		require.NotNil(t, vc.RefreshService)
		require.Equal(t, "https://example.edu/refresh/3732", vc.RefreshService.ID)
		require.Equal(t, "ManualRefreshService2018", vc.RefreshService.Type)

		require.NotNil(t, vc.Evidence)

		require.NotNil(t, vc.TermsOfUse)
		require.Len(t, vc.TermsOfUse, 1)
	})

	t.Run("test a try to create a new Verifiable Credential from JSON with invalid structure", func(t *testing.T) {
		emptyJSONDoc := "{}"
		_, err := NewCredential([]byte(emptyJSONDoc))
		require.Error(t, err)
		require.Contains(t, err.Error(), "verifiable credential is not valid")
	})

	t.Run("test a try to create a new Verifiable Credential from non-JSON doc", func(t *testing.T) {
		_, err := NewCredential([]byte("non json"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "new credential")
	})

	t.Run("test a try to create a new Verifiable Credential with failing custom decoder", func(t *testing.T) {
		_, err := NewCredential(
			[]byte(validCredential),
			WithDecoders([]CredentialDecoder{
				func(dataJSON []byte, credential *Credential) error {
					return errors.New("test decoding error")
				},
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "test decoding error")
	})
}

func TestValidateVerCredContext(t *testing.T) {
	t.Run("test verifiable credential with empty context", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Context = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.Error(t, err)
		require.Contains(t, err.Error(), "@context is required")
	})

	t.Run("test verifiable credential with invalid context", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Context = []interface{}{
			"https://www.w3.org/2018/credentials/v2",
			"https://www.w3.org/2018/credentials/examples/v1"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.Error(t, err)
		require.Contains(t, err.Error(), "Does not match pattern '^https://www.w3.org/2018/credentials/v1$'")
	})

	t.Run("test verifiable credential with object context", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Context = []interface{}{"https://www.w3.org/2018/credentials/examples/v1", map[string]interface{}{
			"image": map[string]string{
				"@id": "schema:image", "@type": "@id",
			},
		}}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.Error(t, err)
		require.Contains(t, err.Error(), "Does not match pattern '^https://www.w3.org/2018/credentials/v1$'")
	})
}

func TestValidateVerCredID(t *testing.T) {
	t.Run("test verifiable credential with non-url id", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.ID = "not valid credential ID URL"
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.Error(t, err)
		require.Contains(t, err.Error(), "id: Does not match format 'uri'")
	})
}

func TestValidateVerCredType(t *testing.T) {
	t.Run("test verifiable credential with no type", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Type = []string{}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.Error(t, err)
		require.Contains(t, err.Error(), "Array must have at least 2 items")
	})

	t.Run("test verifiable credential with not first VerifiableCredential type", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Type = []string{"NotVerifiableCredential"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.Error(t, err)
		require.Contains(t, err.Error(), "Does not match pattern '^VerifiableCredential$")
	})

	t.Run("test verifiable credential with VerifiableCredential type only", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Type = []string{"VerifiableCredential"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.Error(t, err)
		require.Contains(t, err.Error(), "Array must have at least 2 items")
	})

	t.Run("test verifiable credential with VerifiableCredential type only as string", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Type = "VerifiableCredential"
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.NoError(t, err)
	})
}

func TestValidateVerCredCredentialSubject(t *testing.T) {
	t.Run("test verifiable credential with no credential subject", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Subject = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.Error(t, err)
		require.Contains(t, err.Error(), "credentialSubject is required")
	})

	t.Run("test verifiable credential with single credential subject", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		require.NoError(t, json.Unmarshal([]byte(singleCredentialSubject), &raw.Subject))
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with several credential subjects", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		require.NoError(t, json.Unmarshal([]byte(multipleCredentialSubjects), &raw.Subject))
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with invalid type of credential subject", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Subject = 55
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.Error(t, err)
		require.Contains(t, err.Error(), "credentialSubject: Invalid type.")
	})
}

func TestValidateVerCredIssuer(t *testing.T) {
	t.Run("test verifiable credential with no issuer", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Issuer = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.Error(t, err)
		require.Contains(t, err.Error(), "issuer is required")
	})

	t.Run("test verifiable credential with plain id issuer", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Issuer = "https://example.edu/issuers/14"
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with issuer as an object", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		require.NoError(t, json.Unmarshal([]byte(issuerAsObject), &raw.Issuer))
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with invalid type of issuer", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Issuer = 55
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.Error(t, err)
		require.Contains(t, err.Error(), "issuer: Invalid type")
	})
}

func TestValidateVerCredIssuanceDate(t *testing.T) {
	t.Run("test verifiable credential with empty issuance date", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Issued = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.Error(t, err)
		require.Contains(t, err.Error(), "issuanceDate is required")
	})

	t.Run("test verifiable credential with wrong format of issuance date", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		timeNow := time.Now()
		raw.Issued = &timeNow
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.Error(t, err)
		require.Contains(t, err.Error(), "issuanceDate: Does not match pattern")
	})
}

func TestValidateVerCredProof(t *testing.T) {
	t.Run("test verifiable credential with empty proof", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Proof = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.NoError(t, err)
	})
}

func TestValidateVerCredExpirationDate(t *testing.T) {
	t.Run("test verifiable credential with empty expiration date", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Expired = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with wrong format of expiration date", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		timeNow := time.Now()
		raw.Expired = &timeNow
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.Error(t, err)
		require.Contains(t, err.Error(), "expirationDate: Does not match pattern")
	})
}

func TestValidateVerCredStatus(t *testing.T) {
	t.Run("test verifiable credential with empty credential status", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Status = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with undefined id of credential status", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Status = &TypedID{Type: "CredentialStatusList2017"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.Error(t, err)
		require.Contains(t, err.Error(), "credentialStatus: id is required")
	})

	t.Run("test verifiable credential with undefined type of credential status", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Status = &TypedID{ID: "https://example.edu/status/24"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.Error(t, err)
		require.Contains(t, err.Error(), "credentialStatus: type is required")
	})

	t.Run("test verifiable credential with invalid URL of id of credential status", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Status = &TypedID{ID: "invalid URL", Type: "CredentialStatusList2017"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.Error(t, err)
		require.Contains(t, err.Error(), "credentialStatus.id: Does not match format 'uri'")
	})
}

func TestValidateVerCredSchema(t *testing.T) {
	t.Run("test verifiable credential with empty credential schema", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Schema = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with undefined id of credential schema", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Schema = &TypedID{Type: "JsonSchemaValidator2018"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.Error(t, err)
		require.Contains(t, err.Error(), "credentialSchema: id is required")
	})

	t.Run("test verifiable credential with undefined type of credential schema", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Schema = &TypedID{ID: "https://example.org/examples/degree.json"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.Error(t, err)
		require.Contains(t, err.Error(), "credentialSchema: type is required")
	})

	t.Run("test verifiable credential with invalid URL of id of credential schema", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Schema = &TypedID{ID: "invalid URL", Type: "JsonSchemaValidator2018"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.Error(t, err)
		require.Contains(t, err.Error(), "credentialSchema.id: Does not match format 'uri'")
	})
}

func TestValidateVerCredRefreshService(t *testing.T) {
	t.Run("test verifiable credential with empty refresh service", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.RefreshService = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with undefined id of refresh service", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.RefreshService = &TypedID{Type: "ManualRefreshService2018"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.Error(t, err)
		require.Contains(t, err.Error(), "refreshService: id is required")
	})

	t.Run("test verifiable credential with undefined type of refresh service", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.RefreshService = &TypedID{ID: "https://example.edu/refresh/3732"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.Error(t, err)
		require.Contains(t, err.Error(), "refreshService: type is required")
	})

	t.Run("test verifiable credential with invalid URL of id of credential schema", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.RefreshService = &TypedID{ID: "invalid URL", Type: "ManualRefreshService2018"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validate(bytes, nil, &credentialOpts{disabledCustomSchema: true})
		require.Error(t, err)
		require.Contains(t, err.Error(), "refreshService.id: Does not match format 'uri'")
	})
}

func TestJSONConversionWithPlainIssuer(t *testing.T) {
	// setup -> create verifiable credential from json byte data
	vc, err := NewCredential([]byte(validCredential))
	require.NoError(t, err)
	require.NotEmpty(t, vc)

	// convert verifiable credential to json byte data
	byteCred, err := vc.MarshalJSON()
	require.NoError(t, err)
	require.NotEmpty(t, byteCred)

	// convert json byte data to verifiable credential
	cred2, err := NewCredential(byteCred)
	require.NoError(t, err)
	require.NotEmpty(t, cred2)

	// verify verifiable credentials created by NewCredential and JSON function matches
	require.Equal(t, vc, cred2)
}

func TestJSONConversionCompositeIssuer(t *testing.T) {
	// setup -> create verifiable credential from json byte data
	vc, err := NewCredential([]byte(validCredential))
	require.NoError(t, err)
	require.NotEmpty(t, vc)

	// clean issuer name - this means that we have only issuer id and thus it should be serialized
	// as plain issuer id
	vc.Issuer.Name = ""

	// convert verifiable credential to json byte data
	byteCred, err := vc.MarshalJSON()
	require.NoError(t, err)
	require.NotEmpty(t, byteCred)

	// convert json byte data to verifiable credential
	cred2, err := NewCredential(byteCred)
	require.NoError(t, err)
	require.NotEmpty(t, cred2)

	// verify verifiable credentials created by NewCredential and JSON function matches
	require.Equal(t, vc, cred2)
}

func TestWithHttpClient(t *testing.T) {
	client := &http.Client{}
	credentialOpt := WithSchemaDownloadClient(client)
	require.NotNil(t, credentialOpt)

	opts := &credentialOpts{}
	credentialOpt(opts)
	require.NotNil(t, opts.schemaDownloadClient)
}

func TestWithDisabledExternalSchemaCheck(t *testing.T) {
	credentialOpt := WithNoCustomSchemaCheck()
	require.NotNil(t, credentialOpt)

	opts := &credentialOpts{}
	credentialOpt(opts)
	require.True(t, opts.disabledCustomSchema)
}

func TestCustomCredentialJsonSchemaValidator2018(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		rawMap := make(map[string]interface{})
		require.NoError(t, json.Unmarshal([]byte(defaultSchema), &rawMap))

		// extend default schema to require new referenceNumber field to be mandatory
		required, success := rawMap["required"].([]interface{})
		require.True(t, success)
		required = append(required, "referenceNumber")
		rawMap["required"] = required

		bytes, err := json.Marshal(rawMap)
		require.NoError(t, err)

		res.WriteHeader(http.StatusOK)
		_, err = res.Write(bytes)
		require.NoError(t, err)
	}))
	defer func() { testServer.Close() }()

	var raw rawCredential
	require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))

	// define credential schema
	raw.Schema = &TypedID{ID: testServer.URL, Type: "JsonSchemaValidator2018"}
	// but new required field referenceNumber is not defined...

	missingReqFieldSchema, mErr := json.Marshal(raw)
	require.NoError(t, mErr)

	t.Run("Applies custom JSON Schema and detects data inconsistency due to missing new required field", func(t *testing.T) { //nolint:lll
		_, err := NewCredential(missingReqFieldSchema, WithSchemaDownloadClient(&http.Client{}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "referenceNumber is required")
	})

	t.Run("Applies custom credentialSchema and passes new data inconsistency check", func(t *testing.T) {
		raw := make(map[string]interface{})
		require.NoError(t, json.Unmarshal(missingReqFieldSchema, &raw))

		// define required field "referenceNumber"
		raw["referenceNumber"] = 83294847

		customValidSchema, err := json.Marshal(raw)
		require.NoError(t, err)

		vc, err := NewCredential(customValidSchema, WithSchemaDownloadClient(&http.Client{}))
		require.NoError(t, err)

		// check credential schema
		require.NotNil(t, vc.Schemas)
		require.Equal(t, vc.Schemas[0].ID, testServer.URL)
		require.Equal(t, vc.Schemas[0].Type, "JsonSchemaValidator2018")
	})

	t.Run("Error when failed to download custom credentialSchema", func(t *testing.T) {
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))

		// define credential schema with invalid port
		raw.Schema = &TypedID{ID: "http://localhost:0001", Type: "JsonSchemaValidator2018"}
		// but new required field referenceNumber is not defined...

		schemaWithInvalidURLToCredentialSchema, err := json.Marshal(raw)
		require.NoError(t, err)

		_, err = NewCredential(schemaWithInvalidURLToCredentialSchema, WithSchemaDownloadClient(&http.Client{}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "load of custom credential schema")
	})

	t.Run("Uses default schema if custom credentialSchema is not of 'JsonSchemaValidator2018' type", func(t *testing.T) { //nolint:lll
		raw := &rawCredential{}
		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))

		// define credential schema with not supported type
		raw.Schema = &TypedID{ID: testServer.URL, Type: "ZkpExampleSchema2018"}

		unsupportedCredentialTypeOfSchema, err := json.Marshal(raw)
		require.NoError(t, err)

		vc, err := NewCredential(unsupportedCredentialTypeOfSchema, WithSchemaDownloadClient(&http.Client{}))
		require.NoError(t, err)

		// check credential schema
		require.NotNil(t, vc.Schemas)
		require.Equal(t, vc.Schemas[0].ID, testServer.URL)
		require.Equal(t, vc.Schemas[0].Type, "ZkpExampleSchema2018")
	})

	t.Run("Fallback to default schema validation when custom schemas usage is disabled", func(t *testing.T) {
		_, err := NewCredential(missingReqFieldSchema,
			WithSchemaDownloadClient(&http.Client{}),
			WithNoCustomSchemaCheck())

		// without disabling external schema check we would get an error here
		require.NoError(t, err)
	})
}

func TestDownloadCustomSchema(t *testing.T) {
	t.Run("HTTP GET request to download custom credentialSchema successes", func(t *testing.T) {
		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			res.WriteHeader(http.StatusOK)
			_, err := res.Write([]byte("custom schema"))
			require.NoError(t, err)
		}))
		defer func() { testServer.Close() }()

		customSchema, err := loadCredentialSchema(testServer.URL, &http.Client{})
		require.NoError(t, err)
		require.Equal(t, []byte("custom schema"), customSchema)
	})

	t.Run("HTTP GET request to download custom credentialSchema fails", func(t *testing.T) {
		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			res.WriteHeader(http.StatusSeeOther)
		}))
		defer func() { testServer.Close() }()

		_, err := loadCredentialSchema(testServer.URL, &http.Client{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "load credential schema")
	})

	t.Run("HTTP GET request to download custom credentialSchema returns not OK", func(t *testing.T) {
		// HTTP GET failed
		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			res.WriteHeader(http.StatusNotFound)
		}))
		defer func() { testServer.Close() }()

		_, err := loadCredentialSchema(testServer.URL, &http.Client{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "credential schema endpoint HTTP failure")
	})
}

func TestDefaultCredentialOpts(t *testing.T) {
	opts := defaultCredentialOpts()
	require.NotNil(t, opts)
	require.NotNil(t, opts.schemaDownloadClient)
	require.False(t, opts.disabledCustomSchema)
	require.NotNil(t, opts.template)
	require.NotNil(t, opts.decoders)
}

func TestCredentialSubjectId(t *testing.T) {
	t.Run("With single Subject", func(t *testing.T) {
		vcWithSingleSubject := &Credential{Subject: map[string]interface{}{
			"id": "did:example:ebfeb1f712ebc6f1c276e12ecaa",
			"degree": map[string]interface{}{
				"type": "BachelorDegree",
				"name": "Bachelor of Science and Arts",
			},
		}}
		subjectID, err := vcWithSingleSubject.SubjectID()
		require.NoError(t, err)
		require.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ecaa", subjectID)
	})

	t.Run("With single Subject in array", func(t *testing.T) {
		vcWithSingleSubject := &Credential{Subject: []map[string]interface{}{{
			"id": "did:example:ebfeb1f712ebc6f1c276e12ecaa",
			"degree": map[string]interface{}{
				"type": "BachelorDegree",
				"name": "Bachelor of Science and Arts",
			},
		}}}
		subjectID, err := vcWithSingleSubject.SubjectID()
		require.NoError(t, err)
		require.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ecaa", subjectID)
	})

	t.Run("With multiple Subjects", func(t *testing.T) {
		vcWithMultipleSubjects := &Credential{
			Subject: []map[string]interface{}{
				{
					"id":     "did:example:ebfeb1f712ebc6f1c276e12ec21",
					"name":   "Jayden Doe",
					"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1",
				},
				{
					"id":     "did:example:c276e12ec21ebfeb1f712ebc6f1",
					"name":   "Morgan Doe",
					"spouse": "did:example:ebfeb1f712ebc6f1c276e12ec21",
				},
			}}
		_, err := vcWithMultipleSubjects.SubjectID()
		require.Error(t, err)
		require.EqualError(t, err, "more than one subject is defined")
	})

	t.Run("With no Subject", func(t *testing.T) {
		vcWithNoSubject := &Credential{
			Subject: nil,
		}
		_, err := vcWithNoSubject.SubjectID()
		require.Error(t, err)
		require.EqualError(t, err, "subject of unknown structure")
	})

	t.Run("With empty Subject", func(t *testing.T) {
		vcWithNoSubject := &Credential{
			Subject: []map[string]interface{}{},
		}
		_, err := vcWithNoSubject.SubjectID()
		require.Error(t, err)
		require.EqualError(t, err, "no subject is defined")
	})

	t.Run("With non-string Subject ID", func(t *testing.T) {
		vcWithNotStringID := &Credential{Subject: map[string]interface{}{
			"id": 55,
			"degree": map[string]interface{}{
				"type": "BachelorDegree",
				"name": "Bachelor of Science and Arts",
			},
		}}
		_, err := vcWithNotStringID.SubjectID()
		require.Error(t, err)
		require.EqualError(t, err, "subject id is not string")
	})

	t.Run("Subject without ID defined", func(t *testing.T) {
		vcWithSubjectWithoutID := &Credential{
			Subject: map[string]interface{}{
				"givenName":  "Jane",
				"familyName": "Doe",
				"degree": map[string]interface{}{
					"type":    "BachelorDegree",
					"name":    "Bachelor of Science in Mechanical Engineering",
					"college": "College of Engineering",
				},
			},
		}
		_, err := vcWithSubjectWithoutID.SubjectID()
		require.Error(t, err)
		require.EqualError(t, err, "subject id is not defined")
	})
}

func TestRawCredentialSerialization(t *testing.T) {
	cBytes := []byte(validCredential)

	rc := new(rawCredential)
	err := json.Unmarshal(cBytes, rc)
	require.NoError(t, err)
	rcBytes, err := json.Marshal(rc)
	require.NoError(t, err)

	var cMap map[string]interface{}
	err = json.Unmarshal(cBytes, &cMap)
	require.NoError(t, err)

	var rcMap map[string]interface{}
	err = json.Unmarshal(rcBytes, &rcMap)
	require.NoError(t, err)

	require.Equal(t, cMap, rcMap)
}

func TestDecodeType(t *testing.T) {
	t.Run("Decode single Verifiable Credential types", func(t *testing.T) {
		rc := &rawCredential{
			Type: "VerifiableCredential",
		}
		types, err := decodeType(rc)
		require.NoError(t, err)
		require.Equal(t, []string{"VerifiableCredential"}, types)
	})

	t.Run("Decode several Verifiable Credential types", func(t *testing.T) {
		rc := &rawCredential{
			Type: []interface{}{"VerifiableCredential", "UniversityDegreeCredential"},
		}

		types, err := decodeType(rc)
		require.NoError(t, err)
		require.Equal(t, []string{"VerifiableCredential", "UniversityDegreeCredential"}, types)
	})

	t.Run("Error on decoding of invalid Verifiable Credential type", func(t *testing.T) {
		rc := &rawCredential{
			Type: 77,
		}
		_, err := decodeType(rc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "credential type of unknown type")
	})

	t.Run("Error on decoding of invalid Verifiable Credential types", func(t *testing.T) {
		rc := &rawCredential{
			Type: []interface{}{"VerifiableCredential", 777},
		}
		_, err := decodeType(rc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "vc types: array element is not a string")
	})
}

func TestDecodeContext(t *testing.T) {
	t.Run("Decode single context", func(t *testing.T) {
		rc := &rawCredential{
			Context: "https://www.w3.org/2018/credentials/v1",
		}
		contexts, extraContexts, err := decodeContext(rc)
		require.NoError(t, err)
		require.Equal(t, []string{"https://www.w3.org/2018/credentials/v1"}, contexts)
		require.Empty(t, extraContexts)
	})

	t.Run("Decode several contexts", func(t *testing.T) {
		rc := &rawCredential{
			Context: []interface{}{
				"https://www.w3.org/2018/credentials/v1",
				"https://www.w3.org/2018/credentials/examples/v1",
			},
		}
		contexts, extraContexts, err := decodeContext(rc)
		require.NoError(t, err)
		require.Equal(t,
			[]string{"https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"},
			contexts)
		require.Empty(t, extraContexts)
	})

	t.Run("Decode several contexts with custom objects", func(t *testing.T) {
		customContext := map[string]interface{}{
			"image": map[string]interface{}{"@id": "schema:image", "@type": "@id"},
		}
		rc := &rawCredential{
			Context: []interface{}{
				"https://www.w3.org/2018/credentials/v1",
				"https://www.w3.org/2018/credentials/examples/v1",
				customContext,
			},
		}
		contexts, extraContexts, err := decodeContext(rc)
		require.NoError(t, err)
		require.Equal(t,
			[]string{"https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"},
			contexts)
		require.Equal(t, []interface{}{customContext}, extraContexts)
	})

	t.Run("Decode context of invalid type", func(t *testing.T) {
		rc := &rawCredential{
			Context: 55,
		}
		_, _, err := decodeContext(rc)
		require.Error(t, err)
	})
}

func TestDecodeIssuer(t *testing.T) {
	t.Run("Decode Issuer defined by ID only", func(t *testing.T) {
		rc := &rawCredential{
			Issuer: "did:example:76e12ec712ebc6f1c221ebfeb1f",
		}
		issuer, err := decodeIssuer(rc)
		require.NoError(t, err)
		require.Equal(t, "did:example:76e12ec712ebc6f1c221ebfeb1f", issuer.ID)
		require.Empty(t, issuer.Name)
	})

	t.Run("Decode Issuer identified by ID and name", func(t *testing.T) {
		rc := &rawCredential{
			Issuer: map[string]interface{}{
				"id":   "did:example:76e12ec712ebc6f1c221ebfeb1f",
				"name": "Example University",
			},
		}
		issuer, err := decodeIssuer(rc)
		require.NoError(t, err)
		require.Equal(t, "did:example:76e12ec712ebc6f1c221ebfeb1f", issuer.ID)
		require.Equal(t, "Example University", issuer.Name)
	})

	t.Run("Decode Issuer identified by ID and empty name", func(t *testing.T) {
		rc := &rawCredential{
			Issuer: map[string]interface{}{
				"id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
			},
		}
		issuer, err := decodeIssuer(rc)
		require.NoError(t, err)
		require.Equal(t, "did:example:76e12ec712ebc6f1c221ebfeb1f", issuer.ID)
		require.Empty(t, issuer.Name)
	})

	t.Run("Decode Issuer identified by empty ID and name", func(t *testing.T) {
		rc := &rawCredential{
			Issuer: map[string]interface{}{
				"name": "Example University",
			},
		}
		_, err := decodeIssuer(rc)
		require.Error(t, err)
		require.EqualError(t, err, "issuer ID is not defined")
	})

	t.Run("Decode Issuer with invalid type of ID", func(t *testing.T) {
		rc := &rawCredential{
			Issuer: map[string]interface{}{
				"id": 55,
			},
		}
		_, err := decodeIssuer(rc)
		require.Error(t, err)
		require.EqualError(t, err, "value of key 'id' is not a string")
	})

	t.Run("Decode Issuer with invalid type of name", func(t *testing.T) {
		rc := &rawCredential{
			Issuer: map[string]interface{}{
				"id":   "did:example:76e12ec712ebc6f1c221ebfeb1f",
				"name": 55,
			},
		}
		_, err := decodeIssuer(rc)
		require.Error(t, err)
		require.EqualError(t, err, "value of key 'name' is not a string")
	})

	t.Run("Decode Issuer of invalid type", func(t *testing.T) {
		rc := &rawCredential{
			Issuer: 77,
		}
		_, err := decodeIssuer(rc)
		require.Error(t, err)
		require.EqualError(t, err, "unsupported format of issuer")
	})
}

func TestTypesToSerialize(t *testing.T) {
	// single type
	require.Equal(t, "VerifiableCredential", typesToSerialize([]string{"VerifiableCredential"}))

	// several types
	require.Equal(t,
		[]string{"VerifiableCredential", "UniversityDegreeCredential"},
		typesToSerialize([]string{"VerifiableCredential", "UniversityDegreeCredential"}))
}

func TestContextToSerialize(t *testing.T) {
	// single context without custom objects
	require.Equal(t,
		"https://www.w3.org/2018/credentials/v1",
		contextToSerialize([]string{"https://www.w3.org/2018/credentials/v1"}, []interface{}{}))

	// several contexts without custom objects
	require.Equal(t, []string{
		"https://www.w3.org/2018/credentials/v1",
		"https://www.w3.org/2018/credentials/examples/v1"},
		contextToSerialize([]string{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1"},
			[]interface{}{}))

	// context with custom objects
	customContext := map[string]interface{}{
		"image": map[string]interface{}{"@id": "schema:image", "@type": "@id"},
	}
	require.Equal(t,
		[]interface{}{"https://www.w3.org/2018/credentials/v1", customContext},
		contextToSerialize([]string{"https://www.w3.org/2018/credentials/v1"},
			[]interface{}{
				customContext,
			}))
}
