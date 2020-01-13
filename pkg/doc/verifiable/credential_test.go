/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/piprate/json-gold/ld"
	"github.com/xeipuuv/gojsonschema"

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
		vc, vcData, err := NewCredential([]byte(validCredential))
		require.NoError(t, err)
		require.NotNil(t, vc)
		require.NotEmpty(t, vcData)

		// validate @context
		require.Equal(t, []string{"https://www.w3.org/2018/credentials/v1"}, vc.Context)

		// validate id
		require.Equal(t, "http://example.edu/credentials/1872", vc.ID)

		// validate type
		require.Equal(t, []string{"VerifiableCredential"}, vc.Types)

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
		require.Equal(t, "https://example.edu/refresh/3732", vc.RefreshService[0].ID)
		require.Equal(t, "ManualRefreshService2018", vc.RefreshService[0].Type)

		require.NotNil(t, vc.Evidence)

		require.NotNil(t, vc.TermsOfUse)
		require.Len(t, vc.TermsOfUse, 1)
	})

	t.Run("test a try to create a new Verifiable Credential from JSON with invalid structure", func(t *testing.T) {
		emptyJSONDoc := "{}"
		vc, vcBytes, err := NewCredential([]byte(emptyJSONDoc))
		require.Error(t, err)
		require.Contains(t, err.Error(), "credential type of unknown structure")
		require.Nil(t, vc)
		require.Nil(t, vcBytes)
	})

	t.Run("test a try to create a new Verifiable Credential from non-JSON doc", func(t *testing.T) {
		vc, vcBytes, err := NewCredential([]byte("non json"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "new credential")
		require.Nil(t, vc)
		require.Nil(t, vcBytes)
	})
}

func TestValidateVerCredContext(t *testing.T) {
	t.Run("test verifiable credential with a single context", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Context = "https://www.w3.org/2018/credentials/v1"
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with a single invalid context", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Context = "https://www.w3.org/2018/credentials/v2"
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "@context: @context does not match: \"https://www.w3.org/2018/credentials/v1\"")
	})

	t.Run("test verifiable credential with empty context", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Context = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "@context is required")
	})

	t.Run("test verifiable credential with multiple contexts", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Context = []interface{}{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with multiple invalid contexts", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Context = []interface{}{
			"https://www.w3.org/2018/credentials/v2",
			"https://www.w3.org/2018/credentials/examples/v1"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "@context.0: @context.0 does not match: \"https://www.w3.org/2018/credentials/v1\"")
	})

	t.Run("test verifiable credential with object context", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Context = []interface{}{"https://www.w3.org/2018/credentials/examples/v1", map[string]interface{}{
			"image": map[string]string{
				"@id": "schema:image", "@type": "@id",
			},
		}}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "@context.0: @context.0 does not match: \"https://www.w3.org/2018/credentials/v1\"")
	})
}

func TestValidateVerCredID(t *testing.T) {
	raw := rawCredential{}

	require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
	raw.ID = "not valid credential ID URL"
	bytes, err := json.Marshal(raw)
	require.NoError(t, err)
	err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "id: Does not match format 'uri'")
}

func TestValidateVerCredType(t *testing.T) {
	t.Run("test verifiable credential with no type", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Type = []string{}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "Array must have at least 2 items")
	})

	t.Run("test verifiable credential with not first VerifiableCredential type", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Type = []string{"NotVerifiableCredential"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "Does not match pattern '^VerifiableCredential$")
	})

	t.Run("test verifiable credential with VerifiableCredential type only", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Type = []string{"VerifiableCredential"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "Array must have at least 2 items")
	})

	t.Run("test verifiable credential with VerifiableCredential type only as string", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Type = "VerifiableCredential"
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.NoError(t, err)
	})
}

func TestValidateVerCredCredentialSubject(t *testing.T) {
	t.Run("test verifiable credential with no credential subject", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Subject = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "credentialSubject is required")
	})

	t.Run("test verifiable credential with single credential subject", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		require.NoError(t, json.Unmarshal([]byte(singleCredentialSubject), &raw.Subject))
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with several credential subjects", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		require.NoError(t, json.Unmarshal([]byte(multipleCredentialSubjects), &raw.Subject))
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with invalid type of credential subject", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Subject = 55
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "credentialSubject: Invalid type.")
	})
}

func TestValidateVerCredIssuer(t *testing.T) {
	t.Run("test verifiable credential with no issuer", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Issuer = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "issuer is required")
	})

	t.Run("test verifiable credential with plain id issuer", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Issuer = "https://example.edu/issuers/14"
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with issuer as an object", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		require.NoError(t, json.Unmarshal([]byte(issuerAsObject), &raw.Issuer))
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with invalid type of issuer", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Issuer = 55
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "issuer: Invalid type")
	})
}

func TestValidateVerCredIssuanceDate(t *testing.T) {
	t.Run("test verifiable credential with empty issuance date", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Issued = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "issuanceDate is required")
	})

	t.Run("test verifiable credential with wrong format of issuance date", func(t *testing.T) {
		var vcMap map[string]interface{}

		require.NoError(t, json.Unmarshal([]byte(validCredential), &vcMap))
		vcMap["issuanceDate"] = "not a valid date time"
		bytes, err := json.Marshal(vcMap)
		require.NoError(t, err)

		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "issuanceDate: Does not match format 'date-time'")
	})

	for _, timeStr := range []string{"2010-01-01T19:23:24Z", "2010-01-01T19:23:24.385Z"} {
		var vcMap map[string]interface{}

		require.NoError(t, json.Unmarshal([]byte(validCredential), &vcMap))
		vcMap["issuanceDate"] = timeStr
		bytes, err := json.Marshal(vcMap)
		require.NoError(t, err)

		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.NoError(t, err)
	}
}

func TestValidateVerCredProof(t *testing.T) {
	t.Run("test verifiable credential with empty proof", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Proof = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.NoError(t, err)
	})
}

func TestValidateVerCredExpirationDate(t *testing.T) {
	t.Run("test verifiable credential with empty expiration date", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Expired = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with wrong format of expiration date", func(t *testing.T) {
		var vcMap map[string]interface{}

		require.NoError(t, json.Unmarshal([]byte(validCredential), &vcMap))
		vcMap["expirationDate"] = "not a valid date time"
		bytes, err := json.Marshal(vcMap)
		require.NoError(t, err)

		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "expirationDate: Does not match format 'date-time'")
	})

	for _, timeStr := range []string{"2010-01-01T19:23:24Z", "2010-01-01T19:23:24.385Z"} {
		var vcMap map[string]interface{}

		require.NoError(t, json.Unmarshal([]byte(validCredential), &vcMap))
		vcMap["expirationDate"] = timeStr
		bytes, err := json.Marshal(vcMap)
		require.NoError(t, err)

		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.NoError(t, err)
	}
}

func TestValidateVerCredStatus(t *testing.T) {
	t.Run("test verifiable credential with empty credential status", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Status = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with undefined id of credential status", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Status = &TypedID{Type: "CredentialStatusList2017"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "credentialStatus: id is required")
	})

	t.Run("test verifiable credential with undefined type of credential status", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Status = &TypedID{ID: "https://example.edu/status/24"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "credentialStatus: type is required")
	})

	t.Run("test verifiable credential with invalid URL of id of credential status", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Status = &TypedID{ID: "invalid URL", Type: "CredentialStatusList2017"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "credentialStatus.id: Does not match format 'uri'")
	})
}

func TestValidateVerCredSchema(t *testing.T) {
	t.Run("test verifiable credential with empty credential schema", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Schema = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with undefined id of credential schema", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Schema = &TypedID{Type: "JsonSchemaValidator2018"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "credentialSchema: id is required")
	})

	t.Run("test verifiable credential with undefined type of credential schema", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Schema = &TypedID{ID: "https://example.org/examples/degree.json"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "credentialSchema: type is required")
	})

	t.Run("test verifiable credential with invalid URL of id of credential schema", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.Schema = &TypedID{ID: "invalid URL", Type: "JsonSchemaValidator2018"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "credentialSchema.id: Does not match format 'uri'")
	})
}

func TestValidateVerCredRefreshService(t *testing.T) {
	t.Run("test verifiable credential with empty refresh service", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))
		raw.RefreshService = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.NoError(t, err)
	})

	t.Run("test verifiable credential with undefined id of refresh service", func(t *testing.T) {
		vc, _, err := NewCredential([]byte(validCredential))
		require.NoError(t, err)

		vc.RefreshService = []TypedID{{Type: "ManualRefreshService2018"}}
		bytes, err := json.Marshal(vc)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "refreshService: id is required")
	})

	t.Run("test verifiable credential with undefined type of refresh service", func(t *testing.T) {
		vc, _, err := NewCredential([]byte(validCredential))
		require.NoError(t, err)

		vc.RefreshService = []TypedID{{ID: "https://example.edu/refresh/3732"}}
		bytes, err := json.Marshal(vc)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "refreshService: type is required")
	})

	t.Run("test verifiable credential with invalid URL of id of credential schema", func(t *testing.T) {
		vc, _, err := NewCredential([]byte(validCredential))
		require.NoError(t, err)

		vc.RefreshService = []TypedID{{ID: "invalid URL", Type: "ManualRefreshService2018"}}
		bytes, err := json.Marshal(vc)
		require.NoError(t, err)
		err = validateCredentialUsingJSONSchema(bytes, nil, &credentialOpts{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "refreshService.id: Does not match format 'uri'")
	})
}

func TestCredential_MarshalJSON(t *testing.T) {
	t.Run("round trip conversion of credential with plain issuer", func(t *testing.T) {
		// setup -> create verifiable credential from json byte data
		vc, _, err := NewCredential([]byte(validCredential))
		require.NoError(t, err)
		require.NotEmpty(t, vc)

		// convert verifiable credential to json byte data
		byteCred, err := vc.MarshalJSON()
		require.NoError(t, err)
		require.NotEmpty(t, byteCred)

		// convert json byte data to verifiable credential
		cred2, _, err := NewCredential(byteCred)
		require.NoError(t, err)
		require.NotEmpty(t, cred2)

		// verify verifiable credentials created by NewCredential and JSON function matches
		require.Equal(t, vc.stringJSON(t), cred2.stringJSON(t))
	})

	t.Run("round trip conversion of credential with composite issuer", func(t *testing.T) {
		// setup -> create verifiable credential from json byte data
		vc, _, err := NewCredential([]byte(validCredential))
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
		cred2, _, err := NewCredential(byteCred)
		require.NoError(t, err)
		require.NotEmpty(t, cred2)

		// verify verifiable credentials created by NewCredential and JSON function matches
		require.Equal(t, vc.stringJSON(t), cred2.stringJSON(t))
	})

	t.Run("Failure in VC marshalling", func(t *testing.T) {
		vc, _, err := NewCredential([]byte(validCredential))
		require.NoError(t, err)

		vc.CustomFields = map[string]interface{}{
			"invalid field": make(chan int),
		}

		bytes, err := vc.MarshalJSON()
		require.Error(t, err)
		require.Nil(t, bytes)

		vc.CustomFields = map[string]interface{}{}
		vc.TermsOfUse = []TypedID{{CustomFields: map[string]interface{}{
			"invalidField": make(chan int),
		}}}

		bytes, err = vc.MarshalJSON()
		require.Error(t, err)
		require.Nil(t, bytes)
	})
}

func TestWithDisabledExternalSchemaCheck(t *testing.T) {
	credentialOpt := WithNoCustomSchemaCheck()
	require.NotNil(t, credentialOpt)

	opts := &credentialOpts{}
	credentialOpt(opts)
	require.True(t, opts.disabledCustomSchema)
}

func TestWithCredentialSchemaLoader(t *testing.T) {
	httpClient := &http.Client{}
	jsonSchemaLoader := gojsonschema.NewStringLoader(defaultSchema)
	cache := NewExpirableSchemaCache(100, 10*time.Minute)

	credentialOpt := WithCredentialSchemaLoader(
		NewCredentialSchemaLoaderBuilder().
			SetSchemaDownloadClient(httpClient).
			SetCache(cache).
			SetJSONLoader(jsonSchemaLoader).
			Build())
	require.NotNil(t, credentialOpt)

	opts := &credentialOpts{}
	credentialOpt(opts)
	require.NotNil(t, opts.schemaLoader)
	require.Equal(t, httpClient, opts.schemaLoader.schemaDownloadClient)
	require.Equal(t, jsonSchemaLoader, opts.schemaLoader.jsonLoader)
	require.Equal(t, cache, opts.schemaLoader.cache)

	// check that defaults are applied

	credentialOpt = WithCredentialSchemaLoader(
		NewCredentialSchemaLoaderBuilder().Build())
	require.NotNil(t, credentialOpt)

	opts = &credentialOpts{}
	credentialOpt(opts)
	require.NotNil(t, opts.schemaLoader)
	require.NotNil(t, opts.schemaLoader.schemaDownloadClient)
	require.NotNil(t, opts.schemaLoader.jsonLoader)
	require.Nil(t, opts.schemaLoader.cache)
}

func TestWithJSONLDValidation(t *testing.T) {
	credentialOpt := WithJSONLDValidation()
	require.NotNil(t, credentialOpt)

	opts := &credentialOpts{}
	credentialOpt(opts)
	require.Equal(t, jsonldValidation, opts.modelValidationMode)
	require.Empty(t, opts.allowedCustomContexts)
	require.Empty(t, opts.allowedCustomTypes)
}

func TestWithBaseContextValidation(t *testing.T) {
	credentialOpt := WithBaseContextValidation()
	require.NotNil(t, credentialOpt)

	opts := &credentialOpts{}
	credentialOpt(opts)
	require.Equal(t, baseContextValidation, opts.modelValidationMode)
	require.Empty(t, opts.allowedCustomContexts)
	require.Empty(t, opts.allowedCustomTypes)
}

func TestWithBaseContextExtendedValidation(t *testing.T) {
	credentialOpt := WithBaseContextExtendedValidation(
		[]string{"https://www.w3.org/2018/credentials/examples/v1"},
		[]string{"UniversityDegreeCredential", "AlumniCredential"})
	require.NotNil(t, credentialOpt)

	opts := &credentialOpts{}
	credentialOpt(opts)
	require.Equal(t, baseContextExtendedValidation, opts.modelValidationMode)

	require.Equal(t, map[string]bool{
		"https://www.w3.org/2018/credentials/v1":          true,
		"https://www.w3.org/2018/credentials/examples/v1": true},
		opts.allowedCustomContexts)

	require.Equal(t, map[string]bool{
		"VerifiableCredential":       true,
		"UniversityDegreeCredential": true,
		"AlumniCredential":           true},
		opts.allowedCustomTypes)
}

func TestWithJSONLDDocumentLoader(t *testing.T) {
	documentLoader := ld.NewDefaultDocumentLoader(nil)
	credentialOpt := WithJSONLDDocumentLoader(documentLoader)
	require.NotNil(t, credentialOpt)

	opts := &credentialOpts{}
	credentialOpt(opts)
	require.Equal(t, documentLoader, opts.jsonldDocumentLoader)
}

func TestWithStrictValidation(t *testing.T) {
	credentialOpt := WithStrictValidation()
	require.NotNil(t, credentialOpt)

	opts := &credentialOpts{}
	credentialOpt(opts)
	require.True(t, opts.strictValidation)
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
	err := json.Unmarshal([]byte(validCredential), &raw)
	require.NoError(t, err)

	// define credential schema
	raw.Schema = &TypedID{ID: testServer.URL, Type: "JsonSchemaValidator2018"}
	// but new required field referenceNumber is not defined...

	missingReqFieldSchema, mErr := json.Marshal(raw)
	require.NoError(t, mErr)

	t.Run("Applies custom JSON Schema and detects data inconsistency due to missing new required field", func(t *testing.T) { //nolint:lll
		vc, vcBytes, err := NewCredential(missingReqFieldSchema)
		require.Error(t, err)
		require.Contains(t, err.Error(), "referenceNumber is required")
		require.Nil(t, vc)
		require.Nil(t, vcBytes)
	})

	t.Run("Applies custom credentialSchema and passes new data inconsistency check", func(t *testing.T) {
		raw := make(map[string]interface{})
		require.NoError(t, json.Unmarshal(missingReqFieldSchema, &raw))

		// define required field "referenceNumber"
		raw["referenceNumber"] = 83294847

		customValidSchema, err := json.Marshal(raw)
		require.NoError(t, err)

		vc, _, err := NewCredential(customValidSchema, WithBaseContextExtendedValidation([]string{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1",
		}, []string{
			"VerifiableCredential",
			"UniversityDegreeCredential",
		}))
		require.NoError(t, err)

		// check credential schema
		require.NotNil(t, vc.Schemas)
		require.Equal(t, vc.Schemas[0].ID, testServer.URL)
		require.Equal(t, vc.Schemas[0].Type, "JsonSchemaValidator2018")
	})

	t.Run("Error when failed to download custom credentialSchema", func(t *testing.T) {
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))

		// define credential schema with invalid port
		raw.Schema = &TypedID{ID: "http://localhost:0001", Type: "JsonSchemaValidator2018"}
		// but new required field referenceNumber is not defined...

		schemaWithInvalidURLToCredentialSchema, err := json.Marshal(raw)
		require.NoError(t, err)

		vc, vcBytes, err := NewCredential(schemaWithInvalidURLToCredentialSchema)
		require.Error(t, err)
		require.Contains(t, err.Error(), "load of custom credential schema")
		require.Nil(t, vc)
		require.Nil(t, vcBytes)
	})

	t.Run("Uses default schema if custom credentialSchema is not of 'JsonSchemaValidator2018' type", func(t *testing.T) { //nolint:lll
		var raw rawCredential

		require.NoError(t, json.Unmarshal([]byte(validCredential), &raw))

		// define credential schema with not supported type
		raw.Schema = &TypedID{ID: testServer.URL, Type: "ZkpExampleSchema2018"}

		unsupportedCredentialTypeOfSchema, err := json.Marshal(raw)
		require.NoError(t, err)

		vc, _, err := NewCredential(unsupportedCredentialTypeOfSchema)
		require.NoError(t, err)

		// check credential schema
		require.NotNil(t, vc.Schemas)
		require.Equal(t, vc.Schemas[0].ID, testServer.URL)
		require.Equal(t, vc.Schemas[0].Type, "ZkpExampleSchema2018")
	})

	t.Run("Fallback to default schema validation when custom schemas usage is disabled", func(t *testing.T) {
		_, _, err := NewCredential(missingReqFieldSchema, WithNoCustomSchemaCheck())

		// without disabling external schema check we would get an error here
		require.NoError(t, err)
	})
}

func TestDownloadCustomSchema(t *testing.T) {
	t.Parallel()

	httpClient := &http.Client{}

	noCacheOpts := &credentialOpts{schemaLoader: newDefaultSchemaLoader()}
	withCacheOpts := &credentialOpts{schemaLoader: &CredentialSchemaLoader{
		schemaDownloadClient: httpClient,
		jsonLoader:           gojsonschema.NewStringLoader(defaultSchema),
		cache:                NewExpirableSchemaCache(32*1024*1024, time.Hour),
	}}

	t.Run("HTTP GET request to download custom credentialSchema successes", func(t *testing.T) {
		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			res.WriteHeader(http.StatusOK)
			_, err := res.Write([]byte("custom schema"))
			require.NoError(t, err)
		}))

		defer func() { testServer.Close() }()

		customSchema, err := getJSONSchema(testServer.URL, noCacheOpts)
		require.NoError(t, err)
		require.Equal(t, []byte("custom schema"), customSchema)
	})

	t.Run("Check custom schema caching", func(t *testing.T) {
		loadsCount := 0
		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			res.WriteHeader(http.StatusOK)
			_, err := res.Write([]byte("custom schema"))
			require.NoError(t, err)
			loadsCount++
		}))

		defer func() { testServer.Close() }()

		customSchema, err := getJSONSchema(testServer.URL, withCacheOpts)
		require.NoError(t, err)
		require.Equal(t, []byte("custom schema"), customSchema)

		// Check that schema was downloaded only once - i.e. the cache was used second time
		customSchema2, err := getJSONSchema(testServer.URL, withCacheOpts)
		require.NoError(t, err)
		require.Equal(t, []byte("custom schema"), customSchema2)
		require.Equal(t, 1, loadsCount)

		// Check for cache expiration.
		withCacheOpts = &credentialOpts{schemaLoader: &CredentialSchemaLoader{
			schemaDownloadClient: httpClient,
			jsonLoader:           gojsonschema.NewStringLoader(defaultSchema),
			cache:                NewExpirableSchemaCache(32*1024*1024, time.Second),
		}}
		loadsCount = 0
		customSchema4, err := getJSONSchema(testServer.URL, withCacheOpts)
		require.NoError(t, err)
		require.Equal(t, []byte("custom schema"), customSchema4)

		time.Sleep(2 * time.Second)
		customSchema5, err := getJSONSchema(testServer.URL, withCacheOpts)
		require.NoError(t, err)
		require.Equal(t, []byte("custom schema"), customSchema5)
		require.Equal(t, 2, loadsCount)
	})

	t.Run("HTTP GET request to download custom credentialSchema fails", func(t *testing.T) {
		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			res.WriteHeader(http.StatusSeeOther)
		}))

		defer func() { testServer.Close() }()

		customSchema, err := getJSONSchema(testServer.URL, noCacheOpts)
		require.Error(t, err)
		require.Contains(t, err.Error(), "load credential schema")
		require.Nil(t, customSchema)
	})

	t.Run("HTTP GET request to download custom credentialSchema returns not OK", func(t *testing.T) {
		// HTTP GET failed
		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			res.WriteHeader(http.StatusNotFound)
		}))

		defer func() { testServer.Close() }()

		customSchema, err := getJSONSchema(testServer.URL, withCacheOpts)
		require.Error(t, err)
		require.Contains(t, err.Error(), "credential schema endpoint HTTP failure")
		require.Nil(t, customSchema)
	})
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
		subjectID, err := subjectID(vcWithSingleSubject.Subject)
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
		subjectID, err := subjectID(vcWithSingleSubject.Subject)
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
		subjectID, err := subjectID(vcWithMultipleSubjects.Subject)
		require.Error(t, err)
		require.EqualError(t, err, "more than one subject is defined")
		require.Empty(t, subjectID)
	})

	t.Run("With no Subject", func(t *testing.T) {
		vcWithNoSubject := &Credential{
			Subject: nil,
		}
		subjectID, err := subjectID(vcWithNoSubject.Subject)
		require.Error(t, err)
		require.EqualError(t, err, "subject id is not defined")
		require.Empty(t, subjectID)
	})

	t.Run("With empty Subject", func(t *testing.T) {
		vcWithNoSubject := &Credential{
			Subject: []map[string]interface{}{},
		}
		subjectID, err := subjectID(vcWithNoSubject.Subject)
		require.Error(t, err)
		require.EqualError(t, err, "no subject is defined")
		require.Empty(t, subjectID)
	})

	t.Run("With non-string Subject ID", func(t *testing.T) {
		vcWithNotStringID := &Credential{Subject: map[string]interface{}{
			"id": 55,
			"degree": map[string]interface{}{
				"type": "BachelorDegree",
				"name": "Bachelor of Science and Arts",
			},
		}}
		subjectID, err := subjectID(vcWithNotStringID.Subject)
		require.Error(t, err)
		require.EqualError(t, err, "subject id is not string")
		require.Empty(t, subjectID)
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
		subjectID, err := subjectID(vcWithSubjectWithoutID.Subject)
		require.Error(t, err)
		require.EqualError(t, err, "subject id is not defined")
		require.Empty(t, subjectID)
	})

	t.Run("Get subject id from custom structure", func(t *testing.T) {
		type UniversityDegree struct {
			Type       string `json:"type,omitempty"`
			University string `json:"university,omitempty"`
		}

		type UniversityDegreeSubject struct {
			ID     string           `json:"id,omitempty"`
			Name   string           `json:"name,omitempty"`
			Spouse string           `json:"spouse,omitempty"`
			Degree UniversityDegree `json:"degree,omitempty"`
		}

		vcWithSubjectWithoutID := &Credential{
			Subject: UniversityDegreeSubject{
				ID:     "did:example:ebfeb1f712ebc6f1c276e12ec21",
				Name:   "Jayden Doe",
				Spouse: "did:example:c276e12ec21ebfeb1f712ebc6f1",
				Degree: UniversityDegree{
					Type:       "BachelorDegree",
					University: "MIT",
				},
			},
		}
		subjectID, err := subjectID(vcWithSubjectWithoutID.Subject)
		require.NoError(t, err)
		require.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", subjectID)
	})

	t.Run("Get subject id from unmarshalable structure", func(t *testing.T) {
		subjectID, err := subjectID(make(chan int))
		require.Error(t, err)
		require.EqualError(t, err, "subject of unknown structure")
		require.Empty(t, subjectID)
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

func TestDecodeIssuer(t *testing.T) {
	t.Run("Decode Issuer defined by ID only", func(t *testing.T) {
		issuer, err := decodeIssuer("did:example:76e12ec712ebc6f1c221ebfeb1f")
		require.NoError(t, err)
		require.Equal(t, "did:example:76e12ec712ebc6f1c221ebfeb1f", issuer.ID)
		require.Empty(t, issuer.Name)
	})

	t.Run("Decode Issuer identified by ID and name", func(t *testing.T) {
		issuer, err := decodeIssuer(map[string]interface{}{
			"id":   "did:example:76e12ec712ebc6f1c221ebfeb1f",
			"name": "Example University",
		})
		require.NoError(t, err)
		require.Equal(t, "did:example:76e12ec712ebc6f1c221ebfeb1f", issuer.ID)
		require.Equal(t, "Example University", issuer.Name)
	})

	t.Run("Decode Issuer identified by ID and empty name", func(t *testing.T) {
		issuer, err := decodeIssuer(map[string]interface{}{
			"id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
		})
		require.NoError(t, err)
		require.Equal(t, "did:example:76e12ec712ebc6f1c221ebfeb1f", issuer.ID)
		require.Empty(t, issuer.Name)
	})

	t.Run("Decode Issuer identified by empty ID and name", func(t *testing.T) {
		issuerID, err := decodeIssuer(map[string]interface{}{
			"name": "Example University",
		})
		require.Error(t, err)
		require.EqualError(t, err, "issuer ID is not defined")
		require.Empty(t, issuerID)
	})

	t.Run("Decode Issuer with invalid type of ID", func(t *testing.T) {
		issuerID, err := decodeIssuer(map[string]interface{}{
			"id": 55,
		})
		require.Error(t, err)
		require.EqualError(t, err, "value of key 'id' is not a string")
		require.Empty(t, issuerID)
	})

	t.Run("Decode Issuer with invalid type of name", func(t *testing.T) {
		issuerID, err := decodeIssuer(map[string]interface{}{
			"id":   "did:example:76e12ec712ebc6f1c221ebfeb1f",
			"name": 55,
		})
		require.Error(t, err)
		require.EqualError(t, err, "value of key 'name' is not a string")
		require.Empty(t, issuerID)
	})

	t.Run("Decode Issuer of invalid type", func(t *testing.T) {
		issuerID, err := decodeIssuer(77)
		require.Error(t, err)
		require.EqualError(t, err, "unsupported format of issuer")
		require.Empty(t, issuerID)
	})
}

func TestTypesToSerialize(t *testing.T) {
	// single type
	require.Equal(t, "VerifiableCredential", typesToRaw([]string{"VerifiableCredential"}))

	// several types
	require.Equal(t,
		[]string{"VerifiableCredential", "UniversityDegreeCredential"},
		typesToRaw([]string{"VerifiableCredential", "UniversityDegreeCredential"}))
}

func TestContextToSerialize(t *testing.T) {
	// single context without custom objects
	require.Equal(t,
		[]string{"https://www.w3.org/2018/credentials/v1"},
		contextToRaw([]string{"https://www.w3.org/2018/credentials/v1"}, []interface{}{}))

	// several contexts without custom objects
	require.Equal(t, []string{
		"https://www.w3.org/2018/credentials/v1",
		"https://www.w3.org/2018/credentials/examples/v1"},
		contextToRaw([]string{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1"},
			[]interface{}{}))

	// context with custom objects
	customContext := map[string]interface{}{
		"image": map[string]interface{}{"@id": "schema:image", "@type": "@id"},
	}
	require.Equal(t,
		[]interface{}{"https://www.w3.org/2018/credentials/v1", customContext},
		contextToRaw([]string{"https://www.w3.org/2018/credentials/v1"},
			[]interface{}{
				customContext,
			}))
}

func TestNewCredentialFromRaw(t *testing.T) {
	vc, err := newCredential(&rawCredential{
		Schema:  44,
		Type:    "VerifiableCredential",
		Issuer:  "did:example:76e12ec712ebc6f1c221ebfeb1f",
		Context: "https://www.w3.org/2018/credentials/v1",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "fill credential schemas from raw")
	require.Nil(t, vc)

	vc, err = newCredential(&rawCredential{
		Type:    5,
		Issuer:  "did:example:76e12ec712ebc6f1c221ebfeb1f",
		Context: "https://www.w3.org/2018/credentials/v1",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "fill credential types from raw")
	require.Nil(t, vc)

	vc, err = newCredential(&rawCredential{
		Type:    "VerifiableCredential",
		Issuer:  5,
		Context: "https://www.w3.org/2018/credentials/v1",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "fill credential issuer from raw")
	require.Nil(t, vc)

	vc, err = newCredential(&rawCredential{
		Type:    "VerifiableCredential",
		Issuer:  "did:example:76e12ec712ebc6f1c221ebfeb1f",
		Context: 5, // invalid context
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "fill credential context from raw")
	require.Nil(t, vc)

	vc, err = newCredential(&rawCredential{
		Type:       "VerifiableCredential",
		Issuer:     "did:example:76e12ec712ebc6f1c221ebfeb1f",
		Context:    "https://www.w3.org/2018/credentials/v1",
		TermsOfUse: []byte("not json"),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "fill credential terms of use from raw")
	require.Nil(t, vc)

	vc, err = newCredential(&rawCredential{
		Type:           "VerifiableCredential",
		Issuer:         "did:example:76e12ec712ebc6f1c221ebfeb1f",
		Context:        "https://www.w3.org/2018/credentials/v1",
		RefreshService: []byte("not json"),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "fill credential refresh service from raw")
	require.Nil(t, vc)
}

func TestCredential_CreatePresentation(t *testing.T) {
	vc, _, err := NewCredential([]byte(validCredential))
	require.NoError(t, err)

	vp, err := vc.Presentation()
	require.NoError(t, err)

	require.Equal(t, []interface{}{vc}, vp.Credentials())
	require.Equal(t, []string{"VerifiablePresentation"}, vp.Type)
	require.Equal(t, vc.Context, vp.Context)
}

func TestCredential_validateCredential(t *testing.T) {
	t.Parallel()

	r := require.New(t)

	t.Run("test jsonldValidation constraint", func(t *testing.T) {
		vc, _, err := NewCredential([]byte(validCredential))
		require.NoError(t, err)

		vcOpts := &credentialOpts{
			modelValidationMode:  jsonldValidation,
			jsonldDocumentLoader: ld.NewDefaultDocumentLoader(nil),
			strictValidation:     true,
		}

		r.NoError(validateCredential(vc, vc.byteJSON(t), vcOpts))

		// add a field which is not defined in the schema
		vc.CustomFields = map[string]interface{}{
			"referenceNumber": 83294847,
		}
		r.Error(validateCredential(&Credential{}, vc.byteJSON(t), vcOpts))
	})

	t.Run("test baseContextValidation constraint", func(t *testing.T) {
		vc, _, err := NewCredential([]byte(validCredential))
		require.NoError(t, err)

		vc.Types = []string{"VerifiableCredential"}
		vc.Context = []string{"https://www.w3.org/2018/credentials/v1"}
		r.NoError(validateCredential(
			vc, vc.byteJSON(t),
			&credentialOpts{modelValidationMode: baseContextValidation}))

		vc.Types = []string{"VerifiableCredential", "UniversityDegreeCredential"}
		vc.Context = []string{"https://www.w3.org/2018/credentials/v1"}
		err = validateCredential(
			vc, vc.byteJSON(t),
			&credentialOpts{modelValidationMode: baseContextValidation})
		r.Error(err)
		r.EqualError(err, "violated type constraint: not base only type defined")

		vc.Types = []string{"UniversityDegreeCredential"}
		vc.Context = []string{"https://www.w3.org/2018/credentials/v1"}
		err = validateCredential(
			vc, vc.byteJSON(t),
			&credentialOpts{modelValidationMode: baseContextValidation})
		r.Error(err)
		r.EqualError(err, "violated type constraint: not base only type defined")

		vc.Types = []string{"VerifiableCredential"}
		vc.Context = []string{"https://www.w3.org/2018/credentials/v1", "https://www.exaple.org/udc/v1"}
		err = validateCredential(
			vc, vc.byteJSON(t),
			&credentialOpts{modelValidationMode: baseContextValidation})
		r.Error(err)
		r.EqualError(err, "violated @context constraint: not base only @context defined")

		vc.Types = []string{"VerifiableCredential"}
		vc.Context = []string{"https://www.exaple.org/udc/v1"}
		err = validateCredential(
			vc, vc.byteJSON(t),
			&credentialOpts{modelValidationMode: baseContextValidation})
		r.Error(err)
		r.EqualError(err, "violated @context constraint: not base only @context defined")
	})

	t.Run("test baseContextExtendedValidation constraint", func(t *testing.T) {
		vc, _, err := NewCredential([]byte(validCredential))
		require.NoError(t, err)

		vc.Types = []string{"VerifiableCredential", "AlumniCredential"}
		vc.Context = []string{"https://www.w3.org/2018/credentials/v1", "https://www.exaple.org/alumni/v1"}
		r.NoError(validateCredential(
			vc, vc.byteJSON(t),
			&credentialOpts{
				modelValidationMode: baseContextExtendedValidation,
				allowedCustomTypes: map[string]bool{
					"VerifiableCredential": true,
					"AlumniCredential":     true},
				allowedCustomContexts: map[string]bool{
					"https://www.w3.org/2018/credentials/v1": true,
					"https://www.exaple.org/alumni/v1":       true},
			}))

		vc.Types = []string{"VerifiableCredential", "UniversityDegreeCredential"}
		vc.Context = []string{"https://www.w3.org/2018/credentials/v1", "https://www.exaple.org/alumni/v1"}
		err = validateCredential(
			vc, vc.byteJSON(t),
			&credentialOpts{
				modelValidationMode: baseContextExtendedValidation,
				allowedCustomTypes: map[string]bool{
					"VerifiableCredential": true,
					"AlumniCredential":     true},
				allowedCustomContexts: map[string]bool{
					"https://www.w3.org/2018/credentials/v1": true,
					"https://www.exaple.org/alumni/v1":       true},
			})
		r.Error(err)
		r.EqualError(err, "not allowed type: UniversityDegreeCredential")

		vc.Types = []string{"VerifiableCredential", "AlumniCredential"}
		vc.Context = []string{"https://www.w3.org/2018/credentials/v1", "https://www.exaple.org/udc/v1"}
		err = validateCredential(
			vc, vc.byteJSON(t),
			&credentialOpts{
				modelValidationMode: baseContextExtendedValidation,
				allowedCustomTypes: map[string]bool{
					"VerifiableCredential": true,
					"AlumniCredential":     true},
				allowedCustomContexts: map[string]bool{
					"https://www.w3.org/2018/credentials/v1": true,
					"https://www.exaple.org/alumni/v1":       true},
			})
		r.Error(err)
		r.EqualError(err, "not allowed @context: https://www.exaple.org/udc/v1")
	})
}

func TestDecodeWithNullValues(t *testing.T) {
	vcJSON := `
{
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
    ],
    "credentialSubject": {
        "degree": {
            "type": "BachelorDegree",
            "university": "MIT"
        },
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "name": "Jayden Doe",
        "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
    },
    "issuanceDate": "2020-01-08T11:57:26Z",
    "issuer": {
        "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
        "name": "Example University"
    },
    "type": [
        "VerifiableCredential",
        "UniversityDegreeCredential"
    ],

    "credentialSchema": null,
	"proof": null,
	"expirationDate": null,
	"credentialStatus": null,
	"evidence": null,
	"refreshService": null
}
`

	vc, _, err := NewCredential([]byte(vcJSON))
	require.NoError(t, err)
	require.NotNil(t, vc)
}

func TestCredential_raw(t *testing.T) {
	t.Run("Serialize with invalid refresh service", func(t *testing.T) {
		vc, _, err := NewCredential([]byte(validCredential))
		require.NoError(t, err)

		vc.RefreshService = []TypedID{{CustomFields: map[string]interface{}{
			"invalidField": make(chan int),
		}}}

		_, err = vc.raw()
		require.Error(t, err)
	})

	t.Run("Serialize with invalid terms of use", func(t *testing.T) {
		vc, _, err := NewCredential([]byte(validCredential))
		require.NoError(t, err)

		vc.TermsOfUse = []TypedID{{CustomFields: map[string]interface{}{
			"invalidField": make(chan int),
		}}}

		vcRaw, err := vc.raw()
		require.Error(t, err)
		require.Nil(t, vcRaw)
	})
}
