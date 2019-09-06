/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/xeipuuv/gojsonschema"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
)

var logger = log.New("aries-framework/doc/verifiable")

const defaultSchema = `
{
  "required": [
    "@context",
    "type",
    "credentialSubject",
    "issuer",
    "issuanceDate"
  ],
  "properties": {
    "@context": {
      "type": "array",
      "items": [
        {
          "type": "string",
          "pattern": "^https://www.w3.org/2018/credentials/v1$"
        }
      ],
      "additionalItems": {
        "type": "string"
      }
    },
    "id": {
      "type": "string",
      "format": "uri"
    },
    "type": {
      "type": "array",
      "items": [
        {
          "type": "string",
          "pattern": "^VerifiableCredential$"
        }
      ],
      "additionalItems": {
        "type": "string"
      },
      "minItems": 2
    },
    "credentialSubject": {
      "anyOf": [
        {
          "type": "array"
        },
        {
          "type": "object"
        }
      ]
    },
    "issuer": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "object",
          "required": [
            "id"
          ],
          "properties": {
            "id": {
              "type": "string"
            }
          }
        }
      ]
    },
    "issuanceDate": {
      "$ref": "#/definitions/timestamp"
    },
    "proof": {
      "type": "object",
      "required": [
        "type"
      ],
      "properties": {
        "type": {
          "type": "string"
        }
      }
    },
    "expirationDate": {
      "$ref": "#/definitions/timestamp"
    },
    "credentialStatus": {
      "$ref": "#/definitions/typedID"
    },
    "credentialSchema": {
      "$ref": "#/definitions/typedID"
    },
    "refreshService": {
      "$ref": "#/definitions/typedID"
    }
  },
  "definitions": {
    "timestamp": {
      "type": "string",
      "pattern": "\\d{4}-[01]\\d-[0-3]\\dT[0-2]\\d:[0-5]\\d:[0-5]\\dZ"
    },
    "typedID": {
      "type": "object",
      "required": [
        "id",
        "type"
      ],
      "properties": {
        "id": {
          "type": "string",
          "format": "uri"
        },
        "type": {
          "type": "string"
        }
      }
    }
  }
}
`

const jsonSchema2018Type = "JsonSchemaValidator2018"

//nolint:gochecknoglobals
var defaultSchemaLoader = gojsonschema.NewStringLoader(defaultSchema)

// Proof defines embedded proof of Verifiable Credential
type Proof struct {
	Type string `json:"type,omitempty"`
}

type typedID struct {
	ID   string `json:"id,omitempty"`
	Type string `json:"type,omitempty"`
}

// Issuer of the Verifiable Credential
type Issuer struct {
	ID   string
	Name string
}

// Subject of the Verifiable Credential
type Subject interface{}

// CredentialStatus defines status of Verifiable Credential
type CredentialStatus typedID

// CredentialSchema defines a link to data schema which enforces a specific structure of Verifiable Credential.
type CredentialSchema typedID

// RefreshService provides a way to automatic refresh of expired Verifiable Credential
type RefreshService typedID

// Credential Verifiable Credential definition
type Credential struct {
	Context        []string
	ID             string
	Type           []string
	Subject        *Subject
	Issuer         Issuer
	Issued         *time.Time
	Expired        *time.Time
	Proof          *Proof
	Status         *CredentialStatus
	Schema         *CredentialSchema
	RefreshService *RefreshService
}

// rawCredential
type rawCredential struct {
	Context        []string          `json:"@context,omitempty"`
	ID             string            `json:"id,omitempty"`
	Type           []string          `json:"type,omitempty"`
	Subject        *Subject          `json:"credentialSubject,omitempty"`
	Issued         *time.Time        `json:"issuanceDate,omitempty"`
	Expired        *time.Time        `json:"expirationDate,omitempty"`
	Proof          *Proof            `json:"proof,omitempty"`
	Status         *CredentialStatus `json:"credentialStatus,omitempty"`
	Issuer         interface{}       `json:"issuer,omitempty"`
	Schema         *CredentialSchema `json:"credentialSchema,omitempty"`
	RefreshService *RefreshService   `json:"refreshService,omitempty"`
}

type issuerPlain struct {
	ID string `json:"issuer,omitempty"`
}

type compositeIssuer struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type embeddedCompositeIssuer struct {
	CompositeIssuer compositeIssuer `json:"issuer,omitempty"`
}

// CredentialDecoder makes a custom decoding of Verifiable Credential in JSON form to existent
// instance of Credential.
type CredentialDecoder func(dataJSON []byte, credential *Credential) error

// CredentialTemplate defines a factory method to create new Credential template.
type CredentialTemplate func() *Credential

// credentialOpts holds options for the Verifiable Credential decoding
// it has a http.Client instance initialized with default parameters
type credentialOpts struct {
	schemaDownloadClient *http.Client
	disabledCustomSchema bool
	decoders             []CredentialDecoder
	template             CredentialTemplate
}

// CredentialOpt is the Verifiable Credential decoding option
type CredentialOpt func(opts *credentialOpts)

// WithSchemaDownloadClient option is for definition of HTTP(s) client used during decoding of Verifiable Credential.
// If custom credentialSchema is defined in Verifiable Credential, the client downloads from the specified URL.
func WithSchemaDownloadClient(client *http.Client) CredentialOpt {
	return func(opts *credentialOpts) {
		opts.schemaDownloadClient = client
	}
}

// WithNoCustomSchemaCheck option is for disabling of Credential Schemas download if defined
// in Verifiable Credential. Instead, the Verifiable Credential is checked against default Schema.
func WithNoCustomSchemaCheck() CredentialOpt {
	return func(opts *credentialOpts) {
		opts.disabledCustomSchema = true
	}
}

// WithDecoders option is for adding extra JSON decoders into Verifiable Credential data model.
func WithDecoders(decoders []CredentialDecoder) CredentialOpt {
	return func(opts *credentialOpts) {
		opts.decoders = append(opts.decoders, decoders...)
	}
}

// WithTemplate option is for setting a custom factory method to create new Credential instance.
func WithTemplate(template CredentialTemplate) CredentialOpt {
	return func(opts *credentialOpts) {
		opts.template = template
	}
}

func decodeIssuer(data []byte, credential *Credential) error {
	issuerID, issuerName, err := issuerFromBytes(data)
	if err != nil {
		return fmt.Errorf("JSON unmarshalling of Verifiable Credential bytes failed: %w", err)
	}

	credential.Issuer = Issuer{ID: issuerID, Name: issuerName}
	return nil
}

// NewCredential creates an instance of Verifiable Credential by reading a JSON document from bytes.
// It also applies miscellaneous options like custom decoders or settings of schema validation.
func NewCredential(dataJSON []byte, opts ...CredentialOpt) (*Credential, error) {
	// Apply options
	crOpts := defaultCredentialOpts()
	for _, opt := range opts {
		opt(crOpts)
	}

	raw := &rawCredential{}
	err := json.Unmarshal(dataJSON, &raw)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of verifiable credential failed: %w", err)
	}

	err = validate(dataJSON, raw.Schema, crOpts)
	if err != nil {
		return nil, err
	}

	var cred = crOpts.template()
	cred.Context = raw.Context
	cred.ID = raw.ID
	cred.Type = raw.Type
	cred.Subject = raw.Subject
	cred.Issued = raw.Issued
	cred.Expired = raw.Expired
	cred.Proof = raw.Proof
	cred.Status = raw.Status
	cred.Schema = raw.Schema
	cred.RefreshService = raw.RefreshService

	for _, decoder := range crOpts.decoders {
		err = decoder(dataJSON, cred)
		if err != nil {
			return nil, err
		}
	}

	return cred, nil
}

func defaultCredentialOpts() *credentialOpts {
	return &credentialOpts{
		schemaDownloadClient: &http.Client{},
		disabledCustomSchema: false,
		decoders:             []CredentialDecoder{decodeIssuer},
		template:             func() *Credential { return &Credential{} },
	}
}

func issuerFromBytes(data []byte) (issuerID, issuerName string, err error) {
	issuerPlain := &issuerPlain{}
	err = json.Unmarshal(data, &issuerPlain)
	if err == nil {
		return issuerPlain.ID, "", nil
	}

	eci := &embeddedCompositeIssuer{}
	err = json.Unmarshal(data, &eci)
	if err == nil {
		return eci.CompositeIssuer.ID, eci.CompositeIssuer.Name, nil
	}

	return "", "", fmt.Errorf("verifiable credential issuer is not valid")
}

func issuerToSerialize(vc *Credential) interface{} {
	if vc.Issuer.Name != "" {
		return &compositeIssuer{ID: vc.Issuer.ID, Name: vc.Issuer.Name}
	}
	return vc.Issuer.ID
}

func validate(data []byte, schema *CredentialSchema, opts *credentialOpts) error {
	// Validate that the Verifiable Credential conforms to the serialization of the Verifiable Credential data model
	// (https://w3c.github.io/vc-data-model/#example-1-a-simple-example-of-a-verifiable-credential)
	schemaLoader, err := getCredentialSchema(schema, opts)
	if err != nil {
		return err
	}

	loader := gojsonschema.NewStringLoader(string(data))
	result, err := gojsonschema.Validate(schemaLoader, loader)
	if err != nil {
		return fmt.Errorf("validation of verifiable credential failed: %w", err)
	}

	if !result.Valid() {
		errMsg := describeSchemaValidationError(result)
		return errors.New(errMsg)
	}
	return nil
}

func describeSchemaValidationError(result *gojsonschema.Result) string {
	errMsg := "verifiable credential is not valid:\n"
	for _, desc := range result.Errors() {
		errMsg += fmt.Sprintf("- %s\n", desc)
	}
	return errMsg
}

func getCredentialSchema(schema *CredentialSchema, opts *credentialOpts) (gojsonschema.JSONLoader, error) {
	schemaLoader := defaultSchemaLoader
	if schema != nil && !opts.disabledCustomSchema {
		switch schema.Type {
		case jsonSchema2018Type:
			if customSchemaData, err := loadCredentialSchema(schema.ID, opts.schemaDownloadClient); err == nil {
				schemaLoader = gojsonschema.NewBytesLoader(customSchemaData)
			} else {
				return nil, fmt.Errorf("loading custom credential schema from %s failed: %w", schema.ID, err)
			}
		default:
			logger.Warnf("unsupported credential schema: %s. Using default schema for validation", schema.Type)
		}
	}
	return schemaLoader, nil
}

// todo cache credential schema (https://github.com/hyperledger/aries-framework-go/issues/185)
func loadCredentialSchema(url string, client *http.Client) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}

	defer func() {
		e := resp.Body.Close()
		if e != nil {
			logger.Errorf("closing response body failed [%v]", e)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("credential schema endpoint HTTP failure [%v]", resp.StatusCode)
	}

	var gotBody []byte
	gotBody, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body failed: %w", err)
	}

	return gotBody, nil
}

// JSONBytes converts Verifiable Credential to JSON bytes
func (vc *Credential) JSONBytes() ([]byte, error) {
	rawCred := &rawCredential{
		Context:        vc.Context,
		ID:             vc.ID,
		Type:           vc.Type,
		Subject:        vc.Subject,
		Issued:         vc.Issued,
		Expired:        vc.Expired,
		Proof:          vc.Proof,
		Status:         vc.Status,
		Issuer:         issuerToSerialize(vc),
		Schema:         vc.Schema,
		RefreshService: vc.RefreshService,
	}

	byteCred, err := json.Marshal(rawCred)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of verifiable credential failed: %w", err)
	}

	return byteCred, nil
}
