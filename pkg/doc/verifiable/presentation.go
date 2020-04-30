/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/xeipuuv/gojsonschema"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
)

const basePresentationSchema = `
{
  "required": [
    "@context",
    "type",
    "verifiableCredential"
  ],
  "properties": {
    "@context": {
      "oneOf": [
        {
          "type": "string",
          "const": "https://www.w3.org/2018/credentials/v1"
        },
        {
          "type": "array",
          "items": [
            {
              "type": "string",
              "const": "https://www.w3.org/2018/credentials/v1"
            }
          ],
          "uniqueItems": true,
          "additionalItems": {
            "oneOf": [
              {
                "type": "object"
              },
              {
                "type": "string"
              }
            ]
          }
        }
      ]
    },
    "id": {
      "type": "string",
      "format": "uri"
    },
    "type": {
      "oneOf": [
        {
          "type": "array",
          "items": [
            {
              "type": "string",
              "pattern": "^VerifiablePresentation$"
            }
          ],
          "minItems": 1
        },
        {
          "type": "string",
          "pattern": "^VerifiablePresentation$"
        }
      ],
      "additionalItems": {
        "type": "string"
      }
    },
    "verifiableCredential": {
      "anyOf": [
        {
          "type": "array"
        },
        {
          "type": "object"
        },
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ]
    },
    "holder": {
      "type": "string",
      "format": "uri"
    },
    "proof": {
      "anyOf": [
        {
          "type": "array",
          "items": [
            {
              "$ref": "#/definitions/proof"
            }
          ]
        },
        {
          "$ref": "#/definitions/proof"
        }
      ]
    },
    "refreshService": {
      "$ref": "#/definitions/typedID"
    }
  },
  "definitions": {
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
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "array",
              "items": {
                "type": "string"
              }
            }
          ]
        }
      }
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
    }
  }
}
`

//nolint:gochecknoglobals
var basePresentationSchemaLoader = gojsonschema.NewStringLoader(basePresentationSchema)

// MarshalledCredential defines marshalled Verifiable Credential enclosed into Presentation.
// MarshalledCredential can be passed to verifiable.NewCredential().
type MarshalledCredential []byte

// Presentation Verifiable Presentation base data model definition
type Presentation struct {
	Context        []string
	CustomContext  []interface{}
	ID             string
	Type           []string
	credentials    []interface{}
	Holder         string
	Proofs         []Proof
	RefreshService *TypedID
}

// MarshalJSON converts Verifiable Presentation to JSON bytes.
func (vp *Presentation) MarshalJSON() ([]byte, error) {
	raw, err := vp.raw()
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling of verifiable presentation: %w", err)
	}

	byteCred, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling of verifiable presentation: %w", err)
	}

	return byteCred, nil
}

// JWTClaims converts Verifiable Presentation into JWT Presentation claims, which can be than serialized
// e.g. into JWS.
func (vp *Presentation) JWTClaims(audience []string, minimizeVP bool) (*JWTPresClaims, error) {
	return newJWTPresClaims(vp, audience, minimizeVP)
}

// Credentials returns current credentials of presentation.
func (vp *Presentation) Credentials() []interface{} {
	return vp.credentials
}

// SetCredentials defines credentials of presentation.
// The credential could be string/byte (probably serialized JWT) or Credential structure.
func (vp *Presentation) SetCredentials(creds ...interface{}) error {
	var vpCreds []interface{}

	convertToVC := func(vcStr string) (interface{}, error) {
		// Check if passed VC is correct one.
		vc, err := NewUnverifiedCredential([]byte(vcStr))
		if err != nil {
			return nil, fmt.Errorf("check VC: %w", err)
		}

		// If VC was passed in JWT form, left it as is. Otherwise, return parsed VC
		if jose.IsCompactJWS(vcStr) {
			return vcStr, nil
		}

		return vc, nil
	}

	for i := range creds {
		switch rawVC := creds[i].(type) {
		case *Credential:
			vpCreds = append(vpCreds, rawVC)

		case []byte:
			vc, err := convertToVC(string(rawVC))
			if err != nil {
				return err
			}

			vpCreds = append(vpCreds, vc)

		case string:
			vc, err := convertToVC(rawVC)
			if err != nil {
				return err
			}

			vpCreds = append(vpCreds, vc)

		default:
			return errors.New("unsupported credential format")
		}
	}

	vp.credentials = vpCreds

	return nil
}

// MarshalledCredentials provides marshalled credentials enclosed into Presentation in raw byte array format.
// They can be used to decode Credentials into struct.
func (vp *Presentation) MarshalledCredentials() ([]MarshalledCredential, error) {
	mCreds := make([]MarshalledCredential, len(vp.credentials))

	for i := range vp.credentials {
		cred := vp.credentials[i]
		switch c := cred.(type) {
		case string:
			mCreds[i] = MarshalledCredential(c)
		case []byte:
			mCreds[i] = c
		default:
			credBytes, err := json.Marshal(cred)
			if err != nil {
				return nil, fmt.Errorf("marshal credentials from presentation: %w", err)
			}

			mCreds[i] = credBytes
		}
	}

	return mCreds, nil
}

func (vp *Presentation) raw() (*rawPresentation, error) {
	proof, err := proofsToRaw(vp.Proofs)
	if err != nil {
		return nil, err
	}

	return &rawPresentation{
		// TODO single value contexts should be compacted as part of Issue [#1730]
		// Not compacting now to support interoperability
		Context:        vp.Context,
		ID:             vp.ID,
		Type:           typesToRaw(vp.Type),
		Credential:     vp.credentials,
		Holder:         vp.Holder,
		Proof:          proof,
		RefreshService: vp.RefreshService,
	}, nil
}

// rawPresentation is a basic verifiable credential
type rawPresentation struct {
	Context        interface{}     `json:"@context,omitempty"`
	ID             string          `json:"id,omitempty"`
	Type           interface{}     `json:"type,omitempty"`
	Credential     interface{}     `json:"verifiableCredential"`
	Holder         string          `json:"holder,omitempty"`
	Proof          json.RawMessage `json:"proof,omitempty"`
	RefreshService *TypedID        `json:"refreshService,omitempty"`
}

// presentationOpts holds options for the Verifiable Presentation decoding
type presentationOpts struct {
	publicKeyFetcher   PublicKeyFetcher
	disabledProofCheck bool
	ldpSuites          []verifier.SignatureSuite
}

// PresentationOpt is the Verifiable Presentation decoding option
type PresentationOpt func(opts *presentationOpts)

// WithPresPublicKeyFetcher indicates that Verifiable Presentation should be decoded from JWS using
// the public key fetcher.
func WithPresPublicKeyFetcher(fetcher PublicKeyFetcher) PresentationOpt {
	return func(opts *presentationOpts) {
		opts.publicKeyFetcher = fetcher
	}
}

// WithPresEmbeddedSignatureSuites defines the suites which are used to check embedded linked data proof of VP.
func WithPresEmbeddedSignatureSuites(suites ...verifier.SignatureSuite) PresentationOpt {
	return func(opts *presentationOpts) {
		opts.ldpSuites = suites
	}
}

// WithDisabledPresentationProofCheck option for disabling of proof check.
func WithDisabledPresentationProofCheck() PresentationOpt {
	return func(opts *presentationOpts) {
		opts.disabledProofCheck = true
	}
}

// NewPresentation creates an instance of Verifiable Presentation by reading a JSON document from bytes.
// It also applies miscellaneous options like custom decoders or settings of schema validation.
func NewPresentation(vpData []byte, opts ...PresentationOpt) (*Presentation, error) {
	// Apply options
	vpOpts := defaultPresentationOpts()

	for _, opt := range opts {
		opt(vpOpts)
	}

	vpDataDecoded, vpRaw, err := decodeRawPresentation(vpData, vpOpts)
	if err != nil {
		return nil, err
	}

	err = validatePresentation(vpDataDecoded)
	if err != nil {
		return nil, err
	}

	return newPresentation(vpRaw, vpOpts)
}

// NewUnverifiedPresentation decodes Verifiable Presentation from bytes which could be marshalled JSON or
// serialized JWT. It does not make a proof check though. Can be used for purposes of decoding of VP stored in a wallet.
// Please use this function with caution.
func NewUnverifiedPresentation(vpBytes []byte) (*Presentation, error) {
	// Apply options
	vpOpts := &presentationOpts{
		disabledProofCheck: true,
	}

	_, vpRaw, err := decodeRawPresentation(vpBytes, vpOpts)
	if err != nil {
		return nil, err
	}

	return newPresentation(vpRaw, vpOpts)
}

func newPresentation(vpRaw *rawPresentation, vpOpts *presentationOpts) (*Presentation, error) {
	types, err := decodeType(vpRaw.Type)
	if err != nil {
		return nil, fmt.Errorf("fill presentation types from raw: %w", err)
	}

	context, customContext, err := decodeContext(vpRaw.Context)
	if err != nil {
		return nil, fmt.Errorf("fill presentation contexts from raw: %w", err)
	}

	creds, err := decodeCredentials(vpRaw.Credential, vpOpts)
	if err != nil {
		return nil, fmt.Errorf("decode credentials of presentation: %w", err)
	}

	proofs, err := decodeProof(vpRaw.Proof)
	if err != nil {
		return nil, fmt.Errorf("fill credential proof from raw: %w", err)
	}

	return &Presentation{
		Context:        context,
		CustomContext:  customContext,
		ID:             vpRaw.ID,
		Type:           types,
		credentials:    creds,
		Holder:         vpRaw.Holder,
		Proofs:         proofs,
		RefreshService: vpRaw.RefreshService,
	}, nil
}

// decodeCredentials decodes credential(s) embedded into presentation.
// It must be one of the following:
// 1) string - it could be credential decoded into e.g. JWS.
// 2) the same as 1) but as array - e.g. zero ore more JWS
// 3) struct (should be map[string]interface{}) representing credential data model
// 4) the same as 3) but as array - i.e. zero or more credentials structs.
func decodeCredentials(rawCred interface{}, opts *presentationOpts) ([]interface{}, error) {
	// Accept the case when VP does not have any VCs.
	if rawCred == nil {
		return nil, nil
	}

	marshalSingleCredFn := func(cred interface{}) (interface{}, error) {
		// Check the case when VC is defined in string format (e.g. JWT).
		// Decode credential and keep result of decoding.
		if sCred, ok := cred.(string); ok {
			bCred := []byte(sCred)

			credDecoded, err := decodeRaw(bCred, mapOpts(opts))
			if err != nil {
				return nil, fmt.Errorf("decode credential of presentation: %w", err)
			}

			return credDecoded, nil
		}

		// return credential in a structure format as is
		return cred, nil
	}

	switch cred := rawCred.(type) {
	case []interface{}:
		// Accept the case when VP does not have any VCs.
		if len(cred) == 0 {
			return nil, nil
		}

		// 1 or more credentials
		creds := make([]interface{}, len(cred))

		for i := range cred {
			c, err := marshalSingleCredFn(cred[i])
			if err != nil {
				return nil, err
			}

			creds[i] = c
		}

		return creds, nil
	default:
		// single credential
		c, err := marshalSingleCredFn(cred)
		if err != nil {
			return nil, err
		}

		return []interface{}{c}, nil
	}
}

func mapOpts(vpOpts *presentationOpts) *credentialOpts {
	return &credentialOpts{
		publicKeyFetcher:   vpOpts.publicKeyFetcher,
		disabledProofCheck: vpOpts.disabledProofCheck,
		ldpSuites:          vpOpts.ldpSuites,
	}
}

func validatePresentation(data []byte) error {
	loader := gojsonschema.NewStringLoader(string(data))

	result, err := gojsonschema.Validate(basePresentationSchemaLoader, loader)
	if err != nil {
		return fmt.Errorf("validation of verifiable credential: %w", err)
	}

	if !result.Valid() {
		errMsg := describeSchemaValidationError(result, "verifiable presentation")
		return errors.New(errMsg)
	}

	return nil
}

func decodeRawPresentation(vpData []byte, vpOpts *presentationOpts) ([]byte, *rawPresentation, error) {
	vpStr := string(vpData)

	if jwt.IsJWS(vpStr) {
		if vpOpts.publicKeyFetcher == nil {
			return nil, nil, errors.New("public key fetcher is not defined")
		}

		vcDataFromJwt, rawCred, err := decodeVPFromJWS(vpStr, !vpOpts.disabledProofCheck, vpOpts.publicKeyFetcher)
		if err != nil {
			return nil, nil, fmt.Errorf("decoding of Verifiable Presentation from JWS: %w", err)
		}

		return vcDataFromJwt, rawCred, nil
	}

	if jwt.IsJWTUnsecured(vpStr) {
		rawBytes, rawCred, err := decodeVPFromUnsecuredJWT(vpStr)
		if err != nil {
			return nil, nil, fmt.Errorf("decoding of Verifiable Presentation from unsecured JWT: %w", err)
		}

		return rawBytes, rawCred, nil
	}

	vpBytes, vpRaw, err := decodeVPFromJSON(vpData)
	if err != nil {
		return nil, nil, err
	}

	// check that embedded proof is present, if not, it's not a verifiable presentation
	if !vpOpts.disabledProofCheck && vpRaw.Proof == nil {
		return nil, nil, errors.New("embedded proof is missing")
	}

	return vpBytes, vpRaw, err
}

func decodeVPFromJSON(vpData []byte) ([]byte, *rawPresentation, error) {
	// unmarshal VP from JSON
	raw := new(rawPresentation)

	err := json.Unmarshal(vpData, raw)
	if err != nil {
		return nil, nil, fmt.Errorf("JSON unmarshalling of verifiable presentation: %w", err)
	}

	return vpData, raw, nil
}

func defaultPresentationOpts() *presentationOpts {
	return &presentationOpts{}
}
