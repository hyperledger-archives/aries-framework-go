/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	jld "github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	storeverifiable "github.com/hyperledger/aries-framework-go/pkg/store/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
)

const (
	stateNamePresentationReceived = "presentation-received"
	stateNameRequestReceived      = "request-received"
	myDIDKey                      = "myDID"
	theirDIDKey                   = "theirDID"
	namesKey                      = "names"

	mimeTypeApplicationLdJSON = "application/ld+json"
	peDefinitionFormat        = "dif/presentation-exchange/definitions@v1.0"
	peSubmissionFormat        = "dif/presentation-exchange/submission@v1.0"
	bbsContext                = "https://w3id.org/security/bbs/v1"
)

// Metadata is an alias to the original Metadata.
type Metadata presentproof.Metadata

// Provider contains dependencies for the SavePresentation middleware function.
type Provider interface {
	VerifiableStore() storeverifiable.Store
	VDRegistry() vdrapi.Registry
	KMS() kms.KeyManager
	Crypto() crypto.Crypto
}

// SavePresentation the helper function for the present proof protocol which saves the presentations.
func SavePresentation(p Provider) presentproof.Middleware {
	vdr := p.VDRegistry()
	store := p.VerifiableStore()

	return func(next presentproof.Handler) presentproof.Handler {
		return presentproof.HandlerFunc(func(metadata presentproof.Metadata) error {
			if metadata.StateName() != stateNamePresentationReceived {
				return next.Handle(metadata)
			}

			presentation := presentproof.Presentation{}
			if err := metadata.Message().Decode(&presentation); err != nil {
				return fmt.Errorf("decode: %w", err)
			}

			presentations, err := toVerifiablePresentation(vdr, presentation.PresentationsAttach)
			if err != nil {
				return fmt.Errorf("to verifiable presentation: %w", err)
			}

			if len(presentations) == 0 {
				return errors.New("presentations were not provided")
			}

			var names []string
			properties := metadata.Properties()

			// nolint: errcheck
			myDID, _ := properties[myDIDKey].(string)
			// nolint: errcheck
			theirDID, _ := properties[theirDIDKey].(string)
			if myDID == "" || theirDID == "" {
				return errors.New("myDID or theirDID is absent")
			}

			for i, presentation := range presentations {
				names = append(names, getName(i, presentation.ID, metadata))

				err := store.SavePresentation(names[i], presentation,
					storeverifiable.WithMyDID(myDID),
					storeverifiable.WithTheirDID(theirDID),
				)
				if err != nil {
					return fmt.Errorf("save presentation: %w", err)
				}
			}

			properties[namesKey] = names

			return next.Handle(metadata)
		})
	}
}

type presentationExchangePayload struct {
	Challenge              string                           `json:"challenge"`
	Domain                 string                           `json:"domain"`
	PresentationDefinition *presexch.PresentationDefinition `json:"presentation_definition"`
}

// OptPD represents option function for the PresentationDefinition middleware.
type OptPD func(o *pdOptions)

// WithAddProofFn allows providing function that will sign the Presentation.
func WithAddProofFn(sign func(presentation *verifiable.Presentation) error) OptPD {
	return func(o *pdOptions) {
		o.addProof = sign
	}
}

type pdOptions struct {
	addProof func(presentation *verifiable.Presentation) error
}

func defaultPdOptions() *pdOptions {
	return &pdOptions{
		addProof: func(presentation *verifiable.Presentation) error {
			return nil
		},
	}
}

// AddBBSProofFn add BBS+ proof to the Presentation.
func AddBBSProofFn(p Provider) func(presentation *verifiable.Presentation) error {
	km, cr := p.KMS(), p.Crypto()

	return func(presentation *verifiable.Presentation) error {
		bbsLoader, err := bbsJSONLDDocumentLoader()
		if err != nil {
			return err
		}

		kid, pubKey, err := km.CreateAndExportPubKeyBytes(kms.BLS12381G2Type)
		if err != nil {
			return err
		}

		_, didKey := fingerprint.CreateDIDKeyByCode(fingerprint.BLS12381g2PubKeyMultiCodec, pubKey)

		presentation.Context = append(presentation.Context, bbsContext)

		return presentation.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
			SignatureType:           "BbsBlsSignature2020",
			SignatureRepresentation: verifiable.SignatureProofValue,
			Suite:                   bbsblssignature2020.New(suite.WithSigner(newBBSSigner(km, cr, kid))),
			VerificationMethod:      didKey,
		}, jsonld.WithDocumentLoader(bbsLoader))
	}
}

// PresentationDefinition the helper function for the present proof protocol that creates VP based on credentials that
// were provided in the attachments according to the requested presentation definition.
func PresentationDefinition(p Provider, opts ...OptPD) presentproof.Middleware { // nolint: funlen,gocyclo
	vdr := p.VDRegistry()

	options := defaultPdOptions()

	for i := range opts {
		opts[i](options)
	}

	return func(next presentproof.Handler) presentproof.Handler {
		return presentproof.HandlerFunc(func(metadata presentproof.Metadata) error {
			if metadata.StateName() != stateNameRequestReceived {
				return next.Handle(metadata)
			}

			request := presentproof.RequestPresentation{}
			if err := metadata.Message().Decode(&request); err != nil {
				return fmt.Errorf("decode: %w", err)
			}

			if metadata.Presentation() == nil ||
				!hasFormat(request.Formats, peDefinitionFormat) ||
				hasFormat(metadata.Presentation().Formats, peSubmissionFormat) {
				return next.Handle(metadata)
			}

			src, err := getAttachmentByFormat(request.Formats,
				request.RequestPresentationsAttach, peDefinitionFormat)
			if err != nil {
				return fmt.Errorf("get attachment by format: %w", err)
			}

			var payload *presentationExchangePayload

			if err = json.Unmarshal(src, &payload); err != nil {
				return fmt.Errorf("unmarshal definition: %w", err)
			}

			credentials, err := parseCredentials(vdr, metadata.Presentation().PresentationsAttach)
			if err != nil {
				return fmt.Errorf("parse credentials: %w", err)
			}

			presentation, err := payload.PresentationDefinition.CreateVP(credentials,
				verifiable.WithPublicKeyFetcher(verifiable.NewVDRKeyResolver(vdr).PublicKeyFetcher()),
				verifiable.WithJSONLDDocumentLoader(presexch.CachingJSONLDLoader()))
			if err != nil {
				return fmt.Errorf("create VP: %w", err)
			}

			singFn := metadata.GetAddProofFn()
			if singFn == nil {
				singFn = options.addProof
			}

			err = singFn(presentation)
			if err != nil {
				return fmt.Errorf("add proof: %w", err)
			}

			metadata.Presentation().PresentationsAttach = []decorator.Attachment{{
				ID:       uuid.New().String(),
				MimeType: mimeTypeApplicationLdJSON,
				Data:     decorator.AttachmentData{JSON: presentation},
			}}

			return next.Handle(metadata)
		})
	}
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}

	return false
}

// nolint: gocyclo
func parseCredentials(vdr vdrapi.Registry, attachments []decorator.Attachment) ([]*verifiable.Credential, error) {
	var credentials []*verifiable.Credential

	for i := range attachments {
		if attachments[i].MimeType != mimeTypeApplicationLdJSON {
			continue
		}

		src, err := attachments[i].Data.Fetch()
		if err != nil {
			return nil, err
		}

		var types struct {
			Type interface{} `json:"type"`
		}

		err = json.Unmarshal(src, &types)
		if err != nil {
			return nil, err
		}

		var credentialTypes []string

		switch v := types.Type.(type) {
		case string:
			credentialTypes = []string{v}
		case []interface{}:
			for _, e := range v {
				if val, ok := e.(string); ok {
					credentialTypes = append(credentialTypes, val)
				}
			}
		}

		if !contains(credentialTypes, verifiable.VCType) {
			continue
		}

		credential, err := verifiable.ParseCredential(src,
			verifiable.WithPublicKeyFetcher(
				verifiable.NewVDRKeyResolver(vdr).PublicKeyFetcher(),
			),
		)
		if err != nil {
			return nil, err
		}

		credentials = append(credentials, credential)
	}

	return credentials, nil
}

func getAttachmentByFormat(fms []presentproof.Format, attachments []decorator.Attachment, name string) ([]byte, error) {
	for _, format := range fms {
		if format.Format == name {
			for i := range attachments {
				if attachments[i].ID == format.AttachID {
					return attachments[i].Data.Fetch()
				}
			}
		}
	}

	return nil, errors.New("not found")
}

func hasFormat(formats []presentproof.Format, format string) bool {
	for _, fm := range formats {
		if fm.Format == format {
			return true
		}
	}

	return false
}

func getName(idx int, id string, metadata presentproof.Metadata) string {
	name := id
	if len(metadata.PresentationNames()) > idx {
		name = metadata.PresentationNames()[idx]
	}

	if name != "" {
		return name
	}

	return uuid.New().String()
}

func toVerifiablePresentation(vdr vdrapi.Registry, data []decorator.Attachment) ([]*verifiable.Presentation, error) {
	var presentations []*verifiable.Presentation

	for i := range data {
		raw, err := data[i].Data.Fetch()
		if err != nil {
			return nil, fmt.Errorf("fetch: %w", err)
		}

		presentation, err := verifiable.ParsePresentation(raw,
			verifiable.WithPresPublicKeyFetcher(
				verifiable.NewVDRKeyResolver(vdr).PublicKeyFetcher(),
			),
			verifiable.WithPresJSONLDDocumentLoader(presexch.CachingJSONLDLoader()),
		)
		if err != nil {
			return nil, fmt.Errorf("parse presentation: %w", err)
		}

		presentations = append(presentations, presentation)
	}

	return presentations, nil
}

type bbsSigner struct {
	km    kms.KeyManager
	cr    crypto.Crypto
	keyID string
}

func newBBSSigner(km kms.KeyManager, cr crypto.Crypto, keyID string) *bbsSigner {
	return &bbsSigner{km: km, cr: cr, keyID: keyID}
}

func (s *bbsSigner) Sign(data []byte) ([]byte, error) {
	kh, err := s.km.Get(s.keyID)
	if err != nil {
		return nil, err
	}

	return s.cr.SignMulti(s.textToLines(string(data)), kh)
}

func (s *bbsSigner) textToLines(txt string) [][]byte {
	lines := strings.Split(txt, "\n")
	linesBytes := make([][]byte, 0, len(lines))

	for i := range lines {
		if strings.TrimSpace(lines[i]) != "" {
			linesBytes = append(linesBytes, []byte(lines[i]))
		}
	}

	return linesBytes
}

// TODO: context should not be loaded here, the loader should be defined once for the whole system.
func bbsJSONLDDocumentLoader() (*jld.CachingDocumentLoader, error) {
	loader := presexch.CachingJSONLDLoader()

	reader, err := ld.DocumentFromReader(strings.NewReader(contextBBSContent))
	if err != nil {
		return nil, err
	}

	loader.AddDocument(bbsContext, reader)

	return loader, nil
}

const contextBBSContent = `{
  "@context": {
    "@version": 1.1,
    "id": "@id",
    "type": "@type",
    "ldssk": "https://w3id.org/security#",
    "BbsBlsSignature2020": {
      "@id": "https://w3id.org/security#BbsBlsSignature2020",
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",
        "challenge": "sec:challenge",
        "created": {
          "@id": "http://purl.org/dc/terms/created",
          "@type": "xsd:dateTime"
        },
        "domain": "sec:domain",
        "proofValue": "sec:proofValue",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "sec": "https://w3id.org/security#",
            "assertionMethod": {
              "@id": "sec:assertionMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "authentication": {
              "@id": "sec:authenticationMethod",
              "@type": "@id",
              "@container": "@set"
            }
          }
        },
        "verificationMethod": {
          "@id": "sec:verificationMethod",
          "@type": "@id"
        }
      }
    },
    "BbsBlsSignatureProof2020": {
      "@id": "https://w3id.org/security#BbsBlsSignatureProof2020",
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",
        "challenge": "sec:challenge",
        "created": {
          "@id": "http://purl.org/dc/terms/created",
          "@type": "xsd:dateTime"
        },
        "domain": "sec:domain",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "sec": "https://w3id.org/security#",
            "assertionMethod": {
              "@id": "sec:assertionMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "authentication": {
              "@id": "sec:authenticationMethod",
              "@type": "@id",
              "@container": "@set"
            }
          }
        },
        "proofValue": "sec:proofValue",
        "verificationMethod": {
          "@id": "sec:verificationMethod",
          "@type": "@id"
        }
      }
    },
    "Bls12381G2Key2020": "ldssk:Bls12381G2Key2020"
  }
}`
