/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rfc0593

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
)

const (
	// ProofVCDetailFormat is the attachment format used in the proposal, offer, and request message attachments.
	ProofVCDetailFormat = "aries/ld-proof-vc-detail@v1.0"
	// ProofVCFormat is the attachment format used in the issue-credential message attachment.
	ProofVCFormat   = "aries/ld-proof-vc@v1.0"
	mediaTypeJSON   = "application/json"
	mediaTypeJSONLD = "application/ld+json"
)

var errRFC0593DoesNotApply = errors.New("RFC0593 is not applicable")

// CredentialSpec is the attachment payload in messages conforming to the RFC0593 format.
type CredentialSpec struct {
	Template json.RawMessage        `json:"credential"`
	Options  *CredentialSpecOptions `json:"options"`
}

// CredentialSpecOptions are the options for issuance of the credential.
// TODO support CredentialStatus.
type CredentialSpecOptions struct {
	ProofPurpose string            `json:"proofPurpose"`
	Created      string            `json:"created"`
	Domain       string            `json:"domain"`
	Challenge    string            `json:"challenge"`
	Status       *CredentialStatus `json:"credentialStatus"`
	ProofType    string            `json:"proofType"`
}

// CredentialStatus is the requested status for the credential.
type CredentialStatus struct {
	Type string `json:"type"`
}

// AutoExecute will automatically execute the issue-credential V2 protocol using ReplayProposal, ReplayOffer, and
// IssueCredential by handling the associated actions if they contain RFC0593 attachments.
// Other actions are passed through to 'next'.
//
// Usage:
//     client := issuecredential.Client = ...
//     events = make(chan service.DIDCommAction)
//     err := client.RegisterActionEvent(events)
//     if err != nil {
//         panic(err)
//     }
//     var p Provider = ...
//     next := make(chan service.DIDCommAction)
//     go AutoExecute(p, next)(events)
//     for event := range next {
//         // handle events from issue-credential and other protocols
//         // that do not conform to RFC0593
//     }
//
// See also: service.AutoExecuteActionEvent.
func AutoExecute(p Provider, next chan service.DIDCommAction) func(chan service.DIDCommAction) {
	return func(events chan service.DIDCommAction) {
		for event := range events {
			var (
				arg interface{}
				err error
			)

			switch event.Message.Type() {
			case issuecredential.ProposeCredentialMsgType:
				arg, err = ReplayProposal(p, event.Message)
			case issuecredential.OfferCredentialMsgType:
				arg, err = ReplayOffer(p, event.Message)
			case issuecredential.RequestCredentialMsgType:
				arg, err = IssueCredential(p, event.Message)
			default:
				next <- event

				continue
			}

			if errors.Is(err, errRFC0593DoesNotApply) {
				next <- event

				continue
			}

			if err != nil {
				event.Stop(fmt.Errorf("rfc0593: %w", err))

				continue
			}

			event.Continue(arg)
		}
	}
}

// ReplayProposal replays the inbound proposed CredentialSpec as an outbound offer that can be sent back to the
// original sender.
//
// Usage:
//     var p JSONLDDocumentLoaderProvider = ...
//     client := issuecredential.Client = ...
//     var events chan service.DIDCommAction = ...
//     err := client.RegisterActionEvent(events)
//     if err != nil {
//         panic(err)
//     }
//     for event := range events {
//         if event.Message.Type() == issuecredential.ProposeCredentialMsgType {
//             arg, err := ReplayProposal(p, event.Message)
//             if err != nil {
//                 event.Stop(err)
//             }
//
//             event.Continue(arg)
//         }
//     }
func ReplayProposal(p JSONLDDocumentLoaderProvider, msg service.DIDCommMsg) (interface{}, error) {
	proposal := &issuecredential.ProposeCredential{}

	err := msg.Decode(proposal)
	if err != nil {
		return nil, fmt.Errorf("failed to decode msg type %s: %w", msg.Type(), err)
	}

	payload, err := getPayload(p, proposal.Formats, proposal.FiltersAttach)
	if err != nil {
		return nil, fmt.Errorf("failed to extract payload for msg type %s: %w", msg.Type(), err)
	}

	attachID := uuid.New().String()

	return issuecredential.WithOfferCredential(&issuecredential.OfferCredential{
		Type:    issuecredential.OfferCredentialMsgType,
		Comment: fmt.Sprintf("response to msg id: %s", msg.ID()),
		Formats: []issuecredential.Format{{
			AttachID: attachID,
			Format:   ProofVCDetailFormat,
		}},
		OffersAttach: []decorator.Attachment{{
			ID:       attachID,
			MimeType: mediaTypeJSON,
			Data: decorator.AttachmentData{
				JSON: payload,
			},
		}},
	}), nil
}

// ReplayOffer replays the inbound offered CredentialSpec as an outbound request that can be sent back to the
// original sender.
//
// Usage:
//     var p JSONLDDocumentLoaderProvider = ...
//     client := issuecredential.Client = ...
//     var events chan service.DIDCommAction = ...
//     err := client.RegisterActionEvent(events)
//     if err != nil {
//         panic(err)
//     }
//     for event := range events {
//         if event.Message.Type() == issuecredential.OfferCredentialMsgType {
//             arg, err := ReplayOffer(p, event.Message)
//             if err != nil {
//                 event.Stop(err)
//             }
//
//             event.Continue(arg)
//         }
//     }
func ReplayOffer(p JSONLDDocumentLoaderProvider, msg service.DIDCommMsg) (interface{}, error) {
	offer := &issuecredential.OfferCredential{}

	err := msg.Decode(offer)
	if err != nil {
		return nil, fmt.Errorf("failed to decode msg type %s: %w", msg.Type(), err)
	}

	payload, err := getPayload(p, offer.Formats, offer.OffersAttach)
	if err != nil {
		return nil, fmt.Errorf("failed to extract payoad for msg type %s: %w", msg.Type(), err)
	}

	attachID := uuid.New().String()

	return issuecredential.WithRequestCredential(&issuecredential.RequestCredential{
		Type:    issuecredential.RequestCredentialMsgType,
		Comment: fmt.Sprintf("response to msg id: %s", msg.ID()),
		Formats: []issuecredential.Format{{
			AttachID: attachID,
			Format:   ProofVCDetailFormat,
		}},
		RequestsAttach: []decorator.Attachment{{
			ID:       attachID,
			MimeType: mediaTypeJSON,
			Data: decorator.AttachmentData{
				JSON: payload,
			},
		}},
	}), nil
}

// IssueCredential attaches an LD proof to the template VC in the inbound request message and attaches the
// verifiable credential to an outbound issue-credential message.
//
// Usage:
//     var p Provider = ...
//     client := issuecredential.Client = ...
//     var events chan service.DIDCommAction = ...
//     err := client.RegisterActionEvent(events)
//     if err != nil {
//         panic(err)
//     }
//     for event := range events {
//         if event.Message.Type() == issuecredential.RequestCredentialMsgType {
//             arg, err := IssueCredential(p, event.Message)
//             if err != nil {
//                 event.Stop(err)
//             }
//
//             event.Continue(arg)
//         }
//     }
func IssueCredential(p Provider, msg service.DIDCommMsg) (interface{}, error) {
	request := &issuecredential.RequestCredential{}

	err := msg.Decode(request)
	if err != nil {
		return nil, fmt.Errorf("failed to decode msg type %s: %w", msg.Type(), err)
	}

	payload, err := getPayload(p, request.Formats, request.RequestsAttach)
	if err != nil {
		return nil, fmt.Errorf("failed to get payload for msg type %s: %w", msg.Type(), err)
	}

	vc, err := verifiable.ParseCredential(
		payload.Template,
		verifiable.WithDisabledProofCheck(), // no proof is expected in this credential
		verifiable.WithJSONLDDocumentLoader(p.JSONLDDocumentLoader()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse vc for msg type %s: %w", msg.Type(), err)
	}

	ctx, err := ldProofContext(p, payload.Options)
	if err != nil {
		return nil, fmt.Errorf("failed to determine the LD context required to add a proof: %w", err)
	}

	err = vc.AddLinkedDataProof(ctx, jsonld.WithDocumentLoader(p.JSONLDDocumentLoader()))
	if err != nil {
		return nil, fmt.Errorf("failed to add LD proof for msg type %s: %w", msg.Type(), err)
	}

	attachID := uuid.New().String()

	return issuecredential.WithIssueCredential(&issuecredential.IssueCredential{
		Type:    issuecredential.IssueCredentialMsgType,
		Comment: fmt.Sprintf("response to request with id %s", msg.ID()),
		Formats: []issuecredential.Format{{
			AttachID: attachID,
			Format:   ProofVCFormat,
		}},
		CredentialsAttach: []decorator.Attachment{{
			ID:       attachID,
			MimeType: mediaTypeJSONLD,
			Data: decorator.AttachmentData{
				JSON: vc,
			},
		}},
	}), nil
}

func ldProofContext(p Provider, options *CredentialSpecOptions) (*verifiable.LinkedDataProofContext, error) {
	now := time.Now()

	ctx := &verifiable.LinkedDataProofContext{
		SignatureType: options.ProofType,
		Purpose:       "assertionMethod",
		Created:       &now,
		Challenge:     options.Challenge,
		Domain:        options.Domain,
	}

	ss, spec, verMethod, err := signatureSuite(p, options.ProofType)
	if err != nil {
		return nil, fmt.Errorf("failed to init a signature suite: %w", err)
	}

	ctx.Suite = ss
	ctx.VerificationMethod = verMethod
	ctx.SignatureRepresentation = spec.SignatureRepresentation // TODO RFC does not specify representation

	if options.ProofPurpose != "" {
		ctx.Purpose = options.ProofPurpose
	}

	if options.Created != "" {
		// TODO spec does not specify format for `created`
		created, err := time.Parse(time.RFC3339, options.Created)
		if err != nil {
			return nil, fmt.Errorf("failed to parse `created`: %w", err)
		}

		ctx.Created = &created
	}

	return ctx, nil
}

func signatureSuite(p Provider, proofType string) (signer.SignatureSuite, *SignatureSuiteSpec, string, error) {
	spec, supported := DefaultSignatureSuiteSpecs[proofType]
	if !supported {
		return nil, nil, "", fmt.Errorf("unsupported proof type: %s", proofType)
	}

	keyID, kh, err := p.KMS().Create(spec.KeyType)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to create a new signing key: %w", err)
	}

	keyBytes, err := p.KMS().ExportPubKeyBytes(keyID)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to export signing key bytes: %w", err)
	}

	_, verMethod := fingerprint.CreateDIDKeyByCode(spec.KeyMultiCodec, keyBytes)
	suiteSigner := spec.Signer(p, kh)

	return spec.Suite(suite.WithSigner(suiteSigner)), &spec, verMethod, nil
}

func getPayload(p JSONLDDocumentLoaderProvider,
	formats []issuecredential.Format, attachments []decorator.Attachment) (*CredentialSpec, error) {
	attachment, err := findAttachment(ProofVCDetailFormat, formats, attachments)
	if err != nil {
		return nil, fmt.Errorf("failed to find attachment of type %s: %w", ProofVCDetailFormat, err)
	}

	payload := &CredentialSpec{}

	err = unmarshalAttachmentContents(attachment, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal attachment contents: %w", err)
	}

	err = validateCredentialRequestOptions(payload)
	if err != nil {
		return nil, fmt.Errorf("bad request: invalid options: %w", err)
	}

	vc, err := verifiable.ParseCredential(
		payload.Template,
		verifiable.WithDisabledProofCheck(), // no proof is expected in this credential
		verifiable.WithJSONLDDocumentLoader(p.JSONLDDocumentLoader()),
	)
	if err != nil {
		return nil, fmt.Errorf("bad request: unable to parse vc: %w", err)
	}

	err = validateCredentialRequestVC(vc)
	if err != nil {
		return nil, fmt.Errorf("bad request: invalid vc: %w", err)
	}

	return payload, nil
}

// findAttachment returns the attachment corresponding to the RFC0593 format entry.
func findAttachment(formatType string,
	formats []issuecredential.Format, attachments []decorator.Attachment) (*decorator.Attachment, error) {
	// TODO not documented in the RFC but the intent of having `format` and `requests~attach` be an array
	//  is not to enable "bulk issuance" (issuance of multiple vcs), but to requests a single credential
	//  using different request formats.
	// TODO clarify precedence of different enabled middlewares if request has multiple attachment formats
	var attachID string

	for i := range formats {
		if formats[i].Format == formatType {
			attachID = formats[i].AttachID
			break
		}
	}

	if attachID == "" {
		return nil, errRFC0593DoesNotApply
	}

	for i := range attachments {
		if attachments[i].ID == attachID {
			return &attachments[i], nil
		}
	}

	return nil, fmt.Errorf(
		"format with attachID=%s indicates support for %s for no attachment with that ID was found",
		attachID, formatType,
	)
}

func unmarshalAttachmentContents(a *decorator.Attachment, v interface{}) error {
	contents, err := a.Data.Fetch()
	if err != nil {
		return fmt.Errorf("failed to fetch attachment contents: %w", err)
	}

	return json.Unmarshal(contents, v)
}

// TODO this should be configurable.
func validateCredentialRequestOptions(_ *CredentialSpec) error {
	// TODO validatations (eg. valid proofPurpose, created, credentialStatus, proofType)
	return nil
}

// TODO this should be configurable.
func validateCredentialRequestVC(_ *verifiable.Credential) error {
	// TODO validate claims in credential template
	return nil
}

type bbsSigner struct {
	km kms.KeyManager
	cr crypto.Crypto
	kh interface{}
}

func newBBSSigner(km kms.KeyManager, cr crypto.Crypto, keyHandle interface{}) *bbsSigner {
	return &bbsSigner{km: km, cr: cr, kh: keyHandle}
}

func (s *bbsSigner) Sign(data []byte) ([]byte, error) {
	return s.cr.SignMulti(s.textToLines(string(data)), s.kh)
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
