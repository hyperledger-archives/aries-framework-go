/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rfc0593

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
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
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	// ProofVCDetailFormat is the attachment format used in the proposal, offer, and request message attachments.
	ProofVCDetailFormat = "aries/ld-proof-vc-detail@v1.0"
	// ProofVCFormat is the attachment format used in the issue-credential message attachment.
	ProofVCFormat = "aries/ld-proof-vc@v1.0"
	// StoreName is the name of the transient store used by AutoExecute.
	StoreName       = "RFC0593TransientStore"
	mediaTypeJSON   = "application/json"
	mediaTypeJSONLD = "application/ld+json"
)

// ErrRFC0593NotApplicable indicates RFC0593 does not apply to the message being handled because
// it does not contain an attachment with the proof format identifiers.
//
// See also: ProofVCDetailFormat, ProofVCFormat.
var ErrRFC0593NotApplicable = errors.New("RFC0593 is not applicable")

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
//         // handle events from issue-credential that do not conform to RFC0593
//     }
//
// Note: use the protocol Middleware if the protocol needs to be started with a request-credential message.
//
// See also: service.AutoExecuteActionEvent.
func AutoExecute(p Provider, next chan service.DIDCommAction) func(chan service.DIDCommAction) { // nolint:funlen
	return func(events chan service.DIDCommAction) {
		// TODO make AutoExecute return an error if the store cannot be opened?
		db, storeErr := p.ProtocolStateStorageProvider().OpenStore(StoreName)

		for event := range events {
			if storeErr != nil {
				event.Stop(fmt.Errorf("rfc0593: failed to open transient store: %w", storeErr))

				continue
			}

			var (
				arg     interface{}
				options *CredentialSpecOptions
				err     error
			)

			switch event.Message.Type() {
			case issuecredential.ProposeCredentialMsgTypeV2:
				arg, options, err = ReplayProposal(p, event.Message)
				err = saveOptionsIfNoError(err, db, event.Message, options)
			case issuecredential.OfferCredentialMsgTypeV2:
				arg, options, err = ReplayOffer(p, event.Message)
				err = saveOptionsIfNoError(err, db, event.Message, options)
			case issuecredential.RequestCredentialMsgTypeV2:
				arg, options, err = IssueCredential(p, event.Message)
				err = saveOptionsIfNoError(err, db, event.Message, options)
			case issuecredential.IssueCredentialMsgTypeV2:
				// TODO credential issued to us. We have middleware that automatically saves the credentials.
				//  Should this package ensure it's saved?
				//  Should we ensure issued VC is up to spec?
				options, err = fetchCredentialSpecOptions(db, event.Message)
				if err != nil {
					err = fmt.Errorf("failed to fetch credential spec options to validate credential: %w", err)

					break
				}

				arg, err = VerifyCredential(p, options, uuid.New().String(), event.Message)
				err = deleteOptionsIfNoError(err, db, event.Message)
			default:
				next <- event

				continue
			}

			if errors.Is(err, ErrRFC0593NotApplicable) {
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
//             arg, options, err := ReplayProposal(p, event.Message)
//             if errors.Is(err, ErrRFC0593NotApplicable) {
//                 // inspect and handle the event yourself
//                 arg, err = handleEvent(event)
//             }
//
//             if err != nil {
//                 event.Stop(err)
//             }
//
//             // inspect options
//
//             event.Continue(arg)
//         }
//     }
func ReplayProposal(p JSONLDDocumentLoaderProvider,
	msg service.DIDCommMsg) (interface{}, *CredentialSpecOptions, error) {
	proposal := &issuecredential.ProposeCredentialV2{}

	err := msg.Decode(proposal)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode msg type %s: %w", msg.Type(), err)
	}

	payload, err := GetCredentialSpec(p, proposal.Formats, proposal.FiltersAttach)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract payload for msg type %s: %w", msg.Type(), err)
	}

	attachID := uuid.New().String()

	return issuecredential.WithOfferCredentialV2(&issuecredential.OfferCredentialV2{
		Type:    issuecredential.OfferCredentialMsgTypeV2,
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
	}), payload.Options, nil
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
//             arg, options, err := ReplayOffer(p, event.Message)
//             if errors.Is(err, ErrRFC0593NotApplicable) {
//                 // inspect and handle the event yourself
//                 arg, err = handleEvent(event)
//             }
//
//             if err != nil {
//                 event.Stop(err)
//             }
//
//             // inspect options
//
//             event.Continue(arg)
//         }
//     }
func ReplayOffer(p JSONLDDocumentLoaderProvider, msg service.DIDCommMsg) (interface{}, *CredentialSpecOptions, error) {
	offer := &issuecredential.OfferCredentialV2{}

	err := msg.Decode(offer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode msg type %s: %w", msg.Type(), err)
	}

	payload, err := GetCredentialSpec(p, offer.Formats, offer.OffersAttach)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract payoad for msg type %s: %w", msg.Type(), err)
	}

	attachID := uuid.New().String()

	return issuecredential.WithRequestCredentialV2(&issuecredential.RequestCredentialV2{
		Type:    issuecredential.RequestCredentialMsgTypeV2,
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
	}), payload.Options, nil
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
//             arg, options, err := IssueCredential(p, event.Message)
//             if errors.Is(err, ErrRFC0593NotApplicable) {
//                 // inspect and handle the event yourself
//                 arg, err = handleEvent(event)
//             }
//
//             if err != nil {
//                 event.Stop(err)
//             }
//
//             // inspect options
//
//             event.Continue(arg)
//         }
//     }
func IssueCredential(p Provider, msg service.DIDCommMsg) (interface{}, *CredentialSpecOptions, error) {
	request := &issuecredential.RequestCredentialV2{}

	err := msg.Decode(request)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode msg type %s: %w", msg.Type(), err)
	}

	payload, err := GetCredentialSpec(p, request.Formats, request.RequestsAttach)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get payload for msg type %s: %w", msg.Type(), err)
	}

	ic, err := CreateIssueCredentialMsg(p, payload)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create issue-credential msg: %w", err)
	}

	ic.Comment = fmt.Sprintf("response to request with id %s", msg.ID())

	return issuecredential.WithIssueCredentialV2(ic), payload.Options, nil
}

// CreateIssueCredentialMsg creates an issue-credential message using the credential spec.
func CreateIssueCredentialMsg(p Provider, spec *CredentialSpec) (*issuecredential.IssueCredentialV2, error) {
	vc, err := verifiable.ParseCredential(
		spec.Template,
		verifiable.WithDisabledProofCheck(), // no proof is expected in this credential
		verifiable.WithJSONLDDocumentLoader(p.JSONLDDocumentLoader()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse vc: %w", err)
	}

	ctx, err := ldProofContext(p, spec.Options)
	if err != nil {
		return nil, fmt.Errorf("failed to determine the LD context required to add a proof: %w", err)
	}

	err = vc.AddLinkedDataProof(ctx, jsonld.WithDocumentLoader(p.JSONLDDocumentLoader()))
	if err != nil {
		return nil, fmt.Errorf("failed to add LD proof: %w", err)
	}

	attachID := uuid.New().String()

	return &issuecredential.IssueCredentialV2{
		Type: issuecredential.IssueCredentialMsgTypeV2,
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
	}, nil
}

// VerifyCredential verifies the credential received in an RFC0593 issue-credential message.
//
// The credential is validated to ensure it complies with the given CredentialSpecOptions.
//
// The credential will then be saved with the given name.
//
// Usage:
//     var p Provider = ...
//     client := issuecredential.Client = ...
//     var events chan service.DIDCommAction = ...
//     err := client.RegisterActionEvent(events)
//     if err != nil {
//         panic(err)
//     }
//     var options *CredentialSpecOptions
//     for event := range events {
//         switch event.Message.Type() {
//         case issuecredential.OfferCredentialMsgType:
//             arg, opts, err := ReplayOffer(p, event.Message)
//             if err != nil {
//                 event.Stop(err)
//             }
//
//             options = opts
//             event.Continue(arg)
//         case issuecredential.IssueCredentialMsgType:
//             arg, err := VerifyCredential(p, options, "my_vc", event.Message)
//             if errors.Is(err, ErrRFC0593NotApplicable) {
//                 // inspect and handle the event yourself
//                 arg, err = handleEvent(event)
//             }
//
//             if err != nil {
//                 event.Stop(err)
//             }
//
//             event.Continue(arg)
//         }
//     }
func VerifyCredential(p Provider,
	options *CredentialSpecOptions, name string, msg service.DIDCommMsg) (interface{}, error) {
	issueCredential := &issuecredential.IssueCredentialV2{}

	err := msg.Decode(issueCredential)
	if err != nil {
		return nil, fmt.Errorf("failed to decode msg type %s: %w", msg.Type(), err)
	}

	attachment, err := FindAttachment(ProofVCFormat, issueCredential.Formats, issueCredential.CredentialsAttach)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch attachment with format %s: %w", ProofVCFormat, err)
	}

	raw, err := attachment.Data.Fetch()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch the attachment's contents: %w", err)
	}

	vc, err := verifiable.ParseCredential(
		raw,
		verifiable.WithJSONLDDocumentLoader(p.JSONLDDocumentLoader()),
		verifiable.WithPublicKeyFetcher(verifiable.NewVDRKeyResolver(p.VDRegistry()).PublicKeyFetcher()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse vc: %w", err)
	}

	err = validateCredentialRequestVC(vc)
	if err != nil {
		return nil, fmt.Errorf("invalid credential: %w", err)
	}

	err = ValidateVCMatchesSpecOptions(vc, options)
	if err != nil {
		return nil, fmt.Errorf("invalid credential: %w", err)
	}

	return issuecredential.WithFriendlyNames(name), nil
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

// GetCredentialSpec extracts the CredentialSpec from the formats and attachments.
func GetCredentialSpec(p JSONLDDocumentLoaderProvider,
	formats []issuecredential.Format, attachments []decorator.Attachment) (*CredentialSpec, error) {
	attachment, err := FindAttachment(ProofVCDetailFormat, formats, attachments)
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

// FindAttachment returns the attachment corresponding to the RFC0593 format entry.
func FindAttachment(formatType string,
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
		return nil, ErrRFC0593NotApplicable
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

// ValidateVCMatchesSpecOptions ensures the vc matches the spec.
func ValidateVCMatchesSpecOptions(vc *verifiable.Credential, options *CredentialSpecOptions) error { // nolint:gocyclo
	if len(vc.Proofs) == 0 {
		return errors.New("vc is missing a proof")
	}

	// TODO which proof?
	proof := vc.Proofs[0]

	if !reflect.DeepEqual(options.ProofType, proof["type"]) {
		return fmt.Errorf("expected proofType %s but got %s", options.ProofType, proof["type"])
	}

	if !reflect.DeepEqual(options.Domain, proof["domain"]) {
		return fmt.Errorf("expected domain %s but got %s", options.Domain, proof["domain"])
	}

	if !reflect.DeepEqual(options.Challenge, proof["challenge"]) {
		return fmt.Errorf("expected challenge %s but got %s", options.Challenge, proof["challenge"])
	}

	if options.ProofPurpose != "" && !reflect.DeepEqual(options.ProofPurpose, proof["proofPurpose"]) {
		return fmt.Errorf("expected proofPurpose %s but got %s", options.ProofPurpose, proof["proofPurpose"])
	}

	if options.Status != nil {
		if vc.Status == nil {
			return fmt.Errorf("expected credentialStatus of type %s but VC does not have any", options.Status.Type)
		}

		if options.Status.Type != vc.Status.Type {
			return fmt.Errorf("expected credentialStatus of type %s but got %s", options.Status.Type, vc.Status.Type)
		}
	}

	if options.Created == "" {
		return fmt.Errorf("missing 'created' on proof") // RFC: default current system time it unspecified in options
	}

	if options.Created != "" && !reflect.DeepEqual(options.Created, proof["created"]) {
		return fmt.Errorf("expected proof.created %s but got %s", options.Created, proof["created"])
	}

	return nil
}

func saveOptionsIfNoError(err error, s storage.Store, msg service.DIDCommMsg, options *CredentialSpecOptions) error {
	if err != nil {
		return err
	}

	thid, err := msg.ThreadID()
	if err != nil {
		return fmt.Errorf("failed to get message's threadID: %w", err)
	}

	raw, err := json.Marshal(options)
	if err != nil {
		return fmt.Errorf("failed to marshal options: %w", err)
	}

	return s.Put(thid, raw)
}

func fetchCredentialSpecOptions(s storage.Store, msg service.DIDCommMsg) (*CredentialSpecOptions, error) {
	thid, err := msg.ThreadID()
	if err != nil {
		return nil, fmt.Errorf("failed to get message's threadID: %w", err)
	}

	raw, err := s.Get(thid)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch options from store with threadID %s: %w", thid, err)
	}

	options := &CredentialSpecOptions{}

	return options, json.Unmarshal(raw, options)
}

func deleteOptionsIfNoError(err error, s storage.Store, msg service.DIDCommMsg) error {
	if err != nil {
		return err
	}

	thid, err := msg.ThreadID()
	if err != nil {
		return fmt.Errorf("failed to get message's threadID: %w", err)
	}

	return s.Delete(thid)
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
