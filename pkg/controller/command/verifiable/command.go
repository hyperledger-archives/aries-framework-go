/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/doc/util/jwkkid"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	ariescrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	verifiablesigner "github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/jsonwebsignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/internal/kmssigner"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	didstore "github.com/hyperledger/aries-framework-go/pkg/store/did"
	verifiablestore "github.com/hyperledger/aries-framework-go/pkg/store/verifiable"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

var logger = log.New("aries-framework/command/verifiable")

// Error codes.
const (
	// InvalidRequestErrorCode is typically a code for invalid requests.
	InvalidRequestErrorCode = command.Code(iota + command.VC)

	// ValidateCredentialErrorCode for validate vc error.
	ValidateCredentialErrorCode

	// SaveCredentialErrorCode for save vc error.
	SaveCredentialErrorCode

	// GetCredentialErrorCode for get vc error.
	GetCredentialErrorCode

	// GetCredentialByNameErrorCode for get vc by name error.
	GetCredentialByNameErrorCode

	// GeneratePresentationErrorCode for get generate vp error.
	GeneratePresentationErrorCode

	// GeneratePresentationByIDErrorCode for get generate vp by vc id error.
	GeneratePresentationByIDErrorCode

	// SavePresentationErrorCode for save presentation error.
	SavePresentationErrorCode

	// GetPresentationErrorCode for get vp error.
	GetPresentationErrorCode

	// GetCredentialsErrorCode for get credential records.
	GetCredentialsErrorCode

	// GetPresentationsErrorCode for get presentation records.
	GetPresentationsErrorCode

	// SignCredentialErrorCode for sign credential error.
	SignCredentialErrorCode

	// RemoveCredentialByNameErrorCode for remove vc by name errors.
	RemoveCredentialByNameErrorCode

	// RemovePresentationByNameErrorCode for remove vp by name errors.
	RemovePresentationByNameErrorCode

	// DeriveCredentialErrorCode for derive credential error.
	DeriveCredentialErrorCode
)

// constants for the Verifiable protocol.
const (
	CommandName = "verifiable"

	// command methods.
	ValidateCredentialCommandMethod       = "ValidateCredential"
	SaveCredentialCommandMethod           = "SaveCredential"
	GetCredentialCommandMethod            = "GetCredential"
	GetCredentialByNameCommandMethod      = "GetCredentialByName"
	GetCredentialsCommandMethod           = "GetCredentials"
	SignCredentialCommandMethod           = "SignCredential"
	DeriveCredentialCommandMethod         = "DeriveCredential"
	SavePresentationCommandMethod         = "SavePresentation"
	GetPresentationCommandMethod          = "GetPresentation"
	GetPresentationsCommandMethod         = "GetPresentations"
	GeneratePresentationCommandMethod     = "GeneratePresentation"
	GeneratePresentationByIDCommandMethod = "GeneratePresentationByID"
	RemoveCredentialByNameCommandMethod   = "RemoveCredentialByName"
	RemovePresentationByNameCommandMethod = "RemovePresentationByName"

	// error messages.
	errEmptyCredentialName   = "credential name is mandatory"
	errEmptyPresentationName = "presentation name is mandatory"
	errEmptyCredentialID     = "credential id is mandatory"
	errEmptyPresentationID   = "presentation id is mandatory"
	errEmptyDID              = "did is mandatory"
	errEmptyCredential       = "credential is mandatory is mandatory"
	errEmptyFrame            = "frame is mandatory is mandatory"

	// log constants.
	vcID   = "vcID"
	vcName = "vcName"
	vpID   = "vpID"

	creatorParts = 2

	// Ed25519Signature2018 ed25519 signature suite.
	Ed25519Signature2018 = "Ed25519Signature2018"
	// JSONWebSignature2020 json web signature suite.
	JSONWebSignature2020 = "JsonWebSignature2020"

	// BbsBlsSignature2020 BBS signature suite.
	BbsBlsSignature2020 = "BbsBlsSignature2020"

	// Ed25519Curve ed25519 curve.
	Ed25519Curve = "Ed25519"

	// P256KeyCurve EC P-256 curve.
	P256KeyCurve = "P-256"

	// P384KeyCurve EC P-384 curve.
	P384KeyCurve = "P-384"

	// P521KeyCurve EC P-521 curve.
	P521KeyCurve = "P-521"

	// Ed25519VerificationKey ED25519 verification key type.
	Ed25519VerificationKey = "Ed25519VerificationKey"

	// JSONWebKey2020 verification key type.
	JSONWebKey2020 = "JsonWebKey2020"

	p256Alg = "ES256"
	p384Alg = "ES384"
	p521Alg = "ES521"
	edAlg   = "EdDSA"
)

type provable interface {
	AddLinkedDataProof(context *verifiable.LinkedDataProofContext, jsonldOpts ...jsonld.ProcessorOpts) error
}

type keyResolver interface {
	PublicKeyFetcher() verifiable.PublicKeyFetcher
}

func getKID(opts *ProofOptions) string {
	if opts.KID != "" {
		return opts.KID
	}

	idSplit := strings.Split(opts.VerificationMethod, "#")
	if len(idSplit) == creatorParts {
		return idSplit[1]
	}

	return ""
}

func newKMSSigner(keyManager kms.KeyManager, c ariescrypto.Crypto, kid string) (*kmssigner.KMSSigner, error) {
	keyHandler, err := keyManager.Get(kid)
	if err != nil {
		return nil, err
	}

	_, kt, err := keyManager.ExportPubKeyBytes(kid)
	if err != nil {
		return nil, err
	}

	return &kmssigner.KMSSigner{KeyType: kt, KeyHandle: keyHandler, Crypto: c}, nil
}

// provider contains dependencies for the verifiable command and is typically created by using aries.Context().
type provider interface {
	StorageProvider() storage.Provider
	VDRegistry() vdr.Registry
	KMS() kms.KeyManager
	Crypto() ariescrypto.Crypto
	JSONLDDocumentLoader() ld.DocumentLoader
}

// Command contains command operations provided by verifiable credential controller.
type Command struct {
	verifiableStore verifiablestore.Store
	didStore        *didstore.Store
	resolver        keyResolver
	ctx             provider
	documentLoader  ld.DocumentLoader
}

// New returns new verifiable credential controller command instance.
func New(p provider) (*Command, error) {
	verifiableStore, err := verifiablestore.New(p)
	if err != nil {
		return nil, fmt.Errorf("new vc store : %w", err)
	}

	didStore, err := didstore.New(p)
	if err != nil {
		return nil, fmt.Errorf("new did store : %w", err)
	}

	return &Command{
		verifiableStore: verifiableStore,
		didStore:        didStore,
		resolver:        verifiable.NewVDRKeyResolver(p.VDRegistry()),
		ctx:             p,
		documentLoader:  p.JSONLDDocumentLoader(),
	}, nil
}

// GetHandlers returns list of all commands supported by this controller command.
func (o *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(CommandName, ValidateCredentialCommandMethod, o.ValidateCredential),
		cmdutil.NewCommandHandler(CommandName, SaveCredentialCommandMethod, o.SaveCredential),
		cmdutil.NewCommandHandler(CommandName, GetCredentialCommandMethod, o.GetCredential),
		cmdutil.NewCommandHandler(CommandName, GetCredentialByNameCommandMethod, o.GetCredentialByName),
		cmdutil.NewCommandHandler(CommandName, GetCredentialsCommandMethod, o.GetCredentials),
		cmdutil.NewCommandHandler(CommandName, SignCredentialCommandMethod, o.SignCredential),
		cmdutil.NewCommandHandler(CommandName, DeriveCredentialCommandMethod, o.DeriveCredential),
		cmdutil.NewCommandHandler(CommandName, GeneratePresentationCommandMethod, o.GeneratePresentation),
		cmdutil.NewCommandHandler(CommandName, GeneratePresentationByIDCommandMethod, o.GeneratePresentationByID),
		cmdutil.NewCommandHandler(CommandName, SavePresentationCommandMethod, o.SavePresentation),
		cmdutil.NewCommandHandler(CommandName, GetPresentationCommandMethod, o.GetPresentation),
		cmdutil.NewCommandHandler(CommandName, GetPresentationsCommandMethod, o.GetPresentations),
		cmdutil.NewCommandHandler(CommandName, RemoveCredentialByNameCommandMethod, o.RemoveCredentialByName),
		cmdutil.NewCommandHandler(CommandName, RemovePresentationByNameCommandMethod, o.RemovePresentationByName),
	}
}

// ValidateCredential validates the verifiable credential.
func (o *Command) ValidateCredential(rw io.Writer, req io.Reader) command.Error {
	request := &Credential{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, ValidateCredentialCommandMethod, "request decode : "+err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	// we are only validating the VerifiableCredential here, hence ignoring other return values
	_, err = verifiable.ParseCredential([]byte(request.VerifiableCredential),
		verifiable.WithPublicKeyFetcher(verifiable.NewVDRKeyResolver(o.ctx.VDRegistry()).PublicKeyFetcher()),
		verifiable.WithJSONLDDocumentLoader(o.documentLoader))
	if err != nil {
		logutil.LogInfo(logger, CommandName, ValidateCredentialCommandMethod, "validate vc : "+err.Error())

		return command.NewValidationError(ValidateCredentialErrorCode, fmt.Errorf("validate vc : %w", err))
	}

	command.WriteNillableResponse(rw, nil, logger)

	logutil.LogDebug(logger, CommandName, ValidateCredentialCommandMethod, "success")

	return nil
}

// SaveCredential saves the verifiable credential to the store.
func (o *Command) SaveCredential(rw io.Writer, req io.Reader) command.Error {
	request := &CredentialExt{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, SaveCredentialCommandMethod, "request decode : "+err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	if request.Name == "" {
		logutil.LogDebug(logger, CommandName, SaveCredentialCommandMethod, errEmptyCredentialName)
		return command.NewValidationError(SaveCredentialErrorCode, fmt.Errorf(errEmptyCredentialName))
	}

	vc, err := verifiable.ParseCredential([]byte(request.VerifiableCredential),
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(o.documentLoader))
	if err != nil {
		logutil.LogError(logger, CommandName, SaveCredentialCommandMethod, "parse vc : "+err.Error())

		return command.NewValidationError(SaveCredentialErrorCode, fmt.Errorf("parse vc : %w", err))
	}

	err = o.verifiableStore.SaveCredential(request.Name, vc)
	if err != nil {
		logutil.LogError(logger, CommandName, SaveCredentialCommandMethod, "save vc : "+err.Error())

		return command.NewValidationError(SaveCredentialErrorCode, fmt.Errorf("save vc : %w", err))
	}

	command.WriteNillableResponse(rw, nil, logger)

	logutil.LogDebug(logger, CommandName, SaveCredentialCommandMethod, "success")

	return nil
}

// SavePresentation saves the presentation to the store.
func (o *Command) SavePresentation(rw io.Writer, req io.Reader) command.Error {
	request := &PresentationExt{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, SavePresentationCommandMethod, "request decode : "+err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	if request.Name == "" {
		logutil.LogDebug(logger, CommandName, SavePresentationCommandMethod, errEmptyPresentationName)
		return command.NewValidationError(SavePresentationErrorCode, fmt.Errorf(errEmptyPresentationName))
	}

	vp, err := verifiable.ParsePresentation(request.VerifiablePresentation,
		verifiable.WithPresDisabledProofCheck(),
		verifiable.WithPresJSONLDDocumentLoader(o.documentLoader))
	if err != nil {
		logutil.LogError(logger, CommandName, SavePresentationCommandMethod, "parse vp : "+err.Error())

		return command.NewValidationError(SavePresentationErrorCode, fmt.Errorf("parse vp : %w", err))
	}

	err = o.verifiableStore.SavePresentation(request.Name, vp)
	if err != nil {
		logutil.LogError(logger, CommandName, SavePresentationCommandMethod, "save vp : "+err.Error())

		return command.NewValidationError(SavePresentationErrorCode, fmt.Errorf("save vp : %w", err))
	}

	command.WriteNillableResponse(rw, nil, logger)

	logutil.LogDebug(logger, CommandName, SavePresentationCommandMethod, "success")

	return nil
}

// GetCredential retrieves the verifiable credential from the store.
func (o *Command) GetCredential(rw io.Writer, req io.Reader) command.Error {
	var request IDArg

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, GetCredentialCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	if request.ID == "" {
		logutil.LogDebug(logger, CommandName, GetCredentialCommandMethod, errEmptyCredentialID)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyCredentialID))
	}

	vc, err := o.verifiableStore.GetCredential(request.ID)
	if err != nil {
		logutil.LogError(logger, CommandName, GetCredentialCommandMethod, "get vc : "+err.Error(),
			logutil.CreateKeyValueString(vcID, request.ID))

		return command.NewValidationError(GetCredentialErrorCode, fmt.Errorf("get vc : %w", err))
	}

	vcBytes, err := vc.MarshalJSON()
	if err != nil {
		logutil.LogError(logger, CommandName, GetCredentialCommandMethod, "marshal vc : "+err.Error(),
			logutil.CreateKeyValueString(vcID, request.ID))

		return command.NewValidationError(GetCredentialErrorCode, fmt.Errorf("marshal vc : %w", err))
	}

	command.WriteNillableResponse(rw, &Credential{
		VerifiableCredential: string(vcBytes),
	}, logger)

	logutil.LogDebug(logger, CommandName, GetCredentialCommandMethod, "success",
		logutil.CreateKeyValueString(vcID, request.ID))

	return nil
}

// SignCredential adds proof to given verifiable credential.
func (o *Command) SignCredential(rw io.Writer, req io.Reader) command.Error {
	request := &SignCredentialRequest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, SignCredentialCommandMethod, "request decode : "+err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	//  if caches DID, local storage should be looked first
	didDoc, err := o.didStore.GetDID(request.DID)
	if err != nil {
		doc, resolveErr := o.ctx.VDRegistry().Resolve(request.DID)
		if resolveErr != nil {
			logutil.LogError(logger, CommandName, SignCredentialCommandMethod,
				"failed to get did doc from store or vdr: "+resolveErr.Error())

			return command.NewValidationError(SignCredentialErrorCode,
				fmt.Errorf("sign vc - failed to get did doc from store or vdr : %w", resolveErr))
		}

		didDoc = doc.DIDDocument
	}

	vc, err := verifiable.ParseCredential(request.Credential,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(o.documentLoader))
	if err != nil {
		logutil.LogError(logger, CommandName, SignCredentialCommandMethod, "parse credential : "+err.Error())

		return command.NewValidationError(SignCredentialErrorCode, fmt.Errorf("parse vc : %w", err))
	}

	err = o.addCredentialProof(vc, didDoc, request.ProofOptions)
	if err != nil {
		logutil.LogError(logger, CommandName, SignCredentialCommandMethod, "sign credential : "+err.Error())

		return command.NewValidationError(SignCredentialErrorCode, fmt.Errorf("sign credential : %w", err))
	}

	vcBytes, err := vc.MarshalJSON()
	if err != nil {
		logutil.LogError(logger, CommandName, SignCredentialCommandMethod, "marshal credential : "+err.Error())

		return command.NewValidationError(SignCredentialErrorCode, fmt.Errorf("marshal credential : %w", err))
	}

	command.WriteNillableResponse(rw, &SignCredentialResponse{
		VerifiableCredential: vcBytes,
	}, logger)

	logutil.LogDebug(logger, CommandName, SignCredentialCommandMethod, "success")

	return nil
}

// DeriveCredential derives a given verifiable credential for selective disclosure and returns it in response body.
func (o *Command) DeriveCredential(rw io.Writer, req io.Reader) command.Error {
	request := &DeriveCredentialRequest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, DeriveCredentialCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	if len(request.Credential) == 0 {
		logutil.LogDebug(logger, CommandName, DeriveCredentialCommandMethod, errEmptyCredential)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyCredential))
	}

	if len(request.Frame) == 0 {
		logutil.LogDebug(logger, CommandName, DeriveCredentialCommandMethod, errEmptyFrame)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyFrame))
	}

	credential, err := verifiable.ParseCredential(request.Credential, o.getCredentialOpts(request.SkipVerify)...)
	if err != nil {
		logutil.LogError(logger, CommandName, DeriveCredentialCommandMethod,
			fmt.Sprintf("failed to parse request vc : %s", err))

		return command.NewValidationError(DeriveCredentialErrorCode, fmt.Errorf("failed to parse request vc : %w", err))
	}

	derived, err := credential.GenerateBBSSelectiveDisclosure(request.Frame, []byte(request.Nonce),
		o.getCredentialOpts(false)...)
	if err != nil {
		logutil.LogError(logger, CommandName, DeriveCredentialCommandMethod,
			fmt.Sprintf("failed to derive credential : %s", err))

		return command.NewExecuteError(DeriveCredentialErrorCode, fmt.Errorf("failed to derive credential : %w", err))
	}

	vcBytes, err := derived.MarshalJSON()
	if err != nil {
		logutil.LogError(logger, CommandName, DeriveCredentialCommandMethod,
			fmt.Sprintf("failed to marshal derived credential : %s", err))

		return command.NewExecuteError(DeriveCredentialErrorCode,
			fmt.Errorf("failed to marshal derived credential  : %w", err))
	}

	command.WriteNillableResponse(rw, &Credential{
		VerifiableCredential: string(vcBytes),
	}, logger)

	logutil.LogDebug(logger, CommandName, DeriveCredentialCommandMethod, "success")

	return nil
}

// GetPresentation retrieves the verifiable presentation from the store.
func (o *Command) GetPresentation(rw io.Writer, req io.Reader) command.Error {
	var request IDArg

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, GetPresentationCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	if request.ID == "" {
		logutil.LogDebug(logger, CommandName, GetPresentationCommandMethod, errEmptyPresentationID)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyPresentationID))
	}

	vp, err := o.verifiableStore.GetPresentation(request.ID)
	if err != nil {
		logutil.LogError(logger, CommandName, GetPresentationCommandMethod, "get vp : "+err.Error(),
			logutil.CreateKeyValueString(vpID, request.ID))

		return command.NewValidationError(GetPresentationErrorCode, fmt.Errorf("get vp : %w", err))
	}

	vpBytes, err := vp.MarshalJSON()
	if err != nil {
		logutil.LogError(logger, CommandName, GetPresentationCommandMethod, "marshal vp : "+err.Error(),
			logutil.CreateKeyValueString(vpID, request.ID))

		return command.NewValidationError(GetPresentationErrorCode, fmt.Errorf("marshal vp : %w", err))
	}

	command.WriteNillableResponse(rw, &Presentation{
		VerifiablePresentation: vpBytes,
	}, logger)

	logutil.LogDebug(logger, CommandName, GetPresentationCommandMethod, "success",
		logutil.CreateKeyValueString(vpID, request.ID))

	return nil
}

// GetCredentialByName retrieves the verifiable credential by name from the store.
func (o *Command) GetCredentialByName(rw io.Writer, req io.Reader) command.Error {
	var request NameArg

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, GetCredentialByNameCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	if request.Name == "" {
		logutil.LogDebug(logger, CommandName, GetCredentialByNameCommandMethod, errEmptyCredentialName)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyCredentialName))
	}

	id, err := o.verifiableStore.GetCredentialIDByName(request.Name)
	if err != nil {
		logutil.LogError(logger, CommandName, GetCredentialByNameCommandMethod, "get vc by name : "+err.Error(),
			logutil.CreateKeyValueString(vcName, request.Name))

		return command.NewValidationError(GetCredentialByNameErrorCode, fmt.Errorf("get vc by name : %w", err))
	}

	command.WriteNillableResponse(rw, &verifiablestore.Record{
		Name: request.Name,
		ID:   id,
	}, logger)

	logutil.LogDebug(logger, CommandName, GetCredentialByNameCommandMethod, "success",
		logutil.CreateKeyValueString(vcName, request.Name))

	return nil
}

// GetCredentials retrieves the verifiable credential records containing name and fields of interest.
func (o *Command) GetCredentials(rw io.Writer, req io.Reader) command.Error {
	vcRecords, err := o.verifiableStore.GetCredentials()
	if err != nil {
		logutil.LogError(logger, CommandName, GetCredentialsCommandMethod, "get credential records : "+err.Error())

		return command.NewValidationError(GetCredentialsErrorCode, fmt.Errorf("get credential records : %w", err))
	}

	command.WriteNillableResponse(rw, &RecordResult{
		Result: vcRecords,
	}, logger)

	logutil.LogDebug(logger, CommandName, GetCredentialsCommandMethod, "success")

	return nil
}

// GetPresentations retrieves the verifiable presentation records containing name and fields of interest.
func (o *Command) GetPresentations(rw io.Writer, req io.Reader) command.Error {
	vpRecords, err := o.verifiableStore.GetPresentations()
	if err != nil {
		logutil.LogError(logger, CommandName, GetPresentationsCommandMethod, "get presentation records : "+err.Error())

		return command.NewValidationError(GetPresentationsErrorCode, fmt.Errorf("get presentation records : %w", err))
	}

	command.WriteNillableResponse(rw, &RecordResult{
		Result: vpRecords,
	}, logger)

	logutil.LogDebug(logger, CommandName, GetPresentationsCommandMethod, "success")

	return nil
}

// GeneratePresentation generates verifiable presentation from a verifiable credential.
func (o *Command) GeneratePresentation(rw io.Writer, req io.Reader) command.Error {
	request := &PresentationRequest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, GeneratePresentationCommandMethod, "request decode : "+err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	//  if caches DID, local storage should be looked first
	didDoc, err := o.didStore.GetDID(request.DID)
	if err != nil {
		doc, resolveErr := o.ctx.VDRegistry().Resolve(request.DID)
		if resolveErr != nil {
			logutil.LogError(logger, CommandName, GeneratePresentationCommandMethod,
				"failed to get did doc from store or vdr: "+resolveErr.Error())

			return command.NewValidationError(GeneratePresentationErrorCode,
				fmt.Errorf("generate vp - failed to get did doc from store or vdr : %w", resolveErr))
		}

		didDoc = doc.DIDDocument
	}

	credentials, presentation, opts, err := o.parsePresentationRequest(request, didDoc)
	if err != nil {
		logutil.LogError(logger, CommandName, GeneratePresentationCommandMethod,
			"parse presentation request: "+err.Error())

		return command.NewValidationError(GeneratePresentationErrorCode,
			fmt.Errorf("generate vp - parse presentation request: %w", err))
	}

	return o.generatePresentation(rw, credentials, presentation, didDoc.ID, opts)
}

// GeneratePresentationByID generates verifiable presentation from a stored verifiable credential.
func (o *Command) GeneratePresentationByID(rw io.Writer, req io.Reader) command.Error {
	request := &PresentationRequestByID{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, GeneratePresentationCommandMethod, "request decode : "+err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	if request.ID == "" {
		logutil.LogDebug(logger, CommandName, GetCredentialByNameCommandMethod, errEmptyCredentialID)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyCredentialID))
	}

	if request.DID == "" {
		logutil.LogDebug(logger, CommandName, GetCredentialByNameCommandMethod, errEmptyDID)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyDID))
	}

	vc, err := o.verifiableStore.GetCredential(request.ID)
	if err != nil {
		logutil.LogError(logger, CommandName, GetCredentialByNameCommandMethod, "get vc by id : "+err.Error(),
			logutil.CreateKeyValueString(vcID, request.ID))

		return command.NewValidationError(GeneratePresentationByIDErrorCode, fmt.Errorf("get vc by id : %w", err))
	}

	//  if caches DID, local storage should be looked first
	didDoc, err := o.didStore.GetDID(request.DID)
	if err != nil {
		doc, err := o.ctx.VDRegistry().Resolve(request.DID)
		if err != nil {
			logutil.LogError(logger, CommandName, GeneratePresentationByIDCommandMethod,
				"failed to get did doc from store or vdr: "+err.Error())

			return command.NewValidationError(GeneratePresentationByIDErrorCode,
				fmt.Errorf("generate vp by id - failed to get did doc from store or vdr : %w", err))
		}

		didDoc = doc.DIDDocument
	}

	return o.generatePresentationByID(rw, vc, didDoc, request.SignatureType)
}

// RemoveCredentialByName will remove a VC that matches the specified name from the verifiable store.
func (o *Command) RemoveCredentialByName(rw io.Writer, req io.Reader) command.Error {
	var request NameArg

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, RemoveCredentialByNameCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	if request.Name == "" {
		logutil.LogDebug(logger, CommandName, RemoveCredentialByNameCommandMethod, errEmptyCredentialName)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyCredentialName))
	}

	if err := o.verifiableStore.RemoveCredentialByName(request.Name); err != nil {
		logutil.LogError(logger, CommandName, RemoveCredentialByNameCommandMethod, "remove vc by name : "+err.Error(),
			logutil.CreateKeyValueString(vcName, request.Name))

		return command.NewValidationError(RemoveCredentialByNameErrorCode, fmt.Errorf("remove vc by name : %w", err))
	}

	command.WriteNillableResponse(rw, &RemoveCredentialByNameResponse{}, logger)

	logutil.LogDebug(logger, CommandName, RemoveCredentialByNameCommandMethod, "success",
		logutil.CreateKeyValueString(vcName, request.Name))

	return nil
}

// RemovePresentationByName will remove a VP that matches the specified name from the verifiable store.
func (o *Command) RemovePresentationByName(rw io.Writer, req io.Reader) command.Error {
	var request NameArg

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, RemovePresentationByNameCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	if request.Name == "" {
		logutil.LogDebug(logger, CommandName, RemovePresentationByNameCommandMethod, errEmptyCredentialName)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyCredentialName))
	}

	if err := o.verifiableStore.RemovePresentationByName(request.Name); err != nil {
		logutil.LogError(logger, CommandName, RemovePresentationByNameCommandMethod, "remove vp by name : "+err.Error(),
			logutil.CreateKeyValueString(vcName, request.Name))

		return command.NewValidationError(RemovePresentationByNameErrorCode, fmt.Errorf("remove vp by name : %w", err))
	}

	command.WriteNillableResponse(rw, &RemovePresentationByNameResponse{}, logger)

	logutil.LogDebug(logger, CommandName, RemovePresentationByNameCommandMethod, "success",
		logutil.CreateKeyValueString(vcName, request.Name))

	return nil
}

func (o *Command) generatePresentation(rw io.Writer, vcs []*verifiable.Credential, p *verifiable.Presentation,
	holder string, opts *ProofOptions) command.Error {
	// prepare vp
	vp, err := o.createAndSignPresentation(vcs, p, holder, opts)
	if err != nil {
		logutil.LogError(logger, CommandName, GeneratePresentationCommandMethod, "create and sign vp: "+err.Error())

		return command.NewValidationError(GeneratePresentationByIDErrorCode, fmt.Errorf("prepare vp: %w", err))
	}

	command.WriteNillableResponse(rw, &Presentation{
		VerifiablePresentation: vp,
	}, logger)

	logutil.LogDebug(logger, CommandName, GeneratePresentationCommandMethod, "success")

	return nil
}

func (o *Command) generatePresentationByID(rw io.Writer, vc *verifiable.Credential, didDoc *did.Doc,
	signatureType string) command.Error {
	// prepare vp by id
	vp, err := o.createAndSignPresentationByID(vc, didDoc, signatureType)
	if err != nil {
		logutil.LogError(logger, CommandName, GeneratePresentationCommandMethod, "create and sign vp by id: "+err.Error())

		return command.NewValidationError(GeneratePresentationByIDErrorCode, fmt.Errorf("prepare vp by id: %w", err))
	}

	//  TODO : VP is already implementing marshall json. Revisit #1643
	command.WriteNillableResponse(rw, &Presentation{
		VerifiablePresentation: vp,
	}, logger)

	logutil.LogDebug(logger, CommandName, GeneratePresentationCommandMethod, "success")

	return nil
}

func (o *Command) createAndSignPresentation(credentials []*verifiable.Credential, vp *verifiable.Presentation,
	holder string, opts *ProofOptions) ([]byte, error) {
	var err error
	if vp == nil {
		vp, err = verifiable.NewPresentation(verifiable.WithCredentials(credentials...))
		if err != nil {
			return nil, fmt.Errorf("failed to set credentials: %w", err)
		}
	}

	// set holder
	vp.Holder = holder

	// Add proofs to vp - sign presentation
	err = o.addLinkedDataProof(vp, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to sign vp: %w", err)
	}

	return vp.MarshalJSON()
}

func (o *Command) createAndSignPresentationByID(vc *verifiable.Credential,
	didDoc *did.Doc, signatureType string) ([]byte, error) {
	// pk is verification method
	pk, err := getDefaultVerificationMethod(didDoc)
	if err != nil {
		return nil, err
	}

	vp, err := verifiable.NewPresentation(verifiable.WithCredentials(vc))
	if err != nil {
		return nil, fmt.Errorf("failed to create vp by ID: %w", err)
	}

	err = o.addLinkedDataProof(vp, &ProofOptions{VerificationMethod: pk, SignatureType: signatureType})
	if err != nil {
		return nil, fmt.Errorf("failed to sign vp by ID: %w", err)
	}

	return vp.MarshalJSON()
}

func (o *Command) addLinkedDataProof(p provable, opts *ProofOptions) error {
	s, err := newKMSSigner(o.ctx.KMS(), o.ctx.Crypto(), getKID(opts))
	if err != nil {
		return err
	}

	var signatureSuite verifiablesigner.SignatureSuite

	switch opts.SignatureType {
	case Ed25519Signature2018:
		signatureSuite = ed25519signature2018.New(suite.WithSigner(s))
	case JSONWebSignature2020:
		signatureSuite = jsonwebsignature2020.New(suite.WithSigner(s))
	case BbsBlsSignature2020:
		s.MultiMsg = true
		signatureSuite = bbsblssignature2020.New(suite.WithSigner(s))
	default:
		return fmt.Errorf("signature type unsupported %s", opts.SignatureType)
	}

	signatureRepresentation := verifiable.SignatureJWS

	if opts.SignatureRepresentation == nil {
		opts.SignatureRepresentation = &signatureRepresentation
	}

	signingCtx := &verifiable.LinkedDataProofContext{
		VerificationMethod:      opts.VerificationMethod,
		SignatureRepresentation: *opts.SignatureRepresentation,
		SignatureType:           opts.SignatureType,
		Suite:                   signatureSuite,
		Created:                 opts.Created,
		Domain:                  opts.Domain,
		Challenge:               opts.Challenge,
		Purpose:                 opts.proofPurpose,
	}

	err = p.AddLinkedDataProof(signingCtx, jsonld.WithDocumentLoader(o.documentLoader))
	if err != nil {
		return fmt.Errorf("failed to add linked data proof: %w", err)
	}

	return nil
}

func (o *Command) parseVerifiableCredentials(request *PresentationRequest,
	didDoc *did.Doc) ([]*verifiable.Credential, *verifiable.Presentation, *ProofOptions, error) {
	var vcs []*verifiable.Credential

	for _, vcRaw := range request.VerifiableCredentials {
		vc, e := verifiable.ParseCredential(vcRaw, o.getCredentialOpts(request.SkipVerify)...)

		if e != nil {
			logutil.LogError(logger, CommandName, GeneratePresentationCommandMethod,
				"failed to parse credential from request, invalid credential: "+e.Error())
			return nil, nil, nil, fmt.Errorf("parse credential failed: %w", e)
		}

		vcs = append(vcs, vc)
	}

	opts, err := prepareOpts(request.ProofOptions, didDoc, did.Authentication)
	if err != nil {
		logutil.LogError(logger, CommandName, GeneratePresentationCommandMethod,
			"failed to prepare proof options: "+err.Error())
		return nil, nil, nil, fmt.Errorf("failed to prepare proof options: %w", err)
	}

	return vcs, nil, opts, nil
}

func (o *Command) parsePresentation(request *PresentationRequest,
	didDoc *did.Doc) ([]*verifiable.Credential, *verifiable.Presentation, *ProofOptions, error) {
	presentation, err := verifiable.ParsePresentation(
		request.Presentation,
		verifiable.WithPresDisabledProofCheck(),
		verifiable.WithPresJSONLDDocumentLoader(o.documentLoader),
	)
	if err != nil {
		logutil.LogError(logger, CommandName, GeneratePresentationCommandMethod,
			"failed to parse presentation from request: "+err.Error())
		return nil, nil, nil, fmt.Errorf("parse presentation failed: %w", err)
	}

	opts, err := prepareOpts(request.ProofOptions, didDoc, did.Authentication)
	if err != nil {
		logutil.LogError(logger, CommandName, GeneratePresentationCommandMethod,
			"failed to prepare proof options: "+err.Error())
		return nil, nil, nil, fmt.Errorf("failed to prepare proof options: %w", err)
	}

	return nil, presentation, opts, nil
}

func (o *Command) parsePresentationRequest(request *PresentationRequest,
	didDoc *did.Doc) ([]*verifiable.Credential, *verifiable.Presentation, *ProofOptions, error) {
	if request.ProofOptions == nil || request.SignatureType == "" {
		return nil, nil, nil, fmt.Errorf("invalid request, signature type empty")
	}

	if len(request.VerifiableCredentials) > 0 {
		return o.parseVerifiableCredentials(request, didDoc)
	}

	if len(request.Presentation) > 0 {
		return o.parsePresentation(request, didDoc)
	}

	return nil, nil, nil, fmt.Errorf("invalid request, no valid credentials/presentation found")
}

func (o *Command) getCredentialOpts(disableProofCheck bool) []verifiable.CredentialOpt {
	if disableProofCheck {
		return []verifiable.CredentialOpt{
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(o.documentLoader),
		}
	}

	return []verifiable.CredentialOpt{
		verifiable.WithPublicKeyFetcher(
			verifiable.NewVDRKeyResolver(o.ctx.VDRegistry()).PublicKeyFetcher(),
		),
		verifiable.WithJSONLDDocumentLoader(o.documentLoader),
	}
}

// nolint:funlen,gocyclo
func prepareOpts(opts *ProofOptions, didDoc *did.Doc, method did.VerificationRelationship) (*ProofOptions, error) {
	if opts == nil {
		opts = &ProofOptions{}
	}

	var err error

	opts.proofPurpose, err = getProofPurpose(method)
	if err != nil {
		return nil, err
	}

	vmType := ""

	switch opts.SignatureType {
	case "Ed25519Signature2018":
		vmType = "Ed25519VerificationKey2018"
	case "BbsBlsSignature2020":
		vmType = "Bls12381G2Key2020"
	}

	vMs := didDoc.VerificationMethods(method)[method]

	vmMatched := opts.VerificationMethod == ""

	for _, vm := range vMs {
		if opts.VerificationMethod != "" {
			// if verification method is provided as an option, then validate if it belongs to given method
			if opts.VerificationMethod == vm.VerificationMethod.ID {
				vmMatched = true

				break
			}

			continue
		} else {
			// by default first authentication public key

			// skip verification methods that don't match the type needed for the signature
			if vmType != "" && vm.VerificationMethod.Type != vmType {
				continue
			}

			opts.VerificationMethod = vm.VerificationMethod.ID

			break
		}
	}

	if !vmMatched {
		return nil, fmt.Errorf("unable to find matching '%s' key IDs for given verification method", opts.proofPurpose)
	}

	// this is the fallback logic kept for DIDs not having authentication method
	// TODO to be removed [Issue #1693]
	if opts.VerificationMethod == "" {
		logger.Warnf("Could not find matching verification method for '%s' proof purpose", opts.proofPurpose)

		var defaultVM string

		defaultVM, err = getDefaultVerificationMethod(didDoc)
		if err != nil {
			return nil, fmt.Errorf("failed to get default verification method: %w", err)
		}

		opts.VerificationMethod = defaultVM
	}

	// if the VM key has #key-X, then extract key from Value/JWK value and build KID accordingly.
	if strings.Index(opts.VerificationMethod, "#key-") > 0 {
		err = buildKIDOption(opts, didDoc.VerificationMethod)
		if err != nil {
			return nil, fmt.Errorf("build KMS KID error: %w", err)
		}
	}

	return opts, nil
}

func buildKIDOption(opts *ProofOptions, vms []did.VerificationMethod) error {
	for _, vm := range vms {
		if opts.VerificationMethod == vm.ID {
			if len(vm.Value) > 0 {
				kt := kms.ED25519Type

				switch vm.Type {
				case Ed25519VerificationKey:
				case JSONWebKey2020:
					kt = kmsKeyTypeByJWKCurve(vm.JSONWebKey().Crv)
				}

				kid, err := jwkkid.CreateKID(vm.Value, kt)
				if err != nil {
					return fmt.Errorf("failed to get default verification method: %w", err)
				}

				opts.KID = kid
			}
		}
	}

	return nil
}

func kmsKeyTypeByJWKCurve(crv string) kms.KeyType {
	kt := kms.ED25519Type

	switch crv {
	case Ed25519Curve:
	case P256KeyCurve:
		kt = kms.ECDSAP256TypeIEEEP1363
	case P384KeyCurve:
		kt = kms.ECDSAP384TypeIEEEP1363
	case P521KeyCurve:
		kt = kms.ECDSAP521IEEEP1363
	}

	return kt
}

// TODO default verification method logic needs to be revisited, [Issue #1693].
func getDefaultVerificationMethod(didDoc *did.Doc) (string, error) {
	switch {
	case len(didDoc.VerificationMethod) > 0:
		var publicKeyID string

		for _, k := range didDoc.VerificationMethod {
			if strings.HasPrefix(k.Type, Ed25519VerificationKey) {
				publicKeyID = k.ID

				break
			}
		}

		// if there isn't any ed25519 key then pick first one
		if publicKeyID == "" {
			publicKeyID = didDoc.VerificationMethod[0].ID
		}

		// todo Review this logic  #1640
		if !isDID(publicKeyID) {
			return didDoc.ID + publicKeyID, nil
		}

		return publicKeyID, nil
	case len(didDoc.Authentication) > 0:
		return didDoc.Authentication[0].VerificationMethod.ID, nil
	default:
		return "", errors.New("public key not found in DID Document")
	}
}

func (o *Command) addCredentialProof(vc *verifiable.Credential, didDoc *did.Doc, opts *ProofOptions) error {
	var err error

	opts, err = prepareOpts(opts, didDoc, did.AssertionMethod)
	if err != nil {
		return err
	}

	return o.addLinkedDataProof(vc, opts)
}

func isDID(str string) bool {
	return strings.HasPrefix(str, "did:")
}

func getProofPurpose(method did.VerificationRelationship) (string, error) {
	if method != did.Authentication && method != did.AssertionMethod {
		return "", fmt.Errorf("unsupported proof purpose, only authentication or assertionMethod are supported")
	}

	if method == did.Authentication {
		return "authentication", nil
	}

	return "assertionMethod", nil
}
