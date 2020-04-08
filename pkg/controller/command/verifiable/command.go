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

	"github.com/btcsuite/btcutil/base58"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	verifiablestore "github.com/hyperledger/aries-framework-go/pkg/store/verifiable"
)

var logger = log.New("aries-framework/command/verifiable")

// Error codes
const (
	// InvalidRequestErrorCode is typically a code for invalid requests
	InvalidRequestErrorCode = command.Code(iota + command.VC)

	// ValidateCredential for validate vc error
	ValidateCredentialErrorCode

	// SaveCredentialErrorCode for save vc error
	SaveCredentialErrorCode

	// GetCredentialErrorCode for get vc error
	GetCredentialErrorCode

	// GetCredentialErrorCode for get vc by name error
	GetCredentialByNameErrorCode

	// GeneratePresentationErrorCode for get generate vp error
	GeneratePresentationErrorCode

	// GeneratePresentationByIDErrorCode for get generate vp by vc id error
	GeneratePresentationByIDErrorCode
)

const (
	// command name
	commandName = "verifiable"

	// command methods
	validateCredentialCommandMethod       = "ValidateCredential"
	saveCredentialCommandMethod           = "SaveCredential"
	getCredentialCommandMethod            = "GetCredential"
	getCredentialByNameCommandMethod      = "GetCredentialByName"
	getCredentialsCommandMethod           = "GetCredentials"
	generatePresentationCommandMethod     = "GeneratePresentation"
	generatePresentationByIDCommandMethod = "GeneratePresentationByID"

	// error messages
	errEmptyCredentialName = "credential name is mandatory"
	errEmptyCredentialID   = "credential id is mandatory"

	// log constants
	vcID   = "vcID"
	vcName = "vcName"

	creatorParts = 2
	// Ed25519VerificationKey supported Verification Key types
	Ed25519VerificationKey = "Ed25519VerificationKey"
)

type keyResolver interface {
	PublicKeyFetcher() verifiable.PublicKeyFetcher
}

type signer interface {
	// Sign will sign document and return signature
	Sign(data []byte) ([]byte, error)
}

type kmsSigner struct {
	kms   legacykms.KMS
	keyID string
}

func newKMSSigner(kms legacykms.KMS, kResolver keyResolver, creator string) (*kmsSigner, error) {
	// creator will contain didID#keyID
	idSplit := strings.Split(creator, "#")
	if len(idSplit) != creatorParts {
		return nil, fmt.Errorf("wrong id %s to resolve", idSplit)
	}

	k, err := kResolver.PublicKeyFetcher()(idSplit[0], "#"+idSplit[1])
	if err != nil {
		return nil, err
	}

	keyID := base58.Encode(k.Value)

	return &kmsSigner{kms: kms, keyID: keyID}, nil
}

func (s *kmsSigner) Sign(data []byte) ([]byte, error) {
	return s.kms.SignMessage(data, s.keyID)
}


// provider contains dependencies for the verifiable command and is typically created by using aries.Context().
type provider interface {
	StorageProvider() storage.Provider
}

// Command contains command operations provided by verifiable credential controller.
type Command struct {
	verifiableStore *verifiablestore.Store
	kms       legacykms.KMS
	kResolver keyResolver
}

// New returns new verifiable credential controller command instance.
func New(p provider, kms legacykms.KMS, kResolver keyResolver) (*Command, error) {
	verifiableStore, err := verifiablestore.New(p)
	if err != nil {
		return nil, fmt.Errorf("new vc store : %w", err)
	}

	return &Command{
		verifiableStore: verifiableStore,
		kms:kms,
		kResolver:kResolver,
	}, nil
}

// GetHandlers returns list of all commands supported by this controller command.
func (o *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(commandName, validateCredentialCommandMethod, o.ValidateCredential),
		cmdutil.NewCommandHandler(commandName, saveCredentialCommandMethod, o.SaveCredential),
		cmdutil.NewCommandHandler(commandName, getCredentialCommandMethod, o.GetCredential),
		cmdutil.NewCommandHandler(commandName, getCredentialByNameCommandMethod, o.GetCredentialByName),
		cmdutil.NewCommandHandler(commandName, getCredentialsCommandMethod, o.GetCredentials),
		cmdutil.NewCommandHandler(commandName, generatePresentationCommandMethod, o.GeneratePresentation),
		cmdutil.NewCommandHandler(commandName, generatePresentationByIDCommandMethod, o.GeneratePresentationByID),
	}
}

// ValidateCredential validates the verifiable credential.
func (o *Command) ValidateCredential(rw io.Writer, req io.Reader) command.Error {
	request := &Credential{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, commandName, validateCredentialCommandMethod, "request decode : "+err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	// we are only validating the VerifiableCredential here, hence ignoring other return values
	// TODO https://github.com/hyperledger/aries-framework-go/issues/1316 VC Validate Command - Add keys for proof
	//  verification as options to the function.
	_, _, err = verifiable.NewCredential([]byte(request.VerifiableCredential))
	if err != nil {
		logutil.LogInfo(logger, commandName, validateCredentialCommandMethod, "validate vc : "+err.Error())

		return command.NewValidationError(ValidateCredentialErrorCode, fmt.Errorf("validate vc : %w", err))
	}

	command.WriteNillableResponse(rw, nil, logger)

	logutil.LogDebug(logger, commandName, validateCredentialCommandMethod, "success")

	return nil
}

// SaveCredential saves the verifiable credential to the store.
func (o *Command) SaveCredential(rw io.Writer, req io.Reader) command.Error {
	request := &CredentialExt{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, commandName, saveCredentialCommandMethod, "request decode : "+err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	if request.Name == "" {
		logutil.LogDebug(logger, commandName, saveCredentialCommandMethod, errEmptyCredentialName)
		return command.NewValidationError(SaveCredentialErrorCode, fmt.Errorf(errEmptyCredentialName))
	}

	vc, err := verifiable.NewUnverifiedCredential([]byte(request.VerifiableCredential))
	if err != nil {
		logutil.LogError(logger, commandName, saveCredentialCommandMethod, "parse vc : "+err.Error())

		return command.NewValidationError(SaveCredentialErrorCode, fmt.Errorf("parse vc : %w", err))
	}

	err = o.verifiableStore.SaveCredential(request.Name, vc)
	if err != nil {
		logutil.LogError(logger, commandName, saveCredentialCommandMethod, "save vc : "+err.Error())

		return command.NewValidationError(SaveCredentialErrorCode, fmt.Errorf("save vc : %w", err))
	}

	command.WriteNillableResponse(rw, nil, logger)

	logutil.LogDebug(logger, commandName, saveCredentialCommandMethod, "success")

	return nil
}

// GetCredential retrieves the verifiable credential from the store.
func (o *Command) GetCredential(rw io.Writer, req io.Reader) command.Error {
	var request IDArg

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, commandName, getCredentialCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	if request.ID == "" {
		logutil.LogDebug(logger, commandName, getCredentialCommandMethod, errEmptyCredentialID)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyCredentialID))
	}

	vc, err := o.verifiableStore.GetCredential(request.ID)
	if err != nil {
		logutil.LogError(logger, commandName, getCredentialCommandMethod, "get vc : "+err.Error(),
			logutil.CreateKeyValueString(vcID, request.ID))

		return command.NewValidationError(GetCredentialErrorCode, fmt.Errorf("get vc : %w", err))
	}

	vcBytes, err := vc.MarshalJSON()
	if err != nil {
		logutil.LogError(logger, commandName, getCredentialCommandMethod, "marshal vc : "+err.Error(),
			logutil.CreateKeyValueString(vcID, request.ID))

		return command.NewValidationError(GetCredentialErrorCode, fmt.Errorf("marshal vc : %w", err))
	}

	command.WriteNillableResponse(rw, &Credential{
		VerifiableCredential: string(vcBytes),
	}, logger)

	logutil.LogDebug(logger, commandName, getCredentialCommandMethod, "success",
		logutil.CreateKeyValueString(vcID, request.ID))

	return nil
}

// GetCredentialByName retrieves the verifiable credential by name from the store.
func (o *Command) GetCredentialByName(rw io.Writer, req io.Reader) command.Error {
	var request NameArg

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, commandName, getCredentialByNameCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	if request.Name == "" {
		logutil.LogDebug(logger, commandName, getCredentialByNameCommandMethod, errEmptyCredentialName)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyCredentialName))
	}

	id, err := o.verifiableStore.GetCredentialIDByName(request.Name)
	if err != nil {
		logutil.LogError(logger, commandName, getCredentialByNameCommandMethod, "get vc by name : "+err.Error(),
			logutil.CreateKeyValueString(vcName, request.Name))

		return command.NewValidationError(GetCredentialByNameErrorCode, fmt.Errorf("get vc by name : %w", err))
	}

	command.WriteNillableResponse(rw, &verifiablestore.CredentialRecord{
		Name: request.Name,
		ID:   id,
	}, logger)

	logutil.LogDebug(logger, commandName, getCredentialByNameCommandMethod, "success",
		logutil.CreateKeyValueString(vcName, request.Name))

	return nil
}

// GetCredentials retrieves the verifiable credential records containing name and vcID.
func (o *Command) GetCredentials(rw io.Writer, req io.Reader) command.Error {
	vcRecords := o.verifiableStore.GetCredentials()

	command.WriteNillableResponse(rw, &CredentialRecordResult{
		Result: vcRecords,
	}, logger)

	logutil.LogDebug(logger, commandName, getCredentialsCommandMethod, "success")

	return nil
}

// GeneratePresentation generates verifiable presentation from a verifiable credential.
func (o *Command) GeneratePresentation(rw io.Writer, req io.Reader) command.Error {
	request := &PresentationRequest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, commandName, generatePresentationCommandMethod, "request decode : "+err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	// TODO https://github.com/hyperledger/aries-framework-go/issues/1316 Add keys for proof
	//  verification as options to the function.
	vc, _, err := verifiable.NewCredential([]byte(request.VerifiableCredential))
	if err != nil {
		logutil.LogError(logger, commandName, generatePresentationCommandMethod, "generate vp - parse vc : "+err.Error())

		return command.NewValidationError(GeneratePresentationErrorCode, fmt.Errorf("generate vp - parse vc : %w", err))
	}
	doc := &did.Doc{}
	err = json.Unmarshal([]byte(request.DID), doc)
	if err != nil {
		//change error here
		logutil.LogError(logger, commandName, generatePresentationCommandMethod, "unmarshal doc: "+err.Error())

		return command.NewValidationError(GeneratePresentationErrorCode, fmt.Errorf("unmarshall : %w", err))
	}

	return o.generatePresentation(rw, vc, doc, generatePresentationCommandMethod, GeneratePresentationErrorCode)
}

// GeneratePresentationByID generates verifiable presentation from a stored verifiable credential.
func (o *Command) GeneratePresentationByID(rw io.Writer, req io.Reader) command.Error {
	request := &IDArg{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, commandName, generatePresentationCommandMethod, "request decode : "+err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	if request.ID == "" {
		logutil.LogDebug(logger, commandName, getCredentialByNameCommandMethod, errEmptyCredentialID)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyCredentialID))
	}

	vc, err := o.verifiableStore.GetCredential(request.ID)
	if err != nil {
		logutil.LogError(logger, commandName, getCredentialByNameCommandMethod, "get vc by id : "+err.Error(),
			logutil.CreateKeyValueString(vcID, request.ID))

		return command.NewValidationError(GeneratePresentationByIDErrorCode, fmt.Errorf("get vc by id : %w", err))
	}

	doc := &did.Doc{}
	err = json.Unmarshal([]byte(request.DID), doc)
	if err != nil {
		//change error here
		logutil.LogError(logger, commandName, generatePresentationCommandMethod, "unmarshal doc: "+err.Error())

		return command.NewValidationError(GeneratePresentationErrorCode, fmt.Errorf("unmarshall : %w", err))
	}
	return o.generatePresentation(rw, vc, doc, getCredentialByNameCommandMethod, GeneratePresentationByIDErrorCode)
}

func (o *Command) generatePresentation(rw io.Writer, vc *verifiable.Credential, doc *did.Doc,
	commandMethodName string, errCode command.Code) command.Error {

    vp, err := o.SignAndGeneratePresentation(doc, vc)
	if err != nil {
		logutil.LogError(logger, commandName, commandMethodName, "sign and generate vp : "+err.Error())

		return command.NewValidationError(errCode, fmt.Errorf("sign and generate vp : %w", err))
	}

	vpBytes, err := vp.MarshalJSON()
	if err != nil {
		logutil.LogError(logger, commandName, commandMethodName, "generate vp : "+err.Error())

		return command.NewValidationError(errCode, fmt.Errorf("generate vp : %w", err))
	}

	command.WriteNillableResponse(rw, &Presentation{
		VerifiablePresentation: string(vpBytes),
	}, logger)

	logutil.LogDebug(logger, commandName, commandMethodName, "success")

	return nil
}

// SignAndGeneratePresentation sign and generate vp
func (o *Command) SignAndGeneratePresentation(didDoc *did.Doc, vc *verifiable.Credential) (*verifiable.Presentation, error) { // nolint:lll
	var s signer

	pk, err := getPublicKeyID(didDoc)
	if err != nil {
		return nil, err
	}

	s, err = newKMSSigner(o.kms, o.kResolver, pk)
	if err != nil {
		return nil, err
	}

	signingCtx := &verifiable.LinkedDataProofContext{
		VerificationMethod:      pk,
		SignatureRepresentation: verifiable.SignatureJWS,
		SignatureType:           "Ed25519Signature2018",
		Suite: ed25519signature2018.New(
			suite.WithSigner(s)),
	}

	vp, err := vc.Presentation()
	if err != nil {
		return nil, fmt.Errorf("failed to create vp: %w", err)
	}

	err = vp.AddLinkedDataProof(signingCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to sign vc: %w", err)
	}

	return vp, nil
}

func getPublicKeyID(didDoc *did.Doc) (string, error) {
	switch {
	case len(didDoc.PublicKey) > 0:
		var publicKeyID string

		for _, k := range didDoc.PublicKey {
			if strings.HasPrefix(k.Type, Ed25519VerificationKey) {
				publicKeyID = k.ID
				break
			}
		}

		// TODO this is temporary check to support public key ID's which aren't in DID format
		// Will be removed [Issue#140]
		if !isDID(publicKeyID) {
			return didDoc.ID + publicKeyID, nil
		}

		return publicKeyID, nil
	case len(didDoc.Authentication) > 0:
		return didDoc.Authentication[0].PublicKey.ID, nil
	default:
		return "", errors.New("public key not found in DID Document")
	}
}

func isDID(str string) bool {
	return strings.HasPrefix(str, "did:")
}
