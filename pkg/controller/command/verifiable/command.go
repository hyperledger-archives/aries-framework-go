/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/btcsuite/btcutil/base58"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	verifiablesigner "github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/jsonwebsignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	didstore "github.com/hyperledger/aries-framework-go/pkg/store/did"
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
	errEmptyDID            = "did is mandatory"

	// log constants
	vcID   = "vcID"
	vcName = "vcName"

	creatorParts = 2
	// Ed25519VerificationKey supported Verification Key types
	// TODO Support JwsVerificationKey2020 type for verification #1639
	Ed25519VerificationKey = "Ed25519VerificationKey"

	// Ed25519KeyType ed25519 key type
	Ed25519KeyType = "Ed25519"

	// P256KeyType EC P-256 key type
	P256KeyType = "P256"
)

type keyResolver interface {
	PublicKeyFetcher() verifiable.PublicKeyFetcher
}

type kmsSigner struct {
	kms   legacykms.Signer
	keyID string
}

func newKMSSigner(kms legacykms.Signer, kResolver keyResolver, verificationMethod string) (*kmsSigner, error) {
	// creator will contain didID#keyID
	idSplit := strings.Split(verificationMethod, "#")
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

type privateKeySigner struct {
	keyType    string
	privateKey []byte
}

func newPrivateKeySigner(keyType string, privateKey []byte) *privateKeySigner {
	return &privateKeySigner{keyType: keyType, privateKey: privateKey}
}

func (s *privateKeySigner) Sign(data []byte) ([]byte, error) {
	switch s.keyType {
	case Ed25519KeyType:
		return ed25519.Sign(s.privateKey, data), nil
	case P256KeyType:
		ecPrivateKey, err := x509.ParseECPrivateKey(s.privateKey)
		if err != nil {
			return nil, err
		}

		return signEcdsa(data, ecPrivateKey, crypto.SHA256)
	}

	return nil, fmt.Errorf("invalid key type : %s", s.keyType)
}

// provider contains dependencies for the verifiable command and is typically created by using aries.Context().
type provider interface {
	StorageProvider() storage.Provider
	VDRIRegistry() vdri.Registry
	Signer() legacykms.Signer
}

// Command contains command operations provided by verifiable credential controller.
type Command struct {
	verifiableStore *verifiablestore.Store
	didStore        *didstore.Store
	kResolver       keyResolver
	ctx             provider
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
		kResolver:       verifiable.NewDIDKeyResolver(p.VDRIRegistry()),
		ctx:             p,
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

	didDoc, err := o.ctx.VDRIRegistry().Resolve(request.DID)
	//  if did not found in VDRI, look through in local storage
	if err != nil {
		didDoc, err = o.didStore.GetDID(request.DID)
		if err != nil {
			logutil.LogError(logger, commandName, generatePresentationCommandMethod,
				"failed to get did doc from store or vdri: "+err.Error())

			return command.NewValidationError(GeneratePresentationErrorCode,
				fmt.Errorf("generate vp - failed to get did doc from store or vdri : %w", err))
		}
	}

	credentials, presentation, opts, err := o.parsePresentationRequest(request, didDoc)
	if err != nil {
		logutil.LogError(logger, commandName, generatePresentationCommandMethod,
			"parse presentation request: "+err.Error())

		return command.NewValidationError(GeneratePresentationErrorCode,
			fmt.Errorf("generate vp - parse presentation request: %w", err))
	}

	return o.generatePresentation(rw, credentials, presentation, opts)
}

// GeneratePresentationByID generates verifiable presentation from a stored verifiable credential.
func (o *Command) GeneratePresentationByID(rw io.Writer, req io.Reader) command.Error {
	request := &PresentationRequestByID{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, commandName, generatePresentationCommandMethod, "request decode : "+err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	if request.ID == "" {
		logutil.LogDebug(logger, commandName, getCredentialByNameCommandMethod, errEmptyCredentialID)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyCredentialID))
	}

	if request.DID == "" {
		logutil.LogDebug(logger, commandName, getCredentialByNameCommandMethod, errEmptyDID)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyDID))
	}

	vc, err := o.verifiableStore.GetCredential(request.ID)
	if err != nil {
		logutil.LogError(logger, commandName, getCredentialByNameCommandMethod, "get vc by id : "+err.Error(),
			logutil.CreateKeyValueString(vcID, request.ID))

		return command.NewValidationError(GeneratePresentationByIDErrorCode, fmt.Errorf("get vc by id : %w", err))
	}

	doc, err := o.didStore.GetDID(request.DID)
	if err != nil {
		logutil.LogError(logger, commandName, generatePresentationCommandMethod,
			"failed to get did doc from store: "+err.Error())

		return command.NewValidationError(GeneratePresentationErrorCode,
			fmt.Errorf("failed to get did doc from store : %w", err))
	}

	return o.generatePresentationByID(rw, vc, doc)
}

func (o *Command) generatePresentation(rw io.Writer, vcs []interface{}, p *verifiable.Presentation,
	opts *ProofOptions) command.Error {
	// prepare vp
	vp, err := o.createAndSignPresentation(vcs, p, opts)
	if err != nil {
		logutil.LogError(logger, commandName, generatePresentationCommandMethod, "create and sign vp: "+err.Error())

		return command.NewValidationError(GeneratePresentationByIDErrorCode, fmt.Errorf("prepare vp: %w", err))
	}

	command.WriteNillableResponse(rw, &Presentation{
		VerifiablePresentation: string(vp),
	}, logger)

	logutil.LogDebug(logger, commandName, generatePresentationCommandMethod, "success")

	return nil
}

func (o *Command) generatePresentationByID(rw io.Writer, vc *verifiable.Credential, didDoc *did.Doc) command.Error {
	// prepare vp by id
	vp, err := o.createAndSignPresentationByID(vc, didDoc)
	if err != nil {
		logutil.LogError(logger, commandName, generatePresentationCommandMethod, "create and sign vp by id: "+err.Error())

		return command.NewValidationError(GeneratePresentationByIDErrorCode, fmt.Errorf("prepare vp by id: %w", err))
	}

	//  TODO : VP is already implementing marshall json. Revisit #1643
	command.WriteNillableResponse(rw, &Presentation{
		VerifiablePresentation: string(vp),
	}, logger)

	logutil.LogDebug(logger, commandName, generatePresentationCommandMethod, "success")

	return nil
}

func (o *Command) createAndSignPresentation(credentials []interface{}, vp *verifiable.Presentation,
	opts *ProofOptions) ([]byte, error) {
	var err error
	if vp == nil {
		vp, err = credentials[0].(*verifiable.Credential).Presentation()
		if err != nil {
			return nil, err
		}
		// Add array of credentials in the presentation
		err = vp.SetCredentials(credentials...)
		if err != nil {
			return nil, fmt.Errorf("failed to set credentials: %w", err)
		}
	}

	// Add proofs to vp - sign presentation
	vp, err = o.addLinkedDataProof(vp, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to sign vp: %w", err)
	}

	return vp.MarshalJSON()
}

func (o *Command) createAndSignPresentationByID(vc *verifiable.Credential,
	didDoc *did.Doc) ([]byte, error) {
	// pk is verification method
	pk, err := getDefaultVerificationMethod(didDoc)
	if err != nil {
		return nil, err
	}

	vp, err := vc.Presentation()
	if err != nil {
		return nil, fmt.Errorf("failed to create vp by ID: %w", err)
	}

	vp, err = o.addLinkedDataProof(vp, &ProofOptions{VerificationMethod: pk})
	if err != nil {
		return nil, fmt.Errorf("failed to sign vp by ID: %w", err)
	}

	return vp.MarshalJSON()
}

func (o *Command) addLinkedDataProof(vp *verifiable.Presentation, opts *ProofOptions) (*verifiable.Presentation,
	error) {
	var signer verifiablesigner.SignatureSuite

	signatureType := "Ed25519Signature2018"

	// TODO  Need to provide the option to user for signature type. for now create jsonwebsignature2020
	//  private key is not empty.
	if opts.PrivateKey != "" {
		s := newPrivateKeySigner(opts.KeyType, base58.Decode(opts.PrivateKey))

		signatureType = "JsonWebSignature2020"
		signer = jsonwebsignature2020.New(suite.WithSigner(s))
		opts.VerificationMethod = opts.DIDKeyID
	} else {
		s, err := newKMSSigner(o.ctx.Signer(), o.kResolver, opts.VerificationMethod)
		if err != nil {
			return nil, err
		}

		signer = ed25519signature2018.New(suite.WithSigner(s))
	}

	signingCtx := &verifiable.LinkedDataProofContext{
		VerificationMethod:      opts.VerificationMethod,
		SignatureRepresentation: verifiable.SignatureJWS,
		SignatureType:           signatureType,
		Suite:                   signer,
		Created:                 opts.Created,
		Domain:                  opts.Domain,
		Challenge:               opts.Challenge,
		Purpose:                 opts.ProofPurpose,
	}

	err := vp.AddLinkedDataProof(signingCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to add linked data proof: %w", err)
	}

	return vp, nil
}

func (o *Command) parsePresentationRequest(request *PresentationRequest,
	didDoc *did.Doc) ([]interface{}, *verifiable.Presentation, *ProofOptions, error) {
	if len(request.VerifiableCredentials) == 0 && len(request.Presentation) == 0 {
		return nil, nil, nil, fmt.Errorf("invalid request, no valid credentials/presentation found")
	}

	var vcs []interface{}

	var presentation *verifiable.Presentation

	var err error

	if len(request.VerifiableCredentials) > 0 {
		for _, vcRaw := range request.VerifiableCredentials {
			var credOpts []verifiable.CredentialOpt
			if request.SkipVerify {
				credOpts = append(credOpts, verifiable.WithDisabledProofCheck())
			} else {
				credOpts = append(credOpts, verifiable.WithPublicKeyFetcher(
					verifiable.NewDIDKeyResolver(o.ctx.VDRIRegistry()).PublicKeyFetcher(),
				))
			}

			vc, _, e := verifiable.NewCredential(vcRaw, credOpts...)
			if e != nil {
				logutil.LogError(logger, commandName, generatePresentationCommandMethod,
					"failed to parse credential from request, invalid credential: "+e.Error())
				return nil, nil, nil, fmt.Errorf("parse credential failed: %w", e)
			}

			vcs = append(vcs, vc)
		}
	} else {
		presentation, err = verifiable.NewUnverifiedPresentation(request.Presentation)
		if err != nil {
			logutil.LogError(logger, commandName, generatePresentationCommandMethod,
				"failed to parse presentation from request: "+err.Error())
			return nil, nil, nil, fmt.Errorf("parse presentation failed: %w", err)
		}
	}

	opts, err := prepareOpts(request.ProofOptions, didDoc)
	if err != nil {
		logutil.LogError(logger, commandName, generatePresentationCommandMethod,
			"failed to prepare proof options: "+err.Error())
		return nil, nil, nil, fmt.Errorf("failed to prepare proof options: %w", err)
	}

	return vcs, presentation, opts, nil
}

func prepareOpts(opts *ProofOptions, didDoc *did.Doc) (*ProofOptions, error) {
	if opts == nil {
		opts = &ProofOptions{}
	}

	if opts.VerificationMethod == "" {
		defaultVM, err := getDefaultVerificationMethod(didDoc)
		if err != nil {
			logutil.LogError(logger, commandName, generatePresentationCommandMethod,
				"failed to get default verification method: "+err.Error())
			return nil, fmt.Errorf("failed to get default verification method: %w", err)
		}

		opts.VerificationMethod = defaultVM
	}

	return opts, nil
}

func getDefaultVerificationMethod(didDoc *did.Doc) (string, error) {
	switch {
	case len(didDoc.PublicKey) > 0:
		var publicKeyID string

		for _, k := range didDoc.PublicKey {
			if strings.HasPrefix(k.Type, Ed25519VerificationKey) {
				publicKeyID = k.ID
				break
			}
		}

		// todo Review this logic  #1640
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

func signEcdsa(doc []byte, privateKey *ecdsa.PrivateKey, hash crypto.Hash) ([]byte, error) {
	hasher := hash.New()

	_, err := hasher.Write(doc)
	if err != nil {
		return nil, err
	}

	hashed := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed)
	if err != nil {
		return nil, err
	}

	curveBits := privateKey.Curve.Params().BitSize

	const bitsInByte = 8
	keyBytes := curveBits / bitsInByte

	if curveBits%bitsInByte > 0 {
		keyBytes++
	}

	return append(copyPadded(r.Bytes(), keyBytes), copyPadded(s.Bytes(), keyBytes)...), nil
}

func copyPadded(source []byte, size int) []byte {
	dest := make([]byte, size)
	copy(dest[size-len(source):], source)

	return dest
}
