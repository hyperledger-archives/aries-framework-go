/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcwallet

import (
	"bytes"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command/vcwallet"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// All command operations.
const (
	OperationID = "/vcwallet"

	// command Paths.
	CreateProfilePath       = OperationID + "/create-profile"
	UpdateProfilePath       = OperationID + "/update-profile"
	ProfileExistsPath       = OperationID + "/profile/{id}"
	OpenPath                = OperationID + "/open"
	ClosePath               = OperationID + "/close"
	AddPath                 = OperationID + "/add"
	RemovePath              = OperationID + "/remove"
	GetPath                 = OperationID + "/get"
	GetAllPath              = OperationID + "/getall"
	QueryPath               = OperationID + "/query"
	IssuePath               = OperationID + "/issue"
	ProvePath               = OperationID + "/prove"
	VerifyPath              = OperationID + "/verify"
	DerivePath              = OperationID + "/derive"
	CreateKeyPairPath       = OperationID + "/create-key-pair"
	ConnectPath             = OperationID + "/connect"
	ProposePresentationPath = OperationID + "/propose-presentation"
	PresentProofPath        = OperationID + "/present-proof"
)

// provider contains dependencies for the verifiable credential wallet command controller
// and is typically created by using aries.Context().
type provider interface {
	StorageProvider() storage.Provider
	VDRegistry() vdr.Registry
	Crypto() crypto.Crypto
	JSONLDDocumentLoader() ld.DocumentLoader
	MediaTypeProfiles() []string
	didCommProvider // to be used only if wallet needs to be participated in DIDComm.
}

// didCommProvider to be used only if wallet needs to be participated in DIDComm operation.
// TODO: using wallet KMS instead of provider KMS.
// TODO: reconcile Protocol storage with wallet store.
type didCommProvider interface {
	KMS() kms.KeyManager
	ServiceEndpoint() string
	ProtocolStateStorageProvider() storage.Provider
	Service(id string) (interface{}, error)
	KeyType() kms.KeyType
	KeyAgreementType() kms.KeyType
}

// Operation contains REST operations provided by verifiable credential wallet.
type Operation struct {
	handlers []rest.Handler
	command  *vcwallet.Command
}

// New returns new verfiable credential wallet REST controller.
func New(p provider, config *vcwallet.Config) *Operation {
	cmd := vcwallet.New(p, config)

	o := &Operation{command: cmd}

	o.registerHandler()

	return o
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []rest.Handler {
	return o.handlers
}

// registerHandler register handlers to be exposed from this protocol service as REST API endpoints.
func (o *Operation) registerHandler() {
	o.handlers = []rest.Handler{
		cmdutil.NewHTTPHandler(CreateProfilePath, http.MethodPost, o.CreateProfile),
		cmdutil.NewHTTPHandler(UpdateProfilePath, http.MethodPost, o.UpdateProfile),
		cmdutil.NewHTTPHandler(ProfileExistsPath, http.MethodGet, o.ProfileExists),
		cmdutil.NewHTTPHandler(OpenPath, http.MethodPost, o.Open),
		cmdutil.NewHTTPHandler(ClosePath, http.MethodPost, o.Close),
		cmdutil.NewHTTPHandler(AddPath, http.MethodPost, o.Add),
		cmdutil.NewHTTPHandler(RemovePath, http.MethodPost, o.Remove),
		cmdutil.NewHTTPHandler(GetPath, http.MethodPost, o.Get),
		cmdutil.NewHTTPHandler(GetAllPath, http.MethodPost, o.GetAll),
		cmdutil.NewHTTPHandler(QueryPath, http.MethodPost, o.Query),
		cmdutil.NewHTTPHandler(IssuePath, http.MethodPost, o.Issue),
		cmdutil.NewHTTPHandler(ProvePath, http.MethodPost, o.Prove),
		cmdutil.NewHTTPHandler(VerifyPath, http.MethodPost, o.Verify),
		cmdutil.NewHTTPHandler(DerivePath, http.MethodPost, o.Derive),
		cmdutil.NewHTTPHandler(CreateKeyPairPath, http.MethodPost, o.CreateKeyPair),
		cmdutil.NewHTTPHandler(ConnectPath, http.MethodPost, o.Connect),
		cmdutil.NewHTTPHandler(ProposePresentationPath, http.MethodPost, o.ProposePresentation),
		cmdutil.NewHTTPHandler(PresentProofPath, http.MethodPost, o.PresentProof),
	}
}

// CreateProfile swagger:route POST /vcwallet/create-profile vcwallet createProfileReq
//
// Creates new wallet profile and returns error if wallet profile is already created.
//
// Responses:
//    default: genericError
//        200: emptyRes
func (o *Operation) CreateProfile(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.CreateProfile, rw, req.Body)
}

// UpdateProfile swagger:route POST /vcwallet/update-profile vcwallet UpdateProfileReq
//
// Updates an existing wallet profile and returns error if profile doesn't exists.
//
// Caution:
// - you might lose your existing keys if you change kms options.
// - you might lose your existing wallet contents if you change storage/EDV options
// (example: switching context storage provider or changing EDV settings).
//
// Responses:
//    default: genericError
//        200: emptyRes
func (o *Operation) UpdateProfile(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.UpdateProfile, rw, req.Body)
}

// ProfileExists swagger:route GET /vcwallet/profile/{id} vcwallet checkProfile
//
// Checks if profile exists for given wallet user ID and returns error if profile doesn't exists.
//
// Responses:
//    default: genericError
//        200: emptyRes
func (o *Operation) ProfileExists(rw http.ResponseWriter, req *http.Request) {
	id, found := getIDFromRequest(rw, req)
	if !found {
		return
	}

	rest.Execute(o.command.ProfileExists, rw, bytes.NewBufferString(fmt.Sprintf(`{"userID": "%s"}`, id)))
}

// Open swagger:route POST /vcwallet/open vcwallet unlockWalletReq
//
// Unlocks given wallet's key manager instance & content store and
// returns a authorization token to be used for performing wallet operations.
//
// Responses:
//    default: genericError
//        200: unlockWalletRes
func (o *Operation) Open(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.Open, rw, req.Body)
}

// Close swagger:route POST /vcwallet/close vcwallet lockWalletReq
//
// Expires token issued to this VC wallet, removes wallet's key manager instance and closes wallet content store.
//
// returns response containing bool flag false if token is not found or already expired for this wallet user.
//
// Responses:
//    default: genericError
//        200: lockWalletRes
func (o *Operation) Close(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.Close, rw, req.Body)
}

// Add swagger:route POST /vcwallet/add vcwallet addContentReq
//
// adds given data model to wallet content store.
//
// Supported data models:
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Collection
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#DIDResolutionResponse
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Key
//
// Responses:
//    default: genericError
//        200: emptyRes
func (o *Operation) Add(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.Add, rw, req.Body)
}

// Remove swagger:route POST /vcwallet/remove vcwallet removeContentReq
//
// removes given content from wallet content store.
//
// Supported data models:
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Collection
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#DIDResolutionResponse
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
//
// Responses:
//    default: genericError
//        200: emptyRes
func (o *Operation) Remove(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.Remove, rw, req.Body)
}

// Get swagger:route POST /vcwallet/get vcwallet getContentReq
//
// gets content from wallet content store.
//
// Supported data models:
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Collection
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#DIDResolutionResponse
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
//
// Responses:
//    default: genericError
//        200: getContentRes
func (o *Operation) Get(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.Get, rw, req.Body)
}

// GetAll swagger:route POST /vcwallet/getall vcwallet getAllContentReq
//
// gets all contents from wallet content store for given content type.
//
// Supported data models:
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Collection
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#DIDResolutionResponse
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
//
// Responses:
//    default: genericError
//        200: getAllContentRes
func (o *Operation) GetAll(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.GetAll, rw, req.Body)
}

// Query swagger:route POST /vcwallet/query vcwallet contentQueryReq
//
// runs query against wallet credential contents and returns presentation containing credential results.
//
// This function may return multiple presentations as a result based on combination of query types used.
//
// https://w3c-ccg.github.io/universal-wallet-interop-spec/#query
//
// Supported Query Types:
// 	- https://www.w3.org/TR/json-ld11-framing
// 	- https://identity.foundation/presentation-exchange
// 	- https://w3c-ccg.github.io/vp-request-spec/#query-by-example
// 	- https://w3c-ccg.github.io/vp-request-spec/#did-authentication-request
//
// Responses:
//    default: genericError
//        200: contentQueryRes
func (o *Operation) Query(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.Query, rw, req.Body)
}

// Issue swagger:route POST /vcwallet/issue vcwallet issueReq
//
// adds proof to a Verifiable Credential.
//
// https://w3c-ccg.github.io/universal-wallet-interop-spec/#issue
//
// Responses:
//    default: genericError
//        200: issueRes
func (o *Operation) Issue(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.Issue, rw, req.Body)
}

// Prove swagger:route POST /vcwallet/prove vcwallet proveReq
//
// produces a Verifiable Presentation.
//
// https://w3c-ccg.github.io/universal-wallet-interop-spec/#prove
//
// Responses:
//    default: genericError
//        200: proveRes
func (o *Operation) Prove(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.Prove, rw, req.Body)
}

// Verify swagger:route POST /vcwallet/verify vcwallet verifyReq
//
// verifies a Verifiable Credential or a Verifiable Presentation.
//
// https://w3c-ccg.github.io/universal-wallet-interop-spec/#prove
//
// Responses:
//    default: genericError
//        200: verifyRes
func (o *Operation) Verify(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.Verify, rw, req.Body)
}

// Derive swagger:route POST /vcwallet/derive vcwallet deriveReq
//
// derives a Verifiable Credential.
//
// https://w3c-ccg.github.io/universal-wallet-interop-spec/#derive
//
// Responses:
//    default: genericError
//        200: deriveRes
func (o *Operation) Derive(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.Derive, rw, req.Body)
}

// CreateKeyPair swagger:route POST /vcwallet/create-key-pair vcwallet createKeyPairReq
//
// creates a new key pair from wallet.
//
// Responses:
//    default: genericError
//        200: createKeyPairRes
func (o *Operation) CreateKeyPair(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.CreateKeyPair, rw, req.Body)
}

// Connect swagger:route POST /vcwallet/connect vcwallet connectReq
//
// accepts out-of-band invitations and performs DID exchange.
//
// Responses:
//    default: genericError
//        200: connectRes
func (o *Operation) Connect(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.Connect, rw, req.Body)
}

// ProposePresentation swagger:route POST /vcwallet/propose-presentation vcwallet proposePresReq
//
// accepts out-of-band invitation and sends message proposing presentation
// from wallet to relying party.
// https://w3c-ccg.github.io/universal-wallet-interop-spec/#proposepresentation
//
// Currently Supporting
// [0454-present-proof-v2](https://github.com/hyperledger/aries-rfcs/tree/master/features/0454-present-proof-v2)
//
// Responses:
//    default: genericError
//        200: proposePresRes
func (o *Operation) ProposePresentation(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.ProposePresentation, rw, req.Body)
}

// PresentProof swagger:route POST /vcwallet/present-proof vcwallet presentProofReq
//
// sends message present proof message from wallet to relying party.
// https://w3c-ccg.github.io/universal-wallet-interop-spec/#presentproof
//
// Currently Supporting
// [0454-present-proof-v2](https://github.com/hyperledger/aries-rfcs/tree/master/features/0454-present-proof-v2)
//
// Responses:
//    default: genericError
//        200: presentProofRes
func (o *Operation) PresentProof(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.PresentProof, rw, req.Body)
}

// getIDFromRequest returns ID from request.
func getIDFromRequest(rw http.ResponseWriter, req *http.Request) (string, bool) {
	id := mux.Vars(req)["id"]
	if id == "" {
		rest.SendHTTPStatusError(rw, http.StatusBadRequest, vcwallet.InvalidRequestErrorCode,
			fmt.Errorf("empty profile ID"))
		return "", false
	}

	return id, true
}
