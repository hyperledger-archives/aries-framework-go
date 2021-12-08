/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcwallet

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command/vcwallet"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

// createProfileRequest is request model for creating a new wallet profile.
//
// swagger:parameters createProfileRequest
type createProfileRequest struct { // nolint: unused,deadcode
	// Params for creating new wallet profile.
	//
	// in: body
	Params *vcwallet.CreateOrUpdateProfileRequest
}

// updateProfileRequest is request model for updating an existing wallet profile.
//
// swagger:parameters updateProfileRequest
type updateProfileRequest struct { // nolint: unused,deadcode
	// Params for updating an existing wallet profile.
	//
	// in: body
	Params *vcwallet.CreateOrUpdateProfileRequest
}

// unlockWalletRequest contains different options for unlocking wallet.
//
// swagger:parameters unlockWalletReq
type unlockWalletRequest struct { // nolint: unused,deadcode
	// Params for unlocking wallet.
	//
	// in: body
	Params *vcwallet.UnlockWalletRequest
}

// unlockWalletResponse contains response for wallet unlock operation.
//
// swagger:response unlockWalletRes
type unlockWalletResponse struct { // nolint: unused,deadcode
	// in: body
	vcwallet.UnlockWalletResponse
}

// lockWalletRequest contains options for locking wallet.
//
// swagger:parameters lockWalletReq
type lockWalletRequest struct { // nolint: unused,deadcode
	// Params for locking wallet.
	//
	// in: body
	Params *vcwallet.LockWalletRequest
}

// lockWalletResponse contains response for wallet lock operation.
//
// swagger:response lockWalletRes
type lockWalletResponse struct { // nolint: unused,deadcode
	// in: body
	vcwallet.LockWalletResponse
}

// addContentRequest is request for adding a content to wallet.
//
// swagger:parameters addContentReq
type addContentRequest struct { // nolint: unused,deadcode
	// Params for adding content to wallet.
	//
	// in: body
	Params *vcwallet.AddContentRequest
}

// removeContentRequest is request for removing a content from wallet.
//
// swagger:parameters removeContentReq
type removeContentRequest struct { // nolint: unused,deadcode
	// Params for removing content from wallet.
	//
	// in: body
	Params *vcwallet.RemoveContentRequest
}

// getContentRequest is request for getting a content from wallet.
//
// swagger:parameters getContentReq
type getContentRequest struct { // nolint: unused,deadcode
	// Params for getting content from wallet.
	//
	// in: body
	Params *vcwallet.GetContentRequest
}

// getContentResponse response for get content from wallet operation.
//
// swagger:response getContentRes
type getContentResponse struct { // nolint: unused,deadcode
	// content retrieved from wallet content store.
	//
	// in: body
	Content json.RawMessage `json:"content"`
}

// getAllContentRequest is request for getting all contents from wallet for given content type.
//
// swagger:parameters getAllContentReq
type getAllContentRequest struct { // nolint: unused,deadcode
	// Params for getting all contents from wallet.
	//
	// in: body
	Params *vcwallet.GetAllContentRequest
}

// getAllContentResponse response for get all content by content type wallet operation.
//
// swagger:response getAllContentRes
type getAllContentResponse struct { // nolint: unused,deadcode
	// contents retrieved from wallet content store.
	// map of content ID to content.
	//
	// in: body
	Contents json.RawMessage `json:"contents"`
}

// contentQueryRequest is request model for querying wallet contents.
//
// swagger:parameters contentQueryReq
type contentQueryRequest struct { // nolint: unused,deadcode
	// Params for querying credentials from wallet.
	//
	// in: body
	Params *vcwallet.ContentQueryRequest
}

// contentQueryResponse response for wallet content query.
//
// swagger:response contentQueryRes
type contentQueryResponse struct { // nolint: unused,deadcode
	// response presentation(s) containing query results.
	//
	// in: body
	Results []json.RawMessage `json:"results"`
}

// issueRequest is request model for adding proof to credential from wallet.
//
// swagger:parameters issueReq
type issueRequest struct { // nolint: unused,deadcode
	// Params for issuing credential from wallet.
	//
	// in: body
	Params *vcwallet.IssueRequest
}

// issueResponse is response for issue credential interface from wallet.
//
// swagger:response issueRes
type issueResponse struct { // nolint: unused,deadcode
	// credential issued.
	//
	// in: body
	Credential json.RawMessage `json:"credential"`
}

// proveRequest for producing verifiable presentation from wallet.
// Contains options for proofs and credential. Any combination of credential option can be mixed.
//
// swagger:parameters proveReq
type proveRequest struct { // nolint: unused,deadcode
	// Params for producing verifiable presentation from wallet.
	//
	// in: body
	Params *vcwallet.ProveRequest
}

// proveResponse contains response presentation from prove operation.
//
// swagger:response proveRes
type proveResponse struct { // nolint: unused,deadcode
	// presentation response from prove operation.
	//
	// in: body
	Presentation json.RawMessage `json:"presentation"`
}

// verifyRequest request for verifying a credential or presentation from wallet.
// Any one of the credential option should be used.
//
// swagger:parameters verifyReq
type verifyRequest struct { // nolint: unused,deadcode
	// Params for producing verifying a credential or presentation from wallet.
	//
	// in: body
	Params *vcwallet.VerifyRequest
}

// verifyResponse is response model for wallet verify operation.
//
// swagger:response verifyRes
type verifyResponse struct {
	// in: body
	vcwallet.VerifyResponse
}

// deriveRequest is request model for deriving a credential from wallet.
//
// swagger:parameters deriveReq
type deriveRequest struct { // nolint: unused,deadcode
	// Params for deriving a credential from wallet.
	//
	// in: body
	Params *vcwallet.DeriveRequest
}

// deriveResponse is response for derived credential operation.
//
// swagger:response deriveRes
type deriveResponse struct {
	// credential derives
	//
	// in: body
	Credential json.RawMessage `json:"credential"`
}

// createKeyPairRequest is request model for creating a key pair from wallet.
//
// swagger:parameters createKeyPairReq
type createKeyPairRequest struct { // nolint: unused,deadcode
	// Params for creating key pair from wallet.
	//
	// in: body
	Params *vcwallet.CreateKeyPairRequest
}

// createKeyPairResponse is response model for creating a key pair from wallet.
//
// swagger:response createKeyPairRes
type createKeyPairResponse struct {
	// key pair created
	//
	// in: body
	Response *vcwallet.CreateKeyPairResponse `json:"response"`
}

// checkProfileRequest model
//
// to check if wallet profile exists for given wallet user.
//
// swagger:parameters checkProfile
type checkProfileRequest struct { // nolint: unused,deadcode
	// Wallet User's ID used to create profile.
	//
	// in: path
	// required: true
	ID string `json:"id"`
}

// connectRequest is request model for wallet DID connect operation.
//
// swagger:parameters connectReq
type connectRequest struct { // nolint: unused,deadcode
	// Params for connecting to wallet for DIDComm.
	//
	// in: body
	Params *vcwallet.ConnectRequest
}

// connectResponse is response model from wallet DID connect operation.
//
// swagger:response connectRes
type connectResponse struct {
	// wallet connect response.
	//
	// in: body
	Response *vcwallet.ConnectResponse `json:"response"`
}

// proposePresentationRequest is request model for performing propose presentation operation from wallet.
//
// swagger:parameters proposePresReq
type proposePresentationRequest struct { // nolint: unused,deadcode
	// Params for proposing presentation from wallet.
	//
	// in: body
	Params *vcwallet.ProposePresentationRequest
}

// proposePresentationResponse is response model from wallet propose presentation operation.
//
// swagger:response proposePresRes
type proposePresentationResponse struct {
	// response containing request presentation message from relyinig party.
	//
	// in: body
	Response *vcwallet.ProposePresentationResponse `json:"response"`
}

// presentProofRequest is request model for performing present proof operation from wallet.
//
// swagger:parameters presentProofReq
type presentProofRequest struct { // nolint: unused,deadcode
	// Params for accepting presentation request and sending present proof message to relying party.
	//
	// in: body
	Params *vcwallet.PresentProofRequest
}

// presentProofResponse is response model from wallet present proof operation.
//
// swagger:response presentProofRes
type presentProofResponse struct {
	// response containing status of present proof operation.
	//
	// in: body
	Response *wallet.CredentialInteractionStatus `json:"response"`
}

// proposeCredentialRequest is request model for performing propose credential operation from wallet to initiate
// credential issuance flow.
//
// swagger:parameters proposeCredReq
type proposeCredentialRequest struct { // nolint: unused,deadcode
	// Params for proposing credential from wallet.
	//
	// in: body
	Params *vcwallet.ProposeCredentialRequest
}

// proposePresentationResponse is response model from wallet propose credential operation.
//
// swagger:response proposeCredRes
type proposeCredentialResponse struct {
	// response containing offer credential response from issuer.
	//
	// in: body
	Response *vcwallet.ProposeCredentialResponse `json:"response"`
}

// requestCredentialRequest is request model for performing request credential operation from wallet to conclude
// credential issuance flow.
//
// swagger:parameters requestCredReq
type requestCredentialRequest struct { // nolint: unused,deadcode
	// Params for sending request credential message from wallet and optionally wait for credential fulfillment.
	//
	// in: body
	Params *vcwallet.RequestCredentialRequest
}

// requestCredentialResponse is response model from wallet request credential operation which may contain
// credential fulfillment message, status and web redirect info.
//
// swagger:response requestCredRes
type requestCredentialResponse struct {
	// response containing status of request credential operation.
	//
	// in: body
	Response *wallet.CredentialInteractionStatus `json:"response"`
}

// emptyRes model
//
// swagger:response emptyRes
type emptyRes struct{} // nolint: unused,deadcode
