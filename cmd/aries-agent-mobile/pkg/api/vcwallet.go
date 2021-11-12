/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import "github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"

// VCWalletController is a Verifiable Credential Wallet based on Universal Wallet 2020
// https://w3c-ccg.github.io/universal-wallet-interop-spec/#interface.
type VCWalletController interface {

	// Creates new wallet profile and returns error if wallet profile is already created.
	CreateProfile(request *models.RequestEnvelope) *models.ResponseEnvelope

	// Updates an existing wallet profile and returns error if profile doesn't exists.
	UpdateProfile(request *models.RequestEnvelope) *models.ResponseEnvelope

	// Checks if profile exists for given wallet user.
	ProfileExists(request *models.RequestEnvelope) *models.ResponseEnvelope

	// Unlocks given wallet's key manager instance & content store and
	// returns a authorization token to be used for performing wallet operations.
	Open(request *models.RequestEnvelope) *models.ResponseEnvelope

	// Expires token issued to this VC wallet, removes wallet's key manager instance and closes wallet content store.
	// returns response containing bool flag false if token is not found or already expired for this wallet user.
	Close(request *models.RequestEnvelope) *models.ResponseEnvelope

	// adds given data model to wallet content store.
	Add(request *models.RequestEnvelope) *models.ResponseEnvelope

	// removes given content from wallet content store.
	Remove(request *models.RequestEnvelope) *models.ResponseEnvelope

	// gets content from wallet content store.
	Get(request *models.RequestEnvelope) *models.ResponseEnvelope

	// gets all contents from wallet content store for given content type.
	GetAll(request *models.RequestEnvelope) *models.ResponseEnvelope

	// runs query against wallet credential contents and returns presentation containing credential results.
	Query(request *models.RequestEnvelope) *models.ResponseEnvelope

	// adds proof to a Verifiable Credential.
	Issue(request *models.RequestEnvelope) *models.ResponseEnvelope

	// produces a Verifiable Presentation.
	Prove(request *models.RequestEnvelope) *models.ResponseEnvelope

	// verifies a Verifiable Credential or a Verifiable Presentation.
	Verify(request *models.RequestEnvelope) *models.ResponseEnvelope

	// derives a Verifiable Credential.
	Derive(request *models.RequestEnvelope) *models.ResponseEnvelope

	// creates a key pair from wallet.
	CreateKeyPair(request *models.RequestEnvelope) *models.ResponseEnvelope

	// accepts out-of-band invitations and performs DID exchange.
	Connect(request *models.RequestEnvelope) *models.ResponseEnvelope

	// accepts out-of-band invitation and sends message proposing presentation
	// from wallet to relying party.
	ProposePresentation(request *models.RequestEnvelope) *models.ResponseEnvelope

	// sends message present proof message from wallet to relying party.
	PresentProof(request *models.RequestEnvelope) *models.ResponseEnvelope
}
