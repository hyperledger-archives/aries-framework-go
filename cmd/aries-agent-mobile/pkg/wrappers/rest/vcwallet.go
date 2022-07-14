/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	cmddidcommwallet "github.com/hyperledger/aries-framework-go/pkg/controller/command/didcommwallet"
	cmdvcwallet "github.com/hyperledger/aries-framework-go/pkg/controller/command/vcwallet"
)

// VCWallet contains necessary fields to support its operations.
type VCWallet struct {
	httpClient httpClient
	endpoints  map[string]*endpoint

	URL   string
	Token string
}

// CreateProfile creates new wallet profile for given user.
func (wallet *VCWallet) CreateProfile(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return wallet.createRespEnvelope(request, cmdvcwallet.CreateProfileMethod)
}

// UpdateProfile updates an existing wallet profile for given user.
func (wallet *VCWallet) UpdateProfile(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return wallet.createRespEnvelope(request, cmdvcwallet.UpdateProfileMethod)
}

// ProfileExists checks if profile exists for given wallet user, returns error if not found.
func (wallet *VCWallet) ProfileExists(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return wallet.createRespEnvelope(request, cmdvcwallet.ProfileExistsMethod)
}

// Open unlocks given user's wallet and returns a token for subsequent use of wallet features.
func (wallet *VCWallet) Open(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return wallet.createRespEnvelope(request, cmdvcwallet.OpenMethod)
}

// Close locks given user's wallet.
func (wallet *VCWallet) Close(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return wallet.createRespEnvelope(request, cmdvcwallet.CloseMethod)
}

// Add adds given data model to wallet content store.
func (wallet *VCWallet) Add(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return wallet.createRespEnvelope(request, cmdvcwallet.AddMethod)
}

// Remove deletes given content from wallet content store.
func (wallet *VCWallet) Remove(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return wallet.createRespEnvelope(request, cmdvcwallet.RemoveMethod)
}

// Get returns wallet content by ID from wallet content store.
func (wallet *VCWallet) Get(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return wallet.createRespEnvelope(request, cmdvcwallet.GetMethod)
}

// GetAll gets all wallet content from wallet content store for given type.
func (wallet *VCWallet) GetAll(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return wallet.createRespEnvelope(request, cmdvcwallet.GetAllMethod)
}

// Query runs credential queries against wallet credential contents.
func (wallet *VCWallet) Query(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return wallet.createRespEnvelope(request, cmdvcwallet.QueryMethod)
}

// Issue adds proof to a Verifiable Credential from wallet.
func (wallet *VCWallet) Issue(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return wallet.createRespEnvelope(request, cmdvcwallet.IssueMethod)
}

// Prove produces a Verifiable Presentation from wallet.
func (wallet *VCWallet) Prove(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return wallet.createRespEnvelope(request, cmdvcwallet.ProveMethod)
}

// Verify verifies credential/presentation from wallet.
func (wallet *VCWallet) Verify(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return wallet.createRespEnvelope(request, cmdvcwallet.VerifyMethod)
}

// Derive derives a credential from wallet.
func (wallet *VCWallet) Derive(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return wallet.createRespEnvelope(request, cmdvcwallet.DeriveMethod)
}

// CreateKeyPair creates key pair from wallet.
func (wallet *VCWallet) CreateKeyPair(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return wallet.createRespEnvelope(request, cmdvcwallet.CreateKeyPairMethod)
}

// Connect accepts out-of-band invitations and performs DID exchange.
func (wallet *VCWallet) Connect(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return wallet.createRespEnvelope(request, cmddidcommwallet.ConnectMethod)
}

// ProposePresentation accepts out-of-band invitation and sends message proposing presentation
// from wallet to relying party.
func (wallet *VCWallet) ProposePresentation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return wallet.createRespEnvelope(request, cmddidcommwallet.ProposePresentationMethod)
}

// PresentProof sends message present proof message from wallet to relying party.
func (wallet *VCWallet) PresentProof(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return wallet.createRespEnvelope(request, cmddidcommwallet.PresentProofMethod)
}

func (wallet *VCWallet) createRespEnvelope(request *models.RequestEnvelope, endpoint string) *models.ResponseEnvelope {
	return exec(&restOperation{
		url:        wallet.URL,
		token:      wallet.Token,
		httpClient: wallet.httpClient,
		endpoint:   wallet.endpoints[endpoint],
		request:    request,
	})
}
