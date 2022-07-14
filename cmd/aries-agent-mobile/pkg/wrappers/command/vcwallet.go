/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	cmddidcommwallet "github.com/hyperledger/aries-framework-go/pkg/controller/command/didcommwallet"
	cmdvcwallet "github.com/hyperledger/aries-framework-go/pkg/controller/command/vcwallet"
)

// VCWallet contains necessary fields to support its operations.
type VCWallet struct {
	handlers map[string]command.Exec
}

// CreateProfile creates new wallet profile for given user.
func (v *VCWallet) CreateProfile(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdvcwallet.CreateOrUpdateProfileRequest{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmdvcwallet.CreateProfileMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// UpdateProfile updates an existing wallet profile for given user.
func (v *VCWallet) UpdateProfile(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdvcwallet.CreateOrUpdateProfileRequest{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmdvcwallet.UpdateProfileMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// ProfileExists checks if profile exists for given wallet user, returns error if not found.
func (v *VCWallet) ProfileExists(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdvcwallet.WalletUser{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmdvcwallet.ProfileExistsMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// Open unlocks given user's wallet and returns a token for subsequent use of wallet features.
func (v *VCWallet) Open(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdvcwallet.UnlockWalletRequest{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmdvcwallet.OpenMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// Close locks given user's wallet.
func (v *VCWallet) Close(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdvcwallet.LockWalletRequest{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmdvcwallet.CloseMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// Add adds given data model to wallet content store.
func (v *VCWallet) Add(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdvcwallet.AddContentRequest{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmdvcwallet.AddMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// Remove deletes given content from wallet content store.
func (v *VCWallet) Remove(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdvcwallet.RemoveContentRequest{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmdvcwallet.RemoveMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// Get returns wallet content by ID from wallet content store.
func (v *VCWallet) Get(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdvcwallet.GetContentRequest{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmdvcwallet.GetMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// GetAll gets all wallet content from wallet content store for given type.
func (v *VCWallet) GetAll(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdvcwallet.GetAllContentRequest{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmdvcwallet.GetAllMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// Query runs credential queries against wallet credential contents.
func (v *VCWallet) Query(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdvcwallet.ContentQueryRequest{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmdvcwallet.QueryMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// Issue adds proof to a Verifiable Credential from wallet.
func (v *VCWallet) Issue(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdvcwallet.IssueRequest{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmdvcwallet.IssueMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// Prove produces a Verifiable Presentation from wallet.
func (v *VCWallet) Prove(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdvcwallet.ProveRequest{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmdvcwallet.ProveMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// Verify verifies credential/presentation from wallet.
func (v *VCWallet) Verify(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdvcwallet.VerifyRequest{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmdvcwallet.VerifyMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// Derive derives a credential from wallet.
func (v *VCWallet) Derive(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdvcwallet.DeriveRequest{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmdvcwallet.DeriveMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// CreateKeyPair creates key pair from wallet.
func (v *VCWallet) CreateKeyPair(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmdvcwallet.CreateKeyPairRequest{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmdvcwallet.CreateKeyPairMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// Connect accepts out-of-band invitations and performs DID exchange.
func (v *VCWallet) Connect(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmddidcommwallet.ConnectRequest{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmddidcommwallet.ConnectMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// ProposePresentation accepts out-of-band invitation and sends message proposing presentation
// from wallet to relying party.
func (v *VCWallet) ProposePresentation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmddidcommwallet.ProposePresentationRequest{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmddidcommwallet.ProposePresentationMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}

// PresentProof sends present proof message from wallet to relying party.
func (v *VCWallet) PresentProof(request *models.RequestEnvelope) *models.ResponseEnvelope {
	args := cmddidcommwallet.PresentProofRequest{}

	if err := json.Unmarshal(request.Payload, &args); err != nil {
		return &models.ResponseEnvelope{Error: &models.CommandError{Message: err.Error()}}
	}

	response, cmdErr := exec(v.handlers[cmddidcommwallet.PresentProofMethod], args)
	if cmdErr != nil {
		return &models.ResponseEnvelope{Error: cmdErr}
	}

	return &models.ResponseEnvelope{Payload: response}
}
