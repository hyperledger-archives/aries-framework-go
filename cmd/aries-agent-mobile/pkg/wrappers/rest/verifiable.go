/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	cmdverifiable "github.com/hyperledger/aries-framework-go/pkg/controller/command/verifiable"
)

// Verifiable contains necessary fields for each of its operations
type Verifiable struct {
	httpClient httpClient
	endpoints  map[string]*endpoint

	URL   string
	Token string
}

// ValidateCredential validates the verifiable credential.
func (vr *Verifiable) ValidateCredential(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return vr.createRespEnvelop(request, cmdverifiable.ValidateCredentialCommandMethod)
}

// SaveCredential saves the verifiable credential to the store.
func (vr *Verifiable) SaveCredential(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return vr.createRespEnvelop(request, cmdverifiable.SaveCredentialCommandMethod)
}

// SavePresentation saves the presentation to the store.
func (vr *Verifiable) SavePresentation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return vr.createRespEnvelop(request, cmdverifiable.SavePresentationCommandMethod)
}

// GetCredential retrieves the verifiable credential from the store.
func (vr *Verifiable) GetCredential(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return vr.createRespEnvelop(request, cmdverifiable.GetCredentialCommandMethod)
}

// SignCredential adds proof to given verifiable credential
func (vr *Verifiable) SignCredential(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return vr.createRespEnvelop(request, cmdverifiable.SignCredentialCommandMethod)
}

// GetPresentation retrieves the verifiable presentation from the store.
func (vr *Verifiable) GetPresentation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return vr.createRespEnvelop(request, cmdverifiable.GetPresentationCommandMethod)
}

// GetCredentialByName retrieves the verifiable credential by name from the store.
func (vr *Verifiable) GetCredentialByName(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return vr.createRespEnvelop(request, cmdverifiable.GetCredentialByNameCommandMethod)
}

// GetCredentials retrieves the verifiable credential records containing name and fields of interest.
func (vr *Verifiable) GetCredentials(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return vr.createRespEnvelop(request, cmdverifiable.GetCredentialsCommandMethod)
}

// GetPresentations retrieves the verifiable presentation records containing name and fields of interest.
func (vr *Verifiable) GetPresentations(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return vr.createRespEnvelop(request, cmdverifiable.GetPresentationsCommandMethod)
}

// GeneratePresentation generates verifiable presentation from a verifiable credential.
func (vr *Verifiable) GeneratePresentation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return vr.createRespEnvelop(request, cmdverifiable.GeneratePresentationCommandMethod)
}

// GeneratePresentationByID generates verifiable presentation from a stored verifiable credential.
func (vr *Verifiable) GeneratePresentationByID(request *models.RequestEnvelope) *models.ResponseEnvelope {
	return vr.createRespEnvelop(request, cmdverifiable.GeneratePresentationByIDCommandMethod)
}

func (vr *Verifiable) createRespEnvelop(request *models.RequestEnvelope, endpoint string) *models.ResponseEnvelope {
	return exec(&restOperation{
		url:        vr.URL,
		token:      vr.Token,
		httpClient: vr.httpClient,
		endpoint:   vr.endpoints[endpoint],
		request:    request,
	})
}
