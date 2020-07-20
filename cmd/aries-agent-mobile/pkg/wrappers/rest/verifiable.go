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
	respEnvelope := exec(&restOperation{
		url:        vr.URL,
		token:      vr.Token,
		httpClient: vr.httpClient,
		endpoint:   vr.endpoints[cmdverifiable.ValidateCredentialCommandMethod],
		request:    request,
	})

	return respEnvelope
}

// SaveCredential saves the verifiable credential to the store.
func (vr *Verifiable) SaveCredential(request *models.RequestEnvelope) *models.ResponseEnvelope {
	respEnvelope := exec(&restOperation{
		url:        vr.URL,
		token:      vr.Token,
		httpClient: vr.httpClient,
		endpoint:   vr.endpoints[cmdverifiable.SaveCredentialCommandMethod],
		request:    request,
	})

	return respEnvelope
}

// SavePresentation saves the presentation to the store.
func (vr *Verifiable) SavePresentation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	respEnvelope := exec(&restOperation{
		url:        vr.URL,
		token:      vr.Token,
		httpClient: vr.httpClient,
		endpoint:   vr.endpoints[cmdverifiable.SavePresentationCommandMethod],
		request:    request,
	})

	return respEnvelope
}

// GetCredential retrieves the verifiable credential from the store.
func (vr *Verifiable) GetCredential(request *models.RequestEnvelope) *models.ResponseEnvelope {
	respEnvelope := exec(&restOperation{
		url:        vr.URL,
		token:      vr.Token,
		httpClient: vr.httpClient,
		endpoint:   vr.endpoints[cmdverifiable.GetCredentialCommandMethod],
		request:    request,
	})

	return respEnvelope
}

// SignCredential adds proof to given verifiable credential
func (vr *Verifiable) SignCredential(request *models.RequestEnvelope) *models.ResponseEnvelope {
	respEnvelope := exec(&restOperation{
		url:        vr.URL,
		token:      vr.Token,
		httpClient: vr.httpClient,
		endpoint:   vr.endpoints[cmdverifiable.SignCredentialCommandMethod],
		request:    request,
	})

	return respEnvelope
}

// GetPresentation retrieves the verifiable presentation from the store.
func (vr *Verifiable) GetPresentation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	respEnvelope := exec(&restOperation{
		url:        vr.URL,
		token:      vr.Token,
		httpClient: vr.httpClient,
		endpoint:   vr.endpoints[cmdverifiable.GetPresentationCommandMethod],
		request:    request,
	})

	return respEnvelope
}

// GetCredentialByName retrieves the verifiable credential by name from the store.
func (vr *Verifiable) GetCredentialByName(request *models.RequestEnvelope) *models.ResponseEnvelope {
	respEnvelope := exec(&restOperation{
		url:        vr.URL,
		token:      vr.Token,
		httpClient: vr.httpClient,
		endpoint:   vr.endpoints[cmdverifiable.GetCredentialByNameCommandMethod],
		request:    request,
	})

	return respEnvelope
}

// GetCredentials retrieves the verifiable credential records containing name and fields of interest.
func (vr *Verifiable) GetCredentials(request *models.RequestEnvelope) *models.ResponseEnvelope {
	respEnvelope := exec(&restOperation{
		url:        vr.URL,
		token:      vr.Token,
		httpClient: vr.httpClient,
		endpoint:   vr.endpoints[cmdverifiable.GetCredentialsCommandMethod],
		request:    request,
	})

	return respEnvelope
}

// GetPresentations retrieves the verifiable presentation records containing name and fields of interest.
func (vr *Verifiable) GetPresentations(request *models.RequestEnvelope) *models.ResponseEnvelope {
	respEnvelope := exec(&restOperation{
		url:        vr.URL,
		token:      vr.Token,
		httpClient: vr.httpClient,
		endpoint:   vr.endpoints[cmdverifiable.GetPresentationsCommandMethod],
		request:    request,
	})

	return respEnvelope
}

// GeneratePresentation generates verifiable presentation from a verifiable credential.
func (vr *Verifiable) GeneratePresentation(request *models.RequestEnvelope) *models.ResponseEnvelope {
	respEnvelope := exec(&restOperation{
		url:        vr.URL,
		token:      vr.Token,
		httpClient: vr.httpClient,
		endpoint:   vr.endpoints[cmdverifiable.GeneratePresentationCommandMethod],
		request:    request,
	})

	return respEnvelope
}

// GeneratePresentationByID generates verifiable presentation from a stored verifiable credential.
func (vr *Verifiable) GeneratePresentationByID(request *models.RequestEnvelope) *models.ResponseEnvelope {
	respEnvelope := exec(&restOperation{
		url:        vr.URL,
		token:      vr.Token,
		httpClient: vr.httpClient,
		endpoint:   vr.endpoints[cmdverifiable.GeneratePresentationByIDCommandMethod],
		request:    request,
	})

	return respEnvelope
}
