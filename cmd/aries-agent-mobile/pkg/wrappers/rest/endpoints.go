/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"net/http"

	cmdintroduce "github.com/hyperledger/aries-framework-go/pkg/controller/command/introduce"
	cmdverifiable "github.com/hyperledger/aries-framework-go/pkg/controller/command/verifiable"

	opintroduce "github.com/hyperledger/aries-framework-go/pkg/controller/rest/introduce"
	opverifiable "github.com/hyperledger/aries-framework-go/pkg/controller/rest/verifiable"
)

// endpoint describes the fields for making calls to external agents
type endpoint struct {
	Path   string
	Method string
}

func getProtocolEndpoints() map[string]map[string]*endpoint {
	allEndpoints := make(map[string]map[string]*endpoint)

	allEndpoints[opintroduce.OperationID] = getIntroduceEndpoints()
	allEndpoints[opverifiable.VerifiableOperationID] = getVerifiableEndpoints()

	return allEndpoints
}

func getIntroduceEndpoints() map[string]*endpoint {
	return map[string]*endpoint{
		cmdintroduce.Actions: {
			Path:   opintroduce.Actions,
			Method: http.MethodGet,
		},
		cmdintroduce.SendProposal: {
			Path:   opintroduce.SendProposal,
			Method: http.MethodPost,
		},
		cmdintroduce.SendProposalWithOOBRequest: {
			Path:   opintroduce.SendProposalWithOOBRequest,
			Method: http.MethodPost,
		},
		cmdintroduce.SendRequest: {
			Path:   opintroduce.SendRequest,
			Method: http.MethodPost,
		},
		cmdintroduce.AcceptProposalWithOOBRequest: {
			Path:   opintroduce.AcceptProposalWithOOBRequest,
			Method: http.MethodPost,
		},
		cmdintroduce.AcceptProposal: {
			Path:   opintroduce.AcceptProposal,
			Method: http.MethodPost,
		},
		cmdintroduce.AcceptRequestWithPublicOOBRequest: {
			Path:   opintroduce.AcceptRequestWithPublicOOBRequest,
			Method: http.MethodPost,
		},
		cmdintroduce.AcceptRequestWithRecipients: {
			Path:   opintroduce.AcceptRequestWithRecipients,
			Method: http.MethodPost,
		},
		cmdintroduce.DeclineProposal: {
			Path:   opintroduce.DeclineProposal,
			Method: http.MethodPost,
		},
		cmdintroduce.DeclineRequest: {
			Path:   opintroduce.DeclineRequest,
			Method: http.MethodPost,
		},
	}
}

func getVerifiableEndpoints() map[string]*endpoint {
	return map[string]*endpoint{
		cmdverifiable.ValidateCredentialCommandMethod: {
			Path:   opverifiable.ValidateCredentialPath,
			Method: http.MethodPost,
		},
		cmdverifiable.SaveCredentialCommandMethod: {
			Path:   opverifiable.SaveCredentialPath,
			Method: http.MethodPost,
		},
		cmdverifiable.SavePresentationCommandMethod: {
			Path:   opverifiable.SavePresentationPath,
			Method: http.MethodPost,
		},
		cmdverifiable.GetCredentialCommandMethod: {
			Path:   opverifiable.GetCredentialPath,
			Method: http.MethodGet,
		},
		cmdverifiable.SignCredentialCommandMethod: {
			Path:   opverifiable.SignCredentialsPath,
			Method: http.MethodPost,
		},
		cmdverifiable.GetPresentationCommandMethod: {
			Path:   opverifiable.GetPresentationPath,
			Method: http.MethodGet,
		},
		cmdverifiable.GetCredentialByNameCommandMethod: {
			Path:   opverifiable.GetCredentialByNamePath,
			Method: http.MethodGet,
		},
		cmdverifiable.GetCredentialsCommandMethod: {
			Path:   opverifiable.GetCredentialsPath,
			Method: http.MethodGet,
		},
		cmdverifiable.GetPresentationsCommandMethod: {
			Path:   opverifiable.GetPresentationsPath,
			Method: http.MethodGet,
		},
		cmdverifiable.GeneratePresentationCommandMethod: {
			Path:   opverifiable.GeneratePresentationPath,
			Method: http.MethodPost,
		},
		cmdverifiable.GeneratePresentationByIDCommandMethod: {
			Path:   opverifiable.GeneratePresentationByIDPath,
			Method: http.MethodPost,
		},
	}
}
