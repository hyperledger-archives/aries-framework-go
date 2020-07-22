/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"net/http"

	cmddidexch "github.com/hyperledger/aries-framework-go/pkg/controller/command/didexchange"
	cmdintroduce "github.com/hyperledger/aries-framework-go/pkg/controller/command/introduce"
	cmdisscred "github.com/hyperledger/aries-framework-go/pkg/controller/command/issuecredential"
	cmdkms "github.com/hyperledger/aries-framework-go/pkg/controller/command/kms"
	cmdmediator "github.com/hyperledger/aries-framework-go/pkg/controller/command/mediator"
	cmdmessaging "github.com/hyperledger/aries-framework-go/pkg/controller/command/messaging"
	cmdoob "github.com/hyperledger/aries-framework-go/pkg/controller/command/outofband"
	cmdpresproof "github.com/hyperledger/aries-framework-go/pkg/controller/command/presentproof"
	cmdvdri "github.com/hyperledger/aries-framework-go/pkg/controller/command/vdri"
	cmdverifiable "github.com/hyperledger/aries-framework-go/pkg/controller/command/verifiable"

	opdidexch "github.com/hyperledger/aries-framework-go/pkg/controller/rest/didexchange"
	opintroduce "github.com/hyperledger/aries-framework-go/pkg/controller/rest/introduce"
	opisscred "github.com/hyperledger/aries-framework-go/pkg/controller/rest/issuecredential"
	opkms "github.com/hyperledger/aries-framework-go/pkg/controller/rest/kms"
	opmediator "github.com/hyperledger/aries-framework-go/pkg/controller/rest/mediator"
	opmessaging "github.com/hyperledger/aries-framework-go/pkg/controller/rest/messaging"
	opoob "github.com/hyperledger/aries-framework-go/pkg/controller/rest/outofband"
	oppresproof "github.com/hyperledger/aries-framework-go/pkg/controller/rest/presentproof"
	opvdri "github.com/hyperledger/aries-framework-go/pkg/controller/rest/vdri"
	opverifiable "github.com/hyperledger/aries-framework-go/pkg/controller/rest/verifiable"
)

// endpoint describes the fields for making calls to external agents.
type endpoint struct {
	Path   string
	Method string
}

func getControllerEndpoints() map[string]map[string]*endpoint {
	allEndpoints := make(map[string]map[string]*endpoint)

	allEndpoints[opintroduce.OperationID] = getIntroduceEndpoints()
	allEndpoints[opverifiable.VerifiableOperationID] = getVerifiableEndpoints()
	allEndpoints[opdidexch.OperationID] = getDIDExchangeEndpoints()
	allEndpoints[opisscred.OperationID] = getIssueCredentialEndpoints()
	allEndpoints[oppresproof.OperationID] = getPresentProofEndpoints()
	allEndpoints[opvdri.VdriOperationID] = getVDRIEndpoints()
	allEndpoints[opmediator.RouteOperationID] = getMediatorEndpoints()
	allEndpoints[opmessaging.MsgServiceOperationID] = getMessagingEndpoints()
	allEndpoints[opoob.OperationID] = getOutOfBandEndpoints()
	allEndpoints[opkms.KmsOperationID] = getKMSEndpoints()

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
		cmdintroduce.AcceptProblemReport: {
			Path:   opintroduce.AcceptProblemReport,
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
		cmdverifiable.RemoveCredentialByNameCommandMethod: {
			Path:   opverifiable.RemoveCredentialByNamePath,
			Method: http.MethodPost,
		},
		cmdverifiable.RemovePresentationByNameCommandMethod: {
			Path:   opverifiable.RemovePresentationByNamePath,
			Method: http.MethodPost,
		},
	}
}

func getDIDExchangeEndpoints() map[string]*endpoint {
	return map[string]*endpoint{
		cmddidexch.CreateInvitationCommandMethod: {
			Path:   opdidexch.CreateInvitationPath,
			Method: http.MethodPost,
		},
		cmddidexch.ReceiveInvitationCommandMethod: {
			Path:   opdidexch.ReceiveInvitationPath,
			Method: http.MethodPost,
		},
		cmddidexch.AcceptInvitationCommandMethod: {
			Path:   opdidexch.AcceptInvitationPath,
			Method: http.MethodPost,
		},
		cmddidexch.CreateImplicitInvitationCommandMethod: {
			Path:   opdidexch.CreateImplicitInvitationPath,
			Method: http.MethodPost,
		},
		cmddidexch.AcceptExchangeRequestCommandMethod: {
			Path:   opdidexch.AcceptExchangeRequest,
			Method: http.MethodPost,
		},
		cmddidexch.QueryConnectionsCommandMethod: {
			Path:   opdidexch.Connections,
			Method: http.MethodGet,
		},
		cmddidexch.QueryConnectionByIDCommandMethod: {
			Path:   opdidexch.ConnectionsByID,
			Method: http.MethodGet,
		},
		cmddidexch.CreateConnectionCommandMethod: {
			Path:   opdidexch.CreateConnection,
			Method: http.MethodPost,
		},
		cmddidexch.RemoveConnectionCommandMethod: {
			Path:   opdidexch.RemoveConnection,
			Method: http.MethodPost,
		},
	}
}

func getIssueCredentialEndpoints() map[string]*endpoint {
	return map[string]*endpoint{
		cmdisscred.Actions: {
			Path:   opisscred.Actions,
			Method: http.MethodGet,
		},
		cmdisscred.SendOffer: {
			Path:   opisscred.SendOffer,
			Method: http.MethodPost,
		},
		cmdisscred.SendProposal: {
			Path:   opisscred.SendProposal,
			Method: http.MethodPost,
		},
		cmdisscred.SendRequest: {
			Path:   opisscred.SendRequest,
			Method: http.MethodPost,
		},
		cmdisscred.AcceptProposal: {
			Path:   opisscred.AcceptProposal,
			Method: http.MethodPost,
		},
		cmdisscred.NegotiateProposal: {
			Path:   opisscred.NegotiateProposal,
			Method: http.MethodPost,
		},
		cmdisscred.DeclineProposal: {
			Path:   opisscred.DeclineProposal,
			Method: http.MethodPost,
		},
		cmdisscred.AcceptOffer: {
			Path:   opisscred.AcceptOffer,
			Method: http.MethodPost,
		},
		cmdisscred.AcceptProblemReport: {
			Path:   opisscred.AcceptProblemReport,
			Method: http.MethodPost,
		},
		cmdisscred.DeclineOffer: {
			Path:   opisscred.DeclineOffer,
			Method: http.MethodPost,
		},
		cmdisscred.AcceptRequest: {
			Path:   opisscred.AcceptRequest,
			Method: http.MethodPost,
		},
		cmdisscred.DeclineRequest: {
			Path:   opisscred.DeclineRequest,
			Method: http.MethodPost,
		},
		cmdisscred.AcceptCredential: {
			Path:   opisscred.AcceptCredential,
			Method: http.MethodPost,
		},
		cmdisscred.DeclineCredential: {
			Path:   opisscred.DeclineCredential,
			Method: http.MethodPost,
		},
	}
}

func getPresentProofEndpoints() map[string]*endpoint {
	return map[string]*endpoint{
		cmdpresproof.Actions: {
			Path:   oppresproof.Actions,
			Method: http.MethodGet,
		},
		cmdpresproof.SendRequestPresentation: {
			Path:   oppresproof.SendRequestPresentation,
			Method: http.MethodPost,
		},
		cmdpresproof.SendProposePresentation: {
			Path:   oppresproof.SendProposePresentation,
			Method: http.MethodPost,
		},
		cmdpresproof.AcceptRequestPresentation: {
			Path:   oppresproof.AcceptRequestPresentation,
			Method: http.MethodPost,
		},
		cmdpresproof.NegotiateRequestPresentation: {
			Path:   oppresproof.NegotiateRequestPresentation,
			Method: http.MethodPost,
		},
		cmdpresproof.DeclineRequestPresentation: {
			Path:   oppresproof.DeclineRequestPresentation,
			Method: http.MethodPost,
		},
		cmdpresproof.AcceptProposePresentation: {
			Path:   oppresproof.AcceptProposePresentation,
			Method: http.MethodPost,
		},
		cmdpresproof.DeclineProposePresentation: {
			Path:   oppresproof.DeclineProposePresentation,
			Method: http.MethodPost,
		},
		cmdpresproof.AcceptPresentation: {
			Path:   oppresproof.AcceptPresentation,
			Method: http.MethodPost,
		},
		cmdpresproof.AcceptProblemReport: {
			Path:   oppresproof.AcceptProblemReport,
			Method: http.MethodPost,
		},
		cmdpresproof.DeclinePresentation: {
			Path:   oppresproof.DeclinePresentation,
			Method: http.MethodPost,
		},
	}
}

func getVDRIEndpoints() map[string]*endpoint {
	return map[string]*endpoint{
		cmdvdri.GetDIDCommandMethod: {
			Path:   opvdri.GetDIDPath,
			Method: http.MethodGet,
		},
		cmdvdri.GetDIDsCommandMethod: {
			Path:   opvdri.GetDIDRecordsPath,
			Method: http.MethodGet,
		},
		cmdvdri.SaveDIDCommandMethod: {
			Path:   opvdri.SaveDIDPath,
			Method: http.MethodPost,
		},
		cmdvdri.ResolveDIDCommandMethod: {
			Path:   opvdri.ResolveDIDPath,
			Method: http.MethodGet,
		},
	}
}

func getMediatorEndpoints() map[string]*endpoint {
	return map[string]*endpoint{
		cmdmediator.RegisterCommandMethod: {
			Path:   opmediator.RegisterPath,
			Method: http.MethodPost,
		},
		cmdmediator.UnregisterCommandMethod: {
			Path:   opmediator.UnregisterPath,
			Method: http.MethodDelete,
		},
		cmdmediator.GetConnectionIDCommandMethod: {
			Path:   opmediator.GetConnectionPath,
			Method: http.MethodGet,
		},
		cmdmediator.ReconnectCommandMethod: {
			Path:   opmediator.ReconnectPath,
			Method: http.MethodPost,
		},
		cmdmediator.StatusCommandMethod: {
			Path:   opmediator.StatusPath,
			Method: http.MethodPost,
		},
		cmdmediator.BatchPickupCommandMethod: {
			Path:   opmediator.BatchPickupPath,
			Method: http.MethodPost,
		},
	}
}

func getMessagingEndpoints() map[string]*endpoint {
	return map[string]*endpoint{
		cmdmessaging.RegisterMessageServiceCommandMethod: {
			Path:   opmessaging.RegisterMsgService,
			Method: http.MethodPost,
		},
		cmdmessaging.UnregisterMessageServiceCommandMethod: {
			Path:   opmessaging.UnregisterMsgService,
			Method: http.MethodPost,
		},
		cmdmessaging.RegisteredServicesCommandMethod: {
			Path:   opmessaging.MsgServiceList,
			Method: http.MethodGet,
		},
		cmdmessaging.SendNewMessageCommandMethod: {
			Path:   opmessaging.SendNewMsg,
			Method: http.MethodPost,
		},
		cmdmessaging.SendReplyMessageCommandMethod: {
			Path:   opmessaging.SendReplyMsg,
			Method: http.MethodPost,
		},
		cmdmessaging.RegisterHTTPMessageServiceCommandMethod: {
			Path:   opmessaging.RegisterHTTPOverDIDCommService,
			Method: http.MethodPost,
		},
	}
}

func getOutOfBandEndpoints() map[string]*endpoint {
	return map[string]*endpoint{
		cmdoob.Actions: {
			Path:   opoob.Actions,
			Method: http.MethodGet,
		},
		cmdoob.AcceptInvitation: {
			Path:   opoob.AcceptInvitation,
			Method: http.MethodPost,
		},
		cmdoob.CreateRequest: {
			Path:   opoob.CreateRequest,
			Method: http.MethodPost,
		},
		cmdoob.CreateInvitation: {
			Path:   opoob.CreateInvitation,
			Method: http.MethodPost,
		},
		cmdoob.AcceptRequest: {
			Path:   opoob.AcceptRequest,
			Method: http.MethodPost,
		},
		cmdoob.ActionContinue: {
			Path:   opoob.ActionContinue,
			Method: http.MethodPost,
		},
		cmdoob.ActionStop: {
			Path:   opoob.ActionStop,
			Method: http.MethodPost,
		},
	}
}

func getKMSEndpoints() map[string]*endpoint {
	return map[string]*endpoint{
		cmdkms.CreateKeySetCommandMethod: {
			Path:   opkms.CreateKeySetPath,
			Method: http.MethodPost,
		},
		cmdkms.ImportKeyCommandMethod: {
			Path:   opkms.ImportKeyPath,
			Method: http.MethodPost,
		},
	}
}
