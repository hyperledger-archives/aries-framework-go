/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"net/http"

	cmddidcommwallet "github.com/hyperledger/aries-framework-go/pkg/controller/command/didcommwallet"
	cmddidexch "github.com/hyperledger/aries-framework-go/pkg/controller/command/didexchange"
	cmdintroduce "github.com/hyperledger/aries-framework-go/pkg/controller/command/introduce"
	cmdisscred "github.com/hyperledger/aries-framework-go/pkg/controller/command/issuecredential"
	cmdkms "github.com/hyperledger/aries-framework-go/pkg/controller/command/kms"
	cmdld "github.com/hyperledger/aries-framework-go/pkg/controller/command/ld"
	cmdmediator "github.com/hyperledger/aries-framework-go/pkg/controller/command/mediator"
	cmdmessaging "github.com/hyperledger/aries-framework-go/pkg/controller/command/messaging"
	cmdoob "github.com/hyperledger/aries-framework-go/pkg/controller/command/outofband"
	cmdpresproof "github.com/hyperledger/aries-framework-go/pkg/controller/command/presentproof"
	cmdvcwallet "github.com/hyperledger/aries-framework-go/pkg/controller/command/vcwallet"
	cmdvdr "github.com/hyperledger/aries-framework-go/pkg/controller/command/vdr"
	cmdverifiable "github.com/hyperledger/aries-framework-go/pkg/controller/command/verifiable"
	opdidexch "github.com/hyperledger/aries-framework-go/pkg/controller/rest/didexchange"
	opintroduce "github.com/hyperledger/aries-framework-go/pkg/controller/rest/introduce"
	opisscred "github.com/hyperledger/aries-framework-go/pkg/controller/rest/issuecredential"
	opkms "github.com/hyperledger/aries-framework-go/pkg/controller/rest/kms"
	opld "github.com/hyperledger/aries-framework-go/pkg/controller/rest/ld"
	opmediator "github.com/hyperledger/aries-framework-go/pkg/controller/rest/mediator"
	opmessaging "github.com/hyperledger/aries-framework-go/pkg/controller/rest/messaging"
	opoob "github.com/hyperledger/aries-framework-go/pkg/controller/rest/outofband"
	oppresproof "github.com/hyperledger/aries-framework-go/pkg/controller/rest/presentproof"
	opvcwallet "github.com/hyperledger/aries-framework-go/pkg/controller/rest/vcwallet"
	opvdr "github.com/hyperledger/aries-framework-go/pkg/controller/rest/vdr"
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
	allEndpoints[opvdr.VDROperationID] = getVDREndpoints()
	allEndpoints[opmediator.RouteOperationID] = getMediatorEndpoints()
	allEndpoints[opmessaging.MsgServiceOperationID] = getMessagingEndpoints()
	allEndpoints[opoob.OperationID] = getOutOfBandEndpoints()
	allEndpoints[opkms.KmsOperationID] = getKMSEndpoints()
	allEndpoints[opld.OperationID] = getLDEndpoints()
	allEndpoints[opvcwallet.OperationID] = getVCWalletEndpoints()

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
		cmdintroduce.SendProposalWithOOBInvitation: {
			Path:   opintroduce.SendProposalWithOOBInvitation,
			Method: http.MethodPost,
		},
		cmdintroduce.SendRequest: {
			Path:   opintroduce.SendRequest,
			Method: http.MethodPost,
		},
		cmdintroduce.AcceptProposalWithOOBInvitation: {
			Path:   opintroduce.AcceptProposalWithOOBInvitation,
			Method: http.MethodPost,
		},
		cmdintroduce.AcceptProposal: {
			Path:   opintroduce.AcceptProposal,
			Method: http.MethodPost,
		},
		cmdintroduce.AcceptRequestWithPublicOOBInvitation: {
			Path:   opintroduce.AcceptRequestWithPublicOOBInvitation,
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

func getVDREndpoints() map[string]*endpoint {
	return map[string]*endpoint{
		cmdvdr.GetDIDCommandMethod: {
			Path:   opvdr.GetDIDPath,
			Method: http.MethodGet,
		},
		cmdvdr.GetDIDsCommandMethod: {
			Path:   opvdr.GetDIDRecordsPath,
			Method: http.MethodGet,
		},
		cmdvdr.SaveDIDCommandMethod: {
			Path:   opvdr.SaveDIDPath,
			Method: http.MethodPost,
		},
		cmdvdr.ResolveDIDCommandMethod: {
			Path:   opvdr.ResolveDIDPath,
			Method: http.MethodGet,
		},
		cmdvdr.CreateDIDCommandMethod: {
			Path:   opvdr.CreateDIDPath,
			Method: http.MethodPost,
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
		cmdmediator.GetConnectionsCommandMethod: {
			Path:   opmediator.GetConnectionsPath,
			Method: http.MethodGet,
		},
		cmdmediator.ReconnectCommandMethod: {
			Path:   opmediator.ReconnectPath,
			Method: http.MethodPost,
		},
		cmdmediator.ReconnectAllCommandMethod: {
			Path:   opmediator.ReconnectAllPath,
			Method: http.MethodGet,
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
		cmdoob.CreateInvitation: {
			Path:   opoob.CreateInvitation,
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

func getLDEndpoints() map[string]*endpoint {
	return map[string]*endpoint{
		cmdld.AddContextsCommandMethod: {
			Path:   opld.AddContextsPath,
			Method: http.MethodPost,
		},
		cmdld.AddRemoteProviderCommandMethod: {
			Path:   opld.AddRemoteProviderPath,
			Method: http.MethodPost,
		},
		cmdld.RefreshRemoteProviderCommandMethod: {
			Path:   opld.RefreshRemoteProviderPath,
			Method: http.MethodPost,
		},
		cmdld.DeleteRemoteProviderCommandMethod: {
			Path:   opld.DeleteRemoteProviderPath,
			Method: http.MethodDelete,
		},
		cmdld.GetAllRemoteProvidersCommandMethod: {
			Path:   opld.GetAllRemoteProvidersPath,
			Method: http.MethodGet,
		},
		cmdld.RefreshAllRemoteProvidersCommandMethod: {
			Path:   opld.RefreshAllRemoteProvidersPath,
			Method: http.MethodPost,
		},
	}
}

func getVCWalletEndpoints() map[string]*endpoint {
	return map[string]*endpoint{
		cmdvcwallet.CreateProfileMethod: {
			Path: opvcwallet.CreateProfilePath, Method: http.MethodPost,
		},
		cmdvcwallet.UpdateProfileMethod: {
			Path: opvcwallet.UpdateProfilePath, Method: http.MethodPost,
		},
		cmdvcwallet.ProfileExistsMethod: {
			Path: opvcwallet.ProfileExistsPath, Method: http.MethodGet,
		},
		cmdvcwallet.OpenMethod: {
			Path: opvcwallet.OpenPath, Method: http.MethodPost,
		},
		cmdvcwallet.CloseMethod: {
			Path: opvcwallet.ClosePath, Method: http.MethodPost,
		},
		cmdvcwallet.AddMethod: {
			Path: opvcwallet.AddPath, Method: http.MethodPost,
		},
		cmdvcwallet.RemoveMethod: {
			Path: opvcwallet.RemovePath, Method: http.MethodPost,
		},
		cmdvcwallet.GetMethod: {
			Path: opvcwallet.GetPath, Method: http.MethodPost,
		},
		cmdvcwallet.GetAllMethod: {
			Path: opvcwallet.GetAllPath, Method: http.MethodPost,
		},
		cmdvcwallet.QueryMethod: {
			Path: opvcwallet.QueryPath, Method: http.MethodPost,
		},
		cmdvcwallet.IssueMethod: {
			Path: opvcwallet.IssuePath, Method: http.MethodPost,
		},
		cmdvcwallet.ProveMethod: {
			Path: opvcwallet.ProvePath, Method: http.MethodPost,
		},
		cmdvcwallet.VerifyMethod: {
			Path: opvcwallet.VerifyPath, Method: http.MethodPost,
		},
		cmdvcwallet.DeriveMethod: {
			Path: opvcwallet.DerivePath, Method: http.MethodPost,
		},
		cmdvcwallet.CreateKeyPairMethod: {
			Path: opvcwallet.CreateKeyPairPath, Method: http.MethodPost,
		},
		cmddidcommwallet.ConnectMethod: {
			Path: opvcwallet.ConnectPath, Method: http.MethodPost,
		},
		cmddidcommwallet.ProposePresentationMethod: {
			Path: opvcwallet.ProposePresentationPath, Method: http.MethodPost,
		},
		cmddidcommwallet.PresentProofMethod: {
			Path: opvcwallet.PresentProofPath, Method: http.MethodPost,
		},
	}
}
