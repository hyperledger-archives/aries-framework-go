/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package issuecredential provides support for the Issue Credential Protocol 2.0:
// https://github.com/hyperledger/aries-rfcs/blob/master/features/0453-issue-credential-v2/README.md.
//
// Formalizes messages used to issue a credential. The protocol is responsible for orchestrating
// the message flow according to the RFC.
//
// 1. Create your client:
//
// 	client, err := issuecredential.New(ctx)
// 	if err != nil {
// 	 panic(err)
// 	}
//
// 2. Register an action event channel.
//
// 	actions := make(chan service.DIDCommAction)
// 	client.RegisterActionEvent(actions)
//
// 3. Handle incoming actions.
//
//  for {
//    select {
//      case event := <-actions:
//        piid := e.Properties.All()["piid"].(string)
//
//        if event.Message.Type() == presentproof.ProposeCredentialMsgType {
//          // If Issuer is willing to accept the proposal.
//          client.AcceptProposalV2(piid, &OfferCredentialV2{})
//          // If Issuer is not willing to accept the proposal.
//          client.DeclineProposal(piid, reason)
//        }
//
//        if event.Message.Type() == presentproof.OfferCredentialMsgType {
//          // If Holder is willing to accept the offer.
//          client.AcceptOfferV2(piid)
//          // If Holder wants to counter an offer they received with a proposal.
//          client.NegotiateProposalV2(piid, &ProposeCredentialV2{})
//          // If Holder is not willing to accept the offer.
//          client.DeclineOffer(piid, reason)
//        }
//
//        if event.Message.Type() == presentproof.RequestCredentialMsgType {
//          // If Issuer is willing to accept the request.
//          client.AcceptRequestV2(piid, &IssueCredentialV2{})
//          // If Issuer is not willing to accept the request.
//          client.DeclineRequest(piid, reason)
//        }
//        if event.Message.Type() == presentproof.IssueCredentialMsgType {
//          // If Holder is willing to accept the credentials.
//          client.AcceptCredential(piid, names)
//          // If Holder is not willing to accept the credentials.
//          client.DeclineCredential(piid, reason)
//        }
//
//        if event.Message.Type() == presentproof.ProblemReportMsgType {
//          // Problem report message is triggered to notify client about the error.
//          // In that case, there is only one option - accept it.
//          client.AcceptProblemReport(piid)
//        }
//    }
//  }
//
// How to initiate the protocol?
// The protocol can be initiated by the Issuer or by the Holder.
// Issuer initiates the protocol.
//  client.SendOfferV2(&OfferCredentialV2{}, myDID, theirDID)
// Holder initiates the protocol. There are two options of how to initiate the protocol.
//
// 1. The Holder can begin with a proposal.
//  client.SendProposalV2(&ProposeCredentialV2{}, myDID, theirDID)
// 2. Holder can begin with a request.
//  client.SendRequestV2(&RequestCredentialV2{}, myDID, theirDID)
//
package issuecredential
