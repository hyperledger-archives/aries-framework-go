/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package presentproof provides support for the Present Proof Protocol 2.0:
// https://github.com/hyperledger/aries-rfcs/blob/master/features/0454-present-proof-v2/README.md.
//
// A protocol supporting a general purpose verifiable presentation exchange regardless of the specifics of
// the underlying verifiable presentation request and verifiable presentation format.
//
// 1. Create your client:
//
// 	client, err := presentproof.New(ctx)
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
//        if event.Message.Type() == presentproof.ProposePresentationMsgType {
//          // If Verifier is willing to accept the proposal.
//          client.AcceptProposePresentation(piid, &RequestPresentation{})
//          // If Verifier is not willing to accept the proposal.
//          client.DeclineProposePresentation(piid, reason)
//        }
//
//        if event.Message.Type() == presentproof.RequestPresentationMsgType {
//          // If Prover is willing to accept a request.
//          client.AcceptRequestPresentation(piid, &Presentation{})
//          // If Prover wants to counter a request they received with a proposal.
//          client.NegotiateRequestPresentation(piid, &ProposePresentation{})
//          // If Prover is not willing to accept a request.
//          client.DeclineRequestPresentation(piid, reason)
//        }
//
//        if event.Message.Type() == presentproof.PresentationMsgType {
//          // If Verifier is willing to accept the presentation.
//          client.AcceptPresentation(piid, names)
//          // If Verifier is not willing to accept the presentation.
//          client.DeclinePresentation(piid, reason)
//        }
//
//        if event.Message.Type() == presentproof.ProblemReportMsgType {
//          Problem report message is triggered to notify client about the error.
//          In that case, there is only one option - accept it.
//          client.AcceptProblemReport(piid)
//        }
//    }
//  }
//
// How to initiate the protocol?
// The protocol can be initiated by the Verifier or by the Prover.
// Prover initiates the protocol.
//  client.SendProposePresentation(&ProposePresentation{}, myDID, theirDID)
// Verifier initiates the protocol.
//  client.SendRequestPresentation(&RequestPresentation{}, myDID, theirDID)
//
package presentproof
