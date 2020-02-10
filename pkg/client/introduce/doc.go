/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package introduce is responsible for the introduction between agents.
// The protocol involves at least two participants. A maximum of three participants is currently supported.
// The example below shows how to use the client.
// 	introduce := client.New(...)
// 	introduce.RegisterActionEvent(actions)
// 	for {
// 	  select {
// 	    case event := <-actions:
//	      if event.Message.Type() == introduce.RequestMsgType {
//	        // if you want to accept request and you do not have a public invitation
//	        event.Continue(WithRecipients(...))
//	        // or you have a public invitation
//	        event.Continue(WithPublicInvitation(...))
//	      } else {
//	        // to share your invitation
//	        event.Continue(WithInvitation(...))
//	        // or if you do now want to share your invitation
//	        event.Continue(nil)
//	      }
// 	  }
// 	}
//
// Possible use cases:
// 1) The introducer wants to commit an introduction. To do that SendProposal or SendProposalWithInvitation
// functions should be used. SendProposalWithInvitation is used in case if introducer has a public invitation.
// Otherwise, SendProposal function is used. An invitation, in that case, should be provided by one of the introducees.
// 2) Introducee asks the introducer about the agent. SendRequest function is used to do that.
//
//  Basic Flow:
//  1) Prepare client context
//  2) Create client
//  3) Register for action events
//  4) Handle actions
//  5) Send proposal
//
package introduce
