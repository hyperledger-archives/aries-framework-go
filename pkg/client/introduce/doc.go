/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package introduce is responsible for the introduction between agents.
// The protocol involves at least two participants. A maximum of three participants is currently supported.
// When creating a client a default invitation might be provided. It simplifies the usage when
// someone wants to do introduction with your client. The simplest way to handle incoming messages (actions) is:
// 	introduce := client.New(...)
// 	introduce.RegisterActionEvent(actions)
// 	for {
// 	  select {
//	    case event := <-actions:
//	      thID, _ := event.Message.ThreadID()
//	      event.Continue(introduce.InvitationEnvelope(thID))
//	  }
// 	}
//
// But also there is an exception, when receiving a request.
// After receiving a request one of the following functions must be executed.
// - HandleRequest - is used when you do not have a public invitation and
// it should be provided by one of the introducees.
// - HandleRequestWithInvitation - is used when you have a public invitation.
// A bit complicated way to handle incoming messages (actions) is:
// 	introduce := client.New(...)
// 	introduce.RegisterActionEvent(actions)
// 	for {
// 	  select {
// 	    case event := <-actions:
//	      if event.Message.Type() == introduce.RequestMsgType {
//	        introduce.HandleRequest(event.Message, to, recipient)
//	        OR
//	        introduce.HandleRequestWithInvitation(event.Message, inv, to)
//	      }
//	      thID, _ := event.Message.ThreadID()
//	      event.Continue(introduce.InvitationEnvelope(thID))
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
