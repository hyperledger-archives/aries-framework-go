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
//	        // if you want to accept request and you do not have a public out-of-band message
//	        event.Continue(WithRecipients(...))
//	        // or you have a public out-of-band message (eg. request)
//	        event.Continue(WithPublicOOBRequest(...))
//	      } else {
//	        // to share your out-of-band message (eg. request)
//	        event.Continue(WithOOBRequest(...))
//	        // or if you do not want to share your out-of-band message
//	        event.Continue(nil)
//	      }
// 	  }
// 	}
//
// Possible use cases:
// 1) The introducer wants to commit an introduction. To do that SendProposal or SendProposalWithOOBRequest
// functions should be used. SendProposalWithOOBRequest is used in case if introducer has a public out-of-band request.
// Otherwise, SendProposal function is used. A request, in that case, should be provided by one of the introducees.
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
