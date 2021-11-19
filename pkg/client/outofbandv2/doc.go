/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package outofbandv2 provides support for the Out-of-Band protocols following the DIDComm V2 spec:
// https://identity.foundation/didcomm-messaging/spec/#out-of-band-messages.
//
// Create your client:
//
// ctx := getFrameworkContext()
// client, err := outofbandv2.New(ctx)
// if err != nil {
//     panic(err)
// }
//
// You can create requests and invitations with client.CreateInvitation() and client.AcceptInvitation()
// respectively.
//
// Unlike other clients in the framework, this client does not trigger events since an OOB V2 messages
// include a target goal message in the attachment that will be triggered automatically upon the execution
// of the client.AcceptInvitation() function.
//
// Note: the ouf-of-band protocol results in the execution of other protocols. You need to subscribe
// to the event and state streams of those protocols as well.
package outofbandv2
