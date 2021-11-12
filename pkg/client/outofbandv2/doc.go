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
// You can create requests and invitations with client.CreateRequest() and client.CreateInvitation()
// respectively.
//
// You can accept out-of-band requests and invitations received via out of band channels.
// If you have a request or an invitation on hand you can use the client.AcceptRequest() and
// client.AcceptInvitation() respectively. These return the ID of the newly-created connection
// record.
//
// If you're expecting to receive out-of-band invitations or requests via a DIDComm V2 channel then
// you should register to the action event stream and the state event stream:
//
// events := make(chan service.DIDCommAction)
// err = client.RegisterActionEvent(events)
// if err != nil {
//     panic(err)
// }
//
// states := make(chan service.StateMsg)
// err = client.RegisterMsgEvent(states)
// if err != nil {
//    panic(err)
// }
//
// for {
//     select {
//     case event := <-events:
//         switch event.Message.Type() {
//         case outofbandv2.InvitationMsgType:
//             // inspect the request
//             req := &outofbandv2.Invitation{}
//             err = event.Message.Decode(req)
//             if err != nil {
//                 panic(err)
//             }
//
//             // accept the request:
//             event.Continue(&outofbandv2.EventOptions{Label: "Bob"})
//             // OR you may reject this request:
//             // event.Stop(errors.New("rejected"))
//         }
//     }
// }
//
// Note: the ouf-of-band protocol results in the execution of other protocols. You need to subscribe
// to the event and state streams of those protocols as well.
package outofbandv2
