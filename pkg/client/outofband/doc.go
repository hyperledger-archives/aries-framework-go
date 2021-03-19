/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package outofband provides support for the Out-of-Band protocols:
// https://github.com/hyperledger/aries-rfcs/blob/master/features/0434-outofband/README.md.
//
// Create your client:
//
// ctx := getFrameworkContext()
// client, err := outofband.New(ctx)
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
// If you're expecting to receive out-of-band invitations or requests via a DIDComm channel then
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
//         case outofband.RequestMsgType:
//             // inspect the request
//             req := &outofband.Invitation{}
//             err = event.Message.Decode(req)
//             if err != nil {
//                 panic(err)
//             }
//
//             // accept the request:
//             event.Continue(&outofband.EventOptions{Label: "Bob"})
//             // OR you may reject this request:
//             // event.Stop(errors.New("rejected"))
//         case outofband.InvitationMsgType:
//             // inspect and handle the out-of-band invitation just like with the
//             // request message above
//         }
//     case state := <-states:
//         // the connection ID is delivered in a PostState
//         if state.Type == service.PostState {
//             props := state.Properties.(outofband.Event)
//             if props.Error() != nil {
//                 panic(props.Error())
//             }
//
//             // the connection ID
//             connID := props.ConnectionID()
//         }
//     }
// }
//
// Note: the ouf-of-band protocol results in the execution of other protocols. You need to subscribe
// to the event and state streams of those protocols as well.
package outofband
