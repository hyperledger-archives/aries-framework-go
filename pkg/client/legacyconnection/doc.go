/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package legacyconnection enables relationship between two agents via Connection RFC-0160 Protocol.
// The connection request message is used to communicate the DID document of the invitee to the inviter
// using the provisional service information present in the invitation message. The connection response message
// is used to complete the connection and communicate the DID document of the inviter to the invitee.
// After inviter receives the connection response, the establishment of connection is technically complete
// however it is still unconfirmed to the inviter. The invitee sends ACK message to inviter to confirm the connection.
//
//  Basic Flow:
//  1) Prepare client context
//  2) Create client
//  3) Register for action events (enables auto execution)
//  4) Create Invitation
//  5) Handle invitation
//  6) Use connection
//
package legacyconnection
