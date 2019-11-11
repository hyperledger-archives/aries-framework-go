/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package didexchange enables relationship between two agents via DID Exchange Protocol.
// The exchange request message is used to communicate the DID document of the invitee to the inviter
// using the provisional service information present in the invitation message. The exchange response message
// is used to complete the exchange and communicate the DID document of the inviter to the invitee.
// After inviter receives the exchange response, the exchange is technically complete however it is still
// unconfirmed to the inviter. The invitee sends ACK message to inviter to confirm the exchange.
//
//  Basic Flow:
//  1) Prepare client context
//  2) Create client
//  3) Register for action events (enables auto execution)
//  4) Create Invitation
//  5) Handle invitation
//  6) Use connection
//
package didexchange
