/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package event

import "github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"

// DIDCommEvent message type to pass events in go channels.
type DIDCommEvent struct {
	// DIDComm message
	Message dispatcher.DIDCommMsg
	// Callback function to be called by the consumer for further processing the message.
	Callback Callback
}

// DIDCommCallback message type to pass service callback in go channels.
type DIDCommCallback struct {
	// Set the value in case of any error while processing the DIDComm message event by the consumer.
	Err error
}

// Callback type to pass service callbacks.
type Callback func(DIDCommCallback)
