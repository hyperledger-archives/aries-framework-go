/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.
 SPDX-License-Identifier: Apache-2.0
*/

package api

// Handler handles notification from the framework
// USAGE: The client e.g (android, IOS) must implement this interface
// to be able to process the notifications from the framework.
// The handle method plays a callback function role.
type Handler interface {
	Handle(topic string, message []byte) error
}
