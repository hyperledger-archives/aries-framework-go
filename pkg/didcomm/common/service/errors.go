/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

// Service errors.
const (
	ErrChannelRegistered = serviceError("channel is already registered for the action event")
	ErrNilChannel        = serviceError("cannot pass nil channel")
	ErrInvalidChannel    = serviceError("invalid channel passed to unregister the action event")
	ErrThreadIDNotFound  = serviceError("threadID not found")
	ErrInvalidMessage    = serviceError("invalid message")
	ErrNilMessage        = serviceError("message is nil")
)

// serviceError defines service error.
type serviceError string

// Error satisfies build-in error interface.
func (e serviceError) Error() string { return string(e) }
