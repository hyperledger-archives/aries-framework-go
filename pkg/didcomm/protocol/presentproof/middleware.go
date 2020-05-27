/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"

// Handler describes middleware interface
type Handler interface {
	Handle(metadata Metadata) error
}

// Middleware function receives next handler and returns handler that needs to be executed
type Middleware func(next Handler) Handler

// HandlerFunc is a helper type which implements the middleware Handler interface
type HandlerFunc func(metadata Metadata) error

// Handle implements function to satisfy the Handler interface
func (hf HandlerFunc) Handle(metadata Metadata) error {
	return hf(metadata)
}

// Metadata provides helpful information for the processing
type Metadata interface {
	// Message contains the original inbound/outbound message
	Message() service.DIDCommMsg
	// Presentation is pointer to the message provided by the user through the Continue function.
	Presentation() *Presentation
	// ProposePresentation is pointer to the message provided by the user through the Continue function.
	ProposePresentation() *ProposePresentation
	// RequestPresentation is pointer to the message provided by the user through the Continue function.
	RequestPresentation() *RequestPresentation
	// PresentationNames is a slice which contains presentation names provided by the user through the Continue function.
	PresentationNames() []string
	// StateName provides the state name
	StateName() string
}
