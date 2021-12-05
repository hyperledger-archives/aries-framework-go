/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

// Handler describes middleware interface.
type Handler interface {
	Handle(metadata Metadata) error
}

// Middleware function receives next handler and returns handler that needs to be executed.
type Middleware func(next Handler) Handler

// HandlerFunc is a helper type which implements the middleware Handler interface.
type HandlerFunc func(metadata Metadata) error

// Handle implements function to satisfy the Handler interface.
func (hf HandlerFunc) Handle(metadata Metadata) error {
	return hf(metadata)
}

// Metadata provides helpful information for the processing.
type Metadata interface {
	// Message contains the original inbound/outbound message
	Message() service.DIDCommMsg
	// Presentation is pointer to the message provided by the user through the Continue function.
	Presentation() *PresentationV2
	// ProposePresentation is pointer to the message provided by the user through the Continue function.
	ProposePresentation() *ProposePresentationV2
	// RequestPresentation is pointer to the message provided by the user through the Continue function.
	RequestPresentation() *RequestPresentationV2
	// PresentationV3 is pointer to the message provided by the user through the Continue function.
	PresentationV3() *PresentationV3
	// ProposePresentationV3 is pointer to the message provided by the user through the Continue function.
	ProposePresentationV3() *ProposePresentationV3
	// RequestPresentationV3 is pointer to the message provided by the user through the Continue function.
	RequestPresentationV3() *RequestPresentationV3
	// PresentationNames is a slice which contains presentation names provided by the user through the Continue function.
	PresentationNames() []string
	// StateName provides the state name
	StateName() string
	// Properties provides the possibility to set properties
	Properties() map[string]interface{}
	// GetAddProofFn provides function to sign the Presentation.
	GetAddProofFn() func(presentation *verifiable.Presentation) error
}
