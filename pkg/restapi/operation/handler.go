/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
)

// Handler http handler for each controller API endpoint
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// MessageHandler maintains registered message services
// and it allows dynamic registration of message services
type MessageHandler interface {
	// Services returns list of available message services in this message handler
	Services() []dispatcher.MessageService
	// Register registers given message services to this message handler
	Register(msgSvcs ...dispatcher.MessageService) error
	// Unregister unregisters message service with given name from this message handler
	Unregister(name string) error
}
