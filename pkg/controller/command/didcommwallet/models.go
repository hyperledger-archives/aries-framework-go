/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didcommwallet

import (
	"encoding/json"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/vcwallet"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

// ConnectRequest is request model for wallet DID connect operation.
type ConnectRequest struct {
	vcwallet.WalletAuth

	// out-of-band invitation to establish connection.
	Invitation *outofband.Invitation `json:"invitation"`

	ConnectOpts
}

// ConnectOpts is option for accepting out-of-band invitation and to perform DID exchange.
type ConnectOpts struct {
	// Label to be shared with the other agent during the subsequent DID exchange.
	MyLabel string `json:"myLabel,omitempty"`

	// router connections to be used to establish connection.
	RouterConnections []string `json:"routerConnections,omitempty"`

	// DID to be used when reusing a connection.
	ReuseConnection string `json:"reuseConnection,omitempty"`

	// To use any recognized DID in the services array for a reusable connection.
	ReuseAnyConnection bool `json:"reuseAnyConnection,omitempty"`

	// Timeout (in milliseconds) waiting for connection status to be completed.
	Timeout time.Duration `json:"timeout,omitempty"`
}

// ConnectResponse is response model from wallet DID connection operation.
type ConnectResponse struct {
	// connection ID of the connection established.
	ConnectionID string `json:"connectionID"`
}

// ProposePresentationRequest is request model for performing propose presentation operation from wallet.
type ProposePresentationRequest struct {
	vcwallet.WalletAuth

	// out-of-band invitation to establish connection and send propose presentation message.
	Invitation *wallet.GenericInvitation `json:"invitation"`

	// Optional From DID option to customize sender DID.
	FromDID string `json:"from,omitempty"`

	// Timeout (in milliseconds) waiting for operation to be completed.
	Timeout time.Duration `json:"timeout,omitempty"`

	// Options for accepting out-of-band invitation and to perform DID exchange (for DIDComm V1).
	ConnectionOpts ConnectOpts `json:"connectOptions,omitempty"`
}

// ProposePresentationResponse is response model from wallet propose presentation operation.
type ProposePresentationResponse struct {
	// response request presentation message from  relying party.
	PresentationRequest *service.DIDCommMsgMap `json:"presentationRequest,omitempty"`
}

// PresentProofRequest is request model from wallet present proof operation.
// Supported attachment MIME type "application/ld+json".
type PresentProofRequest struct {
	vcwallet.WalletAuth

	// Thread ID from request presentation response
	ThreadID string `json:"threadID,omitempty"`

	// presentation to be sent as part of present proof message.
	Presentation json.RawMessage `json:"presentation,omitempty"`

	// If true then wallet will wait for present proof protocol status to be
	// done or abandoned till given Timeout.
	// Also, will return web redirect info if found in acknowledgment message or problem-report.
	WaitForDone bool `json:"waitForDone,omitempty"`

	// Optional timeout (in milliseconds) waiting for present proof operation to be done.
	// will be taken into account only when WaitForDone is enabled.
	// If not provided then wallet will use its default timeout.
	Timeout time.Duration `json:"WaitForDoneTimeout,omitempty"`
}

// PresentProofResponse is response model from wallet present proof operation.
type PresentProofResponse struct {
	wallet.CredentialInteractionStatus
}

// ProposeCredentialRequest is request model for performing propose credential operation from wallet.
type ProposeCredentialRequest struct {
	vcwallet.WalletAuth

	// out-of-band invitation to establish connection and send propose credential message.
	Invitation *wallet.GenericInvitation `json:"invitation"`

	// Optional From DID option to customize sender DID.
	FromDID string `json:"from,omitempty"`

	// Timeout (in milliseconds) waiting for operation to be completed.
	Timeout time.Duration `json:"timeout,omitempty"`

	// Options for accepting out-of-band invitation and to perform DID exchange (for DIDComm V1).
	ConnectionOpts ConnectOpts `json:"connectOptions,omitempty"`
}

// ProposeCredentialResponse is response model from wallet propose credential operation.
type ProposeCredentialResponse struct {
	// response offer credential message from issuer.
	OfferCredential *service.DIDCommMsgMap `json:"offerCredential,omitempty"`
}

// RequestCredentialRequest is request model from wallet request credential operation.
// Supported attachment MIME type "application/ld+json".
type RequestCredentialRequest struct {
	vcwallet.WalletAuth

	// Thread ID from offer credential response previously received during propose credential interaction.
	ThreadID string `json:"threadID,omitempty"`

	// presentation to be sent as part of request credential message.
	Presentation json.RawMessage `json:"presentation,omitempty"`

	// If true then wallet will wait till it receives credential response response from issuer for given Timeout.
	// Also, will return web redirect info if found in response message or problem-report.
	WaitForDone bool `json:"waitForDone,omitempty"`

	// Optional timeout (in milliseconds) waiting for credential response to arrive.
	// will be taken into account only when WaitForDone is enabled.
	// If not provided then wallet will use its default timeout.
	Timeout time.Duration `json:"WaitForDoneTimeout,omitempty"`
}

// RequestCredentialResponse is response model from wallet request credential operation.
type RequestCredentialResponse struct {
	wallet.CredentialInteractionStatus
}
