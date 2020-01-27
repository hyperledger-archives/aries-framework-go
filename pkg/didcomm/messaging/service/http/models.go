/*
 *
 * Copyright SecureKey Technologies Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 *
 */

package http

// httpOverDIDCommMsg is incoming DIDComm message for http-over-didcomm message types
// Reference:
//  https://github.com/hyperledger/aries-rfcs/blob/master/features/0335-http-over-didcomm/README.md#message-format
type httpOverDIDCommMsg struct {
	ID          string `json:"@id"`
	Method      string `json:"method"`
	ResourceURI string `json:"resource-uri,omitempty"`
	Version     string `json:"version"`
	Headers     []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"headers"`
	BodyB64 string `json:"body,omitempty"`
}
