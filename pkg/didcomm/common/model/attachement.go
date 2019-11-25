/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package model

// Attachment defines the struct for request and issue in the protocol
type Attachment struct {
	ID       string `json:"@id,omitempty"`
	MimeType string `json:"mime-type,omitempty"`
	Data     Data   `json:"data,omitempty"`
}

// Data defines the type of the data to be part of attachment
type Data struct {
	Base64 string `json:"base64,omitempty"`
}
