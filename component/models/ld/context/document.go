/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import "encoding/json"

// Document is a JSON-LD context document with associated metadata.
type Document struct {
	URL         string          `json:"url,omitempty"`         // URL is a context URL that shows up in the documents.
	DocumentURL string          `json:"documentURL,omitempty"` // The final URL of the loaded context document.
	Content     json.RawMessage `json:"content,omitempty"`     // Content of the context document.
}
