/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package decorator

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	// TransportReturnRouteNone return route option none.
	TransportReturnRouteNone = "none"

	// TransportReturnRouteAll return route option all.
	TransportReturnRouteAll = "all"

	// TransportReturnRouteThread return route option thread.
	TransportReturnRouteThread = "thread"
)

// Thread thread data.
type Thread struct {
	ID             string         `json:"thid,omitempty"`
	PID            string         `json:"pthid,omitempty"`
	SenderOrder    int            `json:"sender_order,omitempty"`
	ReceivedOrders map[string]int `json:"received_orders,omitempty"`
}

// Timing keeps expiration time.
type Timing struct {
	ExpiresTime time.Time `json:"expires_time,omitempty"`
}

// Transport transport decorator
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0092-transport-return-route
type Transport struct {
	ReturnRoute *ReturnRoute `json:"~transport,omitempty"`
}

// ReturnRoute works with Transport decorator. Acceptable values - "none", "all" or "thread".
type ReturnRoute struct {
	Value string `json:"~return_route,omitempty"`
}

// Attachment is intended to provide the possibility to include files, links or even JSON payload to the message.
// To find out more please visit https://github.com/hyperledger/aries-rfcs/tree/master/concepts/0017-attachments
type Attachment struct {
	// ID is a JSON-LD construct that uniquely identifies attached content within the scope of a given message.
	// Recommended on appended attachment descriptors. Possible but generally unused on embedded attachment descriptors.
	// Never required if no references to the attachment exist; if omitted, then there is no way
	// to refer to the attachment later in the thread, in error messages, and so forth.
	// Because @id is used to compose URIs, it is recommended that this name be brief and avoid spaces
	// and other characters that require URI escaping.
	ID string `json:"@id,omitempty"`
	// Description is an optional human-readable description of the content.
	Description string `json:"description,omitempty"`
	// FileName is a hint about the name that might be used if this attachment is persisted as a file.
	// It is not required, and need not be unique. If this field is present and mime-type is not,
	// the extension on the filename may be used to infer a MIME type.
	FileName string `json:"filename,omitempty"`
	// MimeType describes the MIME type of the attached content. Optional but recommended.
	MimeType string `json:"mime-type,omitempty"`
	// LastModTime is a hint about when the content in this attachment was last modified.
	LastModTime time.Time `json:"lastmod_time,omitempty"`
	// ByteCount is an optional, and mostly relevant when content is included by reference instead of by value.
	// Lets the receiver guess how expensive it will be, in time, bandwidth, and storage, to fully fetch the attachment.
	ByteCount int64 `json:"byte_count,omitempty"`
	// Data is a JSON object that gives access to the actual content of the attachment.
	Data AttachmentData `json:"data,omitempty"`
}

// AttachmentData contains attachment payload.
type AttachmentData struct {
	// Sha256 is a hash of the content. Optional. Used as an integrity check if content is inlined.
	// if content is only referenced, then including this field makes the content tamper-evident.
	// This may be redundant, if the content is stored in an inherently immutable container like
	// content-addressable storage. This may also be undesirable, if dynamic content at a specified
	// link is beneficial. Including a hash without including a way to fetch the content via link
	// is a form of proof of existence.
	Sha256 string `json:"sha256,omitempty"`
	// Links is a list of zero or more locations at which the content may be fetched.
	Links []string `json:"links,omitempty"`
	// Base64 encoded data, when representing arbitrary content inline instead of via links. Optional.
	Base64 string `json:"base64,omitempty"`
	// JSON is a directly embedded JSON data, when representing content inline instead of via links,
	// and when the content is natively conveyable as JSON. Optional.
	JSON interface{} `json:"json,omitempty"`
}

// Fetch this attachment's contents.
func (d *AttachmentData) Fetch() ([]byte, error) {
	if d.JSON != nil {
		bits, err := json.Marshal(d.JSON)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal json contents : %w", err)
		}

		return bits, nil
	}

	if d.Base64 != "" {
		bits, err := base64.StdEncoding.DecodeString(d.Base64)
		if err != nil {
			return nil, fmt.Errorf("failed to base64 decode attachment contents : %w", err)
		}

		return bits, nil
	}

	// TODO add support for checksum verification

	// TODO add support to fetch links

	// TODO add support for jws signatures

	return nil, errors.New("no contents in this attachment")
}
