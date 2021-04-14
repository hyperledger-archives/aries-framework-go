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
	"strings"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
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
	// JWS is a JSON web signature over the encoded data, in detached format.
	JWS json.RawMessage `json:"jws,omitempty"`
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

	return nil, errors.New("no contents in this attachment")
}

type rawSig struct {
	Header    rawSigHeader `json:"header,omitempty"`
	Signature string       `json:"signature,omitempty"`
	Protected string       `json:"protected,omitempty"`
}

type rawSigHeader struct {
	KID string `json:"kid,omitempty"`
}

type rawProtected struct {
	JWK json.RawMessage `json:"jwk,omitempty"`
	Alg string          `json:"alg,omitempty"`
}

// Sign signs the base64 payload of the AttachmentData, and adds the signature to the attachment.
func (d *AttachmentData) Sign(c crypto.Crypto, kh, pub interface{}, pubBytes []byte) error { // nolint:funlen,gocyclo
	didKey, _ := fingerprint.CreateDIDKey(pubBytes)

	jwk, err := jose.JWKFromKey(pub)
	if err != nil {
		return fmt.Errorf("creating jwk from pub key: %w", err)
	}

	jwk.KeyID = didKey

	jwkBytes, err := jwk.MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshaling jwk: %w", err)
	}

	protected := rawProtected{
		JWK: jwkBytes,
	}

	kty, err := jwk.KeyType()
	if err != nil {
		return fmt.Errorf("getting keytype: %w", err)
	}

	switch kty {
	case kms.ED25519Type:
		protected.Alg = "EdDSA"
	case kms.ECDSAP256TypeIEEEP1363:
		protected.Alg = "ES256"
	case kms.ECDSAP384TypeIEEEP1363:
		protected.Alg = "ES384"
	case kms.ECDSAP521TypeIEEEP1363:
		protected.Alg = "ES512"
	default:
		return fmt.Errorf("unsupported KeyType for attachment signing")
	}

	protectedBytes, err := json.Marshal(protected)
	if err != nil {
		return fmt.Errorf("marshaling protected header: %w", err)
	}

	protectedB64 := base64.RawURLEncoding.EncodeToString(protectedBytes)

	var b64data string

	// interop: the specific behaviour here isn't fully specified by the attachment decorator RFC (as of yet)
	// see issue https://github.com/hyperledger/aries-cloudagent-python/issues/1108
	if doACAPyInterop {
		b64data = b64ToRawURL(d.Base64)
	} else {
		b64data = d.Base64
	}

	signedData := fmt.Sprintf("%s.%s", protectedB64, b64data)

	sig, err := c.Sign([]byte(signedData), kh)
	if err != nil {
		return fmt.Errorf("signing data: %w", err)
	}

	jws := rawSig{
		Header: rawSigHeader{
			KID: didKey,
		},
		Protected: protectedB64,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}

	serializedJWS, err := json.Marshal(jws)
	if err != nil {
		return fmt.Errorf("marshaling jws: %w", err)
	}

	d.JWS = serializedJWS

	return nil
}

func b64ToRawURL(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.Trim(s, "="), "+", "-"), "/", "_")
}

// Verify verify the signature on the attachment data.
func (d *AttachmentData) Verify(c crypto.Crypto, keyManager kms.KeyManager) error { // nolint:funlen,gocyclo
	if d.JWS == nil {
		return fmt.Errorf("no signature to verify")
	}

	jws := rawSig{}

	err := json.Unmarshal(d.JWS, &jws)
	if err != nil {
		return fmt.Errorf("parsing jws: %w", err)
	}

	sigKey, err := fingerprint.PubKeyFromDIDKey(jws.Header.KID)
	if err != nil {
		return fmt.Errorf("parsing did:key '%s': %w", jws.Header.KID, err)
	}

	protectedBytes, err := base64.RawURLEncoding.DecodeString(jws.Protected)
	if err != nil {
		return fmt.Errorf("decoding protected header: %w", err)
	}

	var protected rawProtected

	err = json.Unmarshal(protectedBytes, &protected)
	if err != nil {
		return fmt.Errorf("parsing protected header: %w", err)
	}

	jwk := jose.JWK{}

	err = jwk.UnmarshalJSON(protected.JWK)
	if err != nil {
		return fmt.Errorf("parsing jwk: %w", err)
	}

	keyType, err := jwk.KeyType()
	if err != nil {
		return fmt.Errorf("getting KeyType for jwk: %w", err)
	}

	kh, err := keyManager.PubKeyBytesToHandle(sigKey, keyType)
	if err != nil {
		return fmt.Errorf("creating key handle: %w", err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(jws.Signature)
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}

	var b64data string

	// interop: the specific behaviour here isn't fully specified by the attachment decorator RFC (as of yet)
	// see issue https://github.com/hyperledger/aries-cloudagent-python/issues/1108
	if doACAPyInterop {
		b64data = b64ToRawURL(d.Base64)
	} else {
		b64data = d.Base64
	}

	signedData := fmt.Sprintf("%s.%s", jws.Protected, b64data)

	err = c.Verify(sig, []byte(signedData), kh)
	if err != nil {
		return fmt.Errorf("signature verification: %w", err)
	}

	return nil
}
