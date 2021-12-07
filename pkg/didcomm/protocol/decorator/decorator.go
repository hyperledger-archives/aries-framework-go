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
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
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

// Version represents DIDComm protocol version.
type Version string

// DIDComm versions.
const (
	DIDCommV1  Version = "v1"
	DIDCommV2  Version = "v2"
	AnyVersion Version = "any"
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

// AttachmentV2 is intended to provide the possibility to include files, links or even JSON payload to the message.
// To find out more please visit https://identity.foundation/didcomm-messaging/spec/#attachments
type AttachmentV2 struct {
	// ID is a JSON-LD construct that uniquely identifies attached content within the scope of a given message.
	// Recommended on appended attachment descriptors. Possible but generally unused on embedded attachment descriptors.
	// Never required if no references to the attachment exist; if omitted, then there is no way
	// to refer to the attachment later in the thread, in error messages, and so forth.
	// Because @id is used to compose URIs, it is recommended that this name be brief and avoid spaces
	// and other characters that require URI escaping.
	ID string `json:"id,omitempty"`
	// Description is an optional human-readable description of the content.
	Description string `json:"description,omitempty"`
	// FileName is a hint about the name that might be used if this attachment is persisted as a file.
	// It is not required, and need not be unique. If this field is present and mime-type is not,
	// the extension on the filename may be used to infer a MIME type.
	FileName string `json:"filename,omitempty"`
	// MediaType describes the MIME type of the attached content. Optional but recommended.
	MediaType string `json:"media_type,omitempty"`
	// LastModTime is a hint about when the content in this attachment was last modified.
	LastModTime time.Time `json:"lastmod_time,omitempty"`
	// ByteCount is an optional, and mostly relevant when content is included by reference instead of by value.
	// Lets the receiver guess how expensive it will be, in time, bandwidth, and storage, to fully fetch the attachment.
	ByteCount int64 `json:"byte_count,omitempty"`
	// Data is a JSON object that gives access to the actual content of the attachment.
	Data AttachmentData `json:"data,omitempty"`
	// Format describes the format of the attachment if the media_type is not sufficient.
	Format string `json:"format,omitempty"`
}

// GenericAttachment is used to work with DIDComm attachments that can be either DIDComm v1 or DIDComm v2.
type GenericAttachment struct {
	// ID is the attachment ID..
	ID string `json:"id,omitempty"`
	// Description is an optional human-readable description of the content.
	Description string `json:"description,omitempty"`
	// FileName is a hint about the name that might be used if this attachment is persisted as a file.
	// It is not required, and need not be unique. If this field is present and mime-type is not,
	// the extension on the filename may be used to infer a MIME type.
	FileName string `json:"filename,omitempty"`
	// MediaType describes the MIME type of the attached content in a DIDComm v2 attachment. Optional but recommended.
	MediaType string `json:"media_type,omitempty"`
	// LastModTime is a hint about when the content in this attachment was last modified.
	LastModTime time.Time `json:"lastmod_time,omitempty"`
	// ByteCount is an optional, and mostly relevant when content is included by reference instead of by value.
	// Lets the receiver guess how expensive it will be, in time, bandwidth, and storage, to fully fetch the attachment.
	ByteCount int64 `json:"byte_count,omitempty"`
	// Data is a JSON object that gives access to the actual content of the attachment.
	Data AttachmentData `json:"data,omitempty"`
	// Format describes the format of the attachment if the media_type is not sufficient, in a DIDComm v2 attachment.
	Format  string `json:"format,omitempty"`
	version Version
}

// Version returns the DIDComm version of this attachment.
func (ga *GenericAttachment) Version() Version {
	return ga.version
}

// AsV1 returns the attachment as a DIDComm v1 attachment.
func (ga *GenericAttachment) AsV1() Attachment {
	return Attachment{
		ID:          ga.ID,
		Description: ga.Description,
		FileName:    ga.FileName,
		MimeType:    ga.MediaType,
		LastModTime: ga.LastModTime,
		ByteCount:   ga.ByteCount,
		Data:        ga.Data,
	}
}

// AsV2 returns the attachment as a DIDComm v2 attachment.
func (ga *GenericAttachment) AsV2() AttachmentV2 {
	return AttachmentV2{
		ID:          ga.ID,
		Description: ga.Description,
		FileName:    ga.FileName,
		MediaType:   ga.MediaType,
		LastModTime: ga.LastModTime,
		ByteCount:   ga.ByteCount,
		Data:        ga.Data,
		Format:      ga.Format,
	}
}

// GenericAttachmentsToV1 converts a slice of GenericAttachment to a slice of Attachment.
func GenericAttachmentsToV1(attachments []GenericAttachment) []Attachment {
	if attachments == nil {
		return nil
	}

	out := make([]Attachment, len(attachments))

	for i := 0; i < len(attachments); i++ {
		out[i] = attachments[i].AsV1()
	}

	return out
}

// V1AttachmentsToGeneric converts a slice of Attachment to a slice of GenericAttachment.
func V1AttachmentsToGeneric(attachments []Attachment) []GenericAttachment {
	if attachments == nil {
		return nil
	}

	out := make([]GenericAttachment, len(attachments))

	for i := 0; i < len(attachments); i++ {
		att := attachments[i]

		out[i] = GenericAttachment{
			ID:          att.ID,
			Description: att.Description,
			FileName:    att.FileName,
			MediaType:   att.MimeType,
			LastModTime: att.LastModTime,
			ByteCount:   att.ByteCount,
			Data:        att.Data,
			version:     DIDCommV1,
		}
	}

	return out
}

// GenericAttachmentsToV2 converts a slice of GenericAttachment to a slice of AttachmentV2.
func GenericAttachmentsToV2(attachments []GenericAttachment) []AttachmentV2 {
	if attachments == nil {
		return nil
	}

	out := make([]AttachmentV2, len(attachments))

	for i := 0; i < len(attachments); i++ {
		out[i] = attachments[i].AsV2()
	}

	return out
}

// V2AttachmentsToGeneric converts a slice of AttachmentV2 to a slice of GenericAttachment.
func V2AttachmentsToGeneric(attachments []AttachmentV2) []GenericAttachment {
	if attachments == nil {
		return nil
	}

	out := make([]GenericAttachment, len(attachments))

	for i := 0; i < len(attachments); i++ {
		att := attachments[i]

		out[i] = GenericAttachment{
			ID:          att.ID,
			Description: att.Description,
			FileName:    att.FileName,
			MediaType:   att.MediaType,
			LastModTime: att.LastModTime,
			ByteCount:   att.ByteCount,
			Data:        att.Data,
			Format:      att.Format,
			version:     DIDCommV2,
		}
	}

	return out
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

// WebRedirect decorator for passing web redirect info to ask recipient of the message
// to redirect after completion of flow.
type WebRedirect struct {
	// Status of the operation,
	// Refer https://github.com/hyperledger/aries-rfcs/blob/main/features/0015-acks/README.md#ack-status.
	Status string `json:"status,omitempty"`
	// URL to which recipient of this message is being requested to redirect.
	URL string `json:"url,omitempty"`
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

	j, err := jwksupport.JWKFromKey(pub)
	if err != nil {
		return fmt.Errorf("creating jwk from pub key: %w", err)
	}

	j.KeyID = didKey

	jwkBytes, err := j.MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshaling jwk: %w", err)
	}

	protected := rawProtected{
		JWK: jwkBytes,
	}

	kty, err := j.KeyType()
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

	b64data := b64ToRawURL(d.Base64)

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

// Verify verifies the signature on the attachment data.
func (d *AttachmentData) Verify(c crypto.Crypto, keyManager kms.KeyManager) error { // nolint:gocyclo
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

	j := jwk.JWK{}

	err = j.UnmarshalJSON(protected.JWK)
	if err != nil {
		return fmt.Errorf("parsing jwk: %w", err)
	}

	keyType, err := j.KeyType()
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

	b64data := b64ToRawURL(d.Base64)

	signedData := fmt.Sprintf("%s.%s", jws.Protected, b64data)

	err = c.Verify(sig, []byte(signedData), kh)
	if err != nil {
		return fmt.Errorf("signature verification: %w", err)
	}

	return nil
}
