/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package transport

const (
	// MediaTypeRFC0019EncryptedEnvelope is the original media type for DIDComm V1 encrypted envelopes as per
	// Aries RFC 0019.
	MediaTypeRFC0019EncryptedEnvelope = "JWM/1.0"
	// MediaTypeV1EncryptedEnvelope is the media type for DIDComm V1 encrypted envelopes as per Aries RFC 0044.
	MediaTypeV1EncryptedEnvelope = "application/didcomm-enc-env"
	// MediaTypeV1PlaintextPayload is the media type for DIDComm V1 JWE payloads as per Aries RFC 0044.
	MediaTypeV1PlaintextPayload = "application/json;flavor=didcomm-msg"
	// MediaTypeV2EncryptedEnvelope is the media type for DIDComm V2 encrypted envelopes as per Aries RFC 0044 and the
	// DIF DIDComm spec.
	MediaTypeV2EncryptedEnvelope = "application/didcomm-encrypted+json"
	// MediaTypeV2EncryptedEnvelopeV1PlaintextPayload is the media type for DIDComm V2 encrypted envelopes with a
	// V1 plaintext payload as per Aries RFC 0587.
	MediaTypeV2EncryptedEnvelopeV1PlaintextPayload = MediaTypeV2EncryptedEnvelope + ";cty=" + MediaTypeV1PlaintextPayload
)
