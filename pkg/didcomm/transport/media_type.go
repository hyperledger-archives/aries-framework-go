/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package transport

const (
	// MediaTypeRFC0019EncryptedEnvelope is the original media type for DIDComm V1 encrypted envelopes as per
	// Aries RFC 0019.
	MediaTypeRFC0019EncryptedEnvelope = "JWM/1.0"
	// MediaTypeV1EncryptedEnvelope is the media type for DIDComm V1 encrypted envelopes as per Aries RFC 0044. This
	// media type never materialized as it was in-between state of DIDComm V1 and V2 and the intent was to build the new
	// JWE format which has now become V2. It's treated as V2 in the framework for the sake of JWE compatibility.
	MediaTypeV1EncryptedEnvelope = "application/didcomm-enc-env"
	// MediaTypeV1PlaintextPayload is the media type for DIDComm V1 JWE payloads as per Aries RFC 0044.
	MediaTypeV1PlaintextPayload = "application/json;flavor=didcomm-msg"
	// MediaTypeV2EncryptedEnvelope is the media type for DIDComm V2 encrypted envelopes as per Aries RFC 0044 and the
	// DIF DIDComm spec.
	MediaTypeV2EncryptedEnvelope = "application/didcomm-encrypted+json"
	// MediaTypeV2EncryptedEnvelopeV1PlaintextPayload is the media type for DIDComm V2 encrypted envelopes with a
	// V1 plaintext payload as per Aries RFC 0587.
	MediaTypeV2EncryptedEnvelopeV1PlaintextPayload = MediaTypeV2EncryptedEnvelope + ";cty=" + MediaTypeV1PlaintextPayload
	// MediaTypeV2PlaintextPayload is the media type for DIDComm V1 JWE payloads as per Aries 044.
	MediaTypeV2PlaintextPayload = "application/didcomm-plain+json"

	// below are pre-defined profiles supported by the framework as per
	// https://github.com/hyperledger/aries-rfcs/tree/master/features/0044-didcomm-file-and-mime-types#defined-profiles.

	// MediaTypeAIP2RFC0019Profile for AIP 2.0, circa 2021 using RFC0019 encryption envelope.
	MediaTypeAIP2RFC0019Profile = "didcomm/aip2;env=rfc19"

	// MediaTypeAIP2RFC0587Profile for AIP 2.0, circa 2021 using the new JWE encryption envelope (DIDComm V2 style).
	MediaTypeAIP2RFC0587Profile = "didcomm/aip2;env=rfc587"

	// MediaTypeDIDCommV2Profile is the official DIDComm V2 profile.
	MediaTypeDIDCommV2Profile = "didcomm/v2"
)
