/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package transport

import "fmt"

const (
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

// EnvelopeMediaTypeFor returns the media type that corresponds with a DIDComm envelope given 'typ'
// and optionally 'cty'.
func EnvelopeMediaTypeFor(typ, cty string) (string, error) {
	if cty == "" {
		switch typ {
		case MediaTypeV1EncryptedEnvelope, MediaTypeV2EncryptedEnvelope:
			return typ, nil
		default:
			return "", fmt.Errorf("unsupported: typ=%s", typ)
		}
	}

	m := fmt.Sprintf("%s;cty=%s", typ, cty)
	if m != MediaTypeV2EncryptedEnvelopeV1PlaintextPayload {
		return "", fmt.Errorf("unsupported: typ=%s cty=%s", typ, cty)
	}

	return m, nil
}
