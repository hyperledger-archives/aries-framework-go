/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package didresolver

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

var doc = `{
  "@context": ["https://w3id.org/did/v1","https://w3id.org/did/v2"],
  "id": "did:example:21tDAKCERh95uGgKbJNHYp",
  "publicKey": [
    {
      "id": "did:example:123456789abcdefghi#keys-1",
      "type": "Secp256k1VerificationKey2018",
      "controller": "did:example:123456789abcdefghi",
      "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
    },
    {
      "id": "did:example:123456789abcdefghw#key2",
      "type": "RsaVerificationKey2018",
      "controller": "did:example:123456789abcdefghw",
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAryQICCl6NZ5gDKrnSztO\n3Hy8PEUcuyvg/ikC+VcIo2SFFSf18a3IMYldIugqqqZCs4/4uVW3sbdLs/6PfgdX\n7O9D22ZiFWHPYA2k2N744MNiCD1UE+tJyllUhSblK48bn+v1oZHCM0nYQ2NqUkvS\nj+hwUU3RiWl7x3D2s9wSdNt7XUtW05a/FXehsPSiJfKvHJJnGOX0BgTvkLnkAOTd\nOrUZ/wK69Dzu4IvrN4vs9Nes8vbwPa/ddZEzGR0cQMt0JBkhk9kU/qwqUseP1QRJ\n5I1jR4g8aYPL/ke9K35PxZWuDp3U0UPAZ3PjFAh+5T+fc7gzCs9dPzSHloruU+gl\nFQIDAQAB\n-----END PUBLIC KEY-----"
    }
  ],
  "authentication": [
    "did:example:123456789abcdefghi#keys-1",
    {
      "id": "did:example:123456789abcdefghs#key3",
      "type": "RsaVerificationKey2018",
      "controller": "did:example:123456789abcdefghs",
      "publicKeyHex": "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71"
    }
  ],
  "service": [
    {
      "id": "did:example:123456789abcdefghi#inbox",
      "type": "SocialWebInboxService",
      "serviceEndpoint": "https://social.example.com/83hfh37dj",
      "spamCost": {
        "amount": "0.50",
        "currency": "USD"
      }
    }
  ],
  "created": "2002-10-10T17:00:00Z",
  "proof": {
    "type": "LinkedDataSignature2015",
    "created": "2016-02-08T16:02:20Z",
    "creator": "did:example:8uQhQMGzWxR8vw5P3UWH1ja#keys-1",
    "signatureValue": "QNB13Y7Q9...1tzjn4w=="
  }
}`

func TestNew(t *testing.T) {
	r := New(WithDidMethod("test", nil))
	_, exist := r.didMethods["test"]
	require.True(t, exist)
}

func TestResolve(t *testing.T) {
	t.Run("test invalid did input", func(t *testing.T) {
		r := New(WithDidMethod("test", nil))
		_, err := r.Resolve("did:example")
		require.Error(t, err)
		require.Contains(t, err.Error(), "wrong format did input")
	})

	t.Run("test did method not supported", func(t *testing.T) {
		r := New(WithDidMethod("test", nil))
		_, err := r.Resolve("did:example:1234")
		require.Error(t, err)
		require.Contains(t, err.Error(), "did method example not supported")
	})

	t.Run("test did method read failed", func(t *testing.T) {
		r := New(WithDidMethod("example", mockDidMethod{readErr: fmt.Errorf("read error")}))
		_, err := r.Resolve("did:example:1234")
		require.Error(t, err)
		require.Contains(t, err.Error(), "did method read failed")
	})

	t.Run("test did input not found", func(t *testing.T) {
		r := New(WithDidMethod("example", mockDidMethod{}))
		didDoc, err := r.Resolve("did:example:1234")
		require.NoError(t, err)
		require.Nil(t, didDoc)
	})

	t.Run("test did doc not valid", func(t *testing.T) {
		r := New(WithDidMethod("example", mockDidMethod{readValue: []byte("wrongData")}))
		_, err := r.Resolve("did:example:1234")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to validate did doc")
	})

	t.Run("test result type resolution-result", func(t *testing.T) {
		r := New(WithDidMethod("example", mockDidMethod{readValue: []byte(doc)}))
		_, err := r.Resolve("did:example:1234", WithResultType(ResolutionResult))
		require.Error(t, err)
		require.Contains(t, err.Error(), "result type 'resolution-result' not supported")
	})

	t.Run("test result type did-document", func(t *testing.T) {
		r := New(WithDidMethod("example", mockDidMethod{readValue: []byte(doc)}))
		didDoc, err := r.Resolve("did:example:1234", WithResultType(DidDocumentResult))
		require.NoError(t, err)
		require.Equal(t, didDoc.Context[0], "https://w3id.org/did/v1")
	})

}

type mockDidMethod struct {
	readValue []byte
	readErr   error
}

func (m mockDidMethod) Read(did string, versionID interface{}, versionTime string, noCache bool) ([]byte, error) {
	return m.readValue, m.readErr
}
