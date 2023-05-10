/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jose_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	hybrid "github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/subtle"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/ecdh"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/keyio"
	ecdhpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	ariesjose "github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	resolver "github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/kidresolver"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/util/jwkkid"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/util/kmsdidkey"
	mockkms "github.com/hyperledger/aries-framework-go/component/kmscrypto/mock/kms"
	mockstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mock/storage"
	cryptoapi "github.com/hyperledger/aries-framework-go/spi/crypto"
	"github.com/hyperledger/aries-framework-go/spi/kms"
)

const (
	// EnvelopeEncodingType representing the JWE 'Typ' protected type header for DIDComm V2 (example for tests).
	EnvelopeEncodingType = "application/didcomm-encrypted+json"
	// DIDCommContentEncodingType represent the JWE `Cty` protected type header for DIDComm V2 (example for tests).
	DIDCommContentEncodingType = "application/didcomm-plain+json"

	compactSerialization   = "Compact"
	fullSerialization      = "Full"
	flattenedSerialization = "Flattened"
)

//nolint:gocognit,gocyclo
func TestJWEEncryptRoundTrip(t *testing.T) {
	_, err := ariesjose.NewJWEEncrypt("", "", "", "", nil, nil, nil)
	require.EqualError(t, err, "empty recipientsPubKeys list",
		"NewJWEEncrypt should fail with empty recipientPubKeys")

	singleRecipientNISTPKWError := "jwedecrypt: failed to unwrap cek: [unwrapKey: deriveKEKAndUnwrap:" +
		" failed to AES unwrap key: go-jose/go-jose: key wrap input must be 8 byte blocks]"

	singleRecipientX25519KWError := "jwedecrypt: failed to unwrap cek: [unwrapKey: deriveKEKAndUnwrap: failed to XC20P " +
		"unwrap key: unwrap support: OKP unwrap invalid key]"

	multiRecKWError := "jwedecrypt: failed to build recipients WK: unable to read " +
		"JWK: invalid character 's' looking for beginning of value"

	tests := []struct {
		name             string
		kt               *tinkpb.KeyTemplate
		enc              ariesjose.EncAlg
		keyType          kms.KeyType
		recipientKWError string
		nbRec            int
		useCompact       bool
	}{
		{
			name:             "P-256 ECDH KW and AES256GCM encryption with 2 recipients (Full serialization)",
			kt:               ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:              ariesjose.A256GCM,
			keyType:          kms.NISTP256ECDHKWType,
			nbRec:            2,
			recipientKWError: multiRecKWError,
		},
		{
			name:             "P-256 ECDH KW and AES256GCM encryption with 1 recipient (Flattened serialization)",
			kt:               ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:              ariesjose.A256GCM,
			keyType:          kms.NISTP256ECDHKWType,
			nbRec:            1,
			recipientKWError: singleRecipientNISTPKWError,
		},
		{
			name:             "P-256 ECDH KW and AES256GCM encryption with 1 recipient (Compact serialization)",
			kt:               ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:              ariesjose.A256GCM,
			keyType:          kms.NISTP256ECDHKWType,
			nbRec:            1,
			useCompact:       true,
			recipientKWError: singleRecipientNISTPKWError,
		},
		{
			name:             "P-384 ECDH KW and AES256GCM encryption with 2 recipients (Full serialization)",
			kt:               ecdh.NISTP384ECDHKWKeyTemplate(),
			enc:              ariesjose.A256GCM,
			keyType:          kms.NISTP384ECDHKWType,
			nbRec:            2,
			recipientKWError: multiRecKWError,
		},
		{
			name:             "P-384 ECDH KW and AES256GCM encryption with 1 recipient (Flattened serialization)",
			kt:               ecdh.NISTP384ECDHKWKeyTemplate(),
			enc:              ariesjose.A256GCM,
			keyType:          kms.NISTP384ECDHKWType,
			nbRec:            1,
			recipientKWError: singleRecipientNISTPKWError,
		},
		{
			name:             "P-384 ECDH KW and AES256GCM encryption with 1 recipient (Compact serialization)",
			kt:               ecdh.NISTP384ECDHKWKeyTemplate(),
			enc:              ariesjose.A256GCM,
			keyType:          kms.NISTP384ECDHKWType,
			nbRec:            1,
			useCompact:       true,
			recipientKWError: singleRecipientNISTPKWError,
		},
		{
			name:             "P-521 ECDH KW and AES256GCM encryption with 2 recipients (Full serialization)",
			kt:               ecdh.NISTP521ECDHKWKeyTemplate(),
			enc:              ariesjose.A256GCM,
			keyType:          kms.NISTP521ECDHKWType,
			nbRec:            2,
			recipientKWError: multiRecKWError,
		},
		{
			name:             "P-521 ECDH KW and AES256GCM encryption with 1 recipient (Flattened serialization)",
			kt:               ecdh.NISTP521ECDHKWKeyTemplate(),
			enc:              ariesjose.A256GCM,
			keyType:          kms.NISTP521ECDHKWType,
			nbRec:            1,
			recipientKWError: singleRecipientNISTPKWError,
		},
		{
			name:             "P-521 ECDH KW and AES256GCM encryption with 1 recipient (Compact serialization)",
			kt:               ecdh.NISTP521ECDHKWKeyTemplate(),
			enc:              ariesjose.A256GCM,
			keyType:          kms.NISTP521ECDHKWType,
			nbRec:            1,
			useCompact:       true,
			recipientKWError: singleRecipientNISTPKWError,
		},
		{
			name:             "X25519 ECDH KW and AES256GCM encryption with 2 recipients (Full serialization)",
			kt:               ecdh.X25519ECDHKWKeyTemplate(),
			enc:              ariesjose.A256GCM,
			keyType:          kms.X25519ECDHKWType,
			nbRec:            2,
			recipientKWError: multiRecKWError,
		},
		{
			name:             "X25519 ECDH KW and AES256GCM encryption with 1 recipient (Flattened serialization)",
			kt:               ecdh.X25519ECDHKWKeyTemplate(),
			enc:              ariesjose.A256GCM,
			keyType:          kms.X25519ECDHKWType,
			nbRec:            1,
			recipientKWError: singleRecipientX25519KWError,
		},
		{
			name:             "X25519 ECDH KW and AES256GCM encryption with 1 recipient (Compact serialization)",
			kt:               ecdh.X25519ECDHKWKeyTemplate(),
			enc:              ariesjose.A256GCM,
			keyType:          kms.X25519ECDHKWType,
			nbRec:            1,
			useCompact:       true,
			recipientKWError: singleRecipientX25519KWError,
		},
		{
			name:             "P-256 ECDH KW and XChacha20Poly1305 encryption with 2 recipients (Full serialization)",
			kt:               ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:              ariesjose.XC20P,
			keyType:          kms.NISTP256ECDHKWType,
			nbRec:            2,
			recipientKWError: multiRecKWError,
		},
		{
			name:             "P-256 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Flattened serialization)",
			kt:               ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:              ariesjose.XC20P,
			keyType:          kms.NISTP256ECDHKWType,
			nbRec:            1,
			recipientKWError: singleRecipientNISTPKWError,
		},
		{
			name:             "P-256 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Compact serialization)",
			kt:               ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:              ariesjose.XC20P,
			keyType:          kms.NISTP256ECDHKWType,
			nbRec:            1,
			useCompact:       true,
			recipientKWError: singleRecipientNISTPKWError,
		},
		{
			name:             "P-384 ECDH KW and XChacha20Poly1305 encryption with 2 recipients (Full serialization)",
			kt:               ecdh.NISTP384ECDHKWKeyTemplate(),
			enc:              ariesjose.XC20P,
			keyType:          kms.NISTP384ECDHKWType,
			nbRec:            2,
			recipientKWError: multiRecKWError,
		},
		{
			name:             "P-384 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Flattened serialization)",
			kt:               ecdh.NISTP384ECDHKWKeyTemplate(),
			enc:              ariesjose.XC20P,
			keyType:          kms.NISTP384ECDHKWType,
			nbRec:            1,
			recipientKWError: singleRecipientNISTPKWError,
		},
		{
			name:             "P-384 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Compact serialization)",
			kt:               ecdh.NISTP384ECDHKWKeyTemplate(),
			enc:              ariesjose.XC20P,
			keyType:          kms.NISTP384ECDHKWType,
			nbRec:            1,
			useCompact:       true,
			recipientKWError: singleRecipientNISTPKWError,
		},
		{
			name:             "P-521 ECDH KW and XChacha20Poly1305 encryption with 2 recipients (Full serialization)",
			kt:               ecdh.NISTP521ECDHKWKeyTemplate(),
			enc:              ariesjose.XC20P,
			keyType:          kms.NISTP521ECDHKWType,
			nbRec:            2,
			recipientKWError: multiRecKWError,
		},
		{
			name:             "P-521 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Flattened serialization)",
			kt:               ecdh.NISTP521ECDHKWKeyTemplate(),
			enc:              ariesjose.XC20P,
			keyType:          kms.NISTP521ECDHKWType,
			nbRec:            1,
			recipientKWError: singleRecipientNISTPKWError,
		},
		{
			name:             "P-521 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Compact serialization)",
			kt:               ecdh.NISTP521ECDHKWKeyTemplate(),
			enc:              ariesjose.XC20P,
			keyType:          kms.NISTP521ECDHKWType,
			nbRec:            1,
			useCompact:       true,
			recipientKWError: singleRecipientNISTPKWError,
		},
		{
			name:             "X25519 ECDH KW and XChacha20Poly1305 encryption with 2 recipients (Full serialization)",
			kt:               ecdh.X25519ECDHKWKeyTemplate(),
			enc:              ariesjose.XC20P,
			keyType:          kms.X25519ECDHKWType,
			nbRec:            2,
			recipientKWError: multiRecKWError,
		},
		{
			name:             "X25519 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Flattened serialization)",
			kt:               ecdh.X25519ECDHKWKeyTemplate(),
			enc:              ariesjose.XC20P,
			keyType:          kms.X25519ECDHKWType,
			nbRec:            1,
			recipientKWError: singleRecipientX25519KWError,
		},
		{
			name:             "X25519 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Compact serialization)",
			kt:               ecdh.X25519ECDHKWKeyTemplate(),
			enc:              ariesjose.XC20P,
			keyType:          kms.X25519ECDHKWType,
			nbRec:            1,
			useCompact:       true,
			recipientKWError: singleRecipientX25519KWError,
		},
		{
			name:             "P-256 ECDH KW and A128CBCHS256 encryption with 2 recipients (Full serialization)",
			kt:               ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:              ariesjose.A128CBCHS256,
			keyType:          kms.NISTP256ECDHKWType,
			nbRec:            2,
			recipientKWError: multiRecKWError,
		},
		{
			name:             "P-256 ECDH KW and A128CBCHS256 encryption with 1 recipient (Flattened serialization)",
			kt:               ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:              ariesjose.A128CBCHS256,
			keyType:          kms.NISTP256ECDHKWType,
			nbRec:            1,
			recipientKWError: singleRecipientNISTPKWError,
		},
		{
			name:             "P-256 ECDH KW and A128CBCHS256 encryption with 1 recipient (Compact serialization)",
			kt:               ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:              ariesjose.A128CBCHS256,
			keyType:          kms.NISTP256ECDHKWType,
			nbRec:            1,
			useCompact:       true,
			recipientKWError: singleRecipientNISTPKWError,
		},
		{
			name:             "X25519 ECDH KW and A128CBCHS256 encryption with 2 recipients (Full serialization)",
			kt:               ecdh.X25519ECDHKWKeyTemplate(),
			enc:              ariesjose.A128CBCHS256,
			keyType:          kms.X25519ECDHKWType,
			nbRec:            2,
			recipientKWError: multiRecKWError,
		},
		{
			name:             "X25519 ECDH KW and A128CBCHS256 encryption with 1 recipient (Flattened serialization)",
			kt:               ecdh.X25519ECDHKWKeyTemplate(),
			enc:              ariesjose.A128CBCHS256,
			keyType:          kms.X25519ECDHKWType,
			nbRec:            1,
			recipientKWError: singleRecipientX25519KWError,
		},
		{
			name:             "X25519 ECDH KW and A128CBCHS256 encryption with 1 recipient (Compact serialization)",
			kt:               ecdh.X25519ECDHKWKeyTemplate(),
			enc:              ariesjose.A128CBCHS256,
			keyType:          kms.X25519ECDHKWType,
			nbRec:            1,
			useCompact:       true,
			recipientKWError: singleRecipientX25519KWError,
		},
		{
			name:             "P-256 ECDH KW and A192CBCHS384 encryption with 2 recipients (Full serialization)",
			kt:               ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:              ariesjose.A192CBCHS384,
			keyType:          kms.NISTP256ECDHKWType,
			nbRec:            2,
			recipientKWError: multiRecKWError,
		},
		{
			name:             "P-256 ECDH KW and A192CBCHS384 encryption with 1 recipient (Flattened serialization)",
			kt:               ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:              ariesjose.A192CBCHS384,
			keyType:          kms.NISTP256ECDHKWType,
			nbRec:            1,
			recipientKWError: singleRecipientNISTPKWError,
		},
		{
			name:             "P-256 ECDH KW and A192CBCHS384 encryption with 1 recipient (Compact serialization)",
			kt:               ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:              ariesjose.A192CBCHS384,
			keyType:          kms.NISTP256ECDHKWType,
			nbRec:            1,
			useCompact:       true,
			recipientKWError: singleRecipientNISTPKWError,
		},
		{
			name:             "X25519 ECDH KW and A192CBCHS384 encryption with 2 recipients (Full serialization)",
			kt:               ecdh.X25519ECDHKWKeyTemplate(),
			enc:              ariesjose.A192CBCHS384,
			keyType:          kms.X25519ECDHKWType,
			nbRec:            2,
			recipientKWError: multiRecKWError,
		},
		{
			name:             "X25519 ECDH KW and A192CBCHS384 encryption with 1 recipient (Flattened serialization)",
			kt:               ecdh.X25519ECDHKWKeyTemplate(),
			enc:              ariesjose.A192CBCHS384,
			keyType:          kms.X25519ECDHKWType,
			nbRec:            1,
			recipientKWError: singleRecipientX25519KWError,
		},
		{
			name:             "X25519 ECDH KW and A192CBCHS384 encryption with 1 recipient (Compact serialization)",
			kt:               ecdh.X25519ECDHKWKeyTemplate(),
			enc:              ariesjose.A192CBCHS384,
			keyType:          kms.X25519ECDHKWType,
			nbRec:            1,
			useCompact:       true,
			recipientKWError: singleRecipientX25519KWError,
		},
		{
			name:             "P-256 ECDH KW and A256CBCHS384 encryption with 2 recipients (Full serialization)",
			kt:               ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:              ariesjose.A256CBCHS384,
			keyType:          kms.NISTP256ECDHKWType,
			nbRec:            2,
			recipientKWError: multiRecKWError,
		},
		{
			name:             "P-256 ECDH KW and A256CBCHS384 encryption with 1 recipient (Flattened serialization)",
			kt:               ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:              ariesjose.A256CBCHS384,
			keyType:          kms.NISTP256ECDHKWType,
			nbRec:            1,
			recipientKWError: singleRecipientNISTPKWError,
		},
		{
			name:             "P-256 ECDH KW and A256CBCHS384 encryption with 1 recipient (Compact serialization)",
			kt:               ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:              ariesjose.A256CBCHS384,
			keyType:          kms.NISTP256ECDHKWType,
			nbRec:            1,
			useCompact:       true,
			recipientKWError: singleRecipientNISTPKWError,
		},
		{
			name:             "X25519 ECDH KW and A256CBCHS384 encryption with 2 recipients (Full serialization)",
			kt:               ecdh.X25519ECDHKWKeyTemplate(),
			enc:              ariesjose.A256CBCHS384,
			keyType:          kms.X25519ECDHKWType,
			nbRec:            2,
			recipientKWError: multiRecKWError,
		},
		{
			name:             "X25519 ECDH KW and A256CBCHS384 encryption with 1 recipient (Flattened serialization)",
			kt:               ecdh.X25519ECDHKWKeyTemplate(),
			enc:              ariesjose.A256CBCHS384,
			keyType:          kms.X25519ECDHKWType,
			nbRec:            1,
			recipientKWError: singleRecipientX25519KWError,
		},
		{
			name:             "X25519 ECDH KW and A256CBCHS384 encryption with 1 recipient (Compact serialization)",
			kt:               ecdh.X25519ECDHKWKeyTemplate(),
			enc:              ariesjose.A256CBCHS384,
			keyType:          kms.X25519ECDHKWType,
			nbRec:            1,
			useCompact:       true,
			recipientKWError: singleRecipientX25519KWError,
		},
		{
			name:             "P-256 ECDH KW and A256CBCHS512 encryption with 2 recipients (Full serialization)",
			kt:               ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:              ariesjose.A256CBCHS512,
			keyType:          kms.NISTP256ECDHKWType,
			nbRec:            2,
			recipientKWError: multiRecKWError,
		},
		{
			name:             "P-256 ECDH KW and A256CBCHS512 encryption with 1 recipient (Flattened serialization)",
			kt:               ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:              ariesjose.A256CBCHS512,
			keyType:          kms.NISTP256ECDHKWType,
			nbRec:            1,
			recipientKWError: singleRecipientNISTPKWError,
		},
		{
			name:             "P-256 ECDH KW and A256CBCHS512 encryption with 1 recipient (Compact serialization)",
			kt:               ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:              ariesjose.A256CBCHS512,
			keyType:          kms.NISTP256ECDHKWType,
			nbRec:            1,
			useCompact:       true,
			recipientKWError: singleRecipientNISTPKWError,
		},
		{
			name:             "X25519 ECDH KW and A256CBCHS512 encryption with 2 recipients (Full serialization)",
			kt:               ecdh.X25519ECDHKWKeyTemplate(),
			enc:              ariesjose.A256CBCHS512,
			keyType:          kms.X25519ECDHKWType,
			nbRec:            2,
			recipientKWError: multiRecKWError,
		},
		{
			name:             "X25519 ECDH KW and A256CBCHS512 encryption with 1 recipient (Flattened serialization)",
			kt:               ecdh.X25519ECDHKWKeyTemplate(),
			enc:              ariesjose.A256CBCHS512,
			keyType:          kms.X25519ECDHKWType,
			nbRec:            1,
			recipientKWError: singleRecipientX25519KWError,
		},
		{
			name:             "X25519 ECDH KW and A256CBCHS512 encryption with 1 recipient (Compact serialization)",
			kt:               ecdh.X25519ECDHKWKeyTemplate(),
			enc:              ariesjose.A256CBCHS512,
			keyType:          kms.X25519ECDHKWType,
			nbRec:            1,
			useCompact:       true,
			recipientKWError: singleRecipientX25519KWError,
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			t.Log("creating recipients keys..")
			recECKeys, recKHs, _, recDIDKeys := createRecipientsByKeyTemplate(t, tc.nbRec, tc.kt, tc.keyType)

			cryptoSvc, kmsSvc := createCryptoAndKMSServices(t, recKHs)

			_, err = ariesjose.NewJWEEncrypt("", "", "", "", nil, recECKeys, cryptoSvc)
			require.EqualError(t, err, "encryption algorithm '' not supported",
				"NewJWEEncrypt should fail with empty encAlg")

			jweEncrypter, err := ariesjose.NewJWEEncrypt(tc.enc, EnvelopeEncodingType,
				DIDCommContentEncodingType, "", nil, recECKeys, cryptoSvc)
			require.NoError(t, err, "NewJWEEncrypt should not fail with non empty recipientPubKeys")

			pt := []byte("secret message")
			aad := []byte("aad value")

			if tc.useCompact { // compact serialization does not use AAD
				aad = nil
			}

			testEncTime := time.Now()
			jwe, err := jweEncrypter.EncryptWithAuthData(pt, aad)
			t.Logf("ECDH-ES KW in EncryptWithAuthData took %v", time.Since(testEncTime))
			require.NoError(t, err)
			require.Equal(t, len(recECKeys), len(jwe.Recipients))

			cty, ok := jwe.ProtectedHeaders.ContentType()
			require.True(t, ok)
			require.Equal(t, DIDCommContentEncodingType, cty)

			typ, ok := jwe.ProtectedHeaders.Type()
			require.True(t, ok)
			require.Equal(t, EnvelopeEncodingType, typ)

			alg, ok := jwe.ProtectedHeaders.Algorithm()
			if alg != "" {
				require.True(t, ok)
				require.Contains(t, []string{"ECDH-ES+A256KW", "ECDH-ES+XC20PKW"}, alg)
			} else {
				require.False(t, ok)
			}

			kid, ok := jwe.ProtectedHeaders.KeyID()
			if kid != "" {
				require.True(t, ok)
				require.NotEmpty(t, kid)
			} else {
				require.False(t, ok)
			}

			var serializedJWE, jweStr string
			serialization := fullSerialization

			if tc.useCompact {
				testSerTime := time.Now()
				serializedJWE, err = jwe.CompactSerialize(json.Marshal)
				t.Logf("CompactSerilize took %v", time.Since(testSerTime))
				require.NoError(t, err)
				require.NotEmpty(t, serializedJWE)

				jweStr = serializedJWE
				serialization = compactSerialization
			} else {
				testSerTime := time.Now()
				serializedJWE, err = jwe.FullSerialize(json.Marshal)
				t.Logf("JSON Serialize took %v", time.Since(testSerTime))
				require.NoError(t, err)
				require.NotEmpty(t, serializedJWE)

				jweStr, err = prettyPrint([]byte(serializedJWE))
				require.NoError(t, err)
				if tc.nbRec == 1 {
					serialization = flattenedSerialization
				}
			}

			t.Logf("* anoncrypt JWE (%s serialization): %s", serialization, jweStr)

			mPh, err := json.Marshal(jwe.ProtectedHeaders)
			require.NoError(t, err)

			protectedHeadersStr, err := prettyPrint(mPh)
			require.NoError(t, err)

			t.Logf("* protected headers: %s", protectedHeadersStr)

			// try to deserialize with go-jose (can't decrypt in go-jose since private key is protected by Tink)
			joseJWE, err := jose.ParseEncrypted(serializedJWE)
			require.NoError(t, err)
			require.NotEmpty(t, joseJWE)

			// try to deserialize with local package
			testDeserTime := time.Now()
			localJWE, err := ariesjose.Deserialize(serializedJWE)
			t.Logf("JWE Deserialize took %v", time.Since(testDeserTime))
			require.NoError(t, err)

			t.Run("Decrypting JWE tests failures", func(t *testing.T) {
				jweDecrypter := ariesjose.NewJWEDecrypt(nil, cryptoSvc, kmsSvc)

				// decrypt empty JWE
				_, err = jweDecrypter.Decrypt(nil)
				require.EqualError(t, err, "jwedecrypt: jwe is nil")

				var badJWE *ariesjose.JSONWebEncryption

				badJWE, err = ariesjose.Deserialize(serializedJWE)
				require.NoError(t, err)

				ph := badJWE.ProtectedHeaders
				badJWE.ProtectedHeaders = nil

				// decrypt JWE with empty ProtectHeaders
				_, err = jweDecrypter.Decrypt(badJWE)
				require.EqualError(t, err, "jwedecrypt: jwe is missing protected headers")

				badJWE.ProtectedHeaders = ariesjose.Headers{}
				badJWE.ProtectedHeaders["somKey"] = "badKey"
				_, err = jweDecrypter.Decrypt(badJWE)
				require.EqualError(t, err, "jwedecrypt: jwe is missing encryption algorithm 'enc' header")

				badJWE.ProtectedHeaders = map[string]interface{}{
					ariesjose.HeaderEncryption: "badEncHeader",
					ariesjose.HeaderType:       "test",
				}

				// decrypt JWE with bad Enc header value
				_, err = jweDecrypter.Decrypt(badJWE)
				require.EqualError(t, err, "jwedecrypt: encryption algorithm 'badEncHeader' not supported")

				badJWE.ProtectedHeaders = ph

				// decrypt JWE with invalid recipient key
				badJWE.Recipients = []*ariesjose.Recipient{
					{
						EncryptedKey: "someKey",
						Header: &ariesjose.RecipientHeaders{
							EPK: []byte("somerawbytes"),
						},
					},
				}

				if tc.nbRec > 1 {
					badJWE.Recipients = append(badJWE.Recipients, &ariesjose.Recipient{
						EncryptedKey: "someOtherKey",
						Header: &ariesjose.RecipientHeaders{
							EPK: []byte("someotherrawbytes"),
						},
					})
				}

				_, err = jweDecrypter.Decrypt(badJWE)
				require.EqualError(t, err, tc.recipientKWError)

				// decrypt JWE with unsupported recipient key
				var privKey *rsa.PrivateKey

				privKey, err = rsa.GenerateKey(rand.Reader, 2048)

				unsupportedJWK := jwk.JWK{
					JSONWebKey: jose.JSONWebKey{
						Key: &privKey.PublicKey,
					},
				}

				var mk []byte

				mk, err = unsupportedJWK.MarshalJSON()
				require.NoError(t, err)

				badJWE.Recipients = []*ariesjose.Recipient{
					{
						EncryptedKey: "someKey",
						Header: &ariesjose.RecipientHeaders{
							EPK: mk,
						},
					},
				}

				if tc.nbRec > 1 {
					badJWE.Recipients = append(badJWE.Recipients, &ariesjose.Recipient{
						EncryptedKey: "someOtherKey",
						Header: &ariesjose.RecipientHeaders{
							EPK: mk,
						},
					})
				}

				_, err = jweDecrypter.Decrypt(badJWE)
				if tc.nbRec == 1 {
					require.EqualError(t, err, tc.recipientKWError)
				} else {
					require.EqualError(t, err, "jwedecrypt: failed to build recipients WK: unsupported recipient key type")
				}
			})

			t.Run("Decrypting JWE test success ", func(t *testing.T) {
				jweDecrypter := ariesjose.NewJWEDecrypt(nil, cryptoSvc, kmsSvc)

				var msg []byte

				testDecTime := time.Now()
				msg, err = jweDecrypter.Decrypt(localJWE)
				t.Logf("JWE Decrypt took %v", time.Since(testDecTime))
				require.NoError(t, err)
				require.EqualValues(t, pt, msg)
			})

			t.Run("ECDH-ES Encrypt and Decrypt JWE test success with kid as did:key", func(t *testing.T) {
				recKeys := make([]*cryptoapi.PublicKey, 0)
				for i, k := range recECKeys {
					k.KID = recDIDKeys[i]
					recKeys = append(recKeys, k)
				}

				jweEncrypter, err = ariesjose.NewJWEEncrypt(tc.enc, EnvelopeEncodingType,
					DIDCommContentEncodingType, "", nil, recKeys, cryptoSvc)
				require.NoError(t, err)

				testEncTime = time.Now()
				jwe, err = jweEncrypter.EncryptWithAuthData(pt, aad)
				t.Logf("ECDH-ES KW in EncryptWithAuthData with kid as did:key took %v", time.Since(testEncTime))
				require.NoError(t, err)
				require.Equal(t, len(recECKeys), len(jwe.Recipients))

				if tc.useCompact {
					testSerTime := time.Now()
					serializedJWE, err = jwe.CompactSerialize(json.Marshal)
					t.Logf("CompactSerilize JWE with as did:key took %v", time.Since(testSerTime))
					require.NoError(t, err)
					require.NotEmpty(t, serializedJWE)

					jweStr = serializedJWE
					serialization = compactSerialization
				} else {
					testSerTime := time.Now()
					serializedJWE, err = jwe.FullSerialize(json.Marshal)
					t.Logf("JSON Serialize with kid as did:key took %v", time.Since(testSerTime))
					require.NoError(t, err)
					require.NotEmpty(t, serializedJWE)

					jweStr, err = prettyPrint([]byte(serializedJWE))
					require.NoError(t, err)
					if tc.nbRec == 1 {
						serialization = flattenedSerialization
					}
				}

				t.Logf("* anoncrypt JWE (%s serialization) with kid as did:key: %s", serialization, jweStr)

				// try to deserialize with go-jose (can't decrypt in go-jose since private key is protected by Tink)
				joseJWE, err := jose.ParseEncrypted(serializedJWE)
				require.NoError(t, err)
				require.NotEmpty(t, joseJWE)

				// try to deserialize with local package
				testDeserTime := time.Now()
				localJWE, err = ariesjose.Deserialize(serializedJWE)
				t.Logf("JWE with kid as did:key Deserialize took %v", time.Since(testDeserTime))
				require.NoError(t, err)

				jweDecrypter := ariesjose.NewJWEDecrypt([]resolver.KIDResolver{&resolver.DIDKeyResolver{}}, cryptoSvc, kmsSvc)

				var msg []byte

				testDecTime := time.Now()
				msg, err = jweDecrypter.Decrypt(localJWE)
				t.Logf("JWE with kid as did:key Decrypt took %v", time.Since(testDecTime))
				require.NoError(t, err)
				require.EqualValues(t, pt, msg)

				if tc.nbRec > 1 {
					t.Run("decrypt with failing kid resolver", func(t *testing.T) {
						failingResolver := &mockResolver{resolveError: fmt.Errorf("resolve kid failure")}
						jweDecrypter := ariesjose.NewJWEDecrypt([]resolver.KIDResolver{failingResolver}, cryptoSvc, kmsSvc)

						_, err = jweDecrypter.Decrypt(localJWE)
						require.EqualError(t, err, "jwedecrypt: failed to unwrap cek: [resolveKID: "+
							"[resolve kid failure] resolveKID: [resolve kid failure]]")
					})
				}
			})
		})
	}
}

type mockResolver struct {
	resolveValue *cryptoapi.PublicKey
	resolveError error
}

func (m *mockResolver) Resolve(kid string) (*cryptoapi.PublicKey, error) {
	return m.resolveValue, m.resolveError
}

func TestInteropWithGoJoseEncryptAndLocalJoseDecryptUsingCompactSerialize(t *testing.T) {
	recECKeys, recKHs, recKIDs, _ := createRecipients(t, 1)
	gjRecipients := convertToGoJoseRecipients(t, recECKeys, recKIDs)

	c, k := createCryptoAndKMSServices(t, recKHs)

	eo := &jose.EncrypterOptions{}
	gjEncrypter, err := jose.NewEncrypter(jose.A256GCM, gjRecipients[0],
		eo.WithType(EnvelopeEncodingType))
	require.NoError(t, err)

	pt := []byte("Test secret message")

	// encrypt pt using go-jose encryption
	gjJWEEncrypter, err := gjEncrypter.Encrypt(pt)
	require.NoError(t, err)

	// get go-jose serialized JWE
	gjSerializedJWE, err := gjJWEEncrypter.CompactSerialize()
	require.NoError(t, err)

	// deserialize using local jose package
	localJWE, err := ariesjose.Deserialize(gjSerializedJWE)
	require.NoError(t, err)

	t.Run("Decrypting JWE message encrypted by go-jose test success", func(t *testing.T) {
		jweDecrypter := ariesjose.NewJWEDecrypt(nil, c, k)

		var msg []byte

		msg, err = jweDecrypter.Decrypt(localJWE)
		require.NoError(t, err)
		require.EqualValues(t, pt, msg)
	})
}

func TestInteropWithGoJoseEncryptAndLocalJoseDecrypt(t *testing.T) {
	recECKeys, recKHs, recKIDs, _ := createRecipients(t, 3)
	gjRecipients := convertToGoJoseRecipients(t, recECKeys, recKIDs)

	c, k := createCryptoAndKMSServices(t, recKHs)

	eo := &jose.EncrypterOptions{}
	gjEncrypter, err := jose.NewMultiEncrypter(jose.A256GCM, gjRecipients,
		eo.WithType(EnvelopeEncodingType))
	require.NoError(t, err)

	pt := []byte("Test secret message")
	aad := []byte("Test some auth data")

	// encrypt pt using go-jose encryption
	gjJWEEncrypter, err := gjEncrypter.EncryptWithAuthData(pt, aad)
	require.NoError(t, err)

	// get go-jose serialized JWE
	gjSerializedJWE := gjJWEEncrypter.FullSerialize()

	// deserialize using local jose package
	localJWE, err := ariesjose.Deserialize(gjSerializedJWE)
	require.NoError(t, err)

	t.Run("Decrypting JWE message encrypted by go-jose test success", func(t *testing.T) {
		jweDecrypter := ariesjose.NewJWEDecrypt(nil, c, k)

		var msg []byte

		msg, err = jweDecrypter.Decrypt(localJWE)
		require.NoError(t, err)
		require.EqualValues(t, pt, msg)
	})
}

func TestInteropWithLocalJoseEncryptAndGoJoseDecrypt(t *testing.T) {
	c, err := tinkcrypto.New()
	require.NoError(t, err)

	// get two generated recipient Tink keys
	recECKeys, _, _, _ := createRecipients(t, 2) //nolint:dogsled
	// create a normal recipient key (not using Tink)
	rec3PrivKey, err := ecdsa.GenerateKey(subtle.GetCurve(recECKeys[0].Curve), rand.Reader)
	require.NoError(t, err)

	// add third key to recECKeys
	recECKeys = append(recECKeys, &cryptoapi.PublicKey{
		X:     rec3PrivKey.PublicKey.X.Bytes(),
		Y:     rec3PrivKey.PublicKey.Y.Bytes(),
		Curve: rec3PrivKey.PublicKey.Curve.Params().Name,
		Type:  "EC",
	})

	// encrypt using local jose package
	jweEncrypter, err := ariesjose.NewJWEEncrypt(ariesjose.A256GCM, EnvelopeEncodingType, DIDCommContentEncodingType,
		"", nil, recECKeys, c)
	require.NoError(t, err, "NewJWEEncrypt should not fail with non empty recipientPubKeys")

	pt := []byte("some msg")
	jwe, err := jweEncrypter.EncryptWithAuthData(pt, []byte("aad value"))
	require.NoError(t, err)
	require.Equal(t, len(recECKeys), len(jwe.Recipients))

	serializedJWE, err := jwe.FullSerialize(json.Marshal)
	require.NoError(t, err)

	// now parse serializedJWE using go-jose
	gjParsedJWE, err := jose.ParseEncrypted(serializedJWE)
	require.NoError(t, err)

	// Decrypt with third recipient's private key (non Tink key)
	i, _, msg, err := gjParsedJWE.DecryptMulti(rec3PrivKey)
	require.NoError(t, err)
	require.EqualValues(t, pt, msg)

	// the third recipient's index is 2
	require.Equal(t, 2, i)
}

func TestInteropWithLocalJoseEncryptAndGoJoseDecryptUsingCompactSerialization(t *testing.T) {
	var recECKeys []*cryptoapi.PublicKey
	// create a normal recipient key (not using Tink)
	recPrivKey, err := ecdsa.GenerateKey(subtle.GetCurve("NIST_P256"), rand.Reader)
	require.NoError(t, err)

	c, err := tinkcrypto.New()
	require.NoError(t, err)

	recECKeys = append(recECKeys, &cryptoapi.PublicKey{
		X:     recPrivKey.PublicKey.X.Bytes(),
		Y:     recPrivKey.PublicKey.Y.Bytes(),
		Curve: recPrivKey.PublicKey.Curve.Params().Name,
		Type:  "EC",
	})

	// encrypt using local jose package
	jweEncrypter, err := ariesjose.NewJWEEncrypt(ariesjose.A256GCM, EnvelopeEncodingType, DIDCommContentEncodingType,
		"", nil, recECKeys, c)
	require.NoError(t, err, "NewJWEEncrypt should not fail with non empty recipientPubKeys")

	pt := []byte("some msg")
	jwe, err := jweEncrypter.Encrypt(pt)
	require.NoError(t, err)
	require.Equal(t, len(recECKeys), len(jwe.Recipients))

	serializedJWE, err := jwe.CompactSerialize(json.Marshal)
	require.NoError(t, err)

	// now parse serializedJWE using go-jose
	gjParsedJWE, err := jose.ParseEncrypted(serializedJWE)
	require.NoError(t, err)

	// Decrypt with recipient's private key
	msg, err := gjParsedJWE.Decrypt(recPrivKey)
	require.NoError(t, err)
	require.EqualValues(t, pt, msg)
}

func convertToGoJoseRecipients(t *testing.T, keys []*cryptoapi.PublicKey, kids []string) []jose.Recipient {
	t.Helper()

	var joseRecipients []jose.Recipient

	for i, key := range keys {
		c := subtle.GetCurve(key.Curve)
		gjKey := jose.Recipient{
			KeyID:     kids[i],
			Algorithm: jose.ECDH_ES_A256KW,
			Key: &ecdsa.PublicKey{
				Curve: c,
				X:     new(big.Int).SetBytes(key.X),
				Y:     new(big.Int).SetBytes(key.Y),
			},
		}

		joseRecipients = append(joseRecipients, gjKey)
	}

	return joseRecipients
}

func createRecipients(t *testing.T,
	nbOfEntities int) ([]*cryptoapi.PublicKey, map[string]*keyset.Handle, []string, []string) {
	return createRecipientsByKeyTemplate(t, nbOfEntities, ecdh.NISTP256ECDHKWKeyTemplate(), kms.NISTP256ECDHKWType)
}

// createRecipients and return their public key and keyset.Handle.
func createRecipientsByKeyTemplate(t *testing.T, nbOfEntities int, kt *tinkpb.KeyTemplate,
	keyType kms.KeyType) ([]*cryptoapi.PublicKey, map[string]*keyset.Handle, []string, []string) {
	t.Helper()

	r := make([]*cryptoapi.PublicKey, 0)
	rKH := make(map[string]*keyset.Handle)
	rKID := make([]string, 0)
	rDIDKey := make([]string, 0)

	for i := 0; i < nbOfEntities; i++ {
		mrKey, kh, kid, didKey := createAndMarshalEntityKey(t, kt, keyType)

		ecPubKey := new(cryptoapi.PublicKey)
		err := json.Unmarshal(mrKey, ecPubKey)
		require.NoError(t, err)

		ecPubKey.KID = kid
		rKH[kid] = kh

		r = append(r, ecPubKey)
		rKID = append(rKID, kid)
		rDIDKey = append(rDIDKey, didKey)
	}

	return r, rKH, rKID, rDIDKey
}

// createAndMarshalEntityKey creates a new recipient keyset.Handle, extracts public key, marshals it and returns
// both marshalled public key and original recipient keyset.Handle.
func createAndMarshalEntityKey(t *testing.T, kt *tinkpb.KeyTemplate,
	keyType kms.KeyType) ([]byte, *keyset.Handle, string, string) {
	t.Helper()

	kh, err := keyset.NewHandle(kt)
	require.NoError(t, err)

	pubKH, err := kh.Public()
	require.NoError(t, err)

	buf := new(bytes.Buffer)
	pubKeyWriter := keyio.NewWriter(buf)
	require.NotEmpty(t, pubKeyWriter)

	err = pubKH.WriteWithNoSecrets(pubKeyWriter)
	require.NoError(t, err)

	mKeyBytes := buf.Bytes()

	kid, err := jwkkid.CreateKID(mKeyBytes, keyType)
	require.NoError(t, err)

	didKey, err := kmsdidkey.BuildDIDKeyByKeyType(mKeyBytes, keyType)
	require.NoError(t, err)

	printKey(t, mKeyBytes, kid)

	return mKeyBytes, kh, kid, didKey
}

func printKey(t *testing.T, mPubKey []byte, kid string) {
	t.Helper()

	pubKey := new(cryptoapi.PublicKey)
	err := json.Unmarshal(mPubKey, pubKey)
	require.NoError(t, err)

	switch pubKey.Type {
	case ecdhpb.KeyType_EC.String():
		t.Logf("** EC key: %s, kid: %s", getPrintedECPubKey(t, pubKey), kid)
	case ecdhpb.KeyType_OKP.String():
		t.Logf("** X25519 key: %s, kid: %s", getPrintedX25519PubKey(t, pubKey), kid)
	default:
		t.Errorf("not supported key type: %s", pubKey.Type)
	}
}

func prettyPrint(msg []byte) (string, error) {
	var prettyJSON bytes.Buffer

	err := json.Indent(&prettyJSON, msg, "", "\t")
	if err != nil {
		return "", err
	}

	return prettyJSON.String(), nil
}

func getPrintedECPubKey(t *testing.T, pubKey *cryptoapi.PublicKey) string {
	crv, err := hybrid.GetCurve(pubKey.Curve)
	require.NoError(t, err)

	j := jose.JSONWebKey{
		Key: &ecdsa.PublicKey{
			Curve: crv,
			X:     new(big.Int).SetBytes(pubKey.X),
			Y:     new(big.Int).SetBytes(pubKey.Y),
		},
	}

	jwkByte, err := j.MarshalJSON()
	require.NoError(t, err)
	jwkStr, err := prettyPrint(jwkByte)
	require.NoError(t, err)

	return jwkStr
}

func getPrintedX25519PubKey(t *testing.T, pubKeyType *cryptoapi.PublicKey) string {
	j := jose.JSONWebKey{
		Key: ed25519.PublicKey(pubKeyType.X),
	}

	jwkByte, err := j.MarshalJSON()
	require.NoError(t, err)

	jwkStr, err := prettyPrint(jwkByte)
	require.NoError(t, err)

	return strings.Replace(jwkStr, "Ed25519", "X25519", 1)
}

func TestFailNewJWEEncrypt(t *testing.T) {
	c, err := tinkcrypto.New()
	require.NoError(t, err)

	recipients, recsKH, kids, _ := createRecipients(t, 2)

	t.Run("test with missing skid", func(t *testing.T) {
		_, err = ariesjose.NewJWEEncrypt(ariesjose.A256GCM, EnvelopeEncodingType, DIDCommContentEncodingType,
			"", recsKH[kids[0]], recipients, c)
		require.EqualError(t, err, "senderKID is required with senderKH")
	})

	t.Run("test with missing crypto", func(t *testing.T) {
		_, err = ariesjose.NewJWEEncrypt(ariesjose.A256GCM, EnvelopeEncodingType, DIDCommContentEncodingType,
			kids[0], recsKH[kids[0]], recipients, nil)
		require.EqualError(t, err, "crypto service is required to create a JWEEncrypt instance")
	})
}

//nolint:gocognit
func TestECDH1PU(t *testing.T) {
	tests := []struct {
		name       string
		kt         *tinkpb.KeyTemplate
		enc        ariesjose.EncAlg
		keyType    kms.KeyType
		nbRec      int
		useCompact bool
	}{
		{
			name:    "P-256 ECDH KW and XChacha20Poly1305 encryption with 2 recipients (Full serialization)",
			kt:      ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:     ariesjose.XC20P,
			keyType: kms.NISTP256ECDHKWType,
			nbRec:   2,
		},
		{
			name:    "P-256 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Flattened serialization)",
			kt:      ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:     ariesjose.XC20P,
			keyType: kms.NISTP256ECDHKWType,
			nbRec:   1,
		},
		{
			name:       "P-256 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Compact serialization)",
			kt:         ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:        ariesjose.XC20P,
			keyType:    kms.NISTP256ECDHKWType,
			nbRec:      1,
			useCompact: true,
		},
		{
			name:    "P-384 ECDH KW and XChacha20Poly1305 encryption with 2 recipients (Full serialization)",
			kt:      ecdh.NISTP384ECDHKWKeyTemplate(),
			enc:     ariesjose.XC20P,
			keyType: kms.NISTP384ECDHKWType,
			nbRec:   2,
		},
		{
			name:    "P-384 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Flattened serialization)",
			kt:      ecdh.NISTP384ECDHKWKeyTemplate(),
			enc:     ariesjose.XC20P,
			keyType: kms.NISTP384ECDHKWType,
			nbRec:   1,
		},
		{
			name:       "P-384 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Compact serialization)",
			kt:         ecdh.NISTP384ECDHKWKeyTemplate(),
			enc:        ariesjose.XC20P,
			keyType:    kms.NISTP384ECDHKWType,
			nbRec:      1,
			useCompact: true,
		},
		{
			name:    "P-521 ECDH KW and XChacha20Poly1305 encryption with 2 recipients (Full serialization)",
			kt:      ecdh.NISTP521ECDHKWKeyTemplate(),
			enc:     ariesjose.XC20P,
			keyType: kms.NISTP521ECDHKWType,
			nbRec:   2,
		},
		{
			name:    "P-521 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Flattened serialization)",
			kt:      ecdh.NISTP521ECDHKWKeyTemplate(),
			enc:     ariesjose.XC20P,
			keyType: kms.NISTP521ECDHKWType,
			nbRec:   1,
		},
		{
			name:       "P-521 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Compact serialization)",
			kt:         ecdh.NISTP521ECDHKWKeyTemplate(),
			enc:        ariesjose.XC20P,
			keyType:    kms.NISTP521ECDHKWType,
			nbRec:      1,
			useCompact: true,
		},
		{
			name:    "X25519 ECDH KW and XChacha20Poly1305 encryption with 2 recipients (Full serialization)",
			kt:      ecdh.X25519ECDHKWKeyTemplate(),
			enc:     ariesjose.XC20P,
			keyType: kms.X25519ECDHKWType,
			nbRec:   2,
		},
		{
			name:    "X25519 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Flattened serialization)",
			kt:      ecdh.X25519ECDHKWKeyTemplate(),
			enc:     ariesjose.XC20P,
			keyType: kms.X25519ECDHKWType,
			nbRec:   1,
		},
		{
			name:       "X25519 ECDH KW and XChacha20Poly1305 encryption with 1 recipient (Compact serialization)",
			kt:         ecdh.X25519ECDHKWKeyTemplate(),
			enc:        ariesjose.XC20P,
			keyType:    kms.X25519ECDHKWType,
			nbRec:      1,
			useCompact: true,
		},
		{
			name:    "P-256 ECDH KW and A128CBCHS256 encryption with 2 recipients (Full serialization)",
			kt:      ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:     ariesjose.A128CBCHS256,
			keyType: kms.NISTP256ECDHKWType,
			nbRec:   2,
		},
		{
			name:    "P-256 ECDH KW and A128CBCHS256 encryption with 1 recipient (Flattened serialization)",
			kt:      ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:     ariesjose.A128CBCHS256,
			keyType: kms.NISTP256ECDHKWType,
			nbRec:   1,
		},
		{
			name:       "P-256 ECDH KW and A128CBCHS256 encryption with 1 recipient (Compact serialization)",
			kt:         ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:        ariesjose.A128CBCHS256,
			keyType:    kms.NISTP256ECDHKWType,
			nbRec:      1,
			useCompact: true,
		},
		{
			name:    "X25519 ECDH KW and A128CBCHS256 encryption with 2 recipients (Full serialization)",
			kt:      ecdh.X25519ECDHKWKeyTemplate(),
			enc:     ariesjose.A128CBCHS256,
			keyType: kms.X25519ECDHKWType,
			nbRec:   2,
		},
		{
			name:    "X25519 ECDH KW and A128CBCHS256 encryption with 1 recipient (Flattened serialization)",
			kt:      ecdh.X25519ECDHKWKeyTemplate(),
			enc:     ariesjose.A128CBCHS256,
			keyType: kms.X25519ECDHKWType,
			nbRec:   1,
		},
		{
			name:       "X25519 ECDH KW and A128CBCHS256 encryption with 1 recipient (Compact serialization)",
			kt:         ecdh.X25519ECDHKWKeyTemplate(),
			enc:        ariesjose.A128CBCHS256,
			keyType:    kms.X25519ECDHKWType,
			nbRec:      1,
			useCompact: true,
		},
		{
			name:    "P-256 ECDH KW and A192CBCHS384 encryption with 2 recipients (Full serialization)",
			kt:      ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:     ariesjose.A192CBCHS384,
			keyType: kms.NISTP256ECDHKWType,
			nbRec:   2,
		},
		{
			name:    "P-256 ECDH KW and A192CBCHS384 encryption with 1 recipient (Flattened serialization)",
			kt:      ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:     ariesjose.A192CBCHS384,
			keyType: kms.NISTP256ECDHKWType,
			nbRec:   1,
		},
		{
			name:       "P-256 ECDH KW and A192CBCHS384 encryption with 1 recipient (Compact serialization)",
			kt:         ecdh.NISTP256ECDHKWKeyTemplate(),
			enc:        ariesjose.A192CBCHS384,
			keyType:    kms.NISTP256ECDHKWType,
			nbRec:      1,
			useCompact: true,
		},
		{
			name:    "P-384 ECDH KW and A192CBCHS384 encryption with 2 recipients (Full serialization)",
			kt:      ecdh.NISTP384ECDHKWKeyTemplate(),
			enc:     ariesjose.A192CBCHS384,
			keyType: kms.NISTP384ECDHKWType,
			nbRec:   2,
		},
		{
			name:    "P-384 ECDH KW and A192CBCHS384 encryption with 1 recipient (Flattened serialization)",
			kt:      ecdh.NISTP384ECDHKWKeyTemplate(),
			enc:     ariesjose.A192CBCHS384,
			keyType: kms.NISTP384ECDHKWType,
			nbRec:   1,
		},
		{
			name:       "P-384 ECDH KW and A192CBCHS384 encryption with 1 recipient (Compact serialization)",
			kt:         ecdh.NISTP384ECDHKWKeyTemplate(),
			enc:        ariesjose.A192CBCHS384,
			keyType:    kms.NISTP384ECDHKWType,
			nbRec:      1,
			useCompact: true,
		},
		{
			name:    "X25519 ECDH KW and A192CBCHS384 encryption with 2 recipients (Full serialization)",
			kt:      ecdh.X25519ECDHKWKeyTemplate(),
			enc:     ariesjose.A192CBCHS384,
			keyType: kms.X25519ECDHKWType,
			nbRec:   2,
		},
		{
			name:    "X25519 ECDH KW and A192CBCHS384 encryption with 1 recipient (Flattened serialization)",
			kt:      ecdh.X25519ECDHKWKeyTemplate(),
			enc:     ariesjose.A192CBCHS384,
			keyType: kms.X25519ECDHKWType,
			nbRec:   1,
		},
		{
			name:       "X25519 ECDH KW and A192CBCHS384 encryption with 1 recipient (Compact serialization)",
			kt:         ecdh.X25519ECDHKWKeyTemplate(),
			enc:        ariesjose.A192CBCHS384,
			keyType:    kms.X25519ECDHKWType,
			nbRec:      1,
			useCompact: true,
		},
		{
			name:    "X25519 ECDH KW and A256CBCHS384 encryption with 2 recipients (Full serialization)",
			kt:      ecdh.X25519ECDHKWKeyTemplate(),
			enc:     ariesjose.A256CBCHS384,
			keyType: kms.X25519ECDHKWType,
			nbRec:   2,
		},
		{
			name:    "X25519 ECDH KW and A256CBCHS384 encryption with 1 recipient (Flattened serialization)",
			kt:      ecdh.X25519ECDHKWKeyTemplate(),
			enc:     ariesjose.A256CBCHS384,
			keyType: kms.X25519ECDHKWType,
			nbRec:   1,
		},
		{
			name:       "X25519 ECDH KW and A256CBCHS384 encryption with 1 recipient (Compact serialization)",
			kt:         ecdh.X25519ECDHKWKeyTemplate(),
			enc:        ariesjose.A256CBCHS384,
			keyType:    kms.X25519ECDHKWType,
			nbRec:      1,
			useCompact: true,
		},
		{
			name:    "P-521 ECDH KW and A256CBCHS512 encryption with 2 recipients (Full serialization)",
			kt:      ecdh.NISTP521ECDHKWKeyTemplate(),
			enc:     ariesjose.A256CBCHS512,
			keyType: kms.NISTP521ECDHKWType,
			nbRec:   2,
		},
		{
			name:    "P-521 ECDH KW and A256CBCHS512 encryption with 1 recipient (Flattened serialization)",
			kt:      ecdh.NISTP521ECDHKWKeyTemplate(),
			enc:     ariesjose.A256CBCHS512,
			keyType: kms.NISTP521ECDHKWType,
			nbRec:   1,
		},
		{
			name:       "P-521 ECDH KW and A256CBCHS512 encryption with 1 recipient (Compact serialization)",
			kt:         ecdh.NISTP521ECDHKWKeyTemplate(),
			enc:        ariesjose.A256CBCHS512,
			keyType:    kms.NISTP521ECDHKWType,
			nbRec:      1,
			useCompact: true,
		},
		{
			name:    "X25519 ECDH KW and A256CBCHS512 encryption with 2 recipients (Full serialization)",
			kt:      ecdh.X25519ECDHKWKeyTemplate(),
			enc:     ariesjose.A256CBCHS512,
			keyType: kms.X25519ECDHKWType,
			nbRec:   2,
		},
		{
			name:    "X25519 ECDH KW and A256CBCHS512 encryption with 1 recipient (Flattened serialization)",
			kt:      ecdh.X25519ECDHKWKeyTemplate(),
			enc:     ariesjose.A256CBCHS512,
			keyType: kms.X25519ECDHKWType,
			nbRec:   1,
		},
		{
			name:       "X25519 ECDH KW and A256CBCHS512 encryption with 1 recipient (Compact serialization)",
			kt:         ecdh.X25519ECDHKWKeyTemplate(),
			enc:        ariesjose.A256CBCHS512,
			keyType:    kms.X25519ECDHKWType,
			nbRec:      1,
			useCompact: true,
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			t.Log("creating Sender key..")
			senders, senderKHs, senderKIDs, senderDIDKeys := createRecipientsByKeyTemplate(t, 1, tc.kt, tc.keyType)
			t.Log("creating recipients keys..")
			recipientsKeys, recKHs, _, recDIDKeys := createRecipientsByKeyTemplate(t, tc.nbRec, tc.kt, tc.keyType)

			cryptoSvc, kmsSvc := createCryptoAndKMSServices(t, recKHs)

			senderPubKey, err := json.Marshal(senders[0])
			require.NoError(t, err)

			jweEncrypter, err := ariesjose.NewJWEEncrypt(tc.enc, EnvelopeEncodingType, DIDCommContentEncodingType,
				senderKIDs[0], senderKHs[senderKIDs[0]], recipientsKeys, cryptoSvc)
			require.NoError(t, err)
			require.NotEmpty(t, jweEncrypter)

			mockStoreMap := make(map[string]mockstorage.DBEntry)
			mockStore := &mockstorage.MockStore{
				Store: mockStoreMap,
			}

			storeResolver := []resolver.KIDResolver{&resolver.StoreResolver{Store: mockStore}}

			pt := []byte("secret message")
			aad := []byte("aad value")

			if tc.useCompact { // Compact serialization does not use aad
				aad = nil
			}

			// test JWEEncrypt for ECDH1PU
			testEncTime := time.Now()
			jwe, err := jweEncrypter.EncryptWithAuthData(pt, aad)
			t.Logf("ECDH-1PU KW in EncryptWithAuthData took %v", time.Since(testEncTime))
			require.NoError(t, err)

			cty, ok := jwe.ProtectedHeaders.ContentType()
			require.True(t, ok)
			require.Equal(t, DIDCommContentEncodingType, cty)

			typ, ok := jwe.ProtectedHeaders.Type()
			require.True(t, ok)
			require.Equal(t, EnvelopeEncodingType, typ)

			alg, ok := jwe.ProtectedHeaders.Algorithm()
			if alg != "" {
				cbcHMACAlgs := []string{
					tinkcrypto.ECDH1PUA128KWAlg, tinkcrypto.ECDH1PUA192KWAlg,
					tinkcrypto.ECDH1PUA256KWAlg, tinkcrypto.ECDH1PUXC20PKWAlg,
				}

				require.True(t, ok)
				require.Contains(t, cbcHMACAlgs, alg)
			} else {
				require.False(t, ok)
			}

			kid, ok := jwe.ProtectedHeaders.KeyID()
			if kid != "" {
				require.True(t, ok)
				require.NotEmpty(t, kid)
			} else {
				require.False(t, ok)
			}

			var serializedJWE, jweStr string
			serialization := fullSerialization

			if tc.useCompact {
				testSerTime := time.Now()
				serializedJWE, err = jwe.CompactSerialize(json.Marshal)
				t.Logf("Compact serialize took %v", time.Since(testSerTime))
				require.NoError(t, err)
				require.NotEmpty(t, serializedJWE)

				jweStr = serializedJWE
				serialization = compactSerialization
			} else {
				testSerTime := time.Now()
				serializedJWE, err = jwe.FullSerialize(json.Marshal)
				t.Logf("JSON serialize took %v", time.Since(testSerTime))
				require.NoError(t, err)
				require.NotEmpty(t, serializedJWE)

				jweStr, err = prettyPrint([]byte(serializedJWE))
				require.NoError(t, err)
				if tc.nbRec == 1 {
					serialization = flattenedSerialization
				}
			}

			t.Logf("* authcrypt JWE (%s serialization): %s", serialization, jweStr)

			mPh, err := json.Marshal(jwe.ProtectedHeaders)
			require.NoError(t, err)

			protectedHeadersStr, err := prettyPrint(mPh)
			require.NoError(t, err)

			t.Logf("* protected headers: %s", protectedHeadersStr)

			testDeserTime := time.Now()
			localJWE, err := ariesjose.Deserialize(serializedJWE)
			t.Logf("JWE deserialize took %v", time.Since(testDeserTime))
			require.NoError(t, err)

			t.Run("ECDH-1PU JWE message without kid key in the KID storeResolver's store should fail", func(t *testing.T) {
				jd := ariesjose.NewJWEDecrypt(storeResolver, cryptoSvc, kmsSvc)
				require.NotEmpty(t, jd)

				_, err = jd.Decrypt(localJWE)
				require.EqualError(t, err, "jwedecrypt: failed to add sender public key for skid: fetchSenderPubKey: "+
					"resolveKID: [storeResolver: failed to resolve kid from store: data not found]")
			})

			// add sender pubkey into the recipient's mock store to prepare for a successful JWEDecrypt() for each recipient
			mockStoreMap[senderKIDs[0]] = mockstorage.DBEntry{Value: senderPubKey}

			t.Run("Decrypting JWE message test success", func(t *testing.T) {
				jd := ariesjose.NewJWEDecrypt(storeResolver, cryptoSvc, kmsSvc)
				require.NotEmpty(t, jd)

				var msg []byte

				testDecTime := time.Now()
				msg, err = jd.Decrypt(localJWE)
				t.Logf("JWE deserialize took %v", time.Since(testDecTime))
				require.NoError(t, err)
				require.EqualValues(t, pt, msg)
			})

			t.Run("ECDH-1PU Encrypt and Decrypt JWE test success with skid/kid as did:key", func(t *testing.T) {
				recKeys := make([]*cryptoapi.PublicKey, 0)
				for i, k := range recipientsKeys {
					k.KID = recDIDKeys[i]
					recKeys = append(recKeys, k)
				}

				jweEncrypter, err = ariesjose.NewJWEEncrypt(tc.enc, EnvelopeEncodingType,
					DIDCommContentEncodingType, senderDIDKeys[0], senderKHs[senderKIDs[0]], recKeys, cryptoSvc)
				require.NoError(t, err)

				testEncTime = time.Now()
				jwe, err = jweEncrypter.EncryptWithAuthData(pt, aad)
				t.Logf("ECDH-1PU KW in EncryptWithAuthData with kid as did:key took %v", time.Since(testEncTime))
				require.NoError(t, err)
				require.Equal(t, len(recipientsKeys), len(jwe.Recipients))

				if tc.useCompact {
					testSerTime := time.Now()
					serializedJWE, err = jwe.CompactSerialize(json.Marshal)
					t.Logf("CompactSerilize JWE with as did:key took %v", time.Since(testSerTime))
					require.NoError(t, err)
					require.NotEmpty(t, serializedJWE)

					jweStr = serializedJWE
					serialization = compactSerialization
				} else {
					testSerTime := time.Now()
					serializedJWE, err = jwe.FullSerialize(json.Marshal)
					t.Logf("JSON Serialize with kid as did:key took %v", time.Since(testSerTime))
					require.NoError(t, err)
					require.NotEmpty(t, serializedJWE)

					jweStr, err = prettyPrint([]byte(serializedJWE))
					require.NoError(t, err)
					if tc.nbRec == 1 {
						serialization = flattenedSerialization
					}
				}

				t.Logf("* authcrypt JWE (%s serialization) with kid as did:key: %s", serialization, jweStr)

				// try to deserialize with go-jose (can't decrypt in go-jose since private key is protected by Tink)
				joseJWE, err := jose.ParseEncrypted(serializedJWE)
				require.NoError(t, err)
				require.NotEmpty(t, joseJWE)

				// try to deserialize with local package
				testDeserTime := time.Now()
				localJWE, err = ariesjose.Deserialize(serializedJWE)
				t.Logf("JWE with kid as did:key Deserialize took %v", time.Since(testDeserTime))
				require.NoError(t, err)

				jweDecrypter := ariesjose.NewJWEDecrypt([]resolver.KIDResolver{&resolver.DIDKeyResolver{}}, cryptoSvc, kmsSvc)

				var msg []byte

				testDecTime := time.Now()
				msg, err = jweDecrypter.Decrypt(localJWE)
				t.Logf("JWE with kid as did:key Decrypt took %v", time.Since(testDecTime))
				require.NoError(t, err)
				require.EqualValues(t, pt, msg)
			})
		})
	}
}

func createCryptoAndKMSServices(t *testing.T, keys map[string]*keyset.Handle) (cryptoapi.Crypto, kms.KeyManager) {
	c, err := tinkcrypto.New()
	require.NoError(t, err)

	k := &mockKMSGetter{
		keys: keys,
	}

	require.NoError(t, err)

	return c, k
}

type mockKMSGetter struct {
	mockkms.KeyManager
	keys map[string]*keyset.Handle
}

func (k *mockKMSGetter) Get(kid string) (interface{}, error) {
	return k.keys[kid], nil
}

// nolint:gochecknoglobals // embedded test data
var (
	// test vector retrieved from:
	//nolint:lll
	// (github: https://github.com/NeilMadden/jose-ecdh-1pu/blob/master/draft-madden-jose-ecdh-1pu-04/draft-madden-jose-ecdh-1pu-04.txt#L740)
	// (ietf draft: https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04#appendix-B)
	//go:embed testdata/alice_key_ref.json
	aliceKeyRef string
	//go:embed testdata/bob_key_ref.json
	bobKeyRef string
	//go:embed testdata/charlie_key_ref.json
	charlieKeyRef string
	//go:embed testdata/jwe_ref.json
	jweRef string
)

func Test1PUDraft4ExampleBDecrypt(t *testing.T) {
	testJWE := trimSpace(jweRef)
	aliceKey := trimSpace(aliceKeyRef)
	bobKey := trimSpace(bobKeyRef)
	charlieKey := trimSpace(charlieKeyRef)

	skid := "Alice"
	keys := convertX25519ToKH(t, []string{aliceKey, bobKey, charlieKey}, []string{skid, "bob-key-2", "2021-05-06"})

	c, k := createCryptoAndKMSServices(t, keys)

	mockStoreMap := make(map[string]mockstorage.DBEntry)

	pubKH, err := keys[skid].Public()
	require.NoError(t, err)

	senderPubKey, err := keyio.ExtractPrimaryPublicKey(pubKH)
	require.NoError(t, err)

	mSenderPubKey, err := json.Marshal(senderPubKey)
	require.NoError(t, err)

	mockStoreMap[skid] = mockstorage.DBEntry{Value: mSenderPubKey}

	mockStore := &mockstorage.MockStore{
		Store: mockStoreMap,
	}

	localJWE, err := ariesjose.Deserialize(testJWE)
	require.NoError(t, err)
	require.NotEmpty(t, localJWE)

	dec := ariesjose.NewJWEDecrypt([]resolver.KIDResolver{&resolver.StoreResolver{Store: mockStore}}, c, k)
	require.NotEmpty(t, dec)

	pt, err := dec.Decrypt(localJWE)
	require.NoError(t, err)
	require.EqualValues(t, []byte("Three is a magic number."), pt)
}

func trimSpace(s string) string {
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\n", "")

	return s
}

func convertX25519ToKH(t *testing.T, keys, kids []string) map[string]*keyset.Handle {
	t.Helper()

	var err error

	khs := make(map[string]*keyset.Handle)

	for i, k := range keys {
		delim := ",\"d\""
		idx := strings.Index(k, delim)
		mPubKey := k[:idx] + "}"
		pubKey := &jwk.JWK{}
		err = json.Unmarshal([]byte(mPubKey), pubKey)
		require.NoError(t, err)

		var d []byte

		dVal := k[idx+len(delim)+2 : len(k)-2]
		d, err = base64.RawURLEncoding.DecodeString(dVal)
		require.NoError(t, err)

		privKey := &cryptoapi.PrivateKey{
			PublicKey: cryptoapi.PublicKey{
				X:     pubKey.Key.([]byte),
				Curve: pubKey.Crv,
				Type:  pubKey.Kty,
			},
			D: d,
		}

		var kh *keyset.Handle

		kh, err = keyio.PrivateKeyToKeysetHandle(privKey, ecdh.XC20P)
		require.NoError(t, err)

		khs[kids[i]] = kh
	}

	return khs
}
