/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdh1pu

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
)

func TestECDH1PUKeyTemplateSuccess(t *testing.T) {
	var flagTests = []struct {
		tcName    string
		curveType string
		tmplFunc  func(recPublicKeys []composite.PublicKey) (*tinkpb.KeyTemplate, error)
	}{
		{
			tcName:    "create ECDH1PU 256 key templates test",
			curveType: "P-256",
			tmplFunc:  ECDH1PU256KWAES256GCMKeyTemplateWithRecipients,
		},
		{
			tcName:    "create ECDH1PU 384 key templates test",
			curveType: "P-384",
			tmplFunc:  ECDH1PU384KWAES256GCMKeyTemplateWithRecipients,
		},
		{
			tcName:    "create ECDH1PU 521 key templates test",
			curveType: "P-521",
			tmplFunc:  ECDH1PU521KWAES256GCMKeyTemplateWithRecipients,
		},
	}

	for _, tt := range flagTests {
		tc := tt
		t.Run("Test "+tc.tcName, func(t *testing.T) {
			recPubKeys, recKHs := createRecipients(t, tc.curveType, 10)

			kt, err := tc.tmplFunc(recPubKeys)
			require.NoError(t, err)

			kh, err := keyset.NewHandle(kt)
			require.NoError(t, err)

			pubKH, err := kh.Public()
			require.NoError(t, err)

			e, err := NewECDH1PUEncrypt(pubKH)
			require.NoError(t, err)

			pt := []byte("secret message")
			aad := []byte("aad message")

			ct, err := e.Encrypt(pt, aad)
			require.NoError(t, err)
			require.NotEmpty(t, ct)

			// decrypt for all Recipients
			for _, recKH := range recKHs {
				d, er := NewECDH1PUDecrypt(recKH)
				require.NoError(t, er)

				dpt, er := d.Decrypt(ct, aad)
				require.NoError(t, er)
				require.Equal(t, pt, dpt)
			}
		})
	}
}

// createRecipients and return their public key and keyset.Handle
func createRecipients(t *testing.T, curveType string, nbOfRecipients int) ([]composite.PublicKey, []*keyset.Handle) {
	t.Helper()

	var (
		r   []composite.PublicKey
		rKH []*keyset.Handle
	)

	for i := 0; i < nbOfRecipients; i++ {
		mrKey, kh := createAndMarshalRecipient(t, curveType)
		ecPubKey := new(composite.PublicKey)
		err := json.Unmarshal(mrKey, ecPubKey)
		require.NoError(t, err)

		r = append(r, *ecPubKey)
		rKH = append(rKH, kh)
	}

	return r, rKH
}

// createAndMarshalRecipient creates a new recipient keyset.Handle, extracts public key, marshals it and returns
// both marshalled public key and original recipient keyset.Handle
func createAndMarshalRecipient(t *testing.T, curveType string) ([]byte, *keyset.Handle) {
	t.Helper()

	var tmpl *tinkpb.KeyTemplate

	switch curveType {
	case "P-256":
		tmpl = ECDH1PU256KWAES256GCMKeyTemplate()
	case "P-384":
		tmpl = ECDH1PU384KWAES256GCMKeyTemplate()
	case "P-521":
		tmpl = ECDH1PU521KWAES256GCMKeyTemplate()
	}

	kh, err := keyset.NewHandle(tmpl)
	require.NoError(t, err)

	pubKH, err := kh.Public()
	require.NoError(t, err)

	buf := new(bytes.Buffer)
	pubKeyWriter := keyio.NewWriter(buf)
	require.NotEmpty(t, pubKeyWriter)

	err = pubKH.WriteWithNoSecrets(pubKeyWriter)
	require.NoError(t, err)

	return buf.Bytes(), kh
}

func TestECDH1PUKeyTemplateFailures(t *testing.T) {
	badCurve := "BadCurve"
	badKeyType := "BadKeyType"

	var flagTests = []struct {
		tcName     string
		recPubKeys []composite.PublicKey
		curve      string
		keyType    string
		tmplFunc   func(recPublicKeys []composite.PublicKey) (*tinkpb.KeyTemplate, error)
		errMsg     string
	}{
		{
			tcName: "ECDH1PU P256 Key Template creation with Bad Curve should fail",
			recPubKeys: []composite.PublicKey{
				{
					KID:   "",
					X:     nil,
					Y:     nil,
					Curve: badCurve,
					Type:  "",
				},
			},
			curve:    badCurve,
			keyType:  "EC",
			tmplFunc: ECDH1PU256KWAES256GCMKeyTemplateWithRecipients,
			errMsg:   fmt.Sprintf("curve %s not supported", badCurve),
		},
		{
			tcName: "ECDH1PU P256 Key Template creation with Bad keyType should fail",
			recPubKeys: []composite.PublicKey{
				{
					KID:   "",
					X:     nil,
					Y:     nil,
					Curve: "P-256",
					Type:  badKeyType,
				},
			},
			curve:    "P-256",
			keyType:  badKeyType,
			tmplFunc: ECDH1PU256KWAES256GCMKeyTemplateWithRecipients,
			errMsg:   fmt.Sprintf("key type %s not supported", badKeyType),
		},
		{
			tcName: "ECDH1PU P384 Key Template creation with Bad Curve should fail",
			recPubKeys: []composite.PublicKey{
				{
					KID:   "",
					X:     nil,
					Y:     nil,
					Curve: badCurve,
					Type:  "",
				},
			},
			curve:    badCurve,
			keyType:  "EC",
			tmplFunc: ECDH1PU384KWAES256GCMKeyTemplateWithRecipients,
			errMsg:   fmt.Sprintf("curve %s not supported", badCurve),
		},

		{
			tcName: "ECDH1PU P384 Key Template creation with Bad keyType should fail",
			recPubKeys: []composite.PublicKey{
				{
					KID:   "",
					X:     nil,
					Y:     nil,
					Curve: "P-384",
					Type:  badKeyType,
				},
			},
			curve:    "P-384",
			keyType:  badKeyType,
			tmplFunc: ECDH1PU384KWAES256GCMKeyTemplateWithRecipients,
			errMsg:   fmt.Sprintf("key type %s not supported", badKeyType),
		},
		{
			tcName: "ECDH1PU P521 Key Template creation with Bad Curve should fail",
			recPubKeys: []composite.PublicKey{
				{
					KID:   "",
					X:     nil,
					Y:     nil,
					Curve: badCurve,
					Type:  "",
				},
			},
			curve:    badCurve,
			keyType:  "EC",
			tmplFunc: ECDH1PU521KWAES256GCMKeyTemplateWithRecipients,
			errMsg:   fmt.Sprintf("curve %s not supported", badCurve),
		},

		{
			tcName: "ECDH1PU P521 Key Template creation with Bad keyType should fail",
			recPubKeys: []composite.PublicKey{
				{
					KID:   "",
					X:     nil,
					Y:     nil,
					Curve: "P-521",
					Type:  badKeyType,
				},
			},
			curve:    "P-521",
			keyType:  badKeyType,
			tmplFunc: ECDH1PU521KWAES256GCMKeyTemplateWithRecipients,
			errMsg:   fmt.Sprintf("key type %s not supported", badKeyType),
		},
	}

	for _, tt := range flagTests {
		tc := tt
		t.Run(tc.tcName, func(t *testing.T) {
			_, err := tc.tmplFunc(tc.recPubKeys)
			require.EqualError(t, err, tc.errMsg)
		})
	}
}
