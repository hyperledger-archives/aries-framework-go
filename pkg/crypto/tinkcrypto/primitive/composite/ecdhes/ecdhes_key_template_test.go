/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdhes

import (
	"fmt"
	"testing"

	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
)

func TestECDHESKeyTemplateSuccess(t *testing.T) {
	var flagTests = []struct {
		tcName    string
		curveType string
		tmplFunc  func(recPublicKeys []*composite.PublicKey) (*tinkpb.KeyTemplate, error)
	}{
		{
			tcName:    "create ECDHES 256 key templates test",
			curveType: "P-256",
			tmplFunc:  ECDHES256KWAES256GCMKeyTemplateWithRecipients,
		},
		{
			tcName:    "create ECDHES 384 key templates test",
			curveType: "P-384",
			tmplFunc:  ECDHES384KWAES256GCMKeyTemplateWithRecipients,
		},
		{
			tcName:    "create ECDHES 521 key templates test",
			curveType: "P-521",
			tmplFunc:  ECDHES521KWAES256GCMKeyTemplateWithRecipients,
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

			e, err := NewECDHESEncrypt(pubKH)
			require.NoError(t, err)

			pt := []byte("secret message")
			aad := []byte("aad message")

			ct, err := e.Encrypt(pt, aad)
			require.NoError(t, err)
			require.NotEmpty(t, ct)

			// decrypt for all Recipients
			for _, recKH := range recKHs {
				d, er := NewECDHESDecrypt(recKH)
				require.NoError(t, er)

				dpt, er := d.Decrypt(ct, aad)
				require.NoError(t, er)
				require.Equal(t, pt, dpt)
			}
		})
	}
}

// createRecipients and return their public key and keyset.Handle.
func createRecipients(t *testing.T, curveType string, nbOfRecipients int) ([]*composite.PublicKey, []*keyset.Handle) {
	t.Helper()

	var (
		r   []*composite.PublicKey
		rKH []*keyset.Handle
	)

	for i := 0; i < nbOfRecipients; i++ {
		ecPubKey, kh := createRecipient(t, curveType)

		r = append(r, ecPubKey)
		rKH = append(rKH, kh)
	}

	return r, rKH
}

// createRecipient creates a new recipient keyset.Handle, extracts public key, marshals it and returns
// both marshalled public key and original recipient keyset.Handle.
func createRecipient(t *testing.T, curveType string) (*composite.PublicKey, *keyset.Handle) {
	t.Helper()

	var tmpl *tinkpb.KeyTemplate

	switch curveType {
	case "P-256":
		tmpl = ECDHES256KWAES256GCMKeyTemplate()
	case "P-384":
		tmpl = ECDHES384KWAES256GCMKeyTemplate()
	case "P-521":
		tmpl = ECDHES521KWAES256GCMKeyTemplate()
	}

	kh, err := keyset.NewHandle(tmpl)
	require.NoError(t, err)

	ecPubKey, err := keyio.ExtractPrimaryPublicKey(kh)
	require.NoError(t, err)

	return ecPubKey, kh
}

func TestECDHESKeyTemplateFailures(t *testing.T) {
	badCurve := "BadCurve"
	badKeyType := "BadKeyType"

	var flagTests = []struct {
		tcName     string
		recPubKeys []*composite.PublicKey
		curve      string
		keyType    string
		tmplFunc   func(recPublicKeys []*composite.PublicKey) (*tinkpb.KeyTemplate, error)
		errMsg     string
	}{
		{
			tcName: "ECDHES P256 Key Template creation with Bad Curve should fail",
			recPubKeys: []*composite.PublicKey{
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
			tmplFunc: ECDHES256KWAES256GCMKeyTemplateWithRecipients,
			errMsg:   fmt.Sprintf("curve %s not supported", badCurve),
		},
		{
			tcName: "ECDHES P256 Key Template creation with Bad keyType should fail",
			recPubKeys: []*composite.PublicKey{
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
			tmplFunc: ECDHES256KWAES256GCMKeyTemplateWithRecipients,
			errMsg:   fmt.Sprintf("key type %s not supported", badKeyType),
		},
		{
			tcName: "ECDHES P384 Key Template creation with Bad Curve should fail",
			recPubKeys: []*composite.PublicKey{
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
			tmplFunc: ECDHES384KWAES256GCMKeyTemplateWithRecipients,
			errMsg:   fmt.Sprintf("curve %s not supported", badCurve),
		},

		{
			tcName: "ECDHES P384 Key Template creation with Bad keyType should fail",
			recPubKeys: []*composite.PublicKey{
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
			tmplFunc: ECDHES384KWAES256GCMKeyTemplateWithRecipients,
			errMsg:   fmt.Sprintf("key type %s not supported", badKeyType),
		},
		{
			tcName: "ECDHES P521 Key Template creation with Bad Curve should fail",
			recPubKeys: []*composite.PublicKey{
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
			tmplFunc: ECDHES521KWAES256GCMKeyTemplateWithRecipients,
			errMsg:   fmt.Sprintf("curve %s not supported", badCurve),
		},

		{
			tcName: "ECDHES P521 Key Template creation with Bad keyType should fail",
			recPubKeys: []*composite.PublicKey{
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
			tmplFunc: ECDHES521KWAES256GCMKeyTemplateWithRecipients,
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
