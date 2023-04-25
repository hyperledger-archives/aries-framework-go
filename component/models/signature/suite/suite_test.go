/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package suite

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/models/signature/api"
)

func TestSignatureSuite_Sign(t *testing.T) {
	doc := []byte("test doc")

	ss := InitSuiteOptions(&SignatureSuite{}, WithSigner(&mockSigner{
		signature: []byte("test signature"),
	}))

	bytes, err := ss.Sign(doc)
	require.NoError(t, err)
	require.NotEmpty(t, bytes)

	ss = InitSuiteOptions(&SignatureSuite{}, WithSigner(&mockSigner{
		err: errors.New("signature error"),
	}))

	bytes, err = ss.Sign(doc)
	require.Error(t, err)
	require.EqualError(t, err, "signature error")
	require.Empty(t, bytes)

	ss = &SignatureSuite{}
	bytes, err = ss.Sign(doc)
	require.Error(t, err)
	require.Equal(t, ErrSignerNotDefined, err)
	require.Empty(t, bytes)
}

func TestSignatureSuite_Verify(t *testing.T) {
	pubKey := &api.PublicKey{
		Type:  "some type",
		Value: []byte("any key"),
	}
	ss := InitSuiteOptions(&SignatureSuite{}, WithVerifier(&mockVerifier{}), WithCompactProof())

	// happy path
	err := ss.Verify(pubKey, []byte("any doc"), []byte("any signature"))
	require.NoError(t, err)

	// no verifier defined
	ss = &SignatureSuite{}
	err = ss.Verify(pubKey, []byte("any doc"), []byte("any signature"))
	require.Error(t, err)
	require.Equal(t, ErrVerifierNotDefined, err)

	// verification error
	ss = InitSuiteOptions(&SignatureSuite{}, WithVerifier(&mockVerifier{verifyError: errors.New("verify error")}))
	err = ss.Verify(pubKey, []byte("any doc"), []byte("any signature"))
	require.Error(t, err)
	require.EqualError(t, err, "verify error")
}

func TestWithCompactProof(t *testing.T) {
	ss := InitSuiteOptions(&SignatureSuite{}, WithCompactProof())
	require.True(t, ss.CompactProof())
}

func TestWithSigner(t *testing.T) {
	suiteOpt := WithSigner(&mockSigner{})
	require.NotNil(t, suiteOpt)

	ss := &SignatureSuite{}
	suiteOpt(ss)
	require.NotNil(t, ss.Signer)
}

type mockSigner struct {
	signature []byte
	err       error
}

func (s *mockSigner) Sign(_ []byte) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}

	return s.signature, nil
}

func (s *mockSigner) Alg() string {
	return ""
}

type mockVerifier struct {
	verifyError error
}

func (v *mockVerifier) Verify(_ *api.PublicKey, _, _ []byte) error {
	return v.verifyError
}
