/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbsblssignatureproof2020_test

import (
	_ "embed"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/models/ld/testutil"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite/bbsblssignatureproof2020"
	"github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
)

//nolint:gochecknoglobals
var (
	//go:embed testdata/vc_doc.jsonld
	vcDoc string
	//go:embed testdata/expected_doc.rdf
	expectedDoc string
)

func TestSuite(t *testing.T) {
	blsVerifier := &testVerifier{}

	blsSuite := bbsblssignatureproof2020.New(suite.WithCompactProof(), suite.WithVerifier(blsVerifier))

	//nolint:lll
	pkBase64 := "h/rkcTKXXzRbOPr9UxSfegCbid2U/cVNXQUaKeGF7UhwrMJFP70uMH0VQ9+3+/2zDPAAjflsdeLkOXW3+ShktLxuPy8UlXSNgKNmkfb+rrj+FRwbs13pv/WsIf+eV66+"
	pkBytes, err := base64.RawStdEncoding.DecodeString(pkBase64)
	require.NoError(t, err)

	blsBBSPublicKey := &verifier.PublicKey{
		Type:  "BbsBlsSignature2020",
		Value: pkBytes,
	}

	v, err := verifier.New(&testKeyResolver{
		publicKey: blsBBSPublicKey,
	}, blsSuite)
	require.NoError(t, err)

	err = v.Verify([]byte(vcDoc), testutil.WithDocumentLoader(t))
	require.NoError(t, err)

	require.Equal(t, expectedDoc, blsVerifier.doc)
}

func TestSignatureSuite_GetDigest(t *testing.T) {
	digest := bbsblssignatureproof2020.New().GetDigest([]byte("test doc"))
	require.NotNil(t, digest)
	require.Equal(t, []byte("test doc"), digest)
}

func TestSignatureSuite_Accept(t *testing.T) {
	ss := bbsblssignatureproof2020.New()
	accepted := ss.Accept("BbsBlsSignatureProof2020")
	require.True(t, accepted)

	accepted = ss.Accept("RsaSignature2018")
	require.False(t, accepted)
}

type testVerifier struct {
	err error
	doc string
}

func (v *testVerifier) Verify(_ *verifier.PublicKey, doc, _ []byte) error {
	v.doc = string(doc)
	return v.err
}

type testKeyResolver struct {
	publicKey *verifier.PublicKey
	variants  map[string]*verifier.PublicKey
	err       error
}

func (r *testKeyResolver) Resolve(id string) (*verifier.PublicKey, error) {
	if r.err != nil {
		return nil, r.err
	}

	if len(r.variants) > 0 {
		return r.variants[id], nil
	}

	return r.publicKey, r.err
}
