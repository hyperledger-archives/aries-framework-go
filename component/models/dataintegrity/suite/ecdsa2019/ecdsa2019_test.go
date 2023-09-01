/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdsa2019

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "embed"
	"errors"
	"testing"
	"time"

	"github.com/multiformats/go-multibase"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk/jwksupport"
	mockcrypto "github.com/hyperledger/aries-framework-go/component/kmscrypto/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/component/kmscrypto/mock/kms"
	"github.com/hyperledger/aries-framework-go/component/models/dataintegrity/models"
	"github.com/hyperledger/aries-framework-go/component/models/dataintegrity/suite"
	"github.com/hyperledger/aries-framework-go/component/models/did"
	"github.com/hyperledger/aries-framework-go/component/models/ld/documentloader"
	mockldstore "github.com/hyperledger/aries-framework-go/component/models/ld/mock"
	"github.com/hyperledger/aries-framework-go/component/models/ld/store"
	signatureverifier "github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
)

var (
	//go:embed testdata/valid_credential.jsonld
	validCredential []byte
	//go:embed testdata/invalid_jsonld.jsonld
	invalidJSONLD []byte
)

const (
	fooBar = "foo bar"
)

func TestNew(t *testing.T) {
	docLoader, err := documentloader.NewDocumentLoader(createMockProvider())
	require.NoError(t, err)

	cryp := &mockcrypto.Crypto{}
	kms := &mockkms.KeyManager{}

	signerGetter := WithLocalKMSSigner(kms, cryp)

	t.Run("signer success", func(t *testing.T) {
		sigInit := NewSignerInitializer(&SignerInitializerOptions{
			LDDocumentLoader: docLoader,
			SignerGetter:     signerGetter,
		})

		signer, err := sigInit.Signer()
		require.NoError(t, err)
		require.NotNil(t, signer)
		require.False(t, signer.RequiresCreated())
	})

	t.Run("verifier success", func(t *testing.T) {
		verInit := NewVerifierInitializer(&VerifierInitializerOptions{
			LDDocumentLoader: docLoader,
		})

		verifier, err := verInit.Verifier()
		require.NoError(t, err)
		require.NotNil(t, verifier)
		require.False(t, verifier.RequiresCreated())
	})
}

type testCase struct {
	crypto       *mockcrypto.Crypto
	kms          *mockkms.KeyManager
	docLoader    *documentloader.DocumentLoader
	proofOpts    *models.ProofOptions
	proof        *models.Proof
	p256Verifier Verifier
	p384Verifier Verifier
	document     []byte
	errIs        error
	errStr       string
}

func successCase(t *testing.T) *testCase {
	t.Helper()

	_, mockVM := getVMWithJWK(t)

	docLoader, err := documentloader.NewDocumentLoader(createMockProvider())
	require.NoError(t, err)

	cryp := &mockcrypto.Crypto{}
	keyManager := &mockkms.KeyManager{}

	proofCreated := time.Now()

	proofOpts := &models.ProofOptions{
		VerificationMethod:   mockVM,
		VerificationMethodID: mockVM.ID,
		SuiteType:            SuiteType,
		Purpose:              "assertionMethod",
		ProofType:            models.DataIntegrityProof,
		Created:              proofCreated,
		MaxAge:               100,
	}

	mockSig, err := multibase.Encode(multibase.Base58BTC, []byte("mock signature"))
	require.NoError(t, err)

	proof := &models.Proof{
		Type:               models.DataIntegrityProof,
		CryptoSuite:        SuiteType,
		ProofPurpose:       "assertionMethod",
		VerificationMethod: mockVM.ID,
		Created:            proofCreated.Format(models.DateTimeFormat),
		ProofValue:         mockSig,
	}

	return &testCase{
		crypto:    cryp,
		kms:       keyManager,
		docLoader: docLoader,
		proofOpts: proofOpts,
		proof:     proof,
		document:  validCredential,
		errIs:     nil,
		errStr:    "",
	}
}

func testSign(t *testing.T, tc *testCase) {
	sigInit := NewSignerInitializer(&SignerInitializerOptions{
		LDDocumentLoader: tc.docLoader,
		SignerGetter:     WithLocalKMSSigner(tc.kms, tc.crypto),
	})

	signer, err := sigInit.Signer()
	require.NoError(t, err)

	proof, err := signer.CreateProof(tc.document, tc.proofOpts)

	if tc.errStr == "" && tc.errIs == nil {
		require.NoError(t, err)
		require.NotNil(t, proof)
	} else {
		require.Error(t, err)
		require.Nil(t, proof)

		if tc.errStr != "" {
			require.Contains(t, err.Error(), tc.errStr)
		}

		if tc.errIs != nil {
			require.ErrorIs(t, err, tc.errIs)
		}
	}
}

type mockVerifier struct {
	err error
}

func (mv *mockVerifier) Verify(_ *signatureverifier.PublicKey, _, _ []byte) error {
	return mv.err
}

func testVerify(t *testing.T, tc *testCase) {
	verInit := NewVerifierInitializer(&VerifierInitializerOptions{
		LDDocumentLoader: tc.docLoader,
		P256Verifier:     tc.p256Verifier,
		P384Verifier:     tc.p384Verifier,
	})

	verifier, err := verInit.Verifier()
	require.NoError(t, err)

	err = verifier.VerifyProof(tc.document, tc.proof, tc.proofOpts)

	if tc.errStr == "" && tc.errIs == nil {
		require.NoError(t, err)
	} else {
		require.Error(t, err)

		if tc.errStr != "" {
			require.Contains(t, err.Error(), tc.errStr)
		}

		if tc.errIs != nil {
			require.ErrorIs(t, err, tc.errIs)
		}
	}
}

func TestSuite_CreateProof(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		t.Run("P-256 key", func(t *testing.T) {
			tc := successCase(t)

			testSign(t, tc)
		})

		t.Run("P-384 key", func(t *testing.T) {
			tc := successCase(t)

			tc.proofOpts.VerificationMethod = getP384VM(t)

			testSign(t, tc)
		})
	})

	t.Run("failure", func(t *testing.T) {
		t.Run("compute KMS KID", func(t *testing.T) {
			tc := successCase(t)

			badKey, vm := getVMWithJWK(t)

			badKey.Key = fooBar

			tc.proofOpts.VerificationMethod = vm
			tc.errStr = "computing thumbprint for kms kid"

			testSign(t, tc)
		})

		t.Run("kms key handle error", func(t *testing.T) {
			tc := successCase(t)

			errExpected := errors.New("expected error")

			tc.kms.GetKeyErr = errExpected
			tc.errIs = errExpected

			testSign(t, tc)
		})

		t.Run("crypto sign error", func(t *testing.T) {
			tc := successCase(t)

			errExpected := errors.New("expected error")

			tc.crypto.SignErr = errExpected
			tc.errIs = errExpected

			testSign(t, tc)
		})
	})
}

func TestSuite_VerifyProof(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		t.Run("P-256 key", func(t *testing.T) {
			tc := successCase(t)

			tc.p256Verifier = &mockVerifier{}
			tc.p384Verifier = &mockVerifier{err: errors.New("some error")}

			testVerify(t, tc)
		})

		t.Run("P-384 key", func(t *testing.T) {
			tc := successCase(t)

			tc.proofOpts.VerificationMethod = getP384VM(t)
			tc.p256Verifier = &mockVerifier{err: errors.New("some error")}
			tc.p384Verifier = &mockVerifier{}

			testVerify(t, tc)
		})
	})

	t.Run("failure", func(t *testing.T) {
		t.Run("decode proof signature", func(t *testing.T) {
			tc := successCase(t)

			tc.proof.ProofValue = "!%^@^@#%&#%#@"
			tc.errStr = "decoding proofValue"

			testVerify(t, tc)
		})

		t.Run("crypto verify", func(t *testing.T) {
			tc := successCase(t)

			errExpected := errors.New("expected error")

			tc.p256Verifier = &mockVerifier{err: errExpected}
			tc.errIs = errExpected

			testVerify(t, tc)
		})
	})
}

func TestSharedFailures(t *testing.T) {
	t.Run("unmarshal doc", func(t *testing.T) {
		tc := successCase(t)

		tc.document = []byte("not JSON!")
		tc.errStr = "expects JSON-LD payload"

		testSign(t, tc)
	})

	t.Run("no jwk in vm", func(t *testing.T) {
		tc := successCase(t)

		tc.proofOpts.VerificationMethod = &did.VerificationMethod{
			ID:    tc.proofOpts.VerificationMethodID,
			Value: []byte(fooBar),
		}
		tc.errStr = "verification method needs JWK"

		testSign(t, tc)
	})

	t.Run("unsupported ECDSA curve", func(t *testing.T) {
		tc := successCase(t)

		badKey, vm := getVMWithJWK(t)

		badKey.Crv = fooBar

		tc.proofOpts.VerificationMethod = vm
		tc.errStr = "unsupported ECDSA curve"

		testVerify(t, tc)
	})

	t.Run("invalid proof/suite type", func(t *testing.T) {
		tc := successCase(t)

		tc.proofOpts.ProofType = fooBar
		tc.errIs = suite.ErrProofTransformation

		testSign(t, tc)

		tc.proofOpts.ProofType = models.DataIntegrityProof
		tc.proofOpts.SuiteType = fooBar

		testSign(t, tc)
	})

	t.Run("canonicalize doc", func(t *testing.T) {
		tc := successCase(t)

		tc.document = invalidJSONLD
		tc.errStr = "canonicalizing signature base data"

		testSign(t, tc)
	})
}

func getVMWithJWK(t *testing.T) (*jwk.JWK, *models.VerificationMethod) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwkPriv, err := jwksupport.JWKFromKey(priv)
	require.NoError(t, err)

	mockVM, err := did.NewVerificationMethodFromJWK("#key-1", "JsonWebKey2020", "did:foo:bar", jwkPriv)
	require.NoError(t, err)

	return jwkPriv, mockVM
}

func getP384VM(t *testing.T) *models.VerificationMethod {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	jwkPriv, err := jwksupport.JWKFromKey(priv)
	require.NoError(t, err)

	mockVM, err := did.NewVerificationMethodFromJWK("#key-1", "JsonWebKey2020", "did:foo:bar", jwkPriv)
	require.NoError(t, err)

	return mockVM
}

type provider struct {
	ContextStore        store.ContextStore
	RemoteProviderStore store.RemoteProviderStore
}

func (p *provider) JSONLDContextStore() store.ContextStore {
	return p.ContextStore
}

func (p *provider) JSONLDRemoteProviderStore() store.RemoteProviderStore {
	return p.RemoteProviderStore
}

func createMockProvider() *provider {
	return &provider{
		ContextStore:        mockldstore.NewMockContextStore(),
		RemoteProviderStore: mockldstore.NewMockRemoteProviderStore(),
	}
}
