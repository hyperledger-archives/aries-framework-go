/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdsa2019

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/util/jwkkid"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms/localkms"
	mockkms "github.com/hyperledger/aries-framework-go/component/kmscrypto/mock/kms"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/component/models/dataintegrity/models"
	"github.com/hyperledger/aries-framework-go/component/models/did"
	"github.com/hyperledger/aries-framework-go/component/models/ld/documentloader"
	mockstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mock/storage"
	kmsapi "github.com/hyperledger/aries-framework-go/spi/kms"
)

func TestIntegration(t *testing.T) {
	docLoader, err := documentloader.NewDocumentLoader(createMockProvider())
	require.NoError(t, err)

	storeProv := mockstorage.NewMockStoreProvider()

	kmsProv, err := mockkms.NewProviderForKMS(storeProv, &noop.NoLock{})
	require.NoError(t, err)

	kms, err := localkms.New("local-lock://custom/master/key/", kmsProv)
	require.NoError(t, err)

	cr, err := tinkcrypto.New()
	require.NoError(t, err)

	signerInit := NewSignerInitializer(&SignerInitializerOptions{
		LDDocumentLoader: docLoader,
		SignerGetter:     WithLocalKMSSigner(kms, cr),
	})

	signer, err := signerInit.Signer()
	require.NoError(t, err)

	verifierInit := NewVerifierInitializer(&VerifierInitializerOptions{
		LDDocumentLoader: docLoader,
	})

	verifier, err := verifierInit.Verifier()
	require.NoError(t, err)

	_, p256Bytes, err := kms.CreateAndExportPubKeyBytes(kmsapi.ECDSAP256IEEEP1363)
	require.NoError(t, err)

	p256JWK, err := jwkkid.BuildJWK(p256Bytes, kmsapi.ECDSAP256IEEEP1363)
	require.NoError(t, err)

	_, p384Bytes, err := kms.CreateAndExportPubKeyBytes(kmsapi.ECDSAP384IEEEP1363)
	require.NoError(t, err)

	p384JWK, err := jwkkid.BuildJWK(p384Bytes, kmsapi.ECDSAP384IEEEP1363)
	require.NoError(t, err)

	p256VM, err := did.NewVerificationMethodFromJWK("#key-1", "JsonWebKey2020", "did:foo:bar", p256JWK)
	require.NoError(t, err)

	p384VM, err := did.NewVerificationMethodFromJWK("#key-2", "JsonWebKey2020", "did:foo:bar", p384JWK)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		t.Run("P-256 key", func(t *testing.T) {
			proofOpts := &models.ProofOptions{
				VerificationMethod:   p256VM,
				VerificationMethodID: p256VM.ID,
				SuiteType:            SuiteType,
				Purpose:              "assertionMethod",
				ProofType:            models.DataIntegrityProof,
				Created:              time.Now(),
				MaxAge:               100,
			}

			proof, err := signer.CreateProof(validCredential, proofOpts)
			require.NoError(t, err)

			err = verifier.VerifyProof(validCredential, proof, proofOpts)
			require.NoError(t, err)
		})

		t.Run("P-384 key", func(t *testing.T) {
			proofOpts := &models.ProofOptions{
				VerificationMethod:   p384VM,
				VerificationMethodID: p384VM.ID,
				SuiteType:            SuiteType,
				Purpose:              "assertionMethod",
				ProofType:            models.DataIntegrityProof,
				Created:              time.Now(),
				MaxAge:               100,
			}

			proof, err := signer.CreateProof(validCredential, proofOpts)
			require.NoError(t, err)

			err = verifier.VerifyProof(validCredential, proof, proofOpts)
			require.NoError(t, err)
		})
	})

	t.Run("failure", func(t *testing.T) {
		t.Run("wrong key", func(t *testing.T) {
			signOpts := &models.ProofOptions{
				VerificationMethod:   p256VM,
				VerificationMethodID: p256VM.ID,
				SuiteType:            SuiteType,
				Purpose:              "assertionMethod",
				ProofType:            models.DataIntegrityProof,
				Created:              time.Now(),
			}

			verifyOpts := &models.ProofOptions{
				VerificationMethod:   p384VM,
				VerificationMethodID: p384VM.ID,
				SuiteType:            SuiteType,
				Purpose:              "assertionMethod",
				ProofType:            models.DataIntegrityProof,
				MaxAge:               100,
			}

			proof, err := signer.CreateProof(validCredential, signOpts)
			require.NoError(t, err)

			err = verifier.VerifyProof(validCredential, proof, verifyOpts)
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to verify ecdsa-2019 DI proof")
		})
	})
}
