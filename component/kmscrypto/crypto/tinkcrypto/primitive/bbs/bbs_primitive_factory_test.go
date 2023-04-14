/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs

import (
	"crypto/rand"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/core/cryptofmt"
	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/keyset"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/subtle"
	"github.com/google/tink/go/testkeyset"
	"github.com/google/tink/go/testutil"
	"github.com/google/tink/go/tink"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/bbs/api"
	bbspb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/bbs_go_proto"
)

func TestSignerVerifierFactory(t *testing.T) {
	primaryPrivProto := generatePrivateKeyProto(t)
	sPrimaryPriv, e := proto.Marshal(primaryPrivProto)
	require.NoError(t, e)

	secondPrivProto := generatePrivateKeyProto(t)
	sSecondPriv, e := proto.Marshal(secondPrivProto)
	require.NoError(t, e)

	tests := []struct {
		name   string
		prefix tinkpb.OutputPrefixType
		keyURL string
	}{
		{
			name:   "run bbs with Tink prefixed keys success",
			prefix: tinkpb.OutputPrefixType_TINK,
			keyURL: bbsSignerKeyTypeURL,
		},
		{
			name:   "run bbs with raw (no prefix) keys success",
			prefix: tinkpb.OutputPrefixType_RAW,
			keyURL: bbsSignerKeyTypeURL,
		},
		{
			name:   "run bbs with Legacy prefixed keys success",
			prefix: tinkpb.OutputPrefixType_LEGACY,
			keyURL: bbsSignerKeyTypeURL,
		},
		{
			name:   "run bbs with Crunchy prefixed keys success",
			prefix: tinkpb.OutputPrefixType_CRUNCHY,
			keyURL: bbsSignerKeyTypeURL,
		},
		{
			name:   "run bbs with Tink prefixed keys and invalid key URL",
			prefix: tinkpb.OutputPrefixType_TINK,
			keyURL: "bad/url",
		},
		{
			name:   "run bbs with RAW prefixed keys and invalid key URL",
			prefix: tinkpb.OutputPrefixType_RAW,
			keyURL: "bad/url",
		},
	}

	for _, test := range tests {
		tc := test
		t.Run(tc.name, func(t *testing.T) {
			primaryPrivKey := testutil.NewKey(
				testutil.NewKeyData(tc.keyURL, sPrimaryPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
				tinkpb.KeyStatusType_ENABLED, 5, tc.prefix)

			secondPrivKey := testutil.NewKey(
				testutil.NewKeyData(tc.keyURL, sSecondPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
				tinkpb.KeyStatusType_ENABLED, 9, tc.prefix)

			privKeys := []*tinkpb.Keyset_Key{primaryPrivKey, secondPrivKey}
			privKeyset := testutil.NewKeyset(privKeys[0].KeyId, privKeys)
			khPriv, err := testkeyset.NewHandle(privKeyset)
			require.NoError(t, err)

			tmpKeyURL := tc.keyURL
			khPub, err := khPriv.Public()
			if tc.keyURL == bbsSignerKeyTypeURL {
				require.NoError(t, err)
			} else {
				// set valid keyURL temporarily to rebuild public keyset handle and continue tests
				tc.keyURL = bbsSignerKeyTypeURL

				// build valid public keyset handle to continue tests
				tmpPrimaryPrivKey := testutil.NewKey(
					testutil.NewKeyData(tc.keyURL, sPrimaryPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
					tinkpb.KeyStatusType_ENABLED, 5, tc.prefix)

				tmpSecondPrivKey := testutil.NewKey(
					testutil.NewKeyData(tc.keyURL, sSecondPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
					tinkpb.KeyStatusType_ENABLED, 9, tc.prefix)

				tmpPrivKeys := []*tinkpb.Keyset_Key{tmpPrimaryPrivKey, tmpSecondPrivKey}
				tmpPrivKeyset := testutil.NewKeyset(tmpPrivKeys[0].KeyId, tmpPrivKeys)

				var tmpKHPriv *keyset.Handle

				tmpKHPriv, err = testkeyset.NewHandle(tmpPrivKeyset)
				require.NoError(t, err)

				khPub, err = tmpKHPriv.Public()
				require.NoError(t, err)

				// reset tc.KeyURL
				tc.keyURL = tmpKeyURL
			}

			t.Run("create signer with public key should fail", func(t *testing.T) {
				_, err = NewSigner(khPub)
				require.EqualError(t, err, "bbs_signer_factory: not a BBS Signer primitive", "using a"+
					"public keyset handle in NewSigner() should fail since the handle must point to a private bbs key")
			})

			bbsSigner, err := NewSigner(khPriv)
			if tc.keyURL == bbsSignerKeyTypeURL {
				require.NoError(t, err)
			} else {
				// building new signer with private keyset handle that has a bad Tink key url parameter should fail
				require.EqualError(t, err, "bbs_sign_factory: cannot obtain primitive set: "+
					"registry.PrimitivesWithKeyManager: cannot get primitive from key: registry.GetKeyManager: "+
					"unsupported key type: bad/url")

				// set valid keyURL temporarily to rebuild a valid signer and continue test
				tc.keyURL = bbsSignerKeyTypeURL

				tmpPrimaryPrivKey := testutil.NewKey(
					testutil.NewKeyData(tc.keyURL, sPrimaryPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
					tinkpb.KeyStatusType_ENABLED, 5, tc.prefix)

				tmpSecondPrivKey := testutil.NewKey(
					testutil.NewKeyData(tc.keyURL, sSecondPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
					tinkpb.KeyStatusType_ENABLED, 9, tc.prefix)

				tmpPrivKeys := []*tinkpb.Keyset_Key{tmpPrimaryPrivKey, tmpSecondPrivKey}
				tmpPrivKeyset := testutil.NewKeyset(tmpPrivKeys[0].KeyId, tmpPrivKeys)

				var tmpKHPriv *keyset.Handle

				tmpKHPriv, err = testkeyset.NewHandle(tmpPrivKeyset)
				require.NoError(t, err)

				khPub, err = tmpKHPriv.Public()
				require.NoError(t, err)

				bbsSigner, err = NewSigner(tmpKHPriv)
				require.NoError(t, err)

				t.Run("test newWrappedSigner with one key other than primary key is invalid", func(t *testing.T) {
					// now try to directly call newWrappedSigner with a bad primitive set.
					var badPS *primitiveset.PrimitiveSet

					badPS, err = tmpKHPriv.PrimitivesWithKeyManager(nil)
					require.NoError(t, err)

					// create an ECDSA tink key
					var serializedECKey []byte

					serializedECKey, err = proto.Marshal(testutil.NewRandomECDSAPrivateKey(commonpb.HashType_SHA256,
						commonpb.EllipticCurveType_NIST_P256))
					require.NoError(t, err)

					ecPrivKey := testutil.NewKey(
						testutil.NewKeyData("type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
							serializedECKey, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
						tinkpb.KeyStatusType_ENABLED, 11, tc.prefix)

					tmpPrivKeys = []*tinkpb.Keyset_Key{ecPrivKey}
					tmpPrivKeyset = testutil.NewKeyset(tmpPrivKeys[0].KeyId, tmpPrivKeys)
					tmpKHPriv, err = testkeyset.NewHandle(tmpPrivKeyset)
					require.NoError(t, err)

					var (
						ecPrimitives *primitiveset.PrimitiveSet
						prefix       string
					)

					ecPrimitives, err = tmpKHPriv.Primitives()
					require.NoError(t, err)

					prefix, err = cryptofmt.OutputPrefix(ecPrivKey)
					require.NoError(t, err)

					// copy the ec primitive into badPS to force an error on a bad entry other than the primary one
					badPS.Entries[prefix] = ecPrimitives.Entries[prefix]

					_, err = newWrappedSigner(badPS)
					require.EqualError(t, err, "bbs_signer_factory: not a BBS Signer primitive")
				})

				tc.keyURL = tmpKeyURL
			}

			messagesBytes := [][]byte{
				[]byte("message1 test ABC"),
				[]byte("message2 test DEF"),
				[]byte("message3 test GHI"),
				[]byte("message4 test JKL"),
				[]byte("message5 test MNO"),
			}

			sig, err := bbsSigner.Sign(messagesBytes)
			if tc.keyURL == bbsSignerKeyTypeURL {
				require.NoError(t, err)

				if tc.prefix != tinkpb.OutputPrefixType_LEGACY {
					_, err = bbsSigner.Sign([][]byte{})
					require.EqualError(t, err, "messages are not defined")
				}
			} else {
				tc.keyURL = bbsSignerKeyTypeURL

				// rebuild valid signer to continue tests
				tmpPrimaryPrivKey := testutil.NewKey(
					testutil.NewKeyData(tc.keyURL, sPrimaryPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
					tinkpb.KeyStatusType_ENABLED, 5, tc.prefix)

				tmpSecondPrivKey := testutil.NewKey(
					testutil.NewKeyData(tc.keyURL, sSecondPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
					tinkpb.KeyStatusType_ENABLED, 9, tc.prefix)

				tmpPrivKeys := []*tinkpb.Keyset_Key{tmpPrimaryPrivKey, tmpSecondPrivKey}
				tmpPrivKeyset := testutil.NewKeyset(tmpPrivKeys[0].KeyId, tmpPrivKeys)

				var tmpKHPriv *keyset.Handle

				tmpKHPriv, err = testkeyset.NewHandle(tmpPrivKeyset)
				require.NoError(t, err)

				khPub, err = tmpKHPriv.Public()
				require.NoError(t, err)

				bbsSigner, err = NewSigner(tmpKHPriv)
				require.NoError(t, err)

				var tmpBBSSigner api.Signer

				tmpBBSSigner, err = NewSigner(tmpKHPriv)
				require.NoError(t, err)

				sig, err = bbsSigner.Sign(messagesBytes)
				require.NoError(t, err)

				var serializedECKey []byte

				serializedECKey, err = proto.Marshal(testutil.NewRandomECDSAPrivateKey(commonpb.HashType_SHA256,
					commonpb.EllipticCurveType_NIST_P256))
				require.NoError(t, err)

				ecPrivKey := testutil.NewKey(
					testutil.NewKeyData("type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
						serializedECKey, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
					tinkpb.KeyStatusType_ENABLED, 5, tc.prefix)

				tmpPrivKeys = []*tinkpb.Keyset_Key{ecPrivKey}
				tmpPrivKeyset = testutil.NewKeyset(tmpPrivKeys[0].KeyId, tmpPrivKeys)
				tmpKHPriv, err = testkeyset.NewHandle(tmpPrivKeyset)
				require.NoError(t, err)

				// import Tink signature package to force init() and initialize its key managers.
				var ecSigner tink.Signer

				ecSigner, err = signature.NewSigner(tmpKHPriv)
				require.NoError(t, err)

				_, err = ecSigner.Sign([]byte("loremipsum"))
				require.NoError(t, err)

				// now try to directly call newWrappedSigner with a bad primitive set.
				var badPS *primitiveset.PrimitiveSet

				badPS, err = tmpKHPriv.PrimitivesWithKeyManager(nil)
				require.NoError(t, err)

				_, err = newWrappedSigner(badPS)
				require.EqualError(t, err, "bbs_signer_factory: not a BBS Signer primitive")

				t.Run("execute Sign() with a signer containing bad primary primitive", func(t *testing.T) {
					var (
						ecPrimitives *primitiveset.PrimitiveSet
						prefix       string
					)

					ecPrimitives, err = tmpKHPriv.Primitives()
					require.NoError(t, err)

					prefix, err = cryptofmt.OutputPrefix(ecPrivKey)
					require.NoError(t, err)

					// copy the ec primitive into badPS to force an error on a bad entry other than the primary one
					badPS.Entries[prefix] = ecPrimitives.Entries[prefix]

					wSigner, ok := tmpBBSSigner.(*wrappedSigner)
					require.True(t, ok)

					wSigner.ps = badPS

					_, err = wSigner.Sign(messagesBytes)
					require.EqualError(t, err, "bbs_signer_factory: not a BBS Signer primitive")
				})

				tc.keyURL = tmpKeyURL
			}

			bbsVerifier, err := NewVerifier(khPub)
			require.NoError(t, err)

			if tc.keyURL == bbsSignerKeyTypeURL {
				t.Run("create verifier with private key should fail", func(t *testing.T) {
					_, err = NewVerifier(khPriv)
					require.EqualError(t, err, "bbs_verifier_factory: not a Verifier primitive", "using a"+
						"private keyset handle in NewVerifier should fail since it expects a public bbs key")
				})
			} else {
				t.Run("create bbs verifier with invalid primary public key should fail", func(t *testing.T) {
					var sPubKey []byte

					pubKeyProto := primaryPrivProto.PublicKey
					sPubKey, err = proto.Marshal(pubKeyProto)
					require.NoError(t, err)

					// create public key with invalid keyURL
					tmpPrimaryPubKey := testutil.NewKey(
						testutil.NewKeyData(tc.keyURL, sPubKey, tinkpb.KeyData_ASYMMETRIC_PUBLIC),
						tinkpb.KeyStatusType_ENABLED, 5, tc.prefix)

					tmpPubKeys := []*tinkpb.Keyset_Key{tmpPrimaryPubKey}
					tmpPrivKeyset := testutil.NewKeyset(tmpPubKeys[0].KeyId, tmpPubKeys)

					var tmpKHPub *keyset.Handle

					tmpKHPub, err = testkeyset.NewHandle(tmpPrivKeyset)
					require.NoError(t, err)

					_, err = NewVerifier(tmpKHPub)
					require.EqualError(t, err, "bbs_verifier_factory: cannot obtain primitive set: "+
						"registry.PrimitivesWithKeyManager: cannot get primitive from key: registry.GetKeyManager: "+
						"unsupported key type: bad/url")
				})

				t.Run("create bbs verifier with invalid non primary public key should fail", func(t *testing.T) {
					var sPrimaryPubKey []byte

					sPrimaryPubKey, err = proto.Marshal(primaryPrivProto.PublicKey)
					require.NoError(t, err)

					// create primary public key with valid keyURL
					tmpPrimaryPubKey := testutil.NewKey(
						testutil.NewKeyData(bbsVerifierKeyTypeURL, sPrimaryPubKey, tinkpb.KeyData_ASYMMETRIC_PUBLIC),
						tinkpb.KeyStatusType_ENABLED, 5, tc.prefix)

					// create second public key as ecdsa key to cause an error on second key
					var serializedECKey []byte

					serializedECKey, err = proto.Marshal(testutil.NewRandomECDSAPublicKey(commonpb.HashType_SHA256,
						commonpb.EllipticCurveType_NIST_P256))
					require.NoError(t, err)

					tmpSecondPubKey := testutil.NewKey(
						testutil.NewKeyData("type.googleapis.com/google.crypto.tink.EcdsaPublicKey",
							serializedECKey, tinkpb.KeyData_ASYMMETRIC_PUBLIC),
						tinkpb.KeyStatusType_ENABLED, 9, tc.prefix)

					tmpPubKeys := []*tinkpb.Keyset_Key{tmpPrimaryPubKey, tmpSecondPubKey}
					tmpPubKeyset := testutil.NewKeyset(tmpPubKeys[0].KeyId, tmpPubKeys)

					var tmpKHPub *keyset.Handle

					tmpKHPub, err = testkeyset.NewHandle(tmpPubKeyset)
					require.NoError(t, err)

					_, err = NewVerifier(tmpKHPub)
					require.EqualError(t, err, "bbs_verifier_factory: not a Verifier primitive")
				})

				t.Run("create bbs verifier with non bbs key should fail", func(t *testing.T) {
					var serializedECKey []byte

					serializedECKey, err = proto.Marshal(testutil.NewRandomECDSAPrivateKey(commonpb.HashType_SHA256,
						commonpb.EllipticCurveType_NIST_P256))
					require.NoError(t, err)

					ecPrivKey := testutil.NewKey(
						testutil.NewKeyData("type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
							serializedECKey, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
						tinkpb.KeyStatusType_ENABLED, 5, tc.prefix)

					tmpPrivKeys := []*tinkpb.Keyset_Key{ecPrivKey}
					tmpPrivKeyset := testutil.NewKeyset(tmpPrivKeys[0].KeyId, tmpPrivKeys)

					var (
						tmpKHPriv *keyset.Handle
						tmpPubKH  *keyset.Handle
					)

					tmpKHPriv, err = testkeyset.NewHandle(tmpPrivKeyset)
					require.NoError(t, err)

					tmpPubKH, err = tmpKHPriv.Public()
					require.NoError(t, err)

					_, err = NewVerifier(tmpPubKH)
					require.EqualError(t, err, "bbs_verifier_factory: not a Verifier primitive")
				})
			}

			err = bbsVerifier.Verify(messagesBytes, sig)
			if tc.keyURL == bbsSignerKeyTypeURL {
				require.NoError(t, err)

				err = bbsVerifier.Verify([][]byte{}, sig)
				require.EqualError(t, err, "bbs_verifier_factory: invalid signature")
			} else {
				t.Run("bbs verifier calls with invalid primary public key should fail", func(t *testing.T) {
					// create primary public key as ecdsa key to cause an error in a BBS verifier
					var (
						serializedECKey []byte
						sPrimaryPubKey  []byte
					)

					serializedECKey, err = proto.Marshal(testutil.NewRandomECDSAPublicKey(commonpb.HashType_SHA256,
						commonpb.EllipticCurveType_NIST_P256))
					require.NoError(t, err)

					invalidPrimaryPubKey := testutil.NewKey(
						testutil.NewKeyData("type.googleapis.com/google.crypto.tink.EcdsaPublicKey",
							serializedECKey, tinkpb.KeyData_ASYMMETRIC_PUBLIC),
						tinkpb.KeyStatusType_ENABLED, 5, tc.prefix)

					// create valid public key to be able to create a temporary valid verifier
					sPrimaryPubKey, err = proto.Marshal(primaryPrivProto.PublicKey)
					require.NoError(t, err)
					validSecondPubKey := testutil.NewKey(
						testutil.NewKeyData(bbsVerifierKeyTypeURL, sPrimaryPubKey, tinkpb.KeyData_ASYMMETRIC_PUBLIC),
						tinkpb.KeyStatusType_ENABLED, 11, tc.prefix)

					invalidPubKeys := []*tinkpb.Keyset_Key{invalidPrimaryPubKey}
					invalidPubKeyset := testutil.NewKeyset(invalidPubKeys[0].KeyId, invalidPubKeys)

					validPubKeys := []*tinkpb.Keyset_Key{validSecondPubKey}
					validPubKeyset := testutil.NewKeyset(validPubKeys[0].KeyId, validPubKeys)

					var (
						validKHPub   *keyset.Handle
						invalidKHPub *keyset.Handle
						tmpVerifier  api.Verifier
					)

					invalidKHPub, err = testkeyset.NewHandle(invalidPubKeyset)
					require.NoError(t, err)

					validKHPub, err = testkeyset.NewHandle(validPubKeyset)
					require.NoError(t, err)

					// create temporary verifier with valid public keyset handle
					tmpVerifier, err = NewVerifier(validKHPub)
					require.NoError(t, err)

					var badPS *primitiveset.PrimitiveSet

					badPS, err = invalidKHPub.PrimitivesWithKeyManager(nil)
					require.NoError(t, err)

					invalidVerifier, ok := tmpVerifier.(*wrappedVerifier)
					require.True(t, ok)

					// inject bad primitive set in wrappedVerifier to invoke Verify()/DeriveProof()/VerifyProof()
					// and test the expected error.
					invalidVerifier.ps = badPS

					err = invalidVerifier.Verify(messagesBytes, sig)
					require.EqualError(t, err, "bbs_verifier_factory: not a Verifier primitive")

					_, err = invalidVerifier.DeriveProof(messagesBytes, sig, []byte{}, []int{0})
					require.EqualError(t, err, "bbs_verifier_factory: not a Verifier primitive")

					var proof []byte

					proof, err = bbsVerifier.DeriveProof(messagesBytes, sig, []byte{}, []int{0})
					require.NoError(t, err)

					err = invalidVerifier.VerifyProof(messagesBytes, proof, []byte{})
					require.EqualError(t, err, "bbs_verifier_factory: not a Verifier primitive")
				})
			}

			revealedIndexes := []int{1, 3}
			nonce := make([]byte, 10)

			_, err = rand.Read(nonce)
			require.NoError(t, err)

			proof, err := bbsVerifier.DeriveProof(messagesBytes, sig, nonce, revealedIndexes)
			require.NoError(t, err)

			_, err = bbsVerifier.DeriveProof([][]byte{}, sig, nonce, revealedIndexes)
			require.EqualError(t, err, "bbs_verifier_factory: invalid signature proof")

			revealedMessages := make([][]byte, len(revealedIndexes))
			for i, ind := range revealedIndexes {
				revealedMessages[i] = messagesBytes[ind]
			}

			err = bbsVerifier.VerifyProof(revealedMessages, proof, nonce)
			require.NoError(t, err)

			err = bbsVerifier.VerifyProof([][]byte{{}, {}}, proof, nonce)
			require.EqualError(t, err, "bbs_verifier_factory: invalid signature proof")
		})
	}
}

func generatePrivateKeyProto(t *testing.T) *bbspb.BBSPrivateKey {
	seed := make([]byte, 32)
	hashType := commonpb.HashType_SHA256

	_, err := rand.Read(seed)
	require.NoError(t, err)

	pubKey, privKey, err := bbs12381g2pub.GenerateKeyPair(subtle.GetHashFunc(hashType.String()), seed)
	require.NoError(t, err)

	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)

	pubKeyProto := &bbspb.BBSPublicKey{
		Version: bbsVerifierKeyVersion,
		Params: &bbspb.BBSParams{
			HashType: hashType,
			Curve:    bbspb.BBSCurveType_BLS12_381,
			Group:    bbspb.GroupField_G2,
		},
		KeyValue: pubKeyBytes,
	}

	privKeyBytes, err := privKey.Marshal()
	require.NoError(t, err)

	return &bbspb.BBSPrivateKey{
		Version:   bbsSignerKeyVersion,
		PublicKey: pubKeyProto,
		KeyValue:  privKeyBytes,
	}
}
