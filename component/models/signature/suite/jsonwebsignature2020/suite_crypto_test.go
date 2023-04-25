/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package jsonwebsignature2020

import (
	"errors"
	"fmt"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms/localkms"
	mockkms "github.com/hyperledger/aries-framework-go/component/kmscrypto/mock/kms"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/secretlock/noop"
	sigverifier "github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mock/storage"
	kmsapi "github.com/hyperledger/aries-framework-go/spi/kms"

	"github.com/hyperledger/aries-framework-go/component/models/signature/suite"
)

func TestNewCryptoSignerAndVerifier(t *testing.T) {
	lKMS, err := createKMS(t)
	require.NoError(t, err)

	kid, kh := createKeyHandle(lKMS, kmsapi.ECDSAP256TypeIEEEP1363)

	tinkCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	doc := []byte("test doc")

	suiteSigner := suite.NewCryptoSigner(tinkCrypto, kh)
	suiteVerifier := suite.NewCryptoVerifier(&LocalCrypto{
		Crypto:   tinkCrypto,
		localKMS: lKMS,
	})

	ss := New(suite.WithSigner(suiteSigner), suite.WithVerifier(suiteVerifier))

	docSig, err := ss.Sign(doc)
	require.NoError(t, err)

	pubKeyBytes, _, err := lKMS.ExportPubKeyBytes(kid)
	require.NoError(t, err)

	pubKey := &sigverifier.PublicKey{
		Type:  kmsapi.ECDSAP256IEEEP1363,
		Value: pubKeyBytes,
	}

	err = ss.Verify(pubKey, doc, docSig)
	require.NoError(t, err)
}

// LocalCrypto defines a verifier which is based on Local KMS and Crypto
// which uses keyset.Handle as input for verification.
type LocalCrypto struct {
	*tinkcrypto.Crypto
	localKMS *localkms.LocalKMS
}

func (t *LocalCrypto) Verify(sig, msg []byte, kh interface{}) error {
	pubKey, ok := kh.(*sigverifier.PublicKey)
	if !ok {
		return errors.New("bad key handle format")
	}

	kmsKeyType, err := mapKeyTypeToKMS(pubKey.Type)
	if err != nil {
		return err
	}

	handle, err := t.localKMS.PubKeyBytesToHandle(pubKey.Value, kmsKeyType)
	if err != nil {
		return err
	}

	return t.Crypto.Verify(sig, msg, handle)
}

func createKeyHandle(kms *localkms.LocalKMS, keyType kmsapi.KeyType) (string, *keyset.Handle) {
	kid, kh, err := kms.Create(keyType)
	if err != nil {
		panic(err)
	}

	return kid, kh.(*keyset.Handle)
}

func createKMS(t *testing.T) (*localkms.LocalKMS, error) {
	p, err := mockkms.NewProviderForKMS(storage.NewMockStoreProvider(), &noop.NoLock{})
	require.NoError(t, err)

	return localkms.New("local-lock://custom/master/key/", p)
}

func mapKeyTypeToKMS(t string) (kmsapi.KeyType, error) {
	switch t {
	case kmsapi.ECDSAP256IEEEP1363:
		return kmsapi.ECDSAP256TypeIEEEP1363, nil
	default:
		return "", fmt.Errorf("unsupported key type: %s", t)
	}
}
