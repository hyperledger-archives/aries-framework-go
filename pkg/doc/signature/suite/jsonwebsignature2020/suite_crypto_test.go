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

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	sigverifier "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	kmsapi "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
)

func TestNewCryptoSignerAndVerifier(t *testing.T) {
	lKMS := createKMS()

	kid, kh := createKeyHandle(lKMS, kmsapi.ECDSAP256Type)

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

	pubKeyBytes, err := lKMS.ExportPubKeyBytes(kid)
	require.NoError(t, err)

	pubKey := &sigverifier.PublicKey{
		Type:  kmsapi.ECDSAP256,
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

func createKMS() *localkms.LocalKMS {
	p := mockkms.NewProvider(storage.NewMockStoreProvider(), &noop.NoLock{})

	k, err := localkms.New("local-lock://custom/master/key/", p)
	if err != nil {
		panic(err)
	}

	return k
}

func mapKeyTypeToKMS(t string) (kmsapi.KeyType, error) {
	switch t {
	case kmsapi.ECDSAP256:
		return kmsapi.ECDSAP256Type, nil
	default:
		return "", fmt.Errorf("unsupported key type: %s", t)
	}
}
