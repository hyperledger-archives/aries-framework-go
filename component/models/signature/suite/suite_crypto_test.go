/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package suite

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/mock/crypto"
	"github.com/hyperledger/aries-framework-go/component/models/signature/api"
)

func TestNewCryptoSigner(t *testing.T) {
	var kh interface{}

	cryptoSigner := NewCryptoSigner(&crypto.Crypto{
		SignValue: []byte("signature"),
	}, kh)
	require.NotNil(t, cryptoSigner)

	signature, err := cryptoSigner.Sign([]byte("msg"))
	require.NoError(t, err)
	require.Equal(t, []byte("signature"), signature)
}

func TestNewCryptoVerifier(t *testing.T) {
	cryptoVerifier := NewCryptoVerifier(&crypto.Crypto{
		VerifyErr: errors.New("verify error"),
	})
	require.NotNil(t, cryptoVerifier)

	err := cryptoVerifier.Verify(&api.PublicKey{}, []byte("msg"), []byte("signature"))
	require.Error(t, err)
	require.EqualError(t, err, "verify error")
}
