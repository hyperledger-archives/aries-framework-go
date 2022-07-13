//go:build !ursa
// +build !ursa

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tinkcrypto

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCLStubs(t *testing.T) {
	c := Crypto{}

	t.Run("test CL methods return not implemented", func(t *testing.T) {
		errNotImplemented := errors.New("not implemented")
		var err error

		_, err = c.GetCorrectnessProof(nil)
		require.EqualError(t, err, errNotImplemented.Error())

		_, _, err = c.SignWithSecrets(nil, map[string]interface{}{}, nil, nil, nil, "")
		require.EqualError(t, err, errNotImplemented.Error())

		_, err = c.Blind(nil, map[string]interface{}{})
		require.EqualError(t, err, errNotImplemented.Error())
	})
}
