/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
)

func TestSessionManager_CreateSession(t *testing.T) {
	t.Run("successfully create session", func(t *testing.T) {
		token, err := sessionManager().createSession(uuid.New().String(), &mockkms.KeyManager{}, 0)

		require.NoError(t, err)
		require.NotEmpty(t, token)
	})

	t.Run("fail to create created session - wallet already unlocked", func(t *testing.T) {
		user := uuid.New().String()

		token, err := sessionManager().createSession(user, &mockkms.KeyManager{}, 0)

		require.NoError(t, err)
		require.NotEmpty(t, token)

		_, err = sessionManager().createSession(user, &mockkms.KeyManager{}, 0)
		require.EqualError(t, err, "wallet already unlocked")
	})
}

func TestSessionManager_GetSession(t *testing.T) {
	t.Run("successfully get session", func(t *testing.T) {
		token, err := sessionManager().createSession(uuid.New().String(), &mockkms.KeyManager{}, 0)

		require.NoError(t, err)
		require.NotEmpty(t, token)

		sess, err := sessionManager().getSession(token)

		require.NoError(t, err)
		require.NotEmpty(t, sess)
	})

	t.Run("fail to create created session - wallet already unlocked", func(t *testing.T) {
		token := "token with invalid data"

		err := sessionManager().gstore.Set(token, "invalid sess object")

		require.NoError(t, err)

		_, err = sessionManager().getSession(token)

		require.EqualError(t, err, "failed to cast session object: expects Session, gets string")

		sessionManager().gstore.Remove(token)
	})
}

func TestSessionManager_CloseSession(t *testing.T) {
	t.Run("successfully close session", func(t *testing.T) {
		user := uuid.New().String()

		token, err := sessionManager().createSession(user, &mockkms.KeyManager{}, 0)

		require.NoError(t, err)
		require.NotEmpty(t, token)

		sess, err := sessionManager().getSession(token)

		require.NoError(t, err)
		require.NotEmpty(t, sess)

		closed := sessionManager().closeSession(user)
		require.True(t, closed)

		closed = sessionManager().closeSession(user)
		require.False(t, closed)

		_, err = sessionManager().getSession(token)

		require.EqualError(t, err, "invalid auth token")
	})
}
