/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewJWTPresClaims(t *testing.T) {
	vp, err := newTestPresentation(t, []byte(validPresentation))
	require.NoError(t, err)

	audience := []string{"did:example:4a57546973436f6f6c4a4a57573"}

	t.Run("new JWT claims of VP with minimization", func(t *testing.T) {
		claims, err := newJWTPresClaims(vp, audience, true)
		require.NoError(t, err)
		require.NotNil(t, claims)

		// issuer, ID and audience are filled in JWT claims
		require.Equal(t, vp.Holder, claims.Issuer)
		require.Equal(t, vp.ID, claims.ID)
		require.Equal(t, audience[0], claims.Audience[0])

		require.NotNil(t, claims.Presentation)

		// ID and Holder are cleared (minimized) in "vp" claim
		require.Empty(t, claims.Presentation.ID)
		require.Empty(t, claims.Presentation.Holder)

		// minimization does not affect original VP
		require.NotEqual(t, vp.ID, claims.Presentation.ID)
		require.NotEqual(t, vp.Holder, claims.Presentation.Holder)
	})

	t.Run("new JWT claims of VP without minimization", func(t *testing.T) {
		claims, err := newJWTPresClaims(vp, audience, false)
		require.NoError(t, err)
		require.NotNil(t, claims)

		// issuer, ID and audience are filled in JWT claims
		require.Equal(t, vp.Holder, claims.Issuer)
		require.Equal(t, vp.ID, claims.ID)
		require.Equal(t, audience[0], claims.Audience[0])

		require.NotNil(t, claims.Presentation)

		// ID and Holder are cleared (minimized) in "vp" claim
		require.Equal(t, vp.ID, claims.Presentation.ID)
		require.Equal(t, vp.Holder, claims.Presentation.Holder)
	})
}
