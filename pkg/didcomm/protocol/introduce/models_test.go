/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDescriptionL10N_Locale(t *testing.T) {
	const locale = "en"

	var (
		desc      = DescriptionL10N{"locale": locale}
		descEmpty = DescriptionL10N{}
		descNil   DescriptionL10N
	)

	require.Equal(t, locale, desc.Locale())
	require.Equal(t, "", descEmpty.Locale())
	require.Equal(t, "", descNil.Locale())
}
