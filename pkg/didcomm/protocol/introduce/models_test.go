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
	var desc = DescriptionL10N{"locale": locale}
	require.Equal(t, locale, desc.Locale())

	var descEmpty = DescriptionL10N{}
	require.Equal(t, "", descEmpty.Locale())

	var descNil DescriptionL10N
	require.Equal(t, "", descNil.Locale())
}
