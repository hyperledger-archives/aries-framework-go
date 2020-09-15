/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTimeWithTrailingZeroMsec(t *testing.T) {
	timeTests := []struct {
		in  string
		out string
	}{
		{"2018-03-15T00:00:00Z", "2018-03-15T00:00:00Z"},
		{"2018-03-15T00:00:00.9724Z", "2018-03-15T00:00:00.9724Z"},
		{"2018-03-15T00:00:00.000Z", "2018-03-15T00:00:00.000Z"},
		{"2018-03-15T00:00:00.00000Z", "2018-03-15T00:00:00.00000Z"},
		{"2018-03-15T00:00:00.0000100Z", "2018-03-15T00:00:00.00001Z"},
	}

	for _, tt := range timeTests {
		tt := tt
		t.Run(tt.in, func(t *testing.T) {
			var timeMsec TimeWithTrailingZeroMsec
			err := json.Unmarshal([]byte(quote(tt.in)), &timeMsec)
			require.NoError(t, err)

			timeMsecBytes, err := json.Marshal(timeMsec)
			require.NoError(t, err)
			require.Equal(t, quote(tt.out), string(timeMsecBytes))
		})
	}

	// Marshal corner cases.
	timeMsec := TimeWithTrailingZeroMsec{Time: time.Date(10001, time.January, 1, 0, 0, 0, 0, time.UTC)}
	bytes, err := timeMsec.MarshalJSON()
	require.Error(t, err)
	require.Nil(t, bytes)

	// Unmarshal corner cases.
	newTimeMsec := &TimeWithTrailingZeroMsec{}
	err = newTimeMsec.UnmarshalJSON([]byte(quote("not_date")))
	require.Error(t, err)

	err = newTimeMsec.UnmarshalJSON([]byte("null"))
	require.NoError(t, err)
}

func TestTimeWithTrailingZeroMsec_GetFormat(t *testing.T) {
	timeMsec, err := ParseTimeWithTrailingZeroMsec("2018-03-15T00:00:00Z")
	require.NoError(t, err)
	require.Equal(t, time.RFC3339Nano, timeMsec.GetFormat())

	timeMsec, err = ParseTimeWithTrailingZeroMsec("2018-03-15T00:00:00.972Z")
	require.NoError(t, err)
	require.Equal(t, time.RFC3339Nano, timeMsec.GetFormat())

	timeMsec, err = ParseTimeWithTrailingZeroMsec("2018-03-15T00:00:00.000Z")
	require.NoError(t, err)
	require.Equal(t, "2006-01-02T15:04:05.000Z07:00", timeMsec.GetFormat())
}

func TestParse(t *testing.T) {
	timeMsec, err := ParseTimeWithTrailingZeroMsec("2018-03-15T00:00:00.000Z")
	require.NoError(t, err)
	require.Equal(t, "2018-03-15T00:00:00.000Z", timeMsec.Format(timeMsec.GetFormat()))

	timeMsec, err = ParseTimeWithTrailingZeroMsec("2018-03-15T00:00:00.123Z")
	require.NoError(t, err)
	require.Equal(t, "2018-03-15T00:00:00.123Z", timeMsec.Format(timeMsec.GetFormat()))

	// error case
	timeMsec, err = ParseTimeWithTrailingZeroMsec("invalid")
	require.Error(t, err)
	require.Nil(t, timeMsec)
}

func quote(str string) string {
	return `"` + str + `"`
}
