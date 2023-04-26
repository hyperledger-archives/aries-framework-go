/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package time

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
		{"2018-03-15T00:00:00.0000100Z", "2018-03-15T00:00:00.0000100Z"},
		{"2018-03-15T00:00:00.0000100+07:00", "2018-03-15T00:00:00.0000100+07:00"},
		{"2018-03-15T00:00:00.0000100-07:00", "2018-03-15T00:00:00.0000100-07:00"},
		{"2018-03-15T00:00:00", "2018-03-15T00:00:00"},
		{"2018-03-15T00:00:00.9724", "2018-03-15T00:00:00.9724"},
		{"2018-03-15T00:00:00.000", "2018-03-15T00:00:00.000"},
		{"2018-03-15T00:00:00.00000", "2018-03-15T00:00:00.00000"},
		{"2018-03-15T00:00:00.0000100", "2018-03-15T00:00:00.0000100"},
		{"2021-08-24T22:18:06.333020", "2021-08-24T22:18:06.333020"}, // acapy interop corner case
	}

	for _, tt := range timeTests {
		tt := tt
		t.Run(tt.in, func(t *testing.T) {
			var timeMsec TimeWrapper
			err := json.Unmarshal([]byte(quote(tt.in)), &timeMsec)
			require.NoError(t, err)

			timeMsecBytes, err := json.Marshal(timeMsec)
			require.NoError(t, err)
			require.Equal(t, quote(tt.out), string(timeMsecBytes))
		})
	}

	// Marshal corner cases.
	timeMsec := &TimeWrapper{Time: time.Date(10001, time.January, 1, 0, 0, 0, 0, time.UTC)}
	bytes, err := timeMsec.MarshalJSON()
	require.Error(t, err)
	require.Nil(t, bytes)

	timeMsec = NewTime(time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC))
	bytes, err = timeMsec.MarshalJSON()
	require.NoError(t, err)
	require.NotNil(t, bytes)

	timeMsec = NewTimeWithTrailingZeroMsec(time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC), 0)
	bytes, err = timeMsec.MarshalJSON()
	require.NoError(t, err)
	require.NotNil(t, bytes)

	// Unmarshal corner cases.
	newTimeMsec := &TimeWrapper{}
	err = newTimeMsec.UnmarshalJSON([]byte(quote("not_date")))
	require.Error(t, err)

	err = newTimeMsec.UnmarshalJSON([]byte("null"))
	require.NoError(t, err)

	err = newTimeMsec.UnmarshalJSON([]byte("not string"))
	require.Error(t, err)
}

func TestParse(t *testing.T) {
	timeMsec, err := ParseTimeWrapper("2018-03-15T00:00:00.000Z")
	require.NoError(t, err)
	require.Equal(t, "2018-03-15T00:00:00.000Z", timeMsec.FormatToString())

	timeMsec, err = ParseTimeWrapper("2018-03-15T00:00:00.123Z")
	require.NoError(t, err)
	require.Equal(t, "2018-03-15T00:00:00.123Z", timeMsec.FormatToString())

	timeMsec, err = ParseTimeWithTrailingZeroMsec("2018-03-15T00:00:00.123Z")
	require.NoError(t, err)
	require.Equal(t, "2018-03-15T00:00:00.123Z", timeMsec.FormatToString())

	// error case
	timeMsec, err = ParseTimeWrapper("invalid")
	require.Error(t, err)
	require.Nil(t, timeMsec)
}

func quote(str string) string {
	return `"` + str + `"`
}
