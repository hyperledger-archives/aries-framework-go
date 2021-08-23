/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"encoding/json"
	"time"
)

// TimeWithTrailingZeroMsec overrides marshalling of time.Time. It keeps a format of initial unmarshalling
// in case when date has zero a fractional second (e.g. ".000").
// For example, time.Time marshals 2018-03-15T00:00:00.000Z to 2018-03-15T00:00:00Z
// while TimeWithTrailingZeroMsec marshals to the initial 2018-03-15T00:00:00.000Z value.
type TimeWithTrailingZeroMsec struct {
	time.Time

	trailingZerosMsecCount int
	missingZ               bool
}

const (
	rfc3339NanoWithoutZ = "2006-01-02T15:04:05.999999999"
)

// NewTime creates TimeWithTrailingZeroMsec without zero sub-second precision.
// It functions as a normal time.Time object.
func NewTime(t time.Time) *TimeWithTrailingZeroMsec {
	return &TimeWithTrailingZeroMsec{Time: t}
}

// NewTimeWithTrailingZeroMsec creates TimeWithTrailingZeroMsec with certain zero sub-second precision.
func NewTimeWithTrailingZeroMsec(t time.Time, trailingZerosMsecCount int) *TimeWithTrailingZeroMsec {
	return &TimeWithTrailingZeroMsec{
		Time:                   t,
		trailingZerosMsecCount: trailingZerosMsecCount,
	}
}

// MarshalJSON implements the json.Marshaler interface.
// The time is a quoted string in RFC 3339 format, with sub-second precision added if present.
// In case of zero sub-second precision presence, trailing zeros are included.
func (tm TimeWithTrailingZeroMsec) MarshalJSON() ([]byte, error) {
	if _, err := tm.Time.MarshalJSON(); err != nil {
		return nil, err
	}

	format := tm.GetFormat()

	b := make([]byte, 0, len(format)+len(`""`))
	b = append(b, '"')
	b = tm.AppendFormat(b, format)
	b = append(b, '"')

	return b, nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
// The time is expected to be a quoted string in RFC 3339 format.
// In case of zero sub-second precision, it's kept and applied when e.g. unmarshal the time to JSON.
func (tm *TimeWithTrailingZeroMsec) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}

	timeStr := ""

	err := json.Unmarshal(data, &timeStr)
	if err != nil {
		return err
	}

	err = tm.parse(timeStr)
	if err != nil {
		return err
	}

	return nil
}

func (tm *TimeWithTrailingZeroMsec) parse(timeStr string) error {
	missingZ := false

	t, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		t, err = time.Parse(time.RFC3339, timeStr+"Z")
		if err != nil {
			return err
		}

		missingZ = true
	}

	tm.Time = t
	tm.missingZ = missingZ
	tm.keepTrailingZerosMsecFormat(timeStr)

	return nil
}

// GetFormat returns customized time.RFC3339Nano with trailing zeros included in case of
// zero sub-second precision presence. Otherwise it returns time.RFC3339Nano.
func (tm TimeWithTrailingZeroMsec) GetFormat() string {
	if tm.trailingZerosMsecCount > 0 {
		return tm.getTrailingZeroIncludedFormat()
	} else if tm.missingZ {
		return rfc3339NanoWithoutZ
	}

	return time.RFC3339Nano
}

// ParseTimeWithTrailingZeroMsec parses a formatted string and returns the time value it represents.
// In case of zero sub-second precision, it's kept and applied when e.g. unmarshal the time to JSON.
func ParseTimeWithTrailingZeroMsec(timeStr string) (*TimeWithTrailingZeroMsec, error) {
	tm := TimeWithTrailingZeroMsec{}

	err := tm.parse(timeStr)
	if err != nil {
		return nil, err
	}

	return &tm, nil
}

func (tm TimeWithTrailingZeroMsec) getTrailingZeroIncludedFormat() string {
	format := "2006-01-02T15:04:05."

	for i := 0; i < tm.trailingZerosMsecCount; i++ {
		format += "0"
	}

	if !tm.missingZ {
		format += "Z07:00"
	}

	return format
}

func (tm *TimeWithTrailingZeroMsec) keepTrailingZerosMsecFormat(timeStr string) {
	msecFraction := false
	zerosCount := 0

	i := 0
	for ; i < len(timeStr); i++ {
		c := int(timeStr[i])
		if !msecFraction {
			if c == '.' {
				msecFraction = true
			}

			continue
		}

		if c == 'Z' || c == 'z' {
			if zerosCount > 0 {
				tm.trailingZerosMsecCount = zerosCount
			}

			break
		} else if c != '0' {
			break
		}

		zerosCount++
	}

	// if we run off the end of the string, remember any trailing zeros
	if i == len(timeStr) {
		if zerosCount > 0 {
			tm.trailingZerosMsecCount = zerosCount
		}
	}
}
