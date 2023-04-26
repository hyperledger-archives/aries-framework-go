/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package time

import (
	"encoding/json"
	"time"
)

// TimeWrapper overrides marshalling of time.Time. If a TimeWrapper is created from a time string, or
// unmarshalled from JSON, it saves the string literal, which it uses when marshalling.
// If a TimeWrapper is created using NewTime or a struct literal, it marshals with the default
// time.RFC3339 format.
type TimeWrapper struct { // nolint:golint
	time.Time
	timeStr string
}

// TimeWithTrailingZeroMsec overrides marshalling of time.Time. It keeps a format of initial unmarshalling
// in case when date has zero a fractional second (e.g. ".000").
// For example, time.Time marshals 2018-03-15T00:00:00.000Z to 2018-03-15T00:00:00Z
// while TimeWithTrailingZeroMsec marshals to the initial 2018-03-15T00:00:00.000Z value.
//
// Deprecated: use TimeWrapper instead.
type TimeWithTrailingZeroMsec = TimeWrapper // nolint:golint

// NewTime creates a TimeWrapper wrapped around the given time.Time.
// It functions as a normal time.Time object.
func NewTime(t time.Time) *TimeWrapper {
	return &TimeWrapper{Time: t}
}

// NewTimeWithTrailingZeroMsec creates a TimeWrapper wrapped around the given time.Time.
//
// Deprecated: use NewTime instead. For sub-zero precision,
// use ParseTimeWrapper on a string with the desired precision.
func NewTimeWithTrailingZeroMsec(t time.Time, _ int) *TimeWrapper {
	return &TimeWrapper{
		Time: t,
	}
}

// MarshalJSON implements the json.Marshaler interface.
// The time is a quoted string in RFC 3339 format, with sub-second precision added if present.
// In case of zero sub-second precision presence, trailing zeros are included.
func (tm TimeWrapper) MarshalJSON() ([]byte, error) {
	// catch time.Time marshaling errors
	_, err := tm.Time.MarshalJSON()
	if err != nil {
		return nil, err
	}

	if tm.timeStr != "" {
		return json.Marshal(tm.timeStr)
	}

	return json.Marshal(tm.FormatToString())
}

// UnmarshalJSON implements the json.Unmarshaler interface.
// The time is expected to be a quoted string in RFC 3339 format.
// The source string value is saved, and used if this is marshalled back to JSON.
func (tm *TimeWrapper) UnmarshalJSON(data []byte) error {
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

func (tm *TimeWrapper) parse(timeStr string) error {
	t, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		t, err = time.Parse(time.RFC3339, timeStr+"Z")
		if err != nil {
			return err
		}
	}

	tm.Time = t
	tm.timeStr = timeStr

	return nil
}

// FormatToString returns the string representation of this TimeWrapper.
// If it was unmarshalled from a JSON object, this returns the original string it was parsed from.
// Otherwise, this returns the time in the time.RFC3339Nano format.
func (tm *TimeWrapper) FormatToString() string {
	if tm.timeStr != "" {
		return tm.timeStr
	}

	return tm.Time.Format(time.RFC3339Nano)
}

// ParseTimeWithTrailingZeroMsec parses a formatted string and returns the time value it represents.
//
// Deprecated: use ParseTimeWrapper instead.
func ParseTimeWithTrailingZeroMsec(timeStr string) (*TimeWrapper, error) {
	return ParseTimeWrapper(timeStr)
}

// ParseTimeWrapper parses a formatted string and returns the time value it represents.
func ParseTimeWrapper(timeStr string) (*TimeWrapper, error) {
	tm := TimeWrapper{}

	err := tm.parse(timeStr)
	if err != nil {
		return nil, err
	}

	return &tm, nil
}
