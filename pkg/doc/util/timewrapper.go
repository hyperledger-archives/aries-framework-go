/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"time"

	afgotime "github.com/hyperledger/aries-framework-go/component/models/util/time"
)

// TimeWrapper overrides marshalling of time.Time. If a TimeWrapper is created from a time string, or
// unmarshalled from JSON, it saves the string literal, which it uses when marshalling.
// If a TimeWrapper is created using NewTime or a struct literal, it marshals with the default
// time.RFC3339 format.
type TimeWrapper = afgotime.TimeWrapper

// TimeWithTrailingZeroMsec overrides marshalling of time.Time. It keeps a format of initial unmarshalling
// in case when date has zero a fractional second (e.g. ".000").
// For example, time.Time marshals 2018-03-15T00:00:00.000Z to 2018-03-15T00:00:00Z
// while TimeWithTrailingZeroMsec marshals to the initial 2018-03-15T00:00:00.000Z value.
//
// Deprecated: use TimeWrapper instead.
type TimeWithTrailingZeroMsec = afgotime.TimeWithTrailingZeroMsec

// NewTime creates a TimeWrapper wrapped around the given time.Time.
// It functions as a normal time.Time object.
func NewTime(t time.Time) *TimeWrapper {
	return afgotime.NewTime(t)
}

// NewTimeWithTrailingZeroMsec creates a TimeWrapper wrapped around the given time.Time.
//
// Deprecated: use NewTime instead. For sub-zero precision,
// use ParseTimeWrapper on a string with the desired precision.
func NewTimeWithTrailingZeroMsec(t time.Time, _ int) *TimeWrapper {
	return afgotime.NewTimeWithTrailingZeroMsec(t, 0)
}

// ParseTimeWithTrailingZeroMsec parses a formatted string and returns the time value it represents.
//
// Deprecated: use ParseTimeWrapper instead.
func ParseTimeWithTrailingZeroMsec(timeStr string) (*TimeWrapper, error) {
	return afgotime.ParseTimeWithTrailingZeroMsec(timeStr)
}

// ParseTimeWrapper parses a formatted string and returns the time value it represents.
func ParseTimeWrapper(timeStr string) (*TimeWrapper, error) {
	return afgotime.ParseTimeWrapper(timeStr)
}
