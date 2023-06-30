/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package requirementlogic

import (
	"sort"
	"strings"
)

// StringSet implements a set of strings.
type StringSet map[string]struct{}

// InitFromSlice creates a new StringSet containing all the given values.
func InitFromSlice(values []string) StringSet {
	s := make(StringSet, len(values))

	for _, value := range values {
		s.Add(value)
	}

	return s
}

// MergeAll returns the union of the given StringSet parameters as a new StringSet.
func MergeAll(sets ...StringSet) StringSet {
	out := StringSet{}

	for _, set := range sets {
		for k := range set {
			out.Add(k)
		}
	}

	return out
}

// Has returns whether s contains value.
func (s StringSet) Has(value string) bool {
	_, ok := s[value]
	return ok
}

// Add adds value to s.
func (s StringSet) Add(value string) {
	s[value] = struct{}{}
}

// Len returns the size of s.
func (s StringSet) Len() int {
	return len(s)
}

// ToString creates a string representation of s, guaranteed to be identical for
// two StringSets containing the same strings.
func (s StringSet) ToString() string {
	escaped := make([]string, s.Len())

	for d := range s {
		escaped = append(escaped, strings.ReplaceAll(d, "\x00", "\\x00"))
	}

	sort.Strings(escaped)

	return strings.Join(escaped, "\x00")
}
