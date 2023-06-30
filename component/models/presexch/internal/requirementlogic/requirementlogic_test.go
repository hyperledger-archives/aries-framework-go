/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package requirementlogic

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRequirementLogic_Iterator(t *testing.T) {
	t.Run("basic validation", func(t *testing.T) {
		allDescriptors := []string{"A", "B", "C"}

		// req accepts {A,B,C}
		req := &RequirementLogic{
			InputDescriptorIDs: allDescriptors,
			Count:              3,
		}

		it := req.Iterator(allDescriptors)

		satisfied := toMap(allDescriptors)

		expected := SolutionSet{
			solutionSetKey(satisfied): satisfied,
		}

		actual := runIterator(t, it, satisfied)

		validateSolutionSet(t, req, actual, expected)
	})
}

func TestBitsetIterator(t *testing.T) {
	t.Run("basic validation", func(t *testing.T) {
		allDescriptors := []string{"A", "B", "C"}

		// req accepts {A,B,C}
		req := &RequirementLogic{
			InputDescriptorIDs: allDescriptors,
			Count:              3,
		}

		bsi := NewBitsetIterator(req, allDescriptors)

		satisfied := toMap(allDescriptors)

		expected := SolutionSet{
			solutionSetKey(satisfied): satisfied,
		}

		actual := runIterator(t, bsi, satisfied)

		validateSolutionSet(t, req, actual, expected)

		for i := 0; i < 3; i++ {
			next := bsi.Next(nil)
			require.Nil(t, next)
		}
	})

	t.Run("success testcases", func(t *testing.T) {
		tt := []struct {
			name           string
			req            *RequirementLogic
			allDescriptors []string
			satisfiable    DescriptorIDSet
		}{
			{
				name: "no exclusion",
				req: &RequirementLogic{
					Nested: []*RequirementLogic{
						{
							InputDescriptorIDs: []string{"A", "B", "C"},
							Min:                1,
						},
						{
							InputDescriptorIDs: []string{"A", "D", "E"},
							Min:                1,
						},
					},
					Min: 1,
				},
				allDescriptors: []string{"A", "B", "C", "D", "E"},
				satisfiable:    toMap([]string{"A", "B", "C", "D", "E"}),
			},
			{
				name: "no solutions",
				req: &RequirementLogic{
					Nested: []*RequirementLogic{
						{
							InputDescriptorIDs: toStringSlice(rangeInt(0, 5)),
							Min:                2,
						},
						{
							InputDescriptorIDs: toStringSlice(rangeInt(0, 5)),
							Max:                1,
						},
					},
					Count: 2,
				},
				allDescriptors: toStringSlice(rangeInt(0, 5)),
				satisfiable:    toMap(toStringSlice(rangeInt(0, 5))),
			},
			{
				name: "no satisfiable solutions",
				req: &RequirementLogic{
					InputDescriptorIDs: toStringSlice(rangeInt(0, 5)),
					Min:                3,
				},
				allDescriptors: toStringSlice(rangeInt(0, 5)),
				satisfiable:    DescriptorIDSet{},
			},
			{
				name: "requirement ignores some descriptors",
				req: &RequirementLogic{
					InputDescriptorIDs: toStringSlice(rangeInt(0, 11)),
					Min:                3,
				},
				allDescriptors: toStringSlice(rangeInt(0, 17)),
				satisfiable:    toMap(toStringSlice(rangeInt(6, 13))),
			},
			{
				name: "exclude two at a time",
				req: &RequirementLogic{
					InputDescriptorIDs: toStringSlice(rangeInt(0, 17)),
					Count:              3,
				},
				allDescriptors: toStringSlice(rangeInt(0, 17)),
				satisfiable:    toMap([]string{"2", "5", "8", "11", "14"}),
			},
			{
				name: "complex nested requirement",
				req: &RequirementLogic{
					Min: 2,
					Max: 3,
					Nested: []*RequirementLogic{
						// Shared solution chart:
						//  independent: -
						//  mutually exclusive: x
						//  overlap in solutions with: +
						//  \  0
						//  1  +  1
						//  2  +  +  2
						//  3  -  x  +  3
						//  4  x  -  x  -
						{
							InputDescriptorIDs: []string{"0", "1", "2", "3", "4", "5"},
							Count:              2,
						},
						{
							InputDescriptorIDs: []string{"3", "4", "5", "6", "7", "8"},
							Min:                1,
							Max:                2,
						},
						{
							InputDescriptorIDs: []string{"0", "1", "2", "3", "4", "6", "7"},
							Min:                1,
							Max:                2,
						},
						{
							InputDescriptorIDs: []string{"6", "7", "8"},
							Count:              3,
						},
						{
							InputDescriptorIDs: []string{"0", "1", "2"},
							Count:              3,
						},
					},
				},
				allDescriptors: toStringSlice(rangeInt(0, 9)),
				satisfiable:    toMap(toStringSlice(rangeInt(0, 9))),
			},
		}

		for _, tc := range tt {
			t.Run(tc.name, func(t *testing.T) {
				bsi := NewBitsetIterator(tc.req, tc.allDescriptors)

				expected := bitsetIteratorExpected(tc.req, tc.satisfiable)
				actual := runIterator(t, bsi, tc.satisfiable)

				validateSolutionSet(t, tc.req, actual, expected)
			})
		}
	})
}

func runIterator(
	t *testing.T,
	it SolutionIterator,
	satisfiableDescriptors DescriptorIDSet,
) SolutionSet {
	actual := SolutionSet{}
	alreadyExcluded := DescriptorIDSet{}

	var exclude []string

	for next := it.Next(nil); next != nil; next = it.Next(exclude) {
		solved := true
		exclude = nil

		for _, s := range next {
			if !satisfiableDescriptors.Has(s) {
				require.NotContains(t, alreadyExcluded, s)

				alreadyExcluded.Add(s)

				solved = false

				exclude = append(exclude, s)
			}
		}

		if solved {
			actual.add(toMap(next))
		}
	}

	return actual
}

func bitsetIteratorExpected(req *RequirementLogic, satisfied DescriptorIDSet) SolutionSet {
	expectedMap := SolutionSet{}

	expected := exhaustiveFindSolutions(req)
	for _, descMap := range expected {
		skip := false

		for s := range descMap {
			if !satisfied.Has(s) {
				skip = true
				break
			}
		}

		if !skip {
			expectedMap.add(descMap)
		}
	}

	return expectedMap
}

func toStringSlice(a []int) []string {
	out := make([]string, len(a))

	for idx, val := range a {
		out[idx] = fmt.Sprintf("%d", val)
	}

	return out
}

func validateSolutionSet(t *testing.T, req *RequirementLogic, set SolutionSet, expected SolutionSet) {
	for exp := range expected {
		require.Contains(t, set, exp)
	}

	for _, idSet := range set {
		require.True(t, req.IsSatisfiedBy(idSet))
	}

	require.Len(t, set, len(expected))
}

func exhaustiveFindSolutions(req *RequirementLogic) SolutionSet {
	descMap := req.GetAllDescriptors()

	var descList []string

	for s := range descMap {
		descList = append(descList, s)
	}

	min := 1
	max := len(descList)

	if len(req.Nested) == 0 {
		min, max = req.acceptInterval()

		if max == 0 {
			max = len(descList)
		}
	}

	subsets := allCombinationsInLengthRange(min, max, len(descList))

	out := SolutionSet{}

	for _, subset := range subsets {
		solution := make([]string, len(subset))
		for i, j := range subset {
			solution[i] = descList[j]
		}

		solutionMap := toMap(solution)

		if req.IsSatisfiedBy(solutionMap) {
			out.add(solutionMap)
		}
	}

	return out
}
