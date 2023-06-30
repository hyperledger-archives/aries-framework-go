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

func TestCombinations(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		testCombinationSequence(t, 2, 2, 3)
		testCombinationSequence(t, 0, 7, 7)
		testCombinationSequence(t, 6, 8, 9)
		testCombinationSequence(t, 1, 5, 5)
	})
}

func TestMofN(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		for n := 1; n < 15; n++ {
			for m := 0; m <= n/2; m++ {
				testCombinations(t, n, m)
			}
		}

		testCombinations(t, 52, 5)
		testCombinations(t, 23, 11)
	})

	t.Run("complement ordered in reverse", func(t *testing.T) {
		combs := getMCombinationsOfN(5, 8)

		expectComplement := getMCombinationsOfN(3, 8)

		require.Len(t, combs, len(expectComplement))

		complements := make([][]int, len(combs))

		for i, comb := range combs {
			complements[i] = complement(comb, 8)
		}

		for i := 0; i < len(expectComplement); i++ {
			comb := expectComplement[i]
			comp := complements[len(complements)-i-1]

			require.True(t, matchCombination(comb, comp))
		}
	})

	t.Run("math check", func(t *testing.T) {
		require.Equal(t, 1352078, nChooseM(23, 11))
		require.Equal(t, 2598960, nChooseM(52, 5))
		require.Equal(t, 34597290, nChooseM(29, 11))
		require.Equal(t, 3562467300, nChooseM(37, 13))
		require.Equal(t, 118264581564861424, nChooseM(60, 30))
		require.Equal(t, 225368761961739396, nChooseM(71, 51))
	})
}

func testCombinations(t *testing.T, n, m int) {
	combs := getMCombinationsOfN(m, n)

	validateCombinations(t, n, m, combs)
}

func testCombinationSequence(t *testing.T, min, max, listLength int) {
	combs := allCombinationsInLengthRange(min, max, listLength)

	validateCombinationSequence(t, min, max, listLength, combs)
}

func validateCombinationSequence(t *testing.T, min, max, n int, combs [][]int) {
	if max > n {
		max = n
	}

	currIdx := 0

	for m := min; m <= max; m++ {
		nextIdx := currIdx + nChooseM(n, m)

		require.Less(t, nextIdx, len(combs)+1)

		currSet := combs[currIdx:nextIdx]

		validateCombinations(t, n, m, currSet)

		currIdx = nextIdx
	}

	require.Equal(t, len(combs), currIdx)
}

func validateCombinations(t *testing.T, n, m int, combs [][]int) {
	expectLen := nChooseM(n, m)

	require.Len(t, combs, expectLen)

	if expectLen > 0 {
		valid, errMsg := validateSingleCombination(combs[0], n, m)
		require.True(t, valid, errMsg)

		for i := 1; i < expectLen; i++ {
			valid, errMsg = validateSingleCombination(combs[i], n, m)
			require.True(t, valid, errMsg)

			// validate that combs[i] is lexicographically after combs[i-1]
			require.True(t, isCoLexOrdered(combs[i-1], combs[i]),
				"co-lex order error:", combs[i-1], combs[i])
		}
	}
}

func validateSingleCombination(comb []int, n, m int) (bool, string) {
	if len(comb) != m {
		return false, fmt.Sprintf("len=%d, expected %d", len(comb), m)
	}

	// validate that comb is ordered, without repeats, and elements are non-negative and less than n

	if m == 0 {
		return true, ""
	}

	for i := 0; i < len(comb)-1; i++ {
		if comb[i] >= comb[i+1] {
			return false, "not strictly increasing"
		}
	}

	if comb[0] < 0 || comb[len(comb)-1] >= n {
		return false, "exceeds bounds"
	}

	return true, ""
}

func isCoLexOrdered(smaller, larger []int) bool {
	shorter := len(smaller)

	if shorter > len(larger) {
		shorter = len(larger)
	}

	for i := shorter - 1; i >= 0; i-- {
		if smaller[i] < larger[i] {
			return true
		}

		if smaller[i] > larger[i] {
			return false
		}
	}

	// The longer one is colexicographically larger. If their lengths are the same, they're the same.
	return len(larger) > len(smaller)
}
