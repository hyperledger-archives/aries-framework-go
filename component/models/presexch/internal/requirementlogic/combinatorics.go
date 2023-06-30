/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package requirementlogic

// these functions are combinatorics functions used as part of requirement satisfaction algorithms and testing.

// allCombinationsInLengthRange returns a list of all k-combinations over an arbitrary list of length listLength,
// for all k where min <= k <= max. Combinations are formatted as ordered lists of indices.
func allCombinationsInLengthRange(min, max, listLength int) [][]int {
	totalSize := 0

	if max > listLength {
		max = listLength
	}

	for i := min; i <= max; i++ {
		totalSize += nChooseM(listLength, i)
	}

	resultCombinations := make([][]int, 0, totalSize)

	for k := min; k <= max; k++ {
		kCombinations := getMCombinationsOfN(k, listLength)

		resultCombinations = append(resultCombinations, kCombinations...)
	}

	return resultCombinations
}

// rangeInt returns the list [start, start+1...end-1].
func rangeInt(start, end int) []int {
	if start >= end {
		return []int{}
	}

	out := make([]int, end-start)
	for i := 0; i < end-start; i++ {
		out[i] = start + i
	}

	return out
}

func complement(sortedSet []int, universeLen int) []int {
	if len(sortedSet) == 0 {
		return rangeInt(0, universeLen)
	}

	var (
		out []int
		j   int
	)

	for i := 0; i < universeLen; i++ {
		if j >= len(sortedSet) || i != sortedSet[j] {
			out = append(out, i)
		} else {
			j++
		}
	}

	return out
}

func matchCombination(c1, c2 []int) bool {
	if len(c1) != len(c2) {
		return false
	}

	for i := 0; i < len(c1); i++ {
		if c1[i] != c2[i] {
			return false
		}
	}

	return true
}

func nChooseM(n, m int) int {
	if m > n || n <= 0 || m < 0 {
		return 0
	}

	if m == n || m == 0 {
		return 1
	}

	if m > n-m {
		return nChooseM(n, n-m)
	}

	runningProduct := 1

	for i := 0; i < m; i++ {
		runningProduct *= n - i
		if runningProduct < 0 {
			return -1
		}

		runningProduct /= i + 1
	}

	return runningProduct
}

/*
getMCombinationsOfN generates a list of all m-combinations of the set of integers [0, n).

How this works:

This algorithm maintains a "current combination" slice alongside some additional metadata, and steadily shuffles which
elements are in the combination, until it's stepped through all combinations. As these are combinations and not
permutations, the current combination, and the combination slices returned, are all in ascending order.

The current combination starts by holding the non-negative integers 0 to m-1 in order.

The "shuffling" process involves two steps:
  - Swap First Gap: the first "gap" element is the first element in the current combination whose direct successor is
    absent. This step removes the first gap element from the current combination, and adds its successor.
  - Shift to Start: if:
    1. Swap First Gap increments the first element of the current combination, and
    2. Swap First Gap's next invocation increments a different element,
    Then:
    The first element of the current combination is not 0, and
    All elements before the second swap location are consecutive.
    Under these conditions, the elements before the second swap location are decremented so they form a consecutive
    sequence starting at 0.

These two steps (with some additional nuances) allow the algorithm to step from the current m-combination of n to the
next, in colexicographic order. Essentially, Swap First Gap in most cases can transform the current combination into
its colex successor. In cases where the new first gap is later in the sequence than the previous first gap (which, in
this algorithm, is only possible when the previous first gap was the first element of the combination), this
"skips ahead" in the colex order, and Shift to Start repairs this error.

To keep track of where these "gap elements" are, the algorithm maintains a stack that indexes into the current
combination.
*/
func getMCombinationsOfN(m, n int) [][]int { // nolint:gocyclo
	switch {
	case m > n:
		return nil
	case m == 0:
		return [][]int{{}}
	case m == n:
		return [][]int{rangeInt(0, n)}
	}

	comb := rangeInt(0, m)
	gapStack := []int{m - 1}

	combCopy := make([]int, len(comb))
	copy(combCopy, comb)

	out := [][]int{combCopy}

	shiftingFirstElement := false

	for len(gapStack) > 0 {
		firstGapIndex := gapStack[len(gapStack)-1]

		if comb[firstGapIndex] >= n-2 || (firstGapIndex+1 < m && comb[firstGapIndex+1]-2 <= comb[firstGapIndex]) {
			// the element being moved rightwards will no longer be a gap, so we pop it
			gapStack = gapStack[:len(gapStack)-1]
		}

		if firstGapIndex > 0 && comb[firstGapIndex-1] == comb[firstGapIndex]-1 {
			// if the preceding element in the combination is directly preceding the gap element being swapped,
			// then the preceding element is now a gap.
			gapStack = append(gapStack, firstGapIndex-1)
		}

		comb[firstGapIndex]++

		swappedIndex := firstGapIndex

		if swappedIndex == 0 {
			shiftingFirstElement = true
		} else if shiftingFirstElement {
			// once swappedIndex is nonzero again, do the Shift to Start step
			start := comb[0]

			for i := 0; i < swappedIndex; i++ {
				comb[i] -= start
			}

			shiftingFirstElement = false
		}

		combCopy = make([]int, len(comb))
		copy(combCopy, comb)

		out = append(out, combCopy)
	}

	return out
}
