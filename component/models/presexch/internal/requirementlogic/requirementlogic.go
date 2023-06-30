/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package requirementlogic

import (
	"math/big"
)

// RequirementLogic is a datatype for processing nested submission requirement logic.
type RequirementLogic struct {
	InputDescriptorIDs []string
	Nested             []*RequirementLogic
	Count              int
	Min                int
	Max                int
}

// acceptInterval returns the interval of accepted lengths [min, max] (interval is inclusive on both ends).
// If max == 0, then the upper end of the interval is unbounded.
func (r *RequirementLogic) acceptInterval() (int, int) {
	if r.Count > 0 {
		return r.Count, r.Count
	}

	return r.Min, r.Max
}

// IsSatisfiedBy returns whether the given requirement logic is satisfied by the given set of descriptors.
func (r *RequirementLogic) IsSatisfiedBy(descs DescriptorIDSet) bool {
	if len(r.Nested) == 0 {
		satisfiedDescriptors := DescriptorIDSet{}

		for _, id := range r.InputDescriptorIDs {
			if descs.Has(id) {
				satisfiedDescriptors.Add(id)
			}
		}

		return r.isLenApplicable(satisfiedDescriptors.Len())
	}

	numChildrenSatisfied := 0

	for _, logic := range r.Nested {
		if logic.IsSatisfiedBy(descs) {
			numChildrenSatisfied++
		}
	}

	return r.isLenApplicable(numChildrenSatisfied)
}

// GetAllDescriptors returns the IDs of all InputDescriptors referenced in this RequirementLogic or its children.
func (r *RequirementLogic) GetAllDescriptors() DescriptorIDSet {
	if len(r.Nested) == 0 {
		return toMap(r.InputDescriptorIDs)
	}

	var childSets []DescriptorIDSet

	for _, child := range r.Nested {
		childSets = append(childSets, child.GetAllDescriptors())
	}

	return MergeAll(childSets...)
}

// Iterator returns a SolutionIterator that iterates through all solutions to req, using the given descriptor IDs.
func (r *RequirementLogic) Iterator(descriptors []string) SolutionIterator {
	return NewBitsetIterator(r, descriptors)
}

func (r *RequirementLogic) isLenApplicable(val int) bool {
	if r.Count > 0 && val != r.Count {
		return false
	}

	if r.Min > 0 && r.Min > val {
		return false
	}

	if r.Max > 0 && r.Max < val {
		return false
	}

	return true
}

// SolutionIterator iterates through solutions to a RequirementLogic. Each
// solution is a list of Input Descriptor IDs, that should satisfy the
// RequirementLogic from which the SolutionIterator has been created.
type SolutionIterator interface {
	// Next returns a list of input descriptor IDs, denoting a set of input
	// descriptors that should satisfy the RequirementLogic this SolutionIterator
	// was created for.
	//
	// Parameter exclude: a list of input descriptors that should be excluded from
	// future iterations (for example, if they were evaluated and no credentials
	// were found to satisfy them).
	Next(exclude []string) []string
}

// BitsetSolutionIterator implements SolutionIterator using a bitset. Iterates
// through subsets of descriptor IDs in an order that reaches all subsets of the
// first k input descriptors before adding descriptor k+1.
type BitsetSolutionIterator struct {
	req    *RequirementLogic
	state  *big.Int
	descs  []string
	idxMap map[string]int
	done   bool
}

// NewBitsetIterator returns a BitsetSolutionIterator instantiated to iterate
// solutions to req using descriptor IDs in descs.
func NewBitsetIterator(req *RequirementLogic, descs []string) *BitsetSolutionIterator {
	reqDescriptors := req.GetAllDescriptors()

	idxMap := make(map[string]int, len(reqDescriptors))
	useDescs := make([]string, len(reqDescriptors))

	i := 0

	for _, desc := range descs {
		if _, ok := reqDescriptors[desc]; ok {
			idxMap[desc] = i
			useDescs[i] = desc

			i++
		}
	}

	return &BitsetSolutionIterator{
		req:    req,
		state:  &big.Int{},
		descs:  useDescs,
		idxMap: idxMap,
	}
}

// Next returns the next valid solution to b's RequirementLogic, or nil if iteration is complete.
func (b *BitsetSolutionIterator) Next(excludeIDs []string) []string {
	if b.done {
		return nil
	}

	excludeIndices := map[int]struct{}{}

	for _, desc := range excludeIDs {
		for i, s := range b.descs {
			if desc == s {
				excludeIndices[i] = struct{}{}
			}
		}
	}

	next := b.next(excludeIndices)

	if len(next) == 0 {
		b.done = true
	}

	return next
}

func (b *BitsetSolutionIterator) next(excludeIdx map[int]struct{}) []string {
	if len(excludeIdx) == 0 {
		b.state.Add(b.state, big.NewInt(1))
	} else {
		b.excludeDescriptors(excludeIdx)
	}

	return b.incrementUntilValid()
}

// excludeDescriptors modifies the iterator's state and descs so future calls to Next will skip over the descriptors
// indexed by the indices in excludeIdx.
//
// How this works:
//
// When the iterator returns a value that contains input descriptors that the caller hasn't evaluated yet,
// then we assume the caller evaluates these input descriptors, and will determine whether they can be satisfied by
// available credentials. If such an input descriptor can't be satisfied, we want future iterations of the iterator
// to avoid processing these unsatisfied input descriptors.
//
// Let D be the source list of input descriptors, and let B be the bitset, an arbitrary-precision int indexable by bit
// position. Let both B and D be zero-indexed.
// Iff B[i] == 1, D[i] is included in the current output of the iterator.
//
// Suppose the iterator returns a set that contains a number of unsatisfiable input descriptors.
// The caller evaluates the input descriptors from the set, determines that m descriptors are unsatisfiable,
// and passes a list of these into the iterator next time it calls.
// Take this list, map from each element back to its index in D, and let the largest index be k.
//
// B[k] == 1, since B's value matches the last output of the iterator.
// Since the iterator steps through candidate results in binary digit order, we know that all candidate results
// from Bprev up to B have already been stepped through, where Bprev is defined as:
//
//	Bprev[i] = 0    if i <= k
//	Bprev[i] = B[i] if i >  k
//
// And since we want to exclude D[k], we don't need to step through any further candidate results where B[k] == 1.
// The next candidate result where B[k] == 0, ie, the result of incrementing B by 1 until B[k] == 0, is the result of
// clearing all B[i] for i < k, then adding 2^k to B.
//
// Without any further changes, the iterator would subsequently still generate candidate results containing the
// unsatisfiable descriptors, so we want to remove the unsatisfiable descriptors from D and B entirely.
// If we remove an element D[i] from D, and also right-shift B[i+1:] by 1 (remember, right-shift by 1 is equivalent to
// dividing by 2), then the current state still refers to the same subset (less D[i]), and can continue to iterate
// through all subsequent subsets excluding D[i].
//
// Since the next candidate result has zeroes up to (and including) index k, we can right-shift by up to k+1, and remove
// any number of the elements D[i] where i <= k, and subsequently still be able to iterate all remaining subsets of all
// remaining elements.
//
// So, to remove m descriptors, we do all the above, remove the descriptors from D, and right-shift B by m.
func (b *BitsetSolutionIterator) excludeDescriptors(excludeIdx map[int]struct{}) {
	largestExcludeIdx := 0

	for idx := range excludeIdx {
		if idx > largestExcludeIdx {
			largestExcludeIdx = idx
		}
	}

	// clear all bits less than largestExcludeIdx
	excludeBit := &big.Int{}
	excludeBit.SetBit(excludeBit, largestExcludeIdx, 1)

	clear := &big.Int{}
	clear.Sub(excludeBit, big.NewInt(1))

	b.state.AndNot(b.state, clear)

	// add 1 << largestExcludeIdx
	b.state.Add(b.state, excludeBit)

	// resize updated state, removing the slot for each excludeIdx
	b.state.Rsh(b.state, uint(len(excludeIdx)))

	// remove excluded elements from b.descs
	var updatedDescs []string

	for i, desc := range b.descs {
		if _, skip := excludeIdx[i]; !skip {
			updatedDescs = append(updatedDescs, desc)
		}
	}

	b.descs = updatedDescs
}

func (b *BitsetSolutionIterator) incrementUntilValid() []string {
	curr := b.current()

	if curr == nil {
		return nil
	}

	for !b.req.IsSatisfiedBy(toMap(curr)) {
		b.state.Add(b.state, big.NewInt(1))

		curr = b.current()

		if curr == nil {
			return nil
		}
	}

	return curr
}

func (b *BitsetSolutionIterator) current() []string {
	var out []string

	for i := 0; i < len(b.descs); i++ {
		if b.state.Bit(i) == 1 {
			out = append(out, b.descs[i])
		}
	}

	return out
}

// DescriptorIDSet is a set of InputDescriptor IDs.
type DescriptorIDSet = StringSet

// SolutionSet holds sets of InputDescriptor ID. Each set is a combination of
// InputDescriptorIDs that satisfy the count rules of the SubmissionRequirement
// that this result was derived from.
type SolutionSet map[string]DescriptorIDSet

// add adds elem to s.
func (s SolutionSet) add(elem DescriptorIDSet) {
	key := solutionSetKey(elem)

	s[key] = elem
}

func solutionSetKey(descIDs DescriptorIDSet) string {
	return descIDs.ToString()
}

func toMap(ids []string) DescriptorIDSet {
	return InitFromSlice(ids)
}
