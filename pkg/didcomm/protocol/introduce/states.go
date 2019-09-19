/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
)

const (
	// common states
	stateNameNoop  = "noop"
	stateNameStart = "start"
	stateNameDone  = "done"

	// introducer states
	stateNameArranging  = "arranging"
	stateNameDelivering = "delivering"
	stateNameConfirming = "confirming"
	stateNameAbandoning = "abandoning"

	// introducee states
	stateNameDeciding = "deciding"
	stateNameWaiting  = "waiting"
)

// The introduce protocol's state.
type state interface {
	// Name of this state.
	Name() string
	// Whether this state allows transitioning into the next state.
	CanTransitionTo(next state) bool
	// Executes this state, returning a followup state to be immediately executed as well.
	// The 'noOp' state should be returned if the state has no followup.
	Execute(msg dispatcher.DIDCommMsg) (followup state, err error)
}

type noOp struct {
}

func (s *noOp) Name() string {
	return stateNameNoop
}

func (s *noOp) CanTransitionTo(_ state) bool {
	return false
}

func (s *noOp) Execute(_ dispatcher.DIDCommMsg) (state, error) {
	return nil, errors.New("cannot execute no-op")
}

// start state
type start struct {
}

func (s *start) Name() string {
	return stateNameStart
}

func (s *start) CanTransitionTo(next state) bool {
	return false
}

func (s *start) Execute(msg dispatcher.DIDCommMsg) (state, error) {
	return nil, errors.New("start execute: not implemented yet")
}

// done state
type done struct {
}

func (s *done) Name() string {
	return stateNameDone
}

func (s *done) CanTransitionTo(next state) bool {
	return false
}

func (s *done) Execute(msg dispatcher.DIDCommMsg) (state, error) {
	return nil, errors.New("done execute: not implemented yet")
}

// arranging state
type arranging struct {
}

func (s *arranging) Name() string {
	return stateNameArranging
}

func (s *arranging) CanTransitionTo(next state) bool {
	return false
}

func (s *arranging) Execute(msg dispatcher.DIDCommMsg) (state, error) {
	return nil, errors.New("arranging execute: not implemented yet")
}

// delivering state
type delivering struct {
}

func (s *delivering) Name() string {
	return stateNameDelivering
}

func (s *delivering) CanTransitionTo(next state) bool {
	return false
}

func (s *delivering) Execute(msg dispatcher.DIDCommMsg) (state, error) {
	return nil, errors.New("delivering execute: not implemented yet")
}

// confirming state
type confirming struct {
}

func (s *confirming) Name() string {
	return stateNameConfirming
}

func (s *confirming) CanTransitionTo(next state) bool {
	return false
}

func (s *confirming) Execute(msg dispatcher.DIDCommMsg) (state, error) {
	return nil, errors.New("confirming execute: not implemented yet")
}

// abandoning state
type abandoning struct {
}

func (s *abandoning) Name() string {
	return stateNameAbandoning
}

func (s *abandoning) CanTransitionTo(next state) bool {
	return false
}

func (s *abandoning) Execute(msg dispatcher.DIDCommMsg) (state, error) {
	return nil, errors.New("abandoning execute: not implemented yet")
}

// deciding state
type deciding struct {
}

func (s *deciding) Name() string {
	return stateNameDeciding
}

func (s *deciding) CanTransitionTo(next state) bool {
	return false
}

func (s *deciding) Execute(msg dispatcher.DIDCommMsg) (state, error) {
	return nil, errors.New("deciding execute: not implemented yet")
}

// waiting state
type waiting struct {
}

func (s *waiting) Name() string {
	return stateNameWaiting
}

func (s *waiting) CanTransitionTo(next state) bool {
	return false
}

func (s *waiting) Execute(msg dispatcher.DIDCommMsg) (state, error) {
	return nil, errors.New("waiting execute: not implemented yet")
}
