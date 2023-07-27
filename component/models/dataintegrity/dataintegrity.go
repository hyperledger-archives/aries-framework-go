/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dataintegrity

import "errors"

var (
	// ErrUnsupportedSuite is returned when a Signer or Verifier is required to use a cryptographic suite for which it
	// doesn't have a suite.Signer or suite.Verifier (respectively) initialized.
	ErrUnsupportedSuite = errors.New("data integrity proof requires unsupported cryptographic suite")
)
