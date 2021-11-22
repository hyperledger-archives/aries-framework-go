/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

// Type is command error type.
type Type int32

const (
	// ValidationError is error type for command validation errors.
	ValidationError Type = iota

	// ExecuteError is error type for command execution failure.
	ExecuteError Type = iota
)

// Code is the error code of command errors.
type Code int32

const (
	// UnknownStatus default error code for unknown errors.
	UnknownStatus Code = iota
)

// Group is the error groups.
// Note: recommended to use [0-9]*000 pattern for any new entries
// Example: 2000, 3000, 4000 ...... 25000.
type Group int32

// TODO command types shouldn't be mentioned in common error package, [Issue#1182].
const (
	// Common error group for general command errors.
	Common Group = 1000

	// DIDExchange error group for DID exchange command errors.
	DIDExchange Group = 2000

	// Messaging error group for messaging service errors.
	Messaging Group = 3000

	// VDR error group for VDR command errors.
	VDR Group = 4000

	// ROUTE error group for Route command errors.
	ROUTE Group = 5000

	// VC error group for Verifiable Credential command errors.
	VC Group = 6000

	// KMS error group for key management service errors.
	KMS Group = 7000

	// IssueCredential error group for issue credential command errors.
	IssueCredential = 8000

	// PresentProof error group for present proof command errors.
	PresentProof = 9000

	// Introduce error group for introduce command errors.
	Introduce = 10000

	// Outofband error group for outofband command errors.
	Outofband = 11000

	// OutofbandV2 error group for outofband command errors.
	OutofbandV2 = 11100

	// VCWallet error group for verifiable Credential wallet command errors.
	VCWallet = 12000

	// RFC0593 error group for RFC0593 command errors.
	RFC0593 = 13000

	// LD error group for JSON-LD command errors.
	LD = 14000

	// Connection error group for connection management errors.
	Connection = 15000
)

// Error is the  interface for representing an command error condition, with the nil value representing no error.
type Error interface {
	error
	// Code returns error code for this command error.
	Code() Code
	// Type returns error type for this command error.
	Type() Type
}

// NewValidationError returns new command validation error.
func NewValidationError(code Code, err error) Error {
	return &commandError{err, code, ValidationError}
}

// NewExecuteError returns new command execute error.
func NewExecuteError(code Code, err error) Error {
	return &commandError{err, code, ExecuteError}
}

// commandError implements basic command Error.
type commandError struct {
	error
	code    Code
	errType Type
}

func (c *commandError) Code() Code {
	return c.code
}

func (c *commandError) Type() Type {
	return c.errType
}
