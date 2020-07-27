/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modlog

// Logger - Standard logger interface.
type Logger interface {

	// Fatalf is critical fatal logging, should possibly followed by a call to os.Exit(1)
	Fatalf(msg string, args ...interface{})

	// Panicf is critical logging, should possibly followed by panic
	Panicf(msg string, args ...interface{})

	// Debugf is for logging verbose messages
	Debugf(msg string, args ...interface{})

	// Infof for logging general logging messages
	Infof(msg string, args ...interface{})

	// Warnf is for logging messages about possible issues
	Warnf(msg string, args ...interface{})

	// Errorf is for logging errors
	Errorf(msg string, args ...interface{})
}
