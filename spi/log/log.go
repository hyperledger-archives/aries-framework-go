/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

// Level is a log level for a logging message.
type Level int

// Log levels.
const (
	CRITICAL Level = iota
	ERROR
	WARNING
	INFO
	DEBUG
)

// Logger represents a general-purpose logger.
type Logger interface {
	Panicf(msg string, args ...interface{})
	Fatalf(msg string, args ...interface{})
	Errorf(msg string, args ...interface{})
	Warnf(msg string, args ...interface{})
	Infof(msg string, args ...interface{})
	Debugf(msg string, args ...interface{})
}

// LoggerProvider is a factory for moduled loggers.
type LoggerProvider interface {
	GetLogger(module string) Logger
}
