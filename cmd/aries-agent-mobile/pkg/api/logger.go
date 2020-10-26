/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

// Logger - logger interface.
type Logger interface {
	Fatal(msg string)
	Panic(msg string)
	Debug(msg string)
	Info(msg string)
	Warn(msg string)
	Error(msg string)
}

// LoggerProvider is a factory for moduled loggers.
type LoggerProvider interface {
	GetLogger(module string) Logger
}
