/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metadata

import (
	"github.com/hyperledger/aries-framework-go/spi/log"
)

const (
	defaultLogLevel   = log.INFO
	defaultModuleName = ""
)

func newModuledLevels() *moduleLevels {
	return &moduleLevels{levels: make(map[string]log.Level)}
}

// moduleLevels maintains log levels based on modules.
type moduleLevels struct {
	levels map[string]log.Level
}

// GetLevel returns the log level for given module and level.
func (l *moduleLevels) GetLevel(module string) log.Level {
	level, exists := l.levels[module]
	if !exists {
		level, exists = l.levels[defaultModuleName]
		// no configuration exists, default to info
		if !exists {
			return defaultLogLevel
		}
	}

	return level
}

// SetLevel sets the log level for given module and level.
func (l *moduleLevels) SetLevel(module string, level log.Level) {
	l.levels[module] = level
}

// IsEnabledFor will return true if logging is enabled for given module and level.
func (l *moduleLevels) IsEnabledFor(module string, level log.Level) bool {
	return level <= l.GetLevel(module)
}
