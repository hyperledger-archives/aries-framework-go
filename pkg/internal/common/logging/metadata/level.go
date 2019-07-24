/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metadata

import "github.com/hyperledger/aries-framework-go/pkg/common/logging/api"

const (
	defaultLogLevel   = api.INFO
	defaultModuleName = ""
)

//ModuleLevels maintains log levels based on modules
type ModuleLevels struct {
	levels map[string]api.Level
}

// GetLevel returns the log level for given module and level.
func (l *ModuleLevels) GetLevel(module string) api.Level {
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
func (l *ModuleLevels) SetLevel(module string, level api.Level) {
	if l.levels == nil {
		l.levels = make(map[string]api.Level)
	}
	l.levels[module] = level
}

// IsEnabledFor will return true if logging is enabled for given module and level.
func (l *ModuleLevels) IsEnabledFor(module string, level api.Level) bool {
	return level <= l.GetLevel(module)
}
