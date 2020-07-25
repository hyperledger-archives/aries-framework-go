/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metadata

// Level defines all available log levels for logging messages.
type Level int

// Log levels.
// note: below constants are copy of 'log.Level' constants added to avoid circular references,
// care should be taken before changing below constants including their order.
// For any updates in level constants below, corresponding changes has to be done for constants in 'log.Level'.
const (
	CRITICAL Level = iota
	ERROR
	WARNING
	INFO // default logging level
	DEBUG
)

const (
	defaultLogLevel   = INFO
	defaultModuleName = ""
)

func newModuledLevels() *moduleLevels {
	return &moduleLevels{levels: make(map[string]Level)}
}

// moduleLevels maintains log levels based on modules.
type moduleLevels struct {
	levels map[string]Level
}

// GetLevel returns the log level for given module and level.
func (l *moduleLevels) GetLevel(module string) Level {
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
func (l *moduleLevels) SetLevel(module string, level Level) {
	l.levels[module] = level
}

// IsEnabledFor will return true if logging is enabled for given module and level.
func (l *moduleLevels) IsEnabledFor(module string, level Level) bool {
	return level <= l.GetLevel(module)
}
