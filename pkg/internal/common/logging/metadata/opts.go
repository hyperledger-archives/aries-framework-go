/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metadata

import (
	"sync"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
)

var rwmutex = &sync.RWMutex{}
var levels = newModuledLevels()
var callerInfos = newCallerInfo()

//LoggerOpts for all logger customization options
type LoggerOpts struct {
	LevelEnabled      bool
	CallerInfoEnabled bool
}

//SetLevel - setting log level for given module
func SetLevel(module string, level log.Level) {
	rwmutex.Lock()
	defer rwmutex.Unlock()
	levels.SetLevel(module, level)
}

//GetLevel - getting log level for given module
func GetLevel(module string) log.Level {
	rwmutex.RLock()
	defer rwmutex.RUnlock()
	return levels.GetLevel(module)
}

//IsEnabledFor - Check if given log level is enabled for given module
func IsEnabledFor(module string, level log.Level) bool {
	rwmutex.RLock()
	defer rwmutex.RUnlock()
	return levels.IsEnabledFor(module, level)
}

//ShowCallerInfo - Show caller info in log lines for given log level and module
func ShowCallerInfo(module string, level log.Level) {
	rwmutex.Lock()
	defer rwmutex.Unlock()
	callerInfos.ShowCallerInfo(module, level)
}

//HideCallerInfo - Do not show caller info in log lines for given log level and module
func HideCallerInfo(module string, level log.Level) {
	rwmutex.Lock()
	defer rwmutex.Unlock()
	callerInfos.HideCallerInfo(module, level)
}

//IsCallerInfoEnabled - returns if caller info enabled for given log level and module
func IsCallerInfoEnabled(module string, level log.Level) bool {
	rwmutex.Lock()
	defer rwmutex.Unlock()
	return callerInfos.IsCallerInfoEnabled(module, level)
}

//GetLoggerOpts - returns LoggerOpts which can be used for customization
func GetLoggerOpts(module string, level log.Level) *LoggerOpts {
	rwmutex.RLock()
	defer rwmutex.RUnlock()
	return &LoggerOpts{
		LevelEnabled:      levels.IsEnabledFor(module, level),
		CallerInfoEnabled: callerInfos.IsCallerInfoEnabled(module, level),
	}
}
