/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modlog

import (
	"sync"

	"github.com/hyperledger/aries-framework-go/pkg/internal/common/logging/metadata"

	"github.com/hyperledger/aries-framework-go/pkg/common/logging/api"
)

var rwmutex = &sync.RWMutex{}
var moduleLevels = &metadata.ModuleLevels{}
var callerInfos = &metadata.CallerInfo{}

//loggerOpts  for all logger customization options
type loggerOpts struct {
	levelEnabled      bool
	callerInfoEnabled bool
}

//SetLevel - setting log level for given module
func SetLevel(module string, level api.Level) {
	rwmutex.Lock()
	defer rwmutex.Unlock()
	moduleLevels.SetLevel(module, level)
}

//GetLevel - getting log level for given module
func GetLevel(module string) api.Level {
	rwmutex.RLock()
	defer rwmutex.RUnlock()
	return moduleLevels.GetLevel(module)
}

//IsEnabledFor - Check if given log level is enabled for given module
func IsEnabledFor(module string, level api.Level) bool {
	rwmutex.RLock()
	defer rwmutex.RUnlock()
	return moduleLevels.IsEnabledFor(module, level)
}

//ShowCallerInfo - Show caller info in log lines for given log level and module
func ShowCallerInfo(module string, level api.Level) {
	rwmutex.Lock()
	defer rwmutex.Unlock()
	callerInfos.ShowCallerInfo(module, level)
}

//HideCallerInfo - Do not show caller info in log lines for given log level and module
func HideCallerInfo(module string, level api.Level) {
	rwmutex.Lock()
	defer rwmutex.Unlock()
	callerInfos.HideCallerInfo(module, level)
}

//IsCallerInfoEnabled - returns if caller info enabled for given log level and module
func IsCallerInfoEnabled(module string, level api.Level) bool {
	rwmutex.Lock()
	defer rwmutex.Unlock()
	return callerInfos.IsCallerInfoEnabled(module, level)
}

//getLoggerOpts - returns LoggerOpts which can be used for customization
func getLoggerOpts(module string, level api.Level) *loggerOpts {
	rwmutex.RLock()
	defer rwmutex.RUnlock()
	return &loggerOpts{
		levelEnabled:      moduleLevels.IsEnabledFor(module, level),
		callerInfoEnabled: callerInfos.IsCallerInfoEnabled(module, level),
	}
}
