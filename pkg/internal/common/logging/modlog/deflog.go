/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modlog

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/internal/common/logging/metadata"

	"github.com/hyperledger/aries-framework-go/pkg/common/logging/api"
)

const (
	logLevelFormatter   = "UTC %s-> %s "
	logPrefixFormatter  = " [%s] "
	callerInfoFormatter = "- %s "
)

//defLog is a standard default logger implementation
type defLog struct {
	logger *log.Logger
	module string
}

//Fatalf is CRITICAL log formatted followed by a call to os.Exit(1).
func (l *defLog) Fatalf(format string, args ...interface{}) {
	opts := getLoggerOpts(l.module, api.CRITICAL)
	l.logf(opts, api.CRITICAL, format, args...)
	os.Exit(1)
}

//Panicf is CRITICAL log formatted followed by a call to panic()
func (l *defLog) Panicf(format string, args ...interface{}) {
	opts := getLoggerOpts(l.module, api.CRITICAL)
	l.logf(opts, api.CRITICAL, format, args...)
	panic(fmt.Sprintf(format, args...))
}

//Debugf calls go 'log.Output' and can be used for logging verbose messages.
// Arguments are handled in the manner of fmt.Printf.
func (l *defLog) Debugf(format string, args ...interface{}) {
	opts := getLoggerOpts(l.module, api.DEBUG)
	if !opts.levelEnabled {
		return
	}
	l.logf(opts, api.DEBUG, format, args...)
}

//Infof calls go 'log.Output' and can be used for logging general information messages.
//INFO is default logging level
// Arguments are handled in the manner of fmt.Printf.
func (l *defLog) Infof(format string, args ...interface{}) {
	opts := getLoggerOpts(l.module, api.INFO)
	if !opts.levelEnabled {
		return
	}
	l.logf(opts, api.INFO, format, args...)
}

// Warnf calls go log.Output and can be used for logging possible errors.
// Arguments are handled in the manner of fmt.Printf.
func (l *defLog) Warnf(format string, args ...interface{}) {
	opts := getLoggerOpts(l.module, api.WARNING)
	if !opts.levelEnabled {
		return
	}
	l.logf(opts, api.WARNING, format, args...)
}

// Errorf calls go 'log.Output' and can be used for logging errors.
// Arguments are handled in the manner of fmt.Printf.
func (l *defLog) Errorf(format string, args ...interface{}) {
	opts := getLoggerOpts(l.module, api.ERROR)
	if !opts.levelEnabled {
		return
	}
	l.logf(opts, api.ERROR, format, args...)
}

//ChangeOutput for changing output destination for the logger.
func (l *defLog) ChangeOutput(output io.Writer) {
	l.logger.SetOutput(output)
}

func (l *defLog) logf(opts *loggerOpts, level api.Level, format string, args ...interface{}) {
	//Format prefix to show function name and log level and to indicate that timezone used is UTC
	customPrefix := fmt.Sprintf(logLevelFormatter, l.getCallerInfo(opts), metadata.ParseString(level))
	err := l.logger.Output(2, customPrefix+fmt.Sprintf(format, args...))
	if err != nil {
		fmt.Printf("error from logger.Output %v\n", err)
	}
}

func (l *defLog) getCallerInfo(opts *loggerOpts) string {

	if !opts.callerInfoEnabled {
		return ""
	}

	const MAXCALLERS = 6  // search MAXCALLERS frames for the real caller
	const SKIPCALLERS = 4 // skip SKIPCALLERS frames when determining the real caller
	const NOTFOUND = "n/a"
	const DEFAULTLOGPREFIX = "logging.(*Logger)"

	fpcs := make([]uintptr, MAXCALLERS)

	n := runtime.Callers(SKIPCALLERS, fpcs)
	if n == 0 {
		return fmt.Sprintf(callerInfoFormatter, NOTFOUND)
	}

	frames := runtime.CallersFrames(fpcs[:n])
	funcIsNext := false

	for f, more := frames.Next(); more; f, more = frames.Next() {
		_, fnName := filepath.Split(f.Function)

		if f.Func == nil || f.Function == "" {
			fnName = NOTFOUND // not a function or unknown
		}

		if funcIsNext {
			return fmt.Sprintf(callerInfoFormatter, fnName)
		}

		if strings.HasPrefix(fnName, DEFAULTLOGPREFIX) {
			funcIsNext = true
			continue
		}

		return fmt.Sprintf(callerInfoFormatter, fnName)
	}

	return fmt.Sprintf(callerInfoFormatter, NOTFOUND)
}
