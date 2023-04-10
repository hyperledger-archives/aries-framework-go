/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modlog

import (
	"fmt"
	"io"
	builtinlog "log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/hyperledger/aries-framework-go/component/log/internal/metadata"
	"github.com/hyperledger/aries-framework-go/spi/log"
)

const (
	logLevelFormatter   = "UTC %s-> %s "
	logPrefixFormatter  = " [%s] "
	callerInfoFormatter = "- %s "
)

// NewDefLog returns new DefLog instance based on given module.
func NewDefLog(module string) *DefLog {
	logger := builtinlog.New(os.Stdout, fmt.Sprintf(logPrefixFormatter, module),
		builtinlog.Ldate|builtinlog.Ltime|builtinlog.LUTC)
	return &DefLog{logger: logger, module: module}
}

// DefLog is a logger implementation built on top of standard go log.
// There is a  configurable caller info feature which displays caller function information name in logged lines.
// caller info can be configured by log levels and modules. By default it is enabled.
// Log Format : [<MODULE NAME>] <TIME IN UTC> - <CALLER INFO> -> <LOG LEVEL> <LOG TEXT>.
type DefLog struct {
	logger *builtinlog.Logger
	module string
}

// Fatalf is CRITICAL log formatted followed by a call to os.Exit(1).
func (l *DefLog) Fatalf(format string, args ...interface{}) {
	l.logf(log.CRITICAL, format, args...)
	os.Exit(1)
}

// Panicf is CRITICAL log formatted followed by a call to panic().
func (l *DefLog) Panicf(format string, args ...interface{}) {
	l.logf(log.CRITICAL, format, args...)
	panic(fmt.Sprintf(format, args...))
}

// Debugf calls go 'log.Output' and can be used for logging verbose messages.
// Arguments are handled in the manner of fmt.Printf.
func (l *DefLog) Debugf(format string, args ...interface{}) {
	l.logf(log.DEBUG, format, args...)
}

// Infof calls go 'log.Output' and can be used for logging general information messages.
// INFO is default logging level
// Arguments are handled in the manner of fmt.Printf.
func (l *DefLog) Infof(format string, args ...interface{}) {
	l.logf(log.INFO, format, args...)
}

// Warnf calls go log.Output and can be used for logging possible errors.
// Arguments are handled in the manner of fmt.Printf.
func (l *DefLog) Warnf(format string, args ...interface{}) {
	l.logf(log.WARNING, format, args...)
}

// Errorf calls go 'log.Output' and can be used for logging errors.
// Arguments are handled in the manner of fmt.Printf.
func (l *DefLog) Errorf(format string, args ...interface{}) {
	l.logf(log.ERROR, format, args...)
}

// SetOutput sets the output destination for the logger.
func (l *DefLog) SetOutput(output io.Writer) {
	l.logger.SetOutput(output)
}

func (l *DefLog) logf(level log.Level, format string, args ...interface{}) {
	const callDepth = 2

	// Format prefix to show function name and log level and to indicate that timezone used is UTC
	customPrefix := fmt.Sprintf(logLevelFormatter, l.getCallerInfo(level), metadata.ParseString(level))

	err := l.logger.Output(callDepth, customPrefix+fmt.Sprintf(format, args...))
	if err != nil {
		fmt.Printf("error from logger.Output %v\n", err) //nolint:forbidigo
	}
}

// getCallerInfo going through runtime caller frames to determine the caller of logger function by filtering
// internal logging library functions.
func (l *DefLog) getCallerInfo(level log.Level) string {
	if !metadata.IsCallerInfoEnabled(l.module, level) {
		return ""
	}

	const (
		// search MAXCALLERS caller frames for the real caller,
		// MAXCALLERS defines maximum number of caller frames needed to be recorded to find the actual caller frame
		MAXCALLERS = 6
		// skip SKIPCALLERS frames when determining the real caller
		// SKIPCALLERS is the number of stack frames to skip before recording caller frames,
		// this is mainly used to filter logger library functions in caller frames
		SKIPCALLERS      = 5
		NOTFOUND         = "n/a"
		DEFAULTLOGPREFIX = "log.(*Log)"
	)

	fpcs := make([]uintptr, MAXCALLERS)

	n := runtime.Callers(SKIPCALLERS, fpcs)
	if n == 0 {
		return fmt.Sprintf(callerInfoFormatter, NOTFOUND)
	}

	frames := runtime.CallersFrames(fpcs[:n])
	loggerFrameFound := false

	for f, more := frames.Next(); more; f, more = frames.Next() {
		_, fnName := filepath.Split(f.Function)

		if f.Func == nil || f.Function == "" {
			fnName = NOTFOUND // not a function or unknown
		}

		if loggerFrameFound {
			return fmt.Sprintf(callerInfoFormatter, fnName)
		}

		if strings.HasPrefix(fnName, DEFAULTLOGPREFIX) {
			loggerFrameFound = true

			continue
		}

		return fmt.Sprintf(callerInfoFormatter, fnName)
	}

	return fmt.Sprintf(callerInfoFormatter, NOTFOUND)
}
