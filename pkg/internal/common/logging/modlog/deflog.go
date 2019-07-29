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

	logapi "github.com/hyperledger/aries-framework-go/pkg/common/log"
)

const (
	logLevelFormatter   = "UTC %s-> %s "
	logPrefixFormatter  = " [%s] "
	callerInfoFormatter = "- %s "
)

// defLog is a logger implementation built on top of standard go log.
// There is a  configurable caller info feature which displays caller function information name in logged lines.
// caller info can be configured by log levels and modules. By default it is enabled.
// Log Format : [<MODULE NAME>] <TIME IN UTC> - <CALLER INFO> -> <LOG LEVEL> <LOG TEXT>
type defLog struct {
	logger *log.Logger
	module string
}

//Fatalf is CRITICAL log formatted followed by a call to os.Exit(1).
func (l *defLog) Fatalf(format string, args ...interface{}) {
	l.logf(logapi.CRITICAL, format, args...)
	os.Exit(1)
}

//Panicf is CRITICAL log formatted followed by a call to panic()
func (l *defLog) Panicf(format string, args ...interface{}) {
	l.logf(logapi.CRITICAL, format, args...)
	panic(fmt.Sprintf(format, args...))
}

//Debugf calls go 'log.Output' and can be used for logging verbose messages.
// Arguments are handled in the manner of fmt.Printf.
func (l *defLog) Debugf(format string, args ...interface{}) {
	l.logf(logapi.DEBUG, format, args...)
}

//Infof calls go 'log.Output' and can be used for logging general information messages.
//INFO is default logging level
// Arguments are handled in the manner of fmt.Printf.
func (l *defLog) Infof(format string, args ...interface{}) {
	l.logf(logapi.INFO, format, args...)
}

// Warnf calls go log.Output and can be used for logging possible errors.
// Arguments are handled in the manner of fmt.Printf.
func (l *defLog) Warnf(format string, args ...interface{}) {
	l.logf(logapi.WARNING, format, args...)
}

// Errorf calls go 'log.Output' and can be used for logging errors.
// Arguments are handled in the manner of fmt.Printf.
func (l *defLog) Errorf(format string, args ...interface{}) {
	l.logf(logapi.ERROR, format, args...)
}

//SetOutput sets the output destination for the logger.
func (l *defLog) SetOutput(output io.Writer) {
	l.logger.SetOutput(output)
}

func (l *defLog) logf(level logapi.Level, format string, args ...interface{}) {
	//Format prefix to show function name and log level and to indicate that timezone used is UTC
	customPrefix := fmt.Sprintf(logLevelFormatter, l.getCallerInfo(level), metadata.ParseString(level))
	err := l.logger.Output(2, customPrefix+fmt.Sprintf(format, args...))
	if err != nil {
		fmt.Printf("error from logger.Output %v\n", err)
	}
}

//getCallerInfo going through runtime caller frames to determine the caller of logger function by filtering
// internal logging library functions
func (l *defLog) getCallerInfo(level logapi.Level) string {
	if !metadata.IsCallerInfoEnabled(l.module, level) {
		return ""
	}

	// search MAXCALLERS caller frames for the real caller,
	// MAXCALLERS defines maximum number of caller frames needed to be recorded to find the actual caller frame
	const MAXCALLERS = 6
	// skip SKIPCALLERS frames when determining the real caller
	// SKIPCALLERS is the number of stack frames to skip before recording caller frames,
	// this is mainly used to filter logger library functions in caller frames
	const SKIPCALLERS = 5

	const NOTFOUND = "n/a"
	const DEFAULTLOGPREFIX = "logging.(*Logger)"

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
