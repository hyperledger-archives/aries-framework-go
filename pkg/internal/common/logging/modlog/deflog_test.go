/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modlog

import (
	"fmt"
	"log"
	"testing"
)

func TestDefLog(t *testing.T) {
	const module = "sample-module"
	logger := &defLog{logger: log.New(&buf, fmt.Sprintf(logPrefixFormatter, module), log.Ldate|log.Ltime|log.LUTC), module: module}

	VerifyDefaultLogging(t, logger, module, SetLevel)
}
