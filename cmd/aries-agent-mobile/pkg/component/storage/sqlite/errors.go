/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sqlite

import (
	"errors"
)

const (
	// Error messages we return.
	failureWhileOpeningSQLiteConnectionErrMsg  = "failure while opening SQLite connection using path %s: %w"
	failureWhileClosingSQLiteConnection        = "failure while closing SQLite DB connection: %w"
	failureWhilePingingSQLiteErrMsg            = "failure while pinging SQLite at path %s : %w"
	failureWhileCreatingTableErrMsg            = "failure while creating table %s: %w"
	failureWhileExecutingInsertStatementErrMsg = "failure while executing insert statement on table %s: %w"
	failureWhileQueryingRowErrMsg              = "failure while querying row: %w"
	failureWhileExecutingBatchStatementErrMsg  = "failure while executing batch upsert on table %s: %w"
	// Error messages returned from MySQL that we directly check for.
	valueNotFoundErrMsgFromSQlite = "no rows"
)

var (
	errBlankDBPath    = errors.New("DB Path for new SQLite DB provider can't be blank")
	errBlankStoreName = errors.New("store name is required")
)
