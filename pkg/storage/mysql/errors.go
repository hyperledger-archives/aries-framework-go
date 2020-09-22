/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package mysql

import "errors"

const (
	// Error messages we return.
	failureWhileOpeningMySQLConnectionErrMsg   = "failure while opening MySQL connection using url %s: %w"
	failureWhileClosingMySQLConnection         = "failure while closing MySQL DB connection: %w"
	failureWhilePingingMySQLErrMsg             = "failure while pinging MySQL at url %s : %w"
	failureWhileCreatingDBErrMsg               = "failure while creating DB %s: %w"
	failureWhileCreatingTableErrMsg            = "failure while creating table %s: %w"
	failureWhileExecutingInsertStatementErrMsg = "failure while executing insert statement on table %s: %w"
	failureWhileQueryingRowErrMsg              = "failure while querying row: %w"
	// Error messages returned from MySQL that we directly check for.
	valueNotFoundErrMsgFromMySQL = "no rows"
)

var (
	errBlankDBPath    = errors.New("DB URL for new mySQL DB provider can't be blank")
	errBlankStoreName = errors.New("store name is required")
)
