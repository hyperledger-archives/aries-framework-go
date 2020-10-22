/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package aries-agent-rest (Aries Agent REST Server) of aries-framework-go.
//
//
// Terms Of Service:
//
//
//     Schemes: https
//     Version: 0.1.0
//     License: SPDX-License-Identifier: Apache-2.0
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
// swagger:meta
package main

import (
	"github.com/spf13/cobra"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-rest/startcmd"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
)

// This is an application which starts Aries agent controller API on given port.
func main() {
	rootCmd := &cobra.Command{
		Use: "aries-agent-rest",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	logger := log.New("aries-framework/agent-rest")

	startCmd, err := startcmd.Cmd(&startcmd.HTTPServer{})
	if err != nil {
		logger.Fatalf(err.Error())
	}

	rootCmd.AddCommand(startCmd)

	if err := rootCmd.Execute(); err != nil {
		logger.Fatalf("Failed to run aries-agent-rest: %s", err)
	}
}
