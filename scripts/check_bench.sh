#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

echo "Running $0. This benchmark is not absolute. Add code benchmarks in the framework, then execute it with the same environment setup prior and after a change to compare perf differences."

go test -run=^$ -bench=. ./...
