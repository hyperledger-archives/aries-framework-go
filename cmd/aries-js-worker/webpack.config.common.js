/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

const path = require('path');

const srcDir = path.join(__dirname, "src/")
const buildDir = path.join(__dirname, "dist/")
const assetsDir = path.join(buildDir, "assets/")

const PATHS = {
    srcDir: srcDir,
    buildDir: buildDir,
    assetsDir: assetsDir
}

module.exports.PATHS = PATHS
