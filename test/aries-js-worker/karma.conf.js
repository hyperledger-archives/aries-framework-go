/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

const fs = require("fs")

process.env.CHROME_BIN = require('puppeteer').executablePath()
const ENV_CONFIG = "fixtures/.env";
const ENV_CONFIG_OUT = "test/environment.js";

(() => {
    require("dotenv").config({path: ENV_CONFIG})
    const util = require("util")
    const config = {}
    for (const attr in process.env) {
        if (attr.startsWith("E2E_")) {
            config[attr.replace("E2E_", "")] = process.env[attr]
        }
    }
    fs.writeFileSync(ENV_CONFIG_OUT, "export const environment = " + util.inspect(config))
})()

module.exports = function(config) {
    config.set({
        frameworks: ["mocha", "chai"],
        browsers: ["ChromeHeadless_cors"],
        singleRun: true,
        captureConsole: true,
        files: [
            {pattern: "test/**/*.js", type: "module"},
            {pattern: "public/aries-framework-go/assets/*", included: false},
            {pattern: "node_modules/@hyperledger/aries-framework-go/dist/web/*", type: "module"},
            {pattern: "node_modules/@hyperledger/aries-framework-go/dist/rest/*", type: "module"},
            "node_modules/axios/dist/axios.min.js",
            {pattern: "test/common.js", included: false},
            {pattern: "test/environment.js", included: false},
        ],
        reporters: ["spec"],
        customLaunchers: {
            ChromeHeadless_cors: {
                base: "ChromeHeadless",
                flags: ["--disable-web-security"]
            }
        },
        client: {
            mocha: {
                timeout : 15000
            }
        }
    })
}