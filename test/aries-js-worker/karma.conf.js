/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

const fs = require("fs")
const exec = require('child_process');


process.env.CHROME_BIN = require('puppeteer').executablePath()
const ENV_CONFIG = "fixtures/.env";
const ENV_CONFIG_OUT = "test/environment.js";

(async () => {
    require("dotenv").config({path: ENV_CONFIG})
    const util = require("util")
    const config = {}
    for (const attr in process.env) {
        if (attr.startsWith("E2E_")) {
            config[attr.replace("E2E_", "")] = process.env[attr]
        }
        if (attr.startsWith("HTTP_")) {
            config[attr] = process.env[attr]
        }
    }

    let didID=await createDID()
    console.log(didID)
    config["DID_ID"] = didID.trim()

    fs.writeFileSync(ENV_CONFIG_OUT, "export const environment = " + util.inspect(config))
})()

function createDID() {
    return new Promise((resolve, reject) => {
        exec.exec('../../build/bin/sidetree http://localhost:48326/sidetree/0.0.1/operations key1 axETCKcguKigxZiJIPtgotDbVe72AIXRTbF2MRpZIk0 http://www.example.com', (err, stdout, stderr) => {
            let v
            if (err) {
                //some err occurred
                console.error(err)
            } else {
                v=stdout
            }
            resolve(v);
        });
    });
}

module.exports = function(config) {
    config.set({
        frameworks: ["mocha", "chai"],
        browsers: ["ChromeHeadless_cors"],
        singleRun: true,
        captureConsole: true,
        files: [
            {pattern: "public/aries-framework-go/assets/*", included: false},
            {pattern: "node_modules/@hyperledger/aries-framework-go/dist/web/*", type: "module"},
            {pattern: "node_modules/@hyperledger/aries-framework-go/dist/rest/*", type: "module"},
            {pattern: 'node_modules/axios/dist/axios.min.map', included: false},
            "node_modules/axios/dist/axios.min.js",
            {pattern: "test/common.js", included: false},
            {pattern: "test/environment.js", included: false},
            {pattern: "test/**/*.js", type: "module"}
        ],
        reporters: ["spec"],
        customLaunchers: {
            ChromeHeadless_cors: {
                base: "ChromeHeadless",
                flags: ["--disable-web-security"]
            },
            Chrome_without_security: {
                 base: 'Chrome',
                 flags: ['--disable-web-security', '--disable-site-isolation-trials', '--auto-open-devtools-for-tabs']
             },
        },
        client: {
            mocha: {
                timeout : 15000
            }
        }
    })
}
