/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

const fs = require("fs");
const exec = require("child_process");
const minimist = require("minimist");

process.env.CHROME_BIN = require("puppeteer").executablePath();
const ENV_CONFIG = "fixtures/.env";
const ENV_CONFIG_OUT = "test/environment.js";

(async () => {
    require("dotenv").config({ path: ENV_CONFIG });
    const util = require("util");
    const config = {};
    for (const attr in process.env) {
        if (attr.startsWith("E2E_")) {
            config[attr.replace("E2E_", "")] = process.env[attr];
        }
        if (attr.startsWith("HTTP_")) {
            config[attr] = process.env[attr];
        }
    }

    let didID = await createDID();
    console.log(didID);
    config["DID_ID"] = didID.trim();

    let args = minimist(process.argv.slice(2), {
        default: {
            "log-level": "CRITICAL",
        },
    });

    config["LOG_LEVEL"] = args["log-level"];

    fs.writeFileSync(
        ENV_CONFIG_OUT,
        "export const environment = " + util.inspect(config)
    );
})();

function createDID() {
    return new Promise((resolve, reject) => {
        exec.exec(
            "../../build/bin/sidetree http://localhost:48326/sidetree/0.0.1/operations key1 axETCKcguKigxZiJIPtgotDbVe72AIXRTbF2MRpZIk0 http://www.example.com",
            (err, stdout, stderr) => {
                let v;
                if (err) {
                    //some err occurred
                    console.error(err);
                } else {
                    v = stdout;
                }
                resolve(v);
            }
        );
    });
}
