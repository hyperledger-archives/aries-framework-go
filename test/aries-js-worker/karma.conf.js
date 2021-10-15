/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

module.exports = function (config) {
    config.set({
        frameworks: ["mocha", "chai"],
        browsers: ["ChromeHeadless_cors"],
        singleRun: true,
        files: [
            { pattern: "public/aries-framework-go/assets/*", included: false },
            {
                pattern:
                    "node_modules/@hyperledger/aries-framework-go/dist/web/*",
                type: "module",
            },
            {
                pattern:
                    "node_modules/@hyperledger/aries-framework-go/dist/rest/*",
                type: "module",
            },
            {
                pattern: "node_modules/axios/dist/axios.min.map",
                included: false,
            },
            "node_modules/axios/dist/axios.min.js",
            {
                pattern: "node_modules/base64-js/base64js.min.js",
                included: false,
            },
            {
                pattern: "node_modules/base-58/Base58.js",
                included: false,
            },
            { pattern: "test/common.js", included: false },
            { pattern: "test/environment.js", included: false },
            { pattern: "test/**/*.js", type: "module" },
        ],
        reporters: ["spec"],
        customLaunchers: {
            ChromeHeadless_cors: {
                base: "ChromeHeadless",
                flags: ["--disable-web-security"],
            },
            Chrome_without_security: {
                base: "Chrome",
                flags: [
                    "--disable-web-security",
                    "--disable-site-isolation-trials",
                    "--auto-open-devtools-for-tabs",
                ],
            },
        },
        client: {
            mocha: {
                timeout: 20000,
            },
        },
    });
};
