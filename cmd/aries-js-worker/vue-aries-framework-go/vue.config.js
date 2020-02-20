/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

const CopyPlugin = require("copy-webpack-plugin")

module.exports = {
    chainWebpack: config => config.resolve.symlinks(false),
    configureWebpack: {
        plugins: [
            new CopyPlugin([{
                from: "node_modules/@hyperledger/aries-framework-go/dist/**/*",
                to: "public/aries-framework-go/",
                transformPath(targetPath, absolutePath) {
                    return Promise.resolve("public/" + targetPath.substr(targetPath.lastIndexOf("aries-framework-go")));
                }
            }])
        ]
    }
}
