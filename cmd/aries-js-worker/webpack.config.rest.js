/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

const path = require("path")

const { CleanWebpackPlugin } = require('clean-webpack-plugin')
const WebpackShellPlugin = require('webpack-shell-plugin')

const { PATHS } = require("./webpack.config.common.js")

const OUTPUT = path.join(PATHS.buildDir, "rest/")

const restConfig = {
    entry: path.join(PATHS.srcDir, "aries.js"),
    target: 'web',
    output: {
        path: OUTPUT,
        publicPath: "dist/rest",
        libraryTarget: "umd",
        filename: 'aries.js',
        library: 'Aries'
    },
    plugins: [
        new CleanWebpackPlugin(),
        new WebpackShellPlugin({
            onBuildStart: [
                "mkdir -p " + OUTPUT,
                "cp -p src/worker-impl-rest.js dist/assets"
            ]
        })
    ],
    resolve: {
        alias: {
            worker_loader$: path.join(PATHS.srcDir, "worker-loader-rest.js"),
        },
        mainFields: ['browser', 'module', 'main']
    }
}

const assetConfig = {
    entry: path.join(PATHS.srcDir, "agent-rest-client.js"),
    target: 'webworker',
    output: {
        path: path.resolve(PATHS.buildDir, 'assets'),
        publicPath: "dist/assets",
        filename: 'agent-rest-client.js',
        library: "RESTAgent"
    },
}

module.exports = [ restConfig, assetConfig ];
