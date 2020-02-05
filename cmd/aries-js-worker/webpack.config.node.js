/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

const path = require("path")

const { CleanWebpackPlugin } = require('clean-webpack-plugin')
const WebpackShellPlugin = require('webpack-shell-plugin')
const CompressionPlugin = require("compression-webpack-plugin")

const { PATHS } = require("./webpack.config.common.js")

const OUTPUT = path.join(PATHS.buildDir, "node/")

module.exports = {
    entry: path.join(PATHS.srcDir, "aries.js"),
    target: 'node',
    output: {
        path: OUTPUT,
        publicPath: OUTPUT,
        libraryTarget: 'umd',
        filename: 'aries.js',
        library: 'Aries'
    },
    plugins: [
        new CleanWebpackPlugin(),
        new WebpackShellPlugin({
            onBuildStart: [
                "mkdir -p " + OUTPUT
            ]
        }),
        new CompressionPlugin({
            include: /\.wasm/,
            deleteOriginalAssets: true
        })
    ],
    module: {
        rules: [
            {
                test: /worker-impl-node\.js/,
                loader: "file-loader",
                options: {
                    name: "[name].[ext]"
                }
            },
            {
                test: /wasm_exec\.js/,
                loader: "file-loader",
                options: {
                    name: "[name].[ext]"
                }
            },
            {
                type: "javascript/auto",
                test: /aries-js-worker\.wasm/,
                loader: "file-loader",
                options: {
                    name: "[name].[ext]"
                }
            }
        ]
    },
    resolve: {
        alias: {
            worker_loader$: path.join(PATHS.srcDir, "worker-loader-node.js")
        }
    },
}
