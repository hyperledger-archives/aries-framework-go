/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

const path = require("path")

const { CleanWebpackPlugin } = require('clean-webpack-plugin')
const WebpackShellPlugin = require('webpack-shell-plugin')
const CompressionPlugin = require("compression-webpack-plugin")

const { PATHS } = require("./webpack.config.common.js")

const OUTPUT = path.join(PATHS.buildDir, "web/")

module.exports = {
    entry: path.join(PATHS.srcDir, "aries.js"),
    target: 'web',
    output: {
        path: OUTPUT,
        publicPath: OUTPUT,
        libraryTarget: "assign",
        filename: 'aries.js',
        // TODO fix client usage: currently have to call like this: Aries.Aries.<pkg>.<fn>
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
                test: /worker-impl-web\.js/,
                loader: "file-loader",
                options: {
                    name: "[name].[ext]",
                    publicPath: "dist/web/"
                }
            },
            {
                test: /wasm_exec.js/,
                loader: "file-loader",
                options: {
                    name: "[name].[ext]"
                }
            },
            {
                type: "javascript/auto",
                test: /aries-js-worker.wasm/,
                loader: "file-loader",
                options: {
                    name: "[name].[ext]"
                }
            }
        ]
    },
    resolve: {
        alias: {
            worker_loader$: path.join(PATHS.srcDir, "worker-loader-web.js")
        }
    }
}
