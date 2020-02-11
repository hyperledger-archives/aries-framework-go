/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

const path = require("path")

const { CleanWebpackPlugin } = require('clean-webpack-plugin')
const WebpackShellPlugin = require('webpack-shell-plugin')

const { PATHS } = require("./webpack.config.common.js")

const OUTPUT = path.join(PATHS.buildDir, "node/")

module.exports = {
    entry: path.join(PATHS.srcDir, "aries.js"),
    target: 'node',
    output: {
        path: OUTPUT,
        publicPath: "dist/node/",
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
        })
    ],
    module: {
        rules: [
            {
                test: /worker-impl-node\.js/,
                loader: "file-loader",
                options: {
                    name: "[name].[ext]",
                    postTransformPublicPath: _ => `__webpack_public_path__ + "/dist/node/worker-impl-node.js"`
                }
            },
            {
                test: /wasm_exec\.js/,
                loader: "file-loader",
                options: {
                    name: "[name].[ext]",
                    emitFile: false,
                    postTransformPublicPath: _ => `__webpack_public_path__ + "/dist/assets/wasm_exec.js"`
                }
            },
            {
                type: "javascript/auto",
                test: /aries-js-worker.wasm.gz/,
                loader: "file-loader",
                options: {
                    name: "[name].[ext]",
                    emitFile: false,
                    publicPath: PATHS.assetsDir,
                    postTransformPublicPath: _ => `__webpack_public_path__ + "/dist/assets/aries-js-worker.wasm.gz"`
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
