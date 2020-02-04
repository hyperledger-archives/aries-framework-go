/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

const { Worker } = require('worker_threads')

import wasmJS from "./wasm_exec.js"
import wasm from "./aries-js-worker.wasm"
import workerJS from "./worker-impl-node"

export function _getWorker(pending) {
    const worker = new Worker(workerJS, { workerData: {wasmJS: wasmJS, wasmPath: wasm} })
    worker.on("message", result => {
        const cb = pending.get(result.id)
        pending.delete(result.id)
        cb(result)
    })
    return worker
}
