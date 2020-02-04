/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import wasmJS from "./wasm_exec.js"
import wasm from "./aries-js-worker.wasm"
import workerJS from "./worker-impl-web"

export function _getWorker(pending) {
    const worker = new Worker(workerJS + "?wasmJS=" + wasmJS + "&wasm=" + wasm + ".gz")
    worker.onmessage = e => {
        const result = e.data
        const cb = pending.get(result.id)
        pending.delete(result.id)
        cb(result)
    }
    worker.onerror = e => {
        throw new Error(e.message)
    }
    return worker
}
