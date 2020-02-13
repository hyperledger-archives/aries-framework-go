/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import wasmJS from "./wasm_exec.js"
import wasm from "./aries-js-worker.wasm.gz"
import workerJS from "./worker-impl-web"

export function _getWorker(pending, notifications) {
    const worker = new Worker(workerJS + "?wasmJS=" + wasmJS + "&wasm=" + wasm)
    worker.onmessage = e => {
        const result = e.data
        if (result.topic ){
            if (notifications.get(result.topic)) {
                notifications.get(result.topic)(result)
            }  else if (notifications.get("all")){
                notifications.get("all")(result)
            } else {
                console.log("no subscribers found for this topic", result.topic)
            }
          return
        }
        const cb = pending.get(result.id)
        pending.delete(result.id)
        cb(result)
    }
    worker.onerror = e => {
        throw new Error("aries: failed to load worker: " + e.message)
    }
    return worker
}
