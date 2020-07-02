/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

export function loadWorker(pending, notifications, paths) {
    const workerJS = paths.dir + "/worker-impl-rest.js"
    const worker = new Worker(workerJS)
    worker.onmessage = e => {
        const result = e.data
        if (result.topic){
            let subscribers = notifications.get(result.topic)
            if (subscribers === undefined) {
                subscribers = notifications.get("all")
            }
            if (subscribers === undefined || subscribers.size === 0) {
                console.log("no subscribers found for this topic", result.topic)
                return
            }
            subscribers.forEach((fn) => {
                fn(result)
            })

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
