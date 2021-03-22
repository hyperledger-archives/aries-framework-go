/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

export function loadWorker(pending, notifications, paths) {
    const wasmJS = paths.wasmJS;
    const wasm = paths.wasm;
    const workerJS = paths.dir + "/worker-impl-web.js";
    const worker = new Worker(workerJS + "?wasmJS=" + wasmJS + "&wasm=" + wasm);
    worker.onmessage = (e) => {
        const result = e.data;

        if (result.type === "log_debug") {
            console.debug(result.msg);

            return;
        }

        if (result.type === "log_info") {
            console.info(result.msg);

            return;
        }

        if (result.type === "log_warn") {
            console.warn(result.msg);

            return;
        }

        if (result.type === "log_error") {
            console.error(result.msg);

            return;
        }

        if (result.topic) {
            let subscribers = notifications.get(result.topic);
            if (subscribers === undefined) {
                subscribers = notifications.get("all");
            }
            if (subscribers === undefined || subscribers.size === 0) {
                console.log(
                    "no subscribers found for this topic",
                    result.topic
                );
                return;
            }
            subscribers.forEach((fn) => {
                fn(result);
            });

            return;
        }
        const cb = pending.get(result.id);
        pending.delete(result.id);
        cb(result);
    };
    worker.onerror = (e) => {
        throw new Error("aries: failed to load worker: " + e.message);
    };
    return worker;
}
