/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

self.importScripts("wasm_exec.js")

if (!WebAssembly.instantiateStreaming) { // polyfill
    WebAssembly.instantiateStreaming = async (resp, importObject) => {
        const source = await (await resp).arrayBuffer();
        return await WebAssembly.instantiate(source, importObject);
    };
}

const go = new Go();
WebAssembly.instantiateStreaming(fetch("aries-js-worker.wasm"), go.importObject).then(
    (result) => { go.run(result.instance); }
);

handleResult = function(r) {
    postMessage(JSON.parse(r))
}

onmessage = function(m) {
    handleMsg(JSON.stringify(m.data))
}
