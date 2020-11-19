/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

exports.signAries = function signAries(privateKey, vc, verificationMethod) {
    return new Promise((resolve, reject) => {
        signVCAsync(privateKey, vc, verificationMethod, (err, vcSigned) => {
            if (err) {
                reject(err);
                return;
            }

            resolve(vcSigned);
        });
    });
}

exports.verifyAries = function verifyAries(publicKey, vc) {
    return new Promise((resolve, reject) => {
        verifyVCAsync(publicKey, vc, (err) => {
            if (err) {
                reject(err);
                return;
            }

            resolve();
        });
    });
}
