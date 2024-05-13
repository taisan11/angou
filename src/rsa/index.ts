export function genKeyRss() {
    return crypto.subtle.generateKey(
        {
            name: "RSA-PSS",
            modulusLength: 2048, //can be 1024, 2048, or 4096
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: {name: "SHA-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
        },
        false, //whether the key is extractable (i.e. can be used in exportKey)
        ["sign", "verify"] //can be any combination of "sign" and "verify"
    )
}
export function exportKeyRss(key: CryptoKey) {
    return crypto.subtle.exportKey("jwk", key)
}
export function importKeyRss(key: JsonWebKey) {
    return crypto.subtle.importKey("jwk", key, {name: "RSA-PSS", hash: {name: "SHA-256"}}, true, ["verify"])
}
export function signRss(key: CryptoKey, data: ArrayBuffer) {
    return crypto.subtle.sign("RSA-PSS", key, data)
}
export function verifyRss(key: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer) {
    return crypto.subtle.verify("RSA-PSS", key, signature, data)
}