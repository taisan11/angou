export function genKeyRss(): Promise<CryptoKeyPair> {
    return crypto.subtle.generateKey(
        {
            name: "RSA-PSS",
            modulusLength: 2048, //can be 1024, 2048, or 4096
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: {name: "SHA-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
        },
        false, //whether the key is extractable (i.e. can be used in exportKey)
        ["sign", "verify"] //can be any combination of "sign" and "verify"
    ) as Promise<CryptoKeyPair>;
}

export function exportKeyRss(key: CryptoKey): Promise<JsonWebKey> {
    return crypto.subtle.exportKey("jwk", key) as Promise<JsonWebKey>;
}

export function importKeyRss(key: JsonWebKey): Promise<CryptoKey> {
    return crypto.subtle.importKey("jwk", key, {name: "RSA-PSS", hash: {name: "SHA-256"}}, true, ["verify"]) as Promise<CryptoKey>;
}

export function signRss(key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return crypto.subtle.sign("RSA-PSS", key, data) as Promise<ArrayBuffer>;
}

export function verifyRss(key: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    return crypto.subtle.verify("RSA-PSS", key, signature, data) as Promise<boolean>;
}