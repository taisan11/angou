import * as rsa from '../src/rsa/index'

async function test() {
    const keys = await rsa.genKeyRss()
    console.log(keys)
    const exportKey = await rsa.exportKeyRss(keys.publicKey)
    console.log(exportKey)
    const importKey = await rsa.importKeyRss(exportKey)
    console.log(importKey)
    const data = new TextEncoder().encode('Hello, RSA!')
    const signature = await rsa.signRss(keys.privateKey, data) // Convert Uint8Array to ArrayBuffer
    console.log(signature)
    const verify = await rsa.verifyRss(keys.publicKey, signature, data) // Convert Uint8Array to ArrayBuffer
    console.log(verify)
}

test()