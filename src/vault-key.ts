import {DecryptError} from "./errors";
import {parseEnvelope, FORMAT_ENVELOPE, NONCE_LENGTH} from "./helpers/envelope";
import {RANDOM_BYTES, type RandomSource} from "./helpers/random";

const AES_GCM = (iv: Uint8Array<ArrayBuffer>): AesGcmParams => {
    return {name: "AES-GCM", iv, tagLength: 128};
}

export async function createVaultKey(): Promise<CryptoKey> { 
    return crypto.subtle.generateKey({
        name: "AES-GCM",
        length: 256
    }, true, ["encrypt", "decrypt"]);
}

export async function wrapVaultKey(
    vaultKey: CryptoKey, wrappingKey: CryptoKey, random: RandomSource = RANDOM_BYTES
): Promise<string>{
    const nonce = random(NONCE_LENGTH);
    const wrapped = await crypto.subtle.wrapKey(
        "raw",
        vaultKey,
        wrappingKey,
        AES_GCM(nonce)
    );
    return FORMAT_ENVELOPE(nonce, new Uint8Array(wrapped));
}

export async function unwrapVaultKey(wrapped: string, wrappingKey: CryptoKey): Promise<CryptoKey>{
    const {nonce, ciphertext} = parseEnvelope(wrapped);
    try{
        return await crypto.subtle.unwrapKey(
            "raw",
            ciphertext,
            wrappingKey,
            AES_GCM(nonce),
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        )
    }catch{
        throw new DecryptError();
    }
}