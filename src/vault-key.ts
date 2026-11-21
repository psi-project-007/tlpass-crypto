import {DecryptError} from "./errors.js";
import {parseEnvelope, FORMAT_ENVELOPE, NONCE_LENGTH, AES_GCM} from "./helpers/envelope.js";
import {RANDOM_BYTES, type RandomSource} from "./helpers/random.js";

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

async function unwrapRaw(wrapped: string, wrappingKey: CryptoKey, extractable: boolean): Promise<CryptoKey>{
    const {nonce, ciphertext} = parseEnvelope(wrapped);
    try{
        return await crypto.subtle.unwrapKey(
            "raw",
            ciphertext,
            wrappingKey,
            AES_GCM(nonce),
            { name: "AES-GCM", length: 256 },
            extractable,
            ["encrypt", "decrypt"]
        );
    }catch{
        throw new DecryptError();
    }
}

export async function unwrapVaultKey(wrapped: string, wrappingKey: CryptoKey): Promise<CryptoKey>{
    return unwrapRaw(wrapped, wrappingKey, false);
}

export async function rewrapVaultKey(
    wrapped: string, oldWrappingKey: CryptoKey, newWrappingKey: CryptoKey, random: RandomSource = RANDOM_BYTES
): Promise<string>{
    const vaultKey = await unwrapRaw(wrapped, oldWrappingKey, true);
    return wrapVaultKey(vaultKey, newWrappingKey, random);
}