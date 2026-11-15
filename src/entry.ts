import {DecryptError} from "./errors";
import { utf8 } from "./helpers/encoding";
import {AES_GCM, FORMAT_ENVELOPE, NONCE_LENGTH, parseEnvelope} from "./helpers/envelope";
import {RANDOM_BYTES, type RandomSource} from "./helpers/random";

const ENTRY_AD = (userId: string, itemId: string) => utf8(`${userId}/${itemId}`);

export async function encryptEntry(
    vaultKey: CryptoKey,
    userId: string,
    itemId: string, 
    json: unknown,
    randomSource: RandomSource = RANDOM_BYTES
): Promise<string>{
    const nonce = randomSource(NONCE_LENGTH);
    const cipherText = await crypto.subtle.encrypt(
        AES_GCM(nonce, ENTRY_AD(userId, itemId)),
        vaultKey,
        utf8(JSON.stringify(json))
    );
    return FORMAT_ENVELOPE(nonce, new Uint8Array(cipherText));
}

export async function decryptEntry<T = unknown>(
    vaultKey: CryptoKey,
    userId: string,
    itemId: string,
    encrypted: string
): Promise<T>{
    const {nonce, ciphertext} = parseEnvelope(encrypted);
    let plainText: ArrayBuffer;
    try{
        plainText = await crypto.subtle.decrypt(
            AES_GCM(nonce, ENTRY_AD(userId, itemId)),
            vaultKey,
            ciphertext
        );
    }catch{
        throw new DecryptError();
    }

    return JSON.parse(new TextDecoder().decode(plainText)) as T;
}