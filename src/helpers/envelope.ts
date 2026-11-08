import { DecryptError } from "../errors";
import { fromBase64Url, toBase64Url } from "./base64url";

export const NONCE_LENGTH = 12;
const TAG_LENGTH = 16;
const VERSION = "v1";

export interface Envelope{
    nonce: Uint8Array<ArrayBuffer>;
    ciphertext: Uint8Array<ArrayBuffer>;
}

export const FORMAT_ENVELOPE = (nonce: Uint8Array<ArrayBuffer>, ciphertext: Uint8Array<ArrayBuffer>): string => {
    return `${VERSION}.${toBase64Url(nonce)}.${toBase64Url(ciphertext)}`;
}

export function parseEnvelope(value: string): Envelope {
    const parts = value.split(".");

    if (parts.length !== 3 || parts[0] !== VERSION) throw new DecryptError();

    try{
        const nonce = fromBase64Url(parts[1]);
        const ciphertext = fromBase64Url(parts[2]);

        if (nonce.length === NONCE_LENGTH && ciphertext.length >= TAG_LENGTH) return { nonce, ciphertext };
    } catch { /* ignore */ }
    throw new DecryptError();
}