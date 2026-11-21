import { toBase64Url } from './helpers/base64url.js';
import { utf8 } from './helpers/encoding.js';
import { RANDOM_BYTES, type RandomSource } from './helpers/random.js';
import { entropyToWords, wordsToEntropy, normalizePhrase } from './helpers/bip39.js';
import { HKDF_PARAMS } from './helpers/hkdf.js';

const ENTROPY_LENGTH = 16;
const SLOT_INFO = utf8('tlpass-recovery-key-v1');
const VERIFIER_INFO = utf8('tlpass-recovery-verifier-v1');

export interface RecoveryKeys{
    slotKey: CryptoKey;
    verifier: string;
}

export async function generateRecoveryWords(random: RandomSource = RANDOM_BYTES): Promise<string[]>{
    const entropy = random(ENTROPY_LENGTH);
    try{
        return await entropyToWords(entropy);
    }finally{
        entropy.fill(0);
    }
}

export async function deriveRecoveryKeys(phrase: string): Promise<RecoveryKeys>{
    const entropy = await wordsToEntropy(normalizePhrase(phrase));
    try{
        const baseKey = await crypto.subtle.importKey(
            'raw', entropy,'HKDF', false, ['deriveBits', 'deriveKey']);
        
        const verifierBits = await crypto.subtle.deriveBits(
            HKDF_PARAMS(VERIFIER_INFO), baseKey, 256);

        const slotKey = await crypto.subtle.deriveKey(
            HKDF_PARAMS(SLOT_INFO), baseKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['wrapKey','unwrapKey','encrypt', 'decrypt']);

        return {slotKey, verifier: toBase64Url(new Uint8Array(verifierBits))}
    }finally{
        entropy.fill(0);
    }
}