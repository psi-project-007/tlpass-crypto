import WORDS from './bip39-english.json' with { type: 'json' };
import { InvalidRecoveryPhraseError } from '../errors.js';

const WORD_COUNT = 12;
const ENTROPY_BITS = 128;
const INDEX = new Map(WORDS.map((word, i) => [word, i]));

const toBits = (num: number, width: number) => num.toString(2).padStart(width, '0');
const chunks = (bits: string, size: number): string[] =>
    Array.from({ length: bits.length / size }, (_, i) => bits.slice(i * size, (i + 1) * size));

async function checksumBits(entropy: Uint8Array<ArrayBuffer>): Promise<string>{
    const hash = new Uint8Array(
        await crypto.subtle.digest('SHA-256', entropy)
    );

    return toBits(hash[0] >> 4, 4);
}

export function normalizePhrase(phrase: string): string[] {
    return phrase
        .trim()
        .toLowerCase()
        .split(/\s+/);
}

export async function entropyToWords(entropy: Uint8Array<ArrayBuffer>): Promise<string[]> {
    const bits = Array.from(entropy, (byte) => toBits(byte, 8))
        .join('') + await checksumBits(entropy);

        return chunks(bits, 11).map((chunk) => WORDS[parseInt(chunk, 2)]);
}

export async function wordsToEntropy(words: string[]): Promise<Uint8Array<ArrayBuffer>> {
    const indexes = words.map((word) => INDEX.get(word)).filter((index) => index !== undefined);

    if (words.length !== WORD_COUNT || indexes.length !== WORD_COUNT) {
    throw new InvalidRecoveryPhraseError();
    }

    const bits = indexes.map((index) => toBits(index, 11)).join('');
    const entropy = Uint8Array.from(chunks(bits.slice(0, ENTROPY_BITS), 8), (byte) => parseInt(byte, 2));

    if(await checksumBits(entropy) !== bits.slice(ENTROPY_BITS)) {
        entropy.fill(0);
        throw new InvalidRecoveryPhraseError();
    }
    return entropy;
}
