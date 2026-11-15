import { afterEach, describe, expect, it, vi } from 'vitest';
import { deriveRecoveryKeys, generateRecoveryWords } from '../src/recovery';
import { InvalidRecoveryPhraseError } from '../src/errors';
import WORDS from '../src/helpers/bip39-english.json';
import bip39 from './vectors/bip39.json';
import vectors from './vectors/recovery.json';
import { fromHex, toHex } from '../src/helpers/encoding';

const WORDLIST_SHA256 = '2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda';

afterEach(() => { vi.restoreAllMocks(); });

describe('word list', () => {
    it('matches the published BIP-39 English list', async () => {
        const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(WORDS.join('\n') + '\n'));
        expect(toHex(new Uint8Array(hash))).toBe(WORDLIST_SHA256);
    });
});

describe('generateRecoveryWords', () => {
    it.each(bip39)('matches BIP-39 vector $mnemonic', async ({ entropy, mnemonic }) => {
        const words = await generateRecoveryWords(() => fromHex(entropy));
        expect(words).toHaveLength(12);
        expect(words.join(' ')).toBe(mnemonic);
    });
});

describe('deriveRecoveryKeys', () => {
    it.each(vectors)('matches the verifier for $phrase', async ({ phrase, verifier }) => {
        expect((await deriveRecoveryKeys(phrase)).verifier).toBe(verifier);
    });

    it.each(vectors)('derives the slot key for $phrase', async ({ phrase, slotCheck }) => {
        const { slotKey } = await deriveRecoveryKeys(phrase);
        const ct = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: new Uint8Array(12) }, slotKey, new TextEncoder().encode('tlpass-recovery-check'));
        expect(toHex(new Uint8Array(ct))).toBe(slotCheck);
    });

    it('ignores case and extra spaces', async () => {
        const messy = `  ${vectors[0].phrase.toUpperCase().replace(/ /g, '   ')}  `;
        expect((await deriveRecoveryKeys(messy)).verifier).toBe(vectors[0].verifier);
    });

    it('makes the slot key non-extractable', async () => {
        const { slotKey } = await deriveRecoveryKeys(vectors[0].phrase);
        await expect(crypto.subtle.exportKey('raw', slotKey)).rejects.toThrow();
    });

    it.each([
        ['an unknown word', 'abandon '.repeat(11) + 'notaword'],
        ['a wrong word', 'legal letter thank year wave sausage worth useful legal winner thank yellow'],
        ['a bad checksum', 'abandon '.repeat(12)],
        ['11 words', 'abandon '.repeat(10) + 'about'],
    ])('rejects %s before deriving', async (_, phrase) => {
        const importKey = vi.spyOn(crypto.subtle, 'importKey');
        await expect(deriveRecoveryKeys(phrase)).rejects.toThrow(InvalidRecoveryPhraseError);
        expect(importKey).not.toHaveBeenCalled();
    });
});