import { describe, it, expect } from 'vitest';
import { encryptEntry, decryptEntry, createVaultKey, DecryptError } from '../src';
import { fromHex } from '../src/helpers/encoding';
import vectors from './vectors/entry.json';

const VAULT_KEY = (hex: string) =>
    crypto.subtle.importKey('raw', fromHex(hex), 'AES-GCM', false, ['encrypt', 'decrypt']);

const FLIP = (str: string) => (str[0] === 'A' ? 'B' : 'A') + str.slice(1);
const SWAP_PART = (str: string, index: number) =>
    str.split('.').map((part, j) => (j === index ? FLIP(part) : part)).join('.');

const ARABIC_ENTRY = { site: 'مصرفي', username: 'محمد', password: 'كلمة-سر-123' };

describe('Entry', () => {
    it.each(vectors)('matches vector $encrypted', async ({ vault_key, user_id, item_id, nonce, entry, encrypted }) => {
        const key = await VAULT_KEY(vault_key);
        expect(await encryptEntry(key, user_id, item_id, entry, () => fromHex(nonce))).toBe(encrypted);
        expect(await decryptEntry(key, user_id, item_id, encrypted)).toEqual(entry);
    });

    it('round-trips non-Latin text', async () => {
        const key = await createVaultKey();
        const encrypted = await encryptEntry(key, 'u1', 'i1', ARABIC_ENTRY);
        expect(await decryptEntry(key, 'u1', 'i1', encrypted)).toEqual(ARABIC_ENTRY);
    });

    it('uses a fresh nonce for every encryption', async () => {
        const key = await createVaultKey();
        const [a, b] = [await encryptEntry(key, 'u1', 'i1', ARABIC_ENTRY), await encryptEntry(key, 'u1', 'i1', ARABIC_ENTRY)];
        expect(a).not.toBe(b);
    });

    it.each([
        ['wrong key', async (e: string) => decryptEntry(await createVaultKey(), 'u1', 'i1', e)],
        ['other userId', async (e: string, k: CryptoKey) => decryptEntry(k, 'u2', 'i1', e)],
        ['other itemId', async (e: string, k: CryptoKey) => decryptEntry(k, 'u1', 'i2', e)],
        ['changed nonce', async (e: string, k: CryptoKey) => decryptEntry(k, 'u1', 'i1', SWAP_PART(e, 1))],
        ['changed ciphertext', async (e: string, k: CryptoKey) => decryptEntry(k, 'u1', 'i1', SWAP_PART(e, 2))],
        ['unknown version', async (e: string, k: CryptoKey) => decryptEntry(k, 'u1', 'i1', e.replace(/^v1\./, 'v2.'))],
    ])('throws DecryptError on %s', async (_, attempt) => {
        const key = await createVaultKey();
        const encrypted = await encryptEntry(key, 'u1', 'i1', ARABIC_ENTRY);
        await expect(attempt(encrypted, key)).rejects.toThrow(DecryptError);
    });

    it.each([
    ['invalid base64url characters', 'v1.AAAAAAAAAAAAAAAA.***'],
    ['non-canonical base64url', 'v1.AAAAAAAAAAAAAAAB.' + 'A'.repeat(22)],
    ['nonce not 12 bytes', 'v1.AAAA.' + 'A'.repeat(22)],
    ['ciphertext shorter than the tag', 'v1.AAAAAAAAAAAAAAAA.AAAA'],
    ['wrong number of parts', 'v1.AAAAAAAAAAAAAAAA'],
    ])('throws DecryptError on %s', async (_, malformed) => {
    await expect(decryptEntry(await createVaultKey(), 'u1', 'i1', malformed)).rejects.toThrow(DecryptError);
    });
});

