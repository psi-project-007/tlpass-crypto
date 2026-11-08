import { describe, it, expect, vi } from 'vitest';
import { createVaultKey, wrapVaultKey, unwrapVaultKey } from '../src';
import { DecryptError } from '../src';
import { fromHex } from './helpers/hex';
import vectors from './vectors/vault-key.json';

const AES_KEY = (hex: string, usages: KeyUsage[], extractable = false) =>{
    return crypto.subtle.importKey(
        "raw",
        fromHex(hex),
        'AES-GCM',
        extractable,
        usages
    );
}

const WRAPPING_KEY = () => {
    return crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        false,
        ['wrapKey', 'unwrapKey']
    );
}

const FLIP = (str: string) => (str[0] === 'A' ? 'B' : 'A') + str.slice(1);

const SWAP_PART = (str: string, index: number) => {
    return str.split('.')
      .map((part, j) => j === index ? FLIP(part) : part)
      .join('.');
}

describe('Vault Key', () => {
    it.each(vectors)('matches vector $wrapped', async ({ vault_key, wrapping_key: wk, nonce, wrapped }) => {
        const key = await AES_KEY(vault_key, ['encrypt', 'decrypt'], true);
        const wrapKey = await AES_KEY(wk, ['wrapKey', 'unwrapKey']);
        expect(await wrapVaultKey(key, wrapKey, () => fromHex(nonce))).toBe(wrapped);
    });

    it('creates a random 256-bit AES-GCM key', async () => {
        const [a, b] = await Promise.all([createVaultKey(), createVaultKey()]);
        expect(a.algorithm).toMatchObject({ name: 'AES-GCM', length: 256 });
        const rawA = new Uint8Array(await crypto.subtle.exportKey('raw', a));
        expect(rawA).toHaveLength(32);
        expect(rawA).not.toEqual(new Uint8Array(await crypto.subtle.exportKey('raw', b)));
    });

    it('uses a fresh nonce for every wrap and round-trips', async () => {
        const [key, wk] = [await createVaultKey(), await WRAPPING_KEY()];
        const [w1, w2] = [await wrapVaultKey(key, wk), await wrapVaultKey(key, wk)];
        expect(w1).not.toBe(w2);
        expect(w1).toMatch(/^v1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{64}$/);
        await expect(unwrapVaultKey(w1, wk)).resolves.toBeDefined();
    });

    it.each([
        ['wrong key', async (w: string) => unwrapVaultKey(w, await WRAPPING_KEY())],
        ['changed nonce', async (w: string, wk: CryptoKey) => unwrapVaultKey(SWAP_PART(w, 1), wk)],
        ['changed ciphertext', async (w: string, wk: CryptoKey) => unwrapVaultKey(SWAP_PART(w, 2), wk)],
    ])('throws DecryptError on %s', async (_, attempt) => {
        const wk = await WRAPPING_KEY();
        const wrapped = await wrapVaultKey(await createVaultKey(), wk);
        await expect(attempt(wrapped, wk)).rejects.toThrow(DecryptError);
    });

    it('rejects an unknown version before decrypting', async () => {
        const wk = await WRAPPING_KEY();
        const wrapped = await wrapVaultKey(await createVaultKey(), wk);
        const spy = vi.spyOn(crypto.subtle, 'unwrapKey');
        await expect(unwrapVaultKey(wrapped.replace(/^v1\./, 'v2.'), wk)).rejects.toThrow(DecryptError);
        expect(spy).not.toHaveBeenCalled();
        spy.mockRestore();
    });
});