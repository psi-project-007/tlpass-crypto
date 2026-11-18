import { describe, it, expect, vi } from 'vitest';
import { createVaultKey, wrapVaultKey, unwrapVaultKey, rewrapVaultKey } from '../src';
import { DecryptError } from '../src';
import { fromHex } from '../src/helpers/encoding';
import vectors from './vectors/vault-key.json';
import rewrapVectors from './vectors/vault-key-rewrap.json';

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

const EXTRACT_NO_WRAPPING = async (attempt: Promise<string>) => {
    const spy = vi.spyOn(crypto.subtle, 'wrapKey');
    await expect(attempt).rejects.toThrow(DecryptError);
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
};

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

    it.each(rewrapVectors)('re-wraps vector $new_wrapped', async (v) => {
        const oldKey = await AES_KEY(v.old_wrapping_key, ['wrapKey', 'unwrapKey']);
        const newKey = await AES_KEY(v.new_wrapping_key, ['wrapKey', 'unwrapKey']);
        expect(await rewrapVaultKey(v.old_wrapped, oldKey, newKey, () => fromHex(v.new_nonce))).toBe(v.new_wrapped);
    });

    it('re-wraps to the same Vault Key with a fresh nonce', async () => {
        const [vaultKey, oldKey, newKey] = [await createVaultKey(), await WRAPPING_KEY(), await WRAPPING_KEY()];
        const oldWrapped = await wrapVaultKey(vaultKey, oldKey);
        const newWrapped = await rewrapVaultKey(oldWrapped, oldKey, newKey);

        expect(newWrapped.split('.')[1]).not.toBe(oldWrapped.split('.')[1]);
        const opened = await unwrapVaultKey(newWrapped, newKey);

        const iv = new Uint8Array(12);
        const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, vaultKey, new Uint8Array([1, 2, 3]));
        expect(new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, opened, ct))).toEqual(new Uint8Array([1, 2, 3]));
    });

    it('rewrap throws DecryptError and never wraps on a wrong old key', async () => {
        const wrapped = await wrapVaultKey(await createVaultKey(), await WRAPPING_KEY());
        await EXTRACT_NO_WRAPPING(rewrapVaultKey(wrapped, await WRAPPING_KEY(), await WRAPPING_KEY()));
    });

    it.each([
        ['changed nonce', (w: string) => SWAP_PART(w, 1)],
        ['changed ciphertext', (w: string) => SWAP_PART(w, 2)],
        ['unknown version', (w: string) => w.replace(/^v1\./, 'v2.')],
    ])('rewrap throws DecryptError and never wraps on %s', async (_, tamper) => {
        const oldKey = await WRAPPING_KEY();
        const wrapped = await wrapVaultKey(await createVaultKey(), oldKey);
        await EXTRACT_NO_WRAPPING(rewrapVaultKey(tamper(wrapped), oldKey, await WRAPPING_KEY()));
    });

    it('unwrapVaultKey returns a non-extractable key', async () => {
        const wk = await WRAPPING_KEY();
        const opened = await unwrapVaultKey(await wrapVaultKey(await createVaultKey(), wk), wk);
        expect(opened.extractable).toBe(false);
        await expect(crypto.subtle.exportKey('raw', opened)).rejects.toThrow();
    });
});