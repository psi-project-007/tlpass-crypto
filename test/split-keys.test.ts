import {describe, it, expect} from 'vitest';
import {splitKeys} from '../src/split-keys';
import vectors from './vectors/split-keys.json';
import { fromHex, toHex } from './helpers/hex';

describe('splitKeys', () => {
  it.each(vectors)('matches Auth Hash vector $authHash', async ({ masterKey, authHash }) => {
    const keys = await splitKeys(fromHex(masterKey));
    expect(keys.authHash).toBe(authHash);
    expect(keys.authHash).toHaveLength(43);
  });

  it.each(vectors)('derives the wrapping key from vector $authHash', async ({ masterKey, vaultCheck }) => {
    const { wrappingKey } = await splitKeys(fromHex(masterKey));
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: new Uint8Array(12) }, wrappingKey, new TextEncoder().encode('tlpass-vault-check'));
    expect(toHex(new Uint8Array(ciphertext))).toBe(vaultCheck);
  });

  it('makes the wrapping key non-extractable', async () => {
    const { wrappingKey } = await splitKeys(fromHex(vectors[0].masterKey));
    await expect(crypto.subtle.exportKey('raw', wrappingKey)).rejects.toThrow();
  });

  it('wipes the master key', async () => {
    const masterKey = fromHex(vectors[0].masterKey);
    await splitKeys(masterKey);
    expect(masterKey.every((b) => b === 0)).toBe(true);
  });
})

