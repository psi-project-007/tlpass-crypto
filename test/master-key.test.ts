import { describe, it, expect } from 'vitest'
import { deriveMasterKey, DEFAULT_KDF_SETTINGS } from '../src/master-key'
import vectors from './vectors/master-key.json'

const hex = (buf: Uint8Array) => Array.from(buf, (x) => x.toString(16).padStart(2, '0')).join('')

describe('deriveMasterKey', () => {
  it.each(vectors)('matches vector for $email', async ({email, password, key}) => {
    const derivedKey = await deriveMasterKey(password, email);
    expect(hex(derivedKey)).toBe(key);
  }, 10_000);

  it('ignores email case and spaces', async () => {
    const firstKey = await deriveMasterKey('password123', '  Alice@Example.com  ');
    const secondKey = await deriveMasterKey('password123', 'alice@example.com');
    expect(hex(firstKey)).toBe(hex(secondKey));
  }, 10_000);

  const weakSettings = [{memory: 32}, {iterations: 2}, {parallelism: 2}, {type: 'unsupported'}];
  it.each(weakSettings)('reject weak settings %0', async (bad) => {
    await expect(deriveMasterKey(
        'password123', 'alice@example.com', {...DEFAULT_KDF_SETTINGS, ...bad} as never))
        .rejects.toThrow();
  }, 10_000);
})