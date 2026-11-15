import { describe, expect, it } from 'vitest';
import {
    createVaultKey, decryptEntry, DecryptError, deriveRecoveryKeys,
    encryptEntry, generateRecoveryWords, unwrapVaultKey, wrapVaultKey,
} from '../src';
import vectors from './vectors/recovery.json';

describe('recovery flow', () => {
    it('recovers an existing entry using only the saved phrase and recovery slot', async () => {
        const phrase = (await generateRecoveryWords()).join(' ');
        const original = await deriveRecoveryKeys(phrase);
        const vaultKey = await createVaultKey();
        const entry = { site: 'مصرفي', username: 'محمد', password: 'test-only-password' };
        const encrypted = await encryptEntry(vaultKey, 'user-1', 'item-1', entry);
        const recoverySlot = await wrapVaultKey(vaultKey, original.slotKey);

        const recovered = await deriveRecoveryKeys(phrase);
        expect(recovered.verifier).toBe(original.verifier);
        const recoveredVault = await unwrapVaultKey(recoverySlot, recovered.slotKey);
        expect(await decryptEntry(recoveredVault, 'user-1', 'item-1', encrypted)).toEqual(entry);
        expect(recoveredVault.extractable).toBe(false);
        await expect(crypto.subtle.exportKey('raw', recoveredVault)).rejects.toThrow();
        await expect(decryptEntry(recoveredVault, 'user-2', 'item-1', encrypted)).rejects.toThrow(DecryptError);
    });

    it('rejects a different valid phrase when opening the recovery slot', async () => {
        const correct = await deriveRecoveryKeys(vectors[0].phrase);
        const wrong = await deriveRecoveryKeys(vectors[1].phrase);
        const recoverySlot = await wrapVaultKey(await createVaultKey(), correct.slotKey);
        expect(wrong.verifier).not.toBe(correct.verifier);
        await expect(unwrapVaultKey(recoverySlot, wrong.slotKey)).rejects.toThrow(DecryptError);
    });

    it('rejects a modified recovery slot', async () => {
        const { slotKey } = await deriveRecoveryKeys(vectors[0].phrase);
        const recoverySlot = await wrapVaultKey(await createVaultKey(), slotKey);
        const parts = recoverySlot.split('.');
        parts[2] = (parts[2][0] === 'A' ? 'B' : 'A') + parts[2].slice(1);
        await expect(unwrapVaultKey(parts.join('.'), slotKey)).rejects.toThrow(DecryptError);
    });
});
