import { describe, expect, it } from 'vitest';
import { generatePassword, checkMasterPassword, strengthScore, charsetSize } from '../src/password';
import { fromHex } from '../src/helpers/encoding';
import type { RandomSource } from '../src/helpers/random';
import vectors from './vectors/password.json';

const ALL = { upper: true, lower: true, digits: true, symbols: true, excludeLookAlikes: false };
const STREAM_FROM_HEX = (hex: string): RandomSource => {
    const bytes = fromHex(hex);
    let i = 0;
    return (n) => {
        if (i + n > bytes.length) throw new Error('vector stream exhausted');
        const out = bytes.slice(i, i + n);
        i += n;
        return out;
    };
};


describe('generatePassword', () => {
    it.each([8, 20, 64])('includes every chosen type at length %i', (length) => {
        const pw = generatePassword({ ...ALL, length });
        expect(pw).toHaveLength(length);
        for (const re of [/[A-Z]/, /[a-z]/, /[0-9]/, /[^A-Za-z0-9]/]) expect(pw).toMatch(re);
    });

    it('leaves out look-alikes', () => {
        const pw = generatePassword({ ...ALL, length: 64, excludeLookAlikes: true });
        expect(pw).not.toMatch(/[0Oo1lI|]/);
    });

    it.each([7, 65, 8.5])('rejects length %s', (length) => {
        expect(() => generatePassword({ ...ALL, length })).toThrow(RangeError);
    });

    it('rejects bytes at or above the bias limit', () => {
        const bytes = [255, 250, 3, 3, 3, 3, 3, 3, 3, 3, ...Array(64).fill(0)];
        let i = 0;
        const random = () => Uint8Array.of(bytes[i++]);
        const pw = generatePassword({ length: 8, upper: false, lower: false, digits: true, symbols: false, excludeLookAlikes: false }, random);
        expect(pw).toMatch(/^\d{8}$/);
    });

    it('is uniform over 10,000 passwords (chi-square)', () => {
        const counts = new Map<string, number>();
        for (let i = 0; i < 10_000; i++) {
            for (const c of generatePassword({ length: 16, upper: false, lower: false, digits: true, symbols: false, excludeLookAlikes: false })) {
                counts.set(c, (counts.get(c) ?? 0) + 1);
            }
        }
        const expected = (10_000 * 16) / 10;
        const chi2 = [...counts.values()].reduce((s, n) => s + (n - expected) ** 2 / expected, 0);
        expect(counts.size).toBe(10);
        expect(chi2).toBeLessThan(27.88); // df=9, p=0.001
    });

    it('is uniform over valid mixed passwords (chi-square on digit count)', () => {
        const N = 20_000, L = 8, p = 10 / 36;
        const binom = (n: number, k: number) => { let r = 1; for (let i = 1; i <= k; i++) r = r * (n - k + i) / i; return r; };
        const weights = Array.from({ length: L - 1 }, (_, i) => binom(L, i + 1) * p ** (i + 1) * (1 - p) ** (L - i - 1));
        const total = weights.reduce((a, b) => a + b);

        const counts = Array(L - 1).fill(0);
        for (let i = 0; i < N; i++) {
            const pw = generatePassword({ length: L, upper: true, lower: false, digits: true, symbols: false, excludeLookAlikes: false });
            counts[[...pw].filter((c) => /\d/.test(c)).length - 1]++;
        }
        const chi2 = counts.reduce((s, n, i) => {
            const e = N * weights[i] / total;
            return s + (n - e) ** 2 / e;
        }, 0);
        expect(chi2).toBeLessThan(22.46); // df=6, p=0.001
    });
});

describe('checkMasterPassword', () => {
    it.each([
        ['Abcdefghijk1', []],
        ['Abcdefgh1', ['length']],
        ['abcdefghijk1', ['upper']],
        ['ABCDEFGHIJK1', ['lower']],
        ['Abcdefghijkl', ['digit']],
        ['', ['length', 'upper', 'lower', 'digit']],
    ])('%s fails %j', (pw, failed) => {
        expect(checkMasterPassword(pw)).toEqual(failed);
    });
});

describe('strengthScore', () => {
    it.each([
        [{ ...ALL, upper: false, digits: false, symbols: false, length: 8 }, 0],   
        [{ ...ALL, digits: false, symbols: false, length: 8 }, 1],                
        [{ ...ALL, digits: false, symbols: false, length: 12 }, 2],               
        [{ ...ALL, length: 13 }, 3],                                              
        [{ ...ALL, length: 20 }, 4],                                              
    ])('scores generated password as %i', (opts, score) => {
        expect(strengthScore(generatePassword(opts))).toBe(score);
    });
});

describe('strengthScore with the chosen set size', () => {
    const LOWER_NO_LOOKALIKES = { upper: false, lower: true, digits: false, symbols: false, excludeLookAlikes: true };

    it('uses the set without look-alikes', () => {
        // 13 × log2(24) ≈ 59.6 bits -> 1 (the guessed 26-letter set gives 61.1 -> 2)
        const pw = generatePassword({ ...LOWER_NO_LOOKALIKES, length: 13 });
        expect(strengthScore(pw, charsetSize(LOWER_NO_LOOKALIKES))).toBe(1);
    });

    it('counts the set size', () => {
        expect(charsetSize(LOWER_NO_LOOKALIKES)).toBe(24);
        expect(charsetSize({ ...ALL })).toBe(90);
        expect(charsetSize({ ...ALL, excludeLookAlikes: true })).toBe(83);
    });

    it('still guesses the set when no size is given', () => {
        expect(strengthScore('a'.repeat(13))).toBe(2);
    });
});

describe('password vectors', () => {
    it.each(vectors.generate)('generates $password', ({ options, random, password }) => {
        expect(generatePassword(options, STREAM_FROM_HEX(random))).toBe(password);
    });
    it.each(vectors.master)('checks master rules for "$password"', ({ password, fails }) => {
        expect(checkMasterPassword(password)).toEqual(fails);
    });
    it.each(vectors.strength)('scores $password as $score', ({ password, score }) => {
        expect(strengthScore(password)).toBe(score);
    });
    it.each(vectors.charset)('charset size $size', ({ options, size }) => {
        expect(charsetSize(options)).toBe(size);
    });
});