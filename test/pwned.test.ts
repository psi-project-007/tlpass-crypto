import { describe, expect, it, vi } from 'vitest';
import { isPwned } from '../src/pwned';
import vectors from './vectors/pwned.json';

const SUFFIX = '1E4C9B93F3F0682250B6CF8331B7EE68FD8';
const reply = (body: string) => vi.fn(async () => new Response(body));

describe('isPwned', () => {
    it('sends only the 5-char prefix with Add-Padding', async () => {
        const fetchFn = reply('');
        await isPwned('password', fetchFn);
        expect(fetchFn).toHaveBeenCalledWith(
            'https://api.pwnedpasswords.com/range/5BAA6',
            { headers: { 'Add-Padding': 'true' } },
        );
    });

    it('reports pwned with the count', async () => {
        const result = await isPwned('password', reply(`${'A'.repeat(35)}:1\r\n${SUFFIX}:9659365\r\n`));
        expect(result).toEqual({ status: 'pwned', count: 9659365 });
    });

    it('treats a padding line (count 0) as clean', async () => {
        expect(await isPwned('password', reply(`${SUFFIX}:0`))).toEqual({ status: 'clean', count: 0 });
    });

    it('returns unknown on a network error', async () => {
        const fetchFn = vi.fn(async () => { throw new TypeError('offline'); });
        expect(await isPwned('password', fetchFn)).toEqual({ status: 'unknown', count: 0 });
    });

    it('returns unknown on a non-OK response', async () => {
        expect(await isPwned('password', reply('').mockResolvedValue(new Response('', { status: 503 }))))
            .toEqual({ status: 'unknown', count: 0 });
    });

    it.each([
        ['an empty body', ''],
        ['an HTML page', '<html>Service unavailable</html>'],
        ['a non-numeric count', `${SUFFIX}:abc`],
        ['a negative count', `${SUFFIX}:-1`],
    ])('returns unknown for %s', async (_, body) => {
        expect(await isPwned('password', reply(body))).toEqual({ status: 'unknown', count: 0 });
    });

    it('reports clean when a valid response has no match', async () => {
        const body = `${'A'.repeat(35)}:3\r\n${'B'.repeat(35)}:0\r\n`;
        expect(await isPwned('password', reply(body))).toEqual({ status: 'clean', count: 0 });
    });

    it.each(vectors)('sends the prefix and finds the suffix for $password', async ({ password, prefix, suffix }) => {
        const fetchFn = reply(`${suffix}:42\r\n`);
        expect(await isPwned(password, fetchFn)).toEqual({ status: 'pwned', count: 42 });
        expect(fetchFn).toHaveBeenCalledWith(
            `https://api.pwnedpasswords.com/range/${prefix}`,
            { headers: { 'Add-Padding': 'true' } },
        );
    });
});