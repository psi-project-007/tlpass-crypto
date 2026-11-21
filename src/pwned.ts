import { toHex, utf8 } from './helpers/encoding.js';

export const PWNED_RANGE_URL = 'https://api.pwnedpasswords.com/range/';

export type PwnedStatus = 'pwned' | 'clean' | 'unknown';

export interface PwnedResult {
    status: PwnedStatus;
    count: number;
}

export type FetchFn = (url: string, init?: RequestInit) => Promise<Response>;

async function sha1Hex(password: string): Promise<string> {
    const hash = new Uint8Array(await crypto.subtle.digest('SHA-1', utf8(password)));
    return toHex(hash).toUpperCase();
}

const RANGE_LINE = /^([0-9A-F]{35}):(\d+)$/;

function findCount(body: string, suffix: string): number | undefined {
    const lines = body.split(/\r?\n/).filter((line) => line !== '');
    if (lines.length === 0) return undefined;

    let found = 0;
    for (const line of lines) {
        const match = RANGE_LINE.exec(line);
        if (!match) return undefined;
        if (match[1] === suffix) found = Number(match[2]);
    }
    return found;
}

export async function isPwned(password: string, fetchFn: FetchFn = fetch): Promise<PwnedResult> {
    const hash = await sha1Hex(password);
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);

    try {
        const response = await fetchFn(PWNED_RANGE_URL + prefix, { headers: { 'Add-Padding': 'true' } });
        if (!response.ok) return { status: 'unknown', count: 0 };

        const count = findCount(await response.text(), suffix);
        if (count === undefined) return { status: 'unknown', count: 0 };
        return { status: count > 0 ? 'pwned' : 'clean', count };
    } catch {
        return { status: 'unknown', count: 0 };
    }
}