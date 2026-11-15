import { toHex, utf8 } from './helpers/encoding';

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

function findCount(body: string, suffix: string): number {
    for (const line of body.split(/\r?\n/)) {
        const [lineSuffix, count] = line.split(':');
        if (lineSuffix === suffix) return Number(count);
    }
    return 0;
}

export async function isPwned(password: string, fetchFn: FetchFn = fetch): Promise<PwnedResult> {
    const hash = await sha1Hex(password);
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);

    try {
        const response = await fetchFn(PWNED_RANGE_URL + prefix, { headers: { 'Add-Padding': 'true' } });
        if (!response.ok) return { status: 'unknown', count: 0 };

        const count = findCount(await response.text(), suffix);
        return { status: count > 0 ? 'pwned' : 'clean', count };
    } catch {
        return { status: 'unknown', count: 0 };
    }
}