export const fromHex = 
    (hex: string) => Uint8Array.from({ length: hex.length / 2 }, (_, i) => parseInt(hex.slice(i * 2, i * 2 + 2), 16));

export const toHex = 
    (buf: Uint8Array) => Array.from(buf, (x) => x.toString(16).padStart(2, '0')).join('');
