export function toBase64Url(bytes: Uint8Array): string{
    let binary = '';
    for (const byte of bytes){
        binary += String.fromCharCode(byte);
    }

    return btoa(binary)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

export function fromBase64Url(base64url: string): Uint8Array<ArrayBuffer>{
    if (!/^[A-Za-z0-9_-]*$/.test(base64url)) throw new Error('Invalid base64url');

    const binary = atob(base64url.replace(/-/g, '+').replace(/_/g, '/'));
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));

    if (toBase64Url(bytes) !== base64url) throw new Error('Invalid base64url');
    return bytes;
} 