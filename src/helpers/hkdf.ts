export const HKDF_PARAMS = (info: Uint8Array<ArrayBuffer>): HkdfParams => ({
    name: 'HKDF',
    hash: 'SHA-256',
    salt: new Uint8Array(),
    info,
});