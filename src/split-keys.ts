import { toBase64Url } from './helpers/base64url';
import { utf8 } from './helpers/encoding';


const AUTH_INFO = utf8('tlpass-auth-v1');
const VAULT_INFO = utf8('tlpass-vault-v1');

const HKDF_PARAMS = (info: Uint8Array<ArrayBuffer>): HkdfParams => ({
    name: 'HKDF',
    hash: 'SHA-256',
    salt: new Uint8Array(),
    info: info
})

export interface SplitKeys {
    authHash: string;
    wrappingKey: CryptoKey;
}

export async function splitKeys( masterKey: Uint8Array<ArrayBuffer>): Promise<SplitKeys> {
    try{
        const baseKey = await crypto.subtle.importKey(
            'raw', masterKey, 'HKDF', false, ['deriveBits', 'deriveKey']);
        
        const authBits = await crypto.subtle.deriveBits(
            HKDF_PARAMS(AUTH_INFO), baseKey, 256);

        const wrappingKey = await crypto.subtle.deriveKey(
            HKDF_PARAMS(VAULT_INFO), 
            baseKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['wrapKey', 'unwrapKey', 'encrypt', 'decrypt']
        );

        return { authHash: toBase64Url(new Uint8Array(authBits)), wrappingKey};
    }finally{
        masterKey.fill(0);
    }
}
