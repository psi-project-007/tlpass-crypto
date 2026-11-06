import { argon2id } from 'hash-wasm';

const utf8 = (str: string): Uint8Array<ArrayBuffer> => new TextEncoder().encode(str);

export const normalizedEmail = (email: string) => email.trim().toLowerCase();

export interface KdfSettings{
    type: 'argon2id',
    memory: number,
    iterations: number,
    parallelism: number
}

export const DEFAULT_KDF_SETTINGS: Readonly<KdfSettings> = Object.freeze({
    type: 'argon2id',
    memory: 64,
    iterations: 3,
    parallelism: 4
});

function assertKdf(kdf: KdfSettings): void{
    if(kdf.type !== 'argon2id'){
        throw new Error(`Unsupported KDF type: ${kdf.type}`);
    }

    const OK = (val: number, min: number) => Number.isInteger(val) && val >= min;
    if(!OK(kdf.memory, 64) || !OK(kdf.iterations, 3) || !OK(kdf.parallelism, 4)){
        throw new Error(`KDF settings below minimum`);
    }
}

async function emailSalt(email: string) : Promise<Uint8Array>{
    const digest = await crypto.subtle.digest('SHA-256', utf8(normalizedEmail(email)));
    return new Uint8Array(digest);
}

export async function deriveMasterKey(
    password: string, email: string, kdfSettings: KdfSettings = DEFAULT_KDF_SETTINGS): Promise<Uint8Array>{
    assertKdf(kdfSettings);
    
    return argon2id({
        password: utf8(password),
        salt: await emailSalt(email),
        memorySize: kdfSettings.memory * 1024,
        iterations: kdfSettings.iterations,
        parallelism: kdfSettings.parallelism,
        hashLength: 32,
        outputType: 'binary'
    })
}