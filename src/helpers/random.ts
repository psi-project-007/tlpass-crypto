export type RandomSource = (length: number) => Uint8Array<ArrayBuffer>;

export const RANDOM_BYTES: RandomSource = (length: number) => crypto.getRandomValues(new Uint8Array(length));