import { RANDOM_BYTES , type RandomSource } from './helpers/random';

const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const DIGITS = '0123456789';
const SYMBOLS = '!@#$%^&*()-_=+[]{}|;:,.<>?/~';
const LOOK_ALIKES = new Set('0Oo1lI|');

export const MIN_LENGTH = 8;
export const MAX_LENGTH = 64;

export interface GeneratorOptions{
    length: number;
    upper: boolean;
    lower: boolean;
    digits: boolean;
    symbols: boolean;
    excludeLookAlikes: boolean;
}

export type CharsetOptions = Omit<GeneratorOptions, 'length'>;

function chosenSets(options: CharsetOptions): string[] {
    return [
        options.upper && UPPER, options.lower && LOWER,
        options.digits && DIGITS, options.symbols && SYMBOLS,]
        .filter((set): set is string => typeof set === 'string')
        .map(set => options.excludeLookAlikes ? [...set].filter(char => !LOOK_ALIKES.has(char)).join('') : set);
}

export function charsetSize(options: CharsetOptions): number {
    return chosenSets(options).join('').length;
}

function randomIndex(num: number, random: RandomSource): number{
    const limit = 256 - (256 % num);
    for(;;){
        const byte = random(1)[0];
        if (byte < limit) return byte % num;
    }
}

export function generatePassword(options: GeneratorOptions, random: RandomSource = RANDOM_BYTES): string {
    const { length } = options;

    if(!Number.isInteger(length) || length < MIN_LENGTH || length > MAX_LENGTH){
        throw new RangeError(`Password length must be an integer between ${MIN_LENGTH} and ${MAX_LENGTH}`);
    }

    const sets = chosenSets(options);

    if (sets.length === 0) throw new RangeError('At least one character set must be selected');

    const all = sets.join('');
    const pick = (set: string) => set[randomIndex(set.length, random)];
    const chars = [...sets.map(pick), ...Array.from({ length: length - sets.length }, () => pick(all))];

    for( let i = chars.length - 1; i > 0; i--){
        const j = randomIndex(i + 1, random);
        [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.join('');
}

export type MasterPasswordRule = 'length' | 'upper' | 'lower' | 'digit';

export const MASTER_MIN_LENGTH = 12;

export function checkMasterPassword(password: string): MasterPasswordRule[] {
   const failed: MasterPasswordRule[] = [];
    if ([...password].length < MASTER_MIN_LENGTH) failed.push('length');
    if (!/\p{Lu}/u.test(password)) failed.push('upper');
    if (!/\p{Ll}/u.test(password)) failed.push('lower');
    if (!/\p{Nd}/u.test(password)) failed.push('digit');
    return failed;
}

const POOLS: [RegExp, number][] = [
    [/[A-Z]/, UPPER.length], [/[a-z]/, LOWER.length],
    [/[0-9]/, DIGITS.length], [/[^A-Za-z0-9]/, SYMBOLS.length],
];

const guessPoolSize = (password: string) =>
    POOLS.reduce((sum, [re, size]) => sum + (re.test(password) ? size : 0), 0);

export function strengthScore(password: string, poolSize = guessPoolSize(password)): 0 | 1 | 2 | 3 | 4 {
    const bits = poolSize === 0 ? 0 : [...password].length * Math.log2(poolSize);
    return bits < 40 ? 0 : bits < 60 ? 1 : bits < 80 ? 2 : bits < 100 ? 3 : 4;
}

