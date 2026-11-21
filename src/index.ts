export const VERSION = '0.1.0';

export { deriveMasterKey, normalizedEmail, DEFAULT_KDF_SETTINGS, type KdfSettings } from './master-key.js';

export { splitKeys, type SplitKeys } from './split-keys.js';

export { createVaultKey, wrapVaultKey, unwrapVaultKey, rewrapVaultKey } from './vault-key.js';

export { encryptEntry, decryptEntry } from './entry.js';

export { generateRecoveryWords, deriveRecoveryKeys, type RecoveryKeys } from './recovery.js';

export { isPwned, type PwnedResult, type PwnedStatus } from './pwned.js';

export { generatePassword, checkMasterPassword, strengthScore, charsetSize, type GeneratorOptions, type CharsetOptions, type MasterPasswordRule } from './password.js';

export { DecryptError, InvalidRecoveryPhraseError } from './errors.js';