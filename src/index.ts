export const VERSION = '0.1.0';

export { deriveMasterKey, normalizedEmail, DEFAULT_KDF_SETTINGS, type KdfSettings } from './master-key';

export { splitKeys, type SplitKeys } from './split-keys';

export { createVaultKey, wrapVaultKey, unwrapVaultKey } from './vault-key';

export { encryptEntry, decryptEntry } from './entry';

export { generateRecoveryWords, deriveRecoveryKeys, type RecoveryKeys } from './recovery';

export { generatePassword, checkMasterPassword, strengthScore, charsetSize, type GeneratorOptions, type CharsetOptions, type MasterPasswordRule } from './password';

export { DecryptError, InvalidRecoveryPhraseError } from './errors';