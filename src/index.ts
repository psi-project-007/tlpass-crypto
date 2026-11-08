export const VERSION = '0.1.0';

export { deriveMasterKey, normalizedEmail, DEFAULT_KDF_SETTINGS, type KdfSettings } from './master-key';

export { splitKeys, type SplitKeys } from './split-keys';

export { createVaultKey, wrapVaultKey, unwrapVaultKey } from './vault-key';

export { DecryptError } from './errors';