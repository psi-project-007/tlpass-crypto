# tlpass-crypto

> **Pre-alpha: do not store real passwords.** The format and the API can still change, and nothing here has been audited yet.

All of TLPass's client-side cryptography in one tested TypeScript package. It covers:

- deriving the master key with Argon2id
- splitting it into the Auth Hash and the wrapping key with HKDF
- encrypting the vault and its entries with AES-256-GCM
- the 12-word BIP-39 recovery phrase
- the password generator and strength helpers

Everything runs on the user's device. The server only ever sees the Auth Hash and encrypted data, never a key that can decrypt.

## How it fits

| Repository | Role |
| --- | --- |
| **tlpass-crypto** (this one) | The cryptography, published as `@psi-project-007/tlpass-crypto` |
| tlpass-web | The web portal, which uses this package |
| tlpass-api | The API (Go Lambda handlers), which stores only encrypted data |
| tlpass-infra | The AWS infrastructure (CDK in Go) |

The mobile app will use this same package later, so every client encrypts the same way.

## Licence

[Apache-2.0](LICENSE).

## Security

Please don't report vulnerabilities in public issues. Follow the [security policy](https://github.com/psi-project-007/.github/blob/main/SECURITY.md).
