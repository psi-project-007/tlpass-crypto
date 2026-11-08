import base64, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

cases = [
    ("00" * 32, "00" * 32, "00" * 12),
    (bytes(range(32)).hex(), bytes(range(32, 64)).hex(), bytes(range(12)).hex()),
    ("ff" * 32, "a5" * 32, "0f" * 12),
]

def b64url(data): 
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

out = []
for vault_key, wrapping_key, nonce in cases: 
    ciphertext = AESGCM(bytes.fromhex(wrapping_key)).encrypt(bytes.fromhex(nonce), bytes.fromhex(vault_key), None)
    out.append({
        "vault_key": vault_key,
        "wrapping_key": wrapping_key,
        "nonce": nonce,
        "wrapped": f"v1.{b64url(bytes.fromhex(nonce))}.{b64url(ciphertext)}"
    })
    
print(json.dumps(out, indent=2))