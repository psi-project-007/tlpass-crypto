import base64, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

cases = [
    # vault_key, old_wrapping_key, new_wrapping_key, old_nonce, new_nonce
    ("00" * 32, "00" * 32, "11" * 32, "00" * 12, "01" * 12),
    (bytes(range(32)).hex(), bytes(range(32, 64)).hex(), bytes(range(64, 96)).hex(),
     bytes(range(12)).hex(), bytes(range(12, 24)).hex()),
    ("ff" * 32, "a5" * 32, "5a" * 32, "0f" * 12, "f0" * 12),
]

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def wrap(key_hex, wk_hex, nonce_hex):
    ct = AESGCM(bytes.fromhex(wk_hex)).encrypt(bytes.fromhex(nonce_hex), bytes.fromhex(key_hex), None)
    return f"v1.{b64url(bytes.fromhex(nonce_hex))}.{b64url(ct)}"

out = []
for vk, old_wk, new_wk, old_nonce, new_nonce in cases:
    out.append({
        "vault_key": vk,
        "old_wrapping_key": old_wk,
        "new_wrapping_key": new_wk,
        "new_nonce": new_nonce,
        "old_wrapped": wrap(vk, old_wk, old_nonce),
        "new_wrapped": wrap(vk, new_wk, new_nonce),
    })

print(json.dumps(out, indent=2))