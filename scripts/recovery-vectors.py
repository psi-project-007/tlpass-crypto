import base64, json 
from mnemonic import Mnemonic
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

entropies = [
    "00" * 16,
    "7f" * 16,
    "9e885d952ad362caeb4efe34a8e91bd2",
    "c0ba5a8e914111210f2bd131f3d5e08d",
]

CHECK_NONCE = bytes(12)
CHECK_PLAINTEXT = b"tlpass-recovery-check"
mnemo = Mnemonic("english")

def hkdf(key, info):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(key)

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

out=[]

for e in entropies:
    entropy = bytes.fromhex(e)
    out.append({
        "phrase": mnemo.to_mnemonic(entropy),
        "verifier": b64url(hkdf(entropy, b"tlpass-recovery-verifier-v1")),
        "slotCheck": AESGCM(hkdf(entropy, b"tlpass-recovery-key-v1")).encrypt(CHECK_NONCE, CHECK_PLAINTEXT, None).hex()
    })

print(json.dumps(out, indent=2))