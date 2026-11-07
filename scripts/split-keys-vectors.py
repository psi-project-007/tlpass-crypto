import base64, json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

master_keys = [
    "fc70d44e12605251dc9d904a14151f512ad851f4ccc4ebd6415f50e9e8c91239",
    "bcbd8cd4a3ab571ee52483cc2e5a84be46bfb572cbf4bbcf48092010165a0f9a",
    "bb94dffeebbc4c227ba5240e61e7d85dcb7251868c3ecebd2f90dcdcdb081dc8",
    "00" * 32,
]

CHECK_NONCE = bytes(12)
CHECK_PLAINTEXT = b"tlpass-vault-check"

def hkdf( key, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(key)

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

out =[]

for key in master_keys:
    raw_key = bytes.fromhex(key)
    out.append({
        "masterKey": key,
        "authHash": b64url(hkdf(raw_key, b"tlpass-auth-v1")),
        "vaultCheck": AESGCM(hkdf(raw_key, b"tlpass-vault-v1"))
        .encrypt(CHECK_NONCE, CHECK_PLAINTEXT, None).hex()
    })

print(json.dumps(out, indent=2))