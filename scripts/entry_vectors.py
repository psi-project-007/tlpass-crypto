import base64, json 
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode()

cases = [
    ("00"*32, "00"*12, "user-1", "item-1", {"site": "example.com", "username": "mo", "password": "p@ss"}),
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "000102030405060708090a0b",
     "3f2c9a1e-0000-4000-8000-000000000001", "7b1d4e2a-0000-4000-8000-000000000002",
     {"site": "مصرفي", "username": "محمد", "password": "كلمة-سر-123", "notes": ""}),
     ("ff"*32, "ff"*12, "user-3", "item-3",
     {"site": "", "username": "", "password": "", "notes": "line1\nline2 \"quoted\""}),
]

out = []

for key, nonce, uid, iid, entry in cases: 
    pt = json.dumps(entry, separators=(',', ':'), ensure_ascii=False).encode()
    ct = AESGCM(bytes.fromhex(key)).encrypt(bytes.fromhex(nonce), pt, f"{uid}/{iid}".encode())

    out.append({
        "vault_key": key,
        "user_id": uid,
        "item_id": iid,
        "nonce" : nonce,
        "entry": entry,
        "encrypted": f"v1.{b64(bytes.fromhex(nonce))}.{b64(ct)}"
    })

print(json.dumps(out, ensure_ascii=False, indent=2))