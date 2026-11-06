# Generates test/vectors/master-key.json with the reference Argon2 (pip install argon2-cffi)
import hashlib, json
from argon2.low_level import hash_secret_raw, Type

cases = [("correct horse battery staple", "ana@example.com"),
         ("P@ssw0rd!", " Bob@Example.COM "),
         ("كلمة-سر-طويلة", "carol@example.org")]

out = []

for pwd, email in cases: 
    salt = hashlib.sha256(email.strip().lower().encode()).digest()
    key = hash_secret_raw(
        pwd.encode(), salt, time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, type=Type.ID
    )

    out.append({
        "email": email,
        "password": pwd,
        "key": key.hex()
    })

print(json.dumps(out, ensure_ascii=False, indent=2))