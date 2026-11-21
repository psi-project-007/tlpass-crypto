import hashlib, json

passwords = ["password", "P@ssw0rd!", "كلمة-سر-123"]

out = []
for pw in passwords:
    h = hashlib.sha1(pw.encode()).hexdigest().upper()
    out.append({"password": pw, "prefix": h[:5], "suffix": h[5:]})

print(json.dumps(out, ensure_ascii=False, indent=2))