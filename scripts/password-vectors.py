import hashlib, json, math

UPPER, LOWER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"
DIGITS, SYMBOLS = "0123456789", "!@#$%^&*()-_=+[]{}|;:,.<>?/~"
LOOK_ALIKES = set("0Oo1lI|")

def sets(o):
    chosen = [s for flag, s in [(o["upper"], UPPER), (o["lower"], LOWER),
                                (o["digits"], DIGITS), (o["symbols"], SYMBOLS)] if flag]
    return ["".join(c for c in s if c not in LOOK_ALIKES) if o["excludeLookAlikes"] else s for s in chosen]

def generate(o, stream):
    ss = sets(o); chars = "".join(ss); limit = 256 - 256 % len(chars); it = iter(stream)
    while True:
        pw = ""
        while len(pw) < o["length"]:
            b = next(it)
            if b < limit: pw += chars[b % len(chars)]
        if all(any(c in s for c in pw) for s in ss): return pw

def score(pw, pool):
    bits = len(pw) * math.log2(pool)
    return 0 if bits < 40 else 1 if bits < 60 else 2 if bits < 80 else 3 if bits < 100 else 4

ALL = {"upper": True, "lower": True, "digits": True, "symbols": True}
DIGITS_ONLY = {"upper": False, "lower": False, "digits": True, "symbols": False, "excludeLookAlikes": True}

gen_opts = [
    {"length": 8, **ALL, "excludeLookAlikes": False},
    {"length": 20, **ALL, "excludeLookAlikes": True},
    {"length": 64, **DIGITS_ONLY},
]
generate_cases = []
for i, o in enumerate(gen_opts):
    stream = hashlib.shake_256(f"tlpass-gen-{i}".encode()).digest(1024)
    generate_cases.append({"options": o, "random": stream.hex(), "password": generate(o, stream)})

strength = [("aaaaaaaa", 26), ("abcdefghi", 26), ("Abcdef123456", 62),
            ("Abc-def-123456", 90), ("Abc-def-12345678", 90)]
charset = [{**ALL, "excludeLookAlikes": False}, {**ALL, "excludeLookAlikes": True}, DIGITS_ONLY]

print(json.dumps({
    "generate": generate_cases,
    "master": [
        {"password": "", "fails": ["length", "upper", "lower", "digit"]},
        {"password": "Short1a", "fails": ["length"]},
        {"password": "alllowercase123", "fails": ["upper"]},
        {"password": "ÄÖÜäöü123456", "fails": []},
    ],
    "strength": [{"password": p, "score": score(p, pool)} for p, pool in strength],
    "charset": [{"options": o, "size": len("".join(sets(o)))} for o in charset],
}, ensure_ascii=False, indent=2))