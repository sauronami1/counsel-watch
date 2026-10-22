#!/usr/bin/env python3
"""Counsel Watch data sealing.

The site uses a key pair:
  keys/public.pem         - public key. Anyone (the daily job) can SEAL data with it; it cannot open anything.
  keys/private.enc.json   - private key, encrypted with the shared password (PBKDF2-SHA256 -> AES-256-GCM).
                            Only the page, after the password is typed, can unlock it.
  data/jobs.enc.json      - the listings: AES-256-GCM with a fresh random key, that key wrapped with RSA-OAEP-SHA256.

  python3 tools/cw_crypto.py seal plain.json data/jobs.enc.json      # needs no secret
  CW_PASSWORD=... python3 tools/cw_crypto.py open data/jobs.enc.json plain.json
  CW_PASSWORD=... python3 tools/cw_crypto.py keygen                  # one-time; replaces the key pair
  OLD/NEW: CW_PASSWORD=old CW_NEW_PASSWORD=new python3 tools/cw_crypto.py repass   # change password

Requires: pip install cryptography
"""
import base64, json, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUB = os.path.join(ROOT, "keys", "public.pem")
PRIV = os.path.join(ROOT, "keys", "private.enc.json")
ITER = 310_000
b64e = lambda b: base64.b64encode(b).decode()
b64d = base64.b64decode
OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

def kek(pw, salt, iters):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iters).derive(pw.encode())

def env(name):
    v = os.environ.get(name)
    if not v: sys.exit(f"set {name}")
    return v

def write_private(der, pw):
    salt, iv = os.urandom(16), os.urandom(12)
    ct = AESGCM(kek(pw, salt, ITER)).encrypt(iv, der, None)
    json.dump({"v": 2, "kdf": "PBKDF2-SHA256", "iter": ITER, "salt": b64e(salt), "iv": b64e(iv), "ct": b64e(ct)}, open(PRIV, "w"))

def read_private(pw):
    e = json.load(open(PRIV))
    der = AESGCM(kek(pw, b64d(e["salt"]), e["iter"])).decrypt(b64d(e["iv"]), b64d(e["ct"]), None)
    return serialization.load_der_private_key(der, password=None), der

def keygen():
    pw = env("CW_PASSWORD")
    os.makedirs(os.path.dirname(PUB), exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    der = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    open(PUB, "wb").write(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    write_private(der, pw)
    print("new key pair written to keys/")

def repass():
    _, der = read_private(env("CW_PASSWORD"))
    write_private(der, env("CW_NEW_PASSWORD"))
    print("password changed; data files need no change")

def seal(src, dst):
    data = json.load(open(src))
    assert isinstance(data.get("jobs"), list) and data["jobs"], "plain file must have a non-empty jobs list"
    pub = serialization.load_pem_public_key(open(PUB, "rb").read())
    k, iv = AESGCM.generate_key(256), os.urandom(12)
    ct = AESGCM(k).encrypt(iv, json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode(), None)
    json.dump({"v": 2, "alg": "RSA-OAEP-256+A256GCM", "wrapped": b64e(pub.encrypt(k, OAEP)), "iv": b64e(iv), "ct": b64e(ct)}, open(dst, "w"))
    blob = open(dst).read()
    for j in data["jobs"][:5]:
        assert j.get("employer", "")[:12] not in blob, "plaintext leaked"
    print(f"sealed {len(data['jobs'])} jobs -> {dst}")

def open_(src, dst):
    priv, _ = read_private(env("CW_PASSWORD"))
    e = json.load(open(src))
    k = priv.decrypt(b64d(e["wrapped"]), OAEP)
    data = json.loads(AESGCM(k).decrypt(b64d(e["iv"]), b64d(e["ct"]), None))
    json.dump(data, open(dst, "w"), ensure_ascii=False, indent=1)
    print(f"opened {len(data['jobs'])} jobs -> {dst}")

if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["seal"] and len(a) == 3: seal(a[1], a[2])
    elif a[:1] == ["open"] and len(a) == 3: open_(a[1], a[2])
    elif a == ["keygen"]: keygen()
    elif a == ["repass"]: repass()
    else: sys.exit(__doc__)
