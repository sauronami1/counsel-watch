#!/usr/bin/env python3
"""Encrypt / decrypt the Counsel Watch data file.

The site decrypts data/jobs.enc.json in the browser with the shared password
(PBKDF2-SHA256 -> AES-256-GCM). Same format both sides.

  CW_PASSWORD=... python3 tools/cw_crypto.py decrypt data/jobs.enc.json plain.json
  CW_PASSWORD=... python3 tools/cw_crypto.py encrypt plain.json data/jobs.enc.json

encrypt keeps the salt of an existing output file (so devices that stay signed in
keep working) and always uses a fresh IV. Requires: pip install cryptography
"""
import base64, json, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ITER = 310_000
b64e = lambda b: base64.b64encode(b).decode()
b64d = base64.b64decode

def key_for(password, salt, iters):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iters).derive(password.encode())

def password():
    p = os.environ.get("CW_PASSWORD")
    if not p:
        sys.exit("set CW_PASSWORD")
    return p

def decrypt(src, dst):
    env = json.load(open(src))
    key = key_for(password(), b64d(env["salt"]), env["iter"])
    plain = AESGCM(key).decrypt(b64d(env["iv"]), b64d(env["ct"]), None)
    data = json.loads(plain)
    json.dump(data, open(dst, "w"), ensure_ascii=False, indent=1)
    print(f"decrypted {len(data.get('jobs', []))} jobs -> {dst}")

def encrypt(src, dst):
    data = json.load(open(src))
    assert isinstance(data.get("jobs"), list), "plain file must have a jobs list"
    salt, iters = os.urandom(16), ITER
    if os.path.exists(dst):
        try:
            old = json.load(open(dst)); salt, iters = b64d(old["salt"]), old["iter"]
        except Exception:
            pass
    key = key_for(password(), salt, iters)
    iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode(), None)
    json.dump({"v": 1, "kdf": "PBKDF2-SHA256", "iter": iters, "salt": b64e(salt), "iv": b64e(iv), "ct": b64e(ct)}, open(dst, "w"))
    # round-trip check so a bad write never ships
    assert json.loads(AESGCM(key).decrypt(iv, ct, None))["jobs"] == data["jobs"]
    print(f"encrypted {len(data['jobs'])} jobs -> {dst}")

if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] not in ("encrypt", "decrypt"):
        sys.exit(__doc__)
    (encrypt if sys.argv[1] == "encrypt" else decrypt)(sys.argv[2], sys.argv[3])
