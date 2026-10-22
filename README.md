# counsel-watch

Private, password-protected page. The data in `data/` is encrypted (AES-256-GCM, key from PBKDF2-SHA256) and is only readable with the password.

- `index.html`: the page; it decrypts `data/jobs.enc.json` in the browser.
- `tools/cw_crypto.py`: encrypt or decrypt the data file (`CW_PASSWORD` env var).

Updated daily by a scheduled task.
