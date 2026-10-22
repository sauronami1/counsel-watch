# counsel-watch

Private, password-protected page. Nothing here is readable without the password.

- `keys/public.pem` seals new data (it cannot open anything).
- `keys/private.enc.json` is the private key, encrypted with the password.
- `data/jobs.enc.json` holds the sealed listings; `index.html` opens them in the browser after the password is entered.
- `tools/cw_crypto.py`: `seal` (no secret needed), `open`, `keygen`, `repass` (change the password).

Updated daily by a scheduled task.
