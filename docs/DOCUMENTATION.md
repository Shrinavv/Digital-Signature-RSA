# Digital Signature RSA: Technical Documentation

Design, algorithms, file formats, API and module reference. For installation and a step-by-step run, see the [README](../README.md).

---

## 1. Goals and non-goals

**Goals**
- Show end to end how an RSA digital signature protects a message: key generation, signing, transmission, verification.
- Provide **integrity** (the message was not changed) and **authenticity** (it was signed by the holder of the private key).
- Keep the code small enough to read in one sitting.

**Non-goals:** production-grade security, confidentiality (messages are signed, not encrypted), user management.

---

## 2. Architecture

```
 SENDER (sender/)                        SERVER (server/)                         RECEIVER (receiver/)
┌─────────────────────────┐   HTTPS    ┌───────────────────────────┐            ┌─────────────────────────┐
│ keygen.py   → key pair  │  POST      │ app.py (Flask)            │            │ check_message.py        │
│ sign.py     → signature │ ─────────► │  /api/receive → validate  │ ─────────► │ verify.py               │
│ transmit.py → upload    │            │                 + save    │  (same     │  uses sender's public   │
└─────────────────────────┘            │  /api/download → serve    │   folder)  │  key                    │
                                       └───────────────────────────┘            └─────────────────────────┘
                              shared code: utils/rsa_utils.py
```

The server writes the message into `receiver/checked_message.txt`, which is exactly the file the receiver scripts read by default, so no manual copying is needed.

---

## 3. Cryptographic design

### 3.1 Prime generation

`generate_prime(bits)` draws `bits` random bits from `secrets`, forces the top two bits and the lowest bit to 1 (so the number is odd and the product of two such primes has the full target length), and keeps trying until `is_prime` accepts it.

`is_prime(n, k=40)` is **Miller-Rabin**:
1. Reject `n < 2` and anything divisible by a small prime (up to 199).
2. Write `n − 1 = 2^r · d` with `d` odd.
3. For `k` random bases `a`: compute `x = a^d mod n`; pass if `x` is 1 or `n − 1`; otherwise square up to `r − 1` times looking for `n − 1`; if never found, `n` is composite.

With 40 rounds the probability of accepting a composite is at most 4⁻⁴⁰. Unlike the earlier Fermat test, Miller-Rabin is not fooled by Carmichael numbers such as 561 (covered by a test).

### 3.2 Key generation

`generate_keys(folder, bits=2048)`:
1. `p` and `q`: distinct random primes of `bits/2` bits each.
2. `n = p·q` (must be exactly `bits` long), `phi = (p−1)(q−1)`.
3. `e = 65537`. If `gcd(e, phi) ≠ 1`, draw new primes.
4. `d = e⁻¹ mod phi` via `pow(e, -1, phi)`.
5. Write `e\nn` to `public_key.txt` and `d\nn` to `private_key.txt` (owner-only permissions where supported).

A 2048-bit key takes around a second in CPython.

### 3.3 Message encoding (EMSA-PKCS1-v1_5)

The bare hash is never signed. For a modulus of `k` bytes the signed block is:

```
00 01 | FF FF ... FF | 00 | DigestInfo(SHA-256) || SHA256(message)
```

`DigestInfo` is the fixed DER prefix `3031300d060960864801650304020105000420`. The block is read as a big-endian integer `m`.

### 3.4 Signing

```
signature = m^d mod n          # pow(m, d, n)
```

### 3.5 Verification

```
recovered = signature^e mod n  → k bytes
valid     = (recovered == encode(message))     # constant-time compare
```

A signature outside `[0, n)` is rejected. Why it works: `m^(de) ≡ m (mod n)` because `d·e ≡ 1 (mod phi)`. Why tampering is caught: any change to the message changes SHA-256, so the expected block no longer matches the recovered one.

---

## 4. Data formats

All files are UTF-8 text.

| File | Content |
|------|---------|
| `public_key.txt` | line 1: `e`, line 2: `n` |
| `private_key.txt` | line 1: `d`, line 2: `n` |
| `signed_message.txt` / `checked_message.txt` | message, then a newline, then the signature as a decimal integer on the **last line** |
| `message.txt` | the raw message |

Parsing rule (`parse_signed_text`): normalise `\r\n` to `\n`, treat the last line as the signature (digits only) and everything before it as the message. The message may therefore span several lines when the file is created by hand; `sign.py` itself reads a single line.

---

## 5. HTTP API

Server: `server/app.py`. Local default `https://127.0.0.1:5000`. Request bodies are limited to 64 KB.

### `GET /`
Serves `static/index.html`, with a textarea to paste a signed message and a button to download the stored one. All URLs are relative, so the page works on any host.

### `POST /api/receive`
- Content type: `application/x-www-form-urlencoded`
- Field: `signed_message`
- Behaviour: validates the `message / signature` format, normalises line endings, overwrites `receiver/checked_message.txt`
- Responses: `200` `{"success": ...}`, `400` `{"error": ...}` (empty or malformed), `413` (too large)

### `GET /api/download`
Returns the stored file as an attachment, or `404` if nothing has been stored.

### TLS modes (`python server/app.py`)

| Situation | Behaviour |
|-----------|-----------|
| `PORT` environment variable set | Plain HTTP on `0.0.0.0:$PORT`; the hosting platform terminates TLS |
| `server/cert.pem` and `server/key.pem` exist | HTTPS with those files |
| Neither | HTTPS with a temporary self-signed certificate (`ssl_context="adhoc"`, needs `cryptography`) |

---

## 6. Module reference

### `utils/rsa_utils.py`

| Name | Purpose |
|------|---------|
| `ROOT` | Absolute path of the project root; scripts use it so they run from any directory |
| `PUBLIC_EXPONENT`, `DEFAULT_KEY_BITS` | 65537 and 2048 |
| `gcd(a, b)` | Euclid's algorithm |
| `is_prime(n, k=40)` | Miller-Rabin |
| `generate_prime(bits)` | Random prime of exact bit length |
| `generate_keys(folder, bits)` | Create and write a key pair; returns `(e, d, n)` |
| `read_key(path)` | Parse a key file into `(exponent, n)` |
| `hash_message(message)` | SHA-256 as an integer (kept for reference, no longer used for signing) |
| `sign_message(message, d, n)` | PKCS#1 v1.5 signature as an integer |
| `verify_signature(message, signature, e, n)` | Boolean verification |
| `parse_signed_text(text)` / `read_signed_file(path)` | Split into `(message, signature)` |

### Scripts

| Script | Purpose | Notes |
|--------|---------|-------|
| `sender/keygen.py` | Create sender keys | `--bits N` |
| `sender/sign.py` | Prompt for a message and sign it | Rejects empty messages |
| `sender/transmit.py` | POST the signed file | `--url`, `--file`; certificate checks skipped only for localhost |
| `receiver/keygen.py` | Create receiver keys | Reserved for future encryption |
| `receiver/check_message.py` | Print message and signature | Optional file argument |
| `receiver/verify.py` | Verify signature | Optional file and public-key arguments; exit code 0 or 1 |
| `server/app.py` | Flask server | See section 5 |

---

## 7. Testing

```bash
python -m unittest discover -s tests -v
```

| Area | Checks |
|------|--------|
| Primes | Known primes and composites, Carmichael numbers (561, 1105, 1729, ...), prime bit length |
| Keys | `e = 65537`, modulus length, `(m^e)^d ≡ m`, key-file round trip |
| Signatures | Valid, tampered message, tampered or out-of-range signature, wrong key, determinism |
| Parsing | Basic, CRLF and multi-line, malformed input |
| API | Download before upload (404), empty (400), malformed (400), browser-style CRLF round trip then verify |

Standards check performed during development: a signature produced by `sign_message` was accepted by the `cryptography` library's `PKCS1v15` + `SHA256` verifier using the same public key.

Manual end-to-end test: keygen, sign, start server, transmit from a different working directory, check, verify (valid), change one letter (invalid, exit code 1), send a CRLF-formatted message like a browser would (valid).

---

## 8. Deployment (Render)

1. `requirements.txt` already includes `gunicorn`; `runtime.txt` pins Python 3.10.12.
2. Start command: `gunicorn --chdir server app:app`.
3. The platform provides `PORT` and HTTPS. Send with `python sender/transmit.py --url https://<app>.onrender.com/api/receive`.
4. The free tier's disk is ephemeral, so the stored message is lost on restart; use a database for anything that must persist.
5. Note that anyone with the URL can overwrite the single stored message. Add authentication before relying on a public deployment.

---

## 9. Security notes

Resolved from the first version:

| Earlier issue | Now |
|---------------|-----|
| Fermat primality test, 5 rounds | Miller-Rabin, 40 rounds |
| `random` module | `secrets` (CSPRNG) |
| Roughly 665 to 996 bit modulus | 2048-bit default |
| Random, huge `e` | `e = 65537` |
| Unpadded hash signed directly | PKCS#1 v1.5 (SHA-256) encoding |
| Single-line web input stripped the line break | Textarea, plus tolerant parsing and server validation |
| Manual copy from `checked_message.txt` to `signed_message.txt` | Receiver scripts read `checked_message.txt` directly |
| `transmit.py` only worked from `sender/`; TLS verification always off | Path-independent; verification skipped only for localhost |
| Committed private keys and TLS key | Not in the project; `.gitignore` blocks them |
| `verify.py` comment named the wrong key | Fixed and documented |
| Unused dependencies | Reduced to Flask, Requests, cryptography (dev certificate), Gunicorn |

Remaining:

| Item | Impact | Next step |
|------|--------|-----------|
| Not audited, not constant-time | Hand-written RSA can leak through timing | Use a vetted library in production |
| PKCS#1 v1.5 rather than PSS | Acceptable, but PSS is preferred for new designs | Implement RSA-PSS |
| No key-to-identity binding | Receiver trusts the local public-key file | Certificates, or a user and key database |
| No replay protection | An old valid message can be resent | Timestamps and nonces |
| Unauthenticated, single-slot server | Anyone can overwrite the stored message | Accounts and per-user storage |

If you previously committed key files, they stay in Git history. Treat them as compromised, regenerate, and rewrite the history or start a fresh repository.

---

## 10. Possible extensions

- Username and password database; each user registers a public key; senders address a specific receiver.
- Encrypt the message with the receiver's public key (the receiver key pair exists for this).
- Audit log of signed messages with timestamps, a natural fit for tamper-evident consent records.
- RSA-PSS padding and optional 3072-bit keys.
- Replace the hand-written primitives with the `cryptography` library behind the same function names, keeping the hand-written version as an educational module.

---

## 11. Glossary

- **RSA:** public-key algorithm based on the difficulty of factoring `n = p × q`.
- **Public key `(e, n)`:** shared openly; verifies signatures.
- **Private key `(d, n)`:** kept secret; creates signatures.
- **Hash:** fixed-size fingerprint of a message; here SHA-256.
- **Padding:** fixed structure wrapped around the hash before the RSA operation.
- **Digital signature:** the padded hash raised to the private exponent; anyone with the public key can check it.
- **Integrity:** the message was not altered. **Authenticity:** it was signed by the private-key holder.
