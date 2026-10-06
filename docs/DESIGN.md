# SecureVault: Design Decisions

| # | Decision | Choice |
|---|---|---|
| 1 | Password protection | Argon2id (`argon2-cffi`) |
| 2 | Document encryption | AES-256-GCM, new key per document |
| 3 | Public-key crypto | X25519 + Ed25519 |
| 4 | Trusting a public key | TOFU + safety number |
| 5 | Signatures vs MACs | GCM tag for integrity, Ed25519 for origin |
| 6 | Freshness | version counter, timestamp + nonce, login challenge |
| 7 | Architecture and formats | client/server over sockets, binary formats |
| 8 | Keys, password change, sessions | two keys from the password, signed requests |

---

## 1. Password protection: Argon2id

**Choice:** Argon2id (RFC 9106) from `argon2-cffi`, called in `client/crypto/password_hash.py`.
- Salt: 16 random bytes per user, stored in the clear. It only has to be unique, not secret. Same password + different salt gives a different hash, and each account has to be attacked on its own.
- Parameters: `m = 384 MiB, t = 3, p = 4`, which is about 0.46 s per hash.

**Why:** Argon2id is memory-hard. Every guess needs 384 MiB, so GPUs and ASICs can't run thousands of guesses in parallel cheaply.

**Work factor:** measured with `tools/bench_password_hash.py` (t=3, p=4, median of 5 runs):

| Memory | 64 MiB | 128 MiB | 256 MiB | 384 MiB |
|---|---|---|---|---|
| Time | 0.078 s | 0.162 s | 0.311 s | 0.471 s |

We picked 384 MiB, the closest to our 0.5 s target. When adding cost we chose more memory rather than more passes, because memory is what hurts GPUs.

**Offline attack, estimated** (`tools/crack_estimate.py`): the attacker has one account's salt and `auth_key`, and every guess costs a full Argon2id. On one high-end GPU (~1 TB/s memory bandwidth, 24 GiB; assumed), each guess moves about 3.4 GiB of memory, so the GPU can do at most ~276 guesses/s, and only 64 fit in memory at once. Average time to find the password:

| Password | Our Argon2id | Bare SHA-256 (~22 billion/s) |
|---|---|---|
| 8 lowercase + digits | ~160 years | ~1 minute |
| 8 letters + digits | ~12,500 years | ~1.4 hours |
| 10 letters + digits | ~48 million years | ~220 days |
| one of the top 1,000,000 passwords | ~30 minutes | instant |

Each account has its own salt, so all of this is paid again per account. A common password still falls fast (last row), which is a limitation.

**Why a library:** our own pure-Python version (`experiments/custom_kdf.py`, not real Argon2id) took 3.6 s for just 8 KiB. At a real memory size, one login would take hours.

**Rejected:**
- PBKDF2: not memory-hard, and SHA-256 ASICs are cheap.
- bcrypt: only 4 KiB of memory, and it cuts passwords at 72 bytes.
- scrypt: memory and time cost can't be set separately.

---

## 2. Document encryption: AES-256-GCM

**Choice:** AES-256-GCM, written by us (`aes.py`, `gcm.py`).
- Each document gets a new random 256-bit key (DEK).
- The nonce is 12 random bytes.
- The metadata goes in the AAD. The server can read it but can't change it.
- The tag is checked **before** anything is decrypted.

**Nonce reuse:** can't happen. Each DEK encrypts exactly one document once, so the same (key, nonce) pair never repeats, even after a crash or restart.

**Key size:** our target is 128-bit security. AES-256 costs only 4 extra rounds and gives margin, since we create many keys.

**Rejected:**
- AES-CBC + HMAC: we'd have to compose them ourselves, and a wrong order breaks it.
- ChaCha20-Poly1305: fine, but not in the course, and GCM was already done.
- CCM: two passes, and no gain.

---

## 3. Public-key crypto: X25519 + Ed25519

**Why we need it:** users share no secret beforehand, and the server must not know one.
- **X25519** (RFC 7748) gets a document's key to the recipient.
- **Ed25519** (RFC 8032) proves who sent the document.

Both give about 128-bit security, with 32-byte keys.

**Sharing:** the sender creates a temporary X25519 key and computes X25519(temporary, recipient). HKDF turns that into a wrapping key, which encrypts the DEK with AES-GCM. The server only sees the wrapped DEK.

**Why not P-256 / ECDSA:** ECDSA needs a fresh random number for every signature. If one repeats, the private key leaks (the Sony PS3 hack). Ed25519 doesn't need a random number at all. Also, with X25519 any 32 bytes is a valid public key, so there are no invalid-curve checks to get wrong.

**Rejected:** P-256 (see above), RSA-3072 (384-byte keys for the same security), finite-field DH (needs about 3072 bits).

**ECC vs RSA, measured** (`tools/bench_ecc_vs_rsa.py`, same 128-bit level, both from OpenSSL so we compare algorithms, not code quality):

| Operation | Curve25519 | RSA-3072 | RSA / ECC |
|---|---|---|---|
| key generation | 0.08 ms | 734 ms | ~8,900x |
| key agreement / transport | 0.14 ms | 10 ms | ~73x |
| sign | 0.10 ms | 10 ms | ~100x |
| verify | 0.25 ms | 0.24 ms | ~1x |

Keys are 32 B instead of 384 B, and signatures 64 B instead of 384 B. RSA verification is as fast as ours or faster, because it uses a small public exponent (65537). That doesn't change our choice: every signup generates keys, and every share does a key agreement and a signature. With our own pure-Python code against RSA using the same Python big integers, the picture is the same (key agreement ~45x, sign ~14x, verify faster for RSA).

---

## 4. Trusting a public key: TOFU + safety number

**Problem:** the server could hand Layla its own key instead of Omar's, then read everything (man-in-the-middle).

**Choice** (the same idea as WhatsApp's security code):
1. The first time Layla gets Omar's key, her client saves it.
2. Both clients show the same 20-digit safety number (5 groups of 4), computed with SHA-256 from both users' names and public keys. We use 20 digits and not 12 because 12 digits is only about 40 bits: an attacker could generate fake keys until one gives the same number. 20 digits is about 66 bits, which is far too many keys to try.
3. They compare it by phone or in person, then mark each other as verified.
4. **Sharing is blocked until the recipient is verified.**
5. If a saved key ever changes, the client blocks. There's no "continue anyway".

A swapped key gives a different number on each screen, so the attack shows up.

**Rejected:**
- A CA on the server: the server is the party we don't trust.
- A separate CA: it still has to check identities somehow.
- Plain TOFU: the first contact is unprotected.
- Full fingerprints: too long, so people skip the check.

---

## 5. Signatures vs MACs

| Where | Tool | Why |
|---|---|---|
| document | GCM tag (MAC) | catches any change to the content or metadata |
| wrapped DEK | GCM tag (MAC) | the wrapped key can't be swapped or edited |
| who sent it | Ed25519 signature | shows the sender and can be proven to others |

**Signed statement:**
```
"SVS1" || doc_id || version || sender || recipient || SHA-256(metadata) || SHA-256(plaintext)
```
The recipient's name is in there so Omar can't forward the document and pretend Layla sent it to someone else.

The signature is stored **encrypted inside the key grant**. If it were in the clear, the server could test guesses about a file's contents against it.

**Proof to a third party:** Omar gives them the plaintext, the metadata and the signature. They rebuild the statement and check it with Layla's public key.

**Why a MAC can't give non-repudiation:** both sides hold the same MAC key, so Omar could have made the tag himself. A longer tag doesn't change that.

---

## 6. Freshness

A replayed message is real: Layla actually signed it. A signature proves *who* sent something, not *when*, so freshness needs its own checks.

| Where | Mechanism | Rejects |
|---|---|---|
| requests to the server | timestamp + 16-byte nonce, signed | older than 5 min, or a nonce already seen |
| documents | version number inside the signed statement | a version lower than the last one accepted, or the same version but a different object; shown as **stale**. Downloading the very same copy again is allowed. |
| login | fresh random challenge, answered with HMAC(auth_key) | a recorded old login |

The server only keeps nonces from the last 5 minutes. Anything older is already rejected by the timestamp.

**Rejected:**
- A timestamp alone for documents: stored documents are old by nature.
- A nonce list alone: it grows forever and can't tell which version is newer.

---

## 7. Architecture and formats

**Choice:** a client and a server over TCP sockets, with an attacker proxy in the middle for the demo:
```
[client] <-> [attacker proxy] <-> [server]
```
The spec says the attacker controls the network, and the proxy really does: it can flip a byte, edit metadata, replay a message or swap a key live.
Rejected: a shared folder (the attack is just a hand-edited file) and peer-to-peer (extra work, nothing gained).

**Programs:**
- `client/client.py` (terminal) and `client/gui.py` (graphical) are two front ends for the same client logic.
- `client prove <doc>` + `tools/verify_proof.py`: a third party checks the sender's signature with no account and no server.
- `attacks/attacker.py` (network attacker) and `attacks/weakened_build.py` (a reused nonce and a skipped tag check, both broken on purpose) are demo only, aimed at our own system.

**The server:** stores users and documents, relays keys and documents, and checks login challenges, signatures, timestamps and nonces.

**What it can't do:**

| It can't... | because... |
|---|---|
| read documents | DEKs only reach it wrapped for the recipients |
| learn passwords | it only receives `auth_key` |
| read private keys | they're encrypted with `enc_key`, which never leaves the client |
| forge documents or requests | it has no one's Ed25519 private key |
| swap a public key unnoticed | the safety numbers won't match |
| change metadata or serve an old version | GCM tag, signature, version number |

It **can** see file names, sizes, times, and who shares with whom.

### Byte formats
Integers are big-endian. **LV** means a 2-byte length followed by the value, so field boundaries can't be confused.

**Document object** (on the server). AAD = every field before the nonce.

| magic `SVD1` | doc_id | owner | filename | mime | size | timestamp | version | nonce | ciphertext | tag |
|---|---|---|---|---|---|---|---|---|---|---|
| 4 | 16 | LV | LV | LV | 8 | 8 | 4 | 12 | 4 + n | 16 |

**Key grant** (one per recipient, plus one for the owner). AAD = every field before the nonce.

| magic `SVK1` | doc_id | version | sender | recipient | temporary X25519 key | nonce | enc(DEK ‖ signature) | tag |
|---|---|---|---|---|---|---|---|---|
| 4 | 16 | 4 | LV | LV | 32 | 12 | 96 | 16 |

Wrapping key = HKDF-SHA256(X25519(temporary, recipient), salt = temporary_pk ‖ recipient_pk, info = "SecureVault key grant v1")

**User record** (on the server)

| username | salt | auth_key | X25519 pk | Ed25519 pk | encrypted private keys |
|---|---|---|---|---|---|
| LV | 16 | 32 | 32 | 32 | 12 + 64 + 16 |

**Request frame.** The signature covers everything from `type` to `body`, not the length.

| length | type | username | timestamp | nonce | body | signature |
|---|---|---|---|---|---|---|
| 4 | 1 | LV | 8 | 16 | varies | 64 |

**Server reply**

| length | status (0 = OK, 1 = error) | payload |
|---|---|---|
| 4 | 1 | varies |

**Message types** (`shared/protocol.py`). The three login messages are sent before the user has keys, so their signature field is all zeros and isn't checked. Every other message must be signed.

| # | Message | Signed | Body --> reply |
|---|---|---|---|
| 1 | REGISTER | with the new key | user record --> - |
| 2 | GET_SALT | no | - --> salt (a fake one for unknown users) |
| 3 | LOGIN_START | no | - --> 32-byte challenge |
| 4 | LOGIN_PROOF | no | HMAC --> salt, key blob, public keys |
| 10 | GET_KEYS | yes | username --> Ed25519 pk + X25519 pk |
| 11 | UPLOAD | yes | document + grant for myself --> - |
| 12 | SHARE | yes | grant --> - |
| 13 | LIST | yes | - --> my documents |
| 14 | DOWNLOAD | yes | doc_id + version --> document + my grant |
| 15 | CHANGE_PASSWORD | yes | new user record --> - |

Big fields in a body (document, grant) are each prefixed by a 4-byte length.

### When verification fails
The client doesn't show or save anything, and doesn't tell the server why it failed. The user sees one short line:

| Case | Message |
|---|---|
| content **or** metadata changed | `Rejected: document was modified` |
| old version | `Rejected: stale version` |
| bad signature | `Rejected: sender could not be verified` |
| saved key changed | `Blocked: key changed` |

It never gives more detail than that, such as which byte or which check failed.

The server's replies travel over the network, so they stay generic. A failed login always gets `Invalid username or password`. For an unknown username, the server returns a fake salt, the first 16 bytes of `HMAC(server_secret, "fake salt" || username)`, and does the same work, so the reply and its timing look the same.

---

## 8. Keys, password change, sessions

```
password --Argon2id--> master --HKDF--> auth_key  (sent to the server, for login)
                                   \--> enc_key   (never leaves the client)
enc_key      locks  the private keys (X25519 + Ed25519)
X25519 keys  lock   each document's DEK
DEK          locks  the document
```

**Two keys, not one:** the server holds `auth_key`. If that same key unlocked the private keys, the server could read everything.

**Exact derivations** (`client/keys.py`):
- `auth_key` = HKDF(master, salt = none, info = "SecureVault auth key v1")
- `enc_key` = HKDF(master, salt = none, info = "SecureVault enc key v1")
- key blob = AES-GCM(`enc_key`, x25519_sk ‖ ed25519_sk), with AAD = "SVU1" ‖ LV(username), so a blob can't be moved to another account
- login answer = HMAC(`auth_key`, "SecureVault login v1" ‖ challenge)

**Password change:**
1. The old password unlocks the private keys.
2. With a new salt, the new password gives a new `auth_key` and `enc_key`.
3. The same private keys are re-encrypted with the new `enc_key`.
4. The new salt, `auth_key` and key blob are sent in one signed request, and the server replaces all three together.

Documents, public keys and safety numbers don't change, so nobody has to re-verify.

**Sessions:** no tokens. Every request is signed with Ed25519 and carries a timestamp and nonce, so there's nothing to steal and old requests can't be replayed. The "session" is just the unlocked keys in the client's memory, and logout wipes them. Login is still needed so the user can get their encrypted private keys on a new machine.
Rejected: session tokens, because the attacker sees the network and could steal one.

---

## Libraries (our 30%)

| Component | Library | Why |
|---|---|---|
| Argon2id | `argon2-cffi` | pure Python is too slow for a real memory cost |

Not counted as crypto: `os.urandom`, sockets, storage, UI.
`cryptography` is never used by the running system. It's used in tests to cross-check our code, and in `tools/bench_ecc_vs_rsa.py` to measure RSA for the comparison.

## Limitations

- Our code isn't constant-time. That's acceptable because the client machine is trusted.
- Common-word passwords still fall fast. A strength check at sign-up would help.
- The safety number only protects users who actually compare it.
- AES-GCM in Python runs at about 105 KiB/s (about 10 s per MB).
- A stolen database gives `auth_key`, which is enough to log in, but not to read files or sign.
- A forgotten password loses the private keys and every document. A recovery key would fix this.
- Changing the password doesn't protect against an old stolen database copy if the old password gets cracked. Key rotation would fix this.
- The server sees file names, sizes, times, and who shares with whom.
- Sign-up says when a name is taken, and a logged-in user can ask for anyone's public keys, so account names aren't secret. We only hide whether an account exists on a *failed login*, which is what the spec asks for.
- Sharing needs one extra step compared to "name him and the system does the rest": the recipient must be verified with the safety number first. That's the price of not trusting the server with public keys.

## References

FIPS 180-4, FIPS 197, NIST SP 800-38D, RFC 2104, RFC 5869, RFC 9106, RFC 7748, RFC 8032, ENCS4320 lectures 05–08.
