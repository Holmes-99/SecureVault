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

**To do:** measure ECC against RSA at the same security level.

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
| documents | version number inside the signed statement | a version ≤ the last one accepted, shown as **stale** |
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

**Request frame.** The signature covers every field before it.

| length | type | username | timestamp | nonce | body | signature |
|---|---|---|---|---|---|---|
| 4 | 1 | LV | 8 | 16 | varies | 64 |

### When verification fails
The client doesn't show or save anything, and doesn't tell the server why it failed. The user sees one short line:

| Case | Message |
|---|---|
| content **or** metadata changed | `Rejected: document was modified` |
| old version | `Rejected: stale version` |
| bad signature | `Rejected: sender could not be verified` |
| saved key changed | `Blocked: key changed` |

It never gives more detail than that, such as which byte or which check failed.

The server's replies travel over the network, so they stay generic. A failed login always gets `Invalid username or password`. For an unknown username, the server returns a fake salt, `HMAC(server_secret, username)`, and does the same work, so the reply and its timing look the same.

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
`cryptography` is used only in tests, to cross-check our code.

## Limitations

- Our code isn't constant-time. That's acceptable because the client machine is trusted.
- Common-word passwords still fall fast. A strength check at sign-up would help.
- The safety number only protects users who actually compare it.
- AES-GCM in Python runs at about 105 KiB/s (about 10 s per MB).
- A stolen database gives `auth_key`, which is enough to log in, but not to read files or sign.
- A forgotten password loses the private keys and every document. A recovery key would fix this.
- Changing the password doesn't protect against an old stolen database copy if the old password gets cracked. Key rotation would fix this.
- The server sees file names, sizes, times, and who shares with whom.

## References

FIPS 180-4, FIPS 197, NIST SP 800-38D, RFC 2104, RFC 5869, RFC 9106, RFC 7748, RFC 8032, ENCS4320 lectures 05–08.
