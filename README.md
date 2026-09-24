# SecureVault

SecureVault is a multi-user encrypted document exchange system developed for the ENCS4320 Applied Cryptography course at Birzeit University.

## Current Implementation

The project currently includes implementations and tests for:

- SHA-256
- HMAC-SHA256
- AES-256 block encryption and decryption
- AES-256-GCM authenticated encryption

From a library (declared in our 30%):

- Argon2id password hashing (`argon2-cffi`)

## Requirements

- Python 3.12 or later
- pytest
- cryptography
- argon2-cffi

## Development Setup

Create a virtual environment:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1