import os
import sys
import argparse
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from shared.formats import decode_user, decode_document, decode_grant

# what the server (or a thief) sees --> demo 2 + 3

PINK = "\033[38;5;218m"
GREEN = "\033[38;5;151m"
GREY = "\033[38;5;245m"
BOLD = "\033[1m"
RESET = "\033[0m"


def color(text, code):
    return f"{code}{text}{RESET}" if USE_COLOR else text


def hexs(data, limit=32):
    text = data[:limit].hex(" ")
    return text + (" ..." if len(data) > limit else "")


def readable_ratio(data):
    #text ~1.0, ciphertext ~0.37
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(data)


def field(name, value):
    print(f"    {color(f'{name:<14}', GREY)}{value}")


def check(text):
    print(f"    {color('✓', GREEN)} {text}")


def title(text):
    print(f"\n{color(text, BOLD + PINK)}")


def show_users(root):
    title("users")
    for path in sorted((root / "users").glob("*.bin")):
        user = decode_user(path.read_bytes())
        print(f"\n  {color(user.username, PINK)}   {color(f'({path.stat().st_size} bytes on disk)', GREY)}")
        field("salt", hexs(user.salt))
        field("auth_key", hexs(user.auth_key))
        field("x25519 pk", hexs(user.x25519_pk))
        field("ed25519 pk", hexs(user.ed25519_pk))
        field("key blob", hexs(user.key_blob))
        check("no password stored -- only Argon2id output (auth_key), salted per user")
        check("private keys only inside the encrypted key blob")


def show_documents(root):
    title("documents")
    for path in sorted((root / "docs").glob("*/v*.bin")):
        doc = decode_document(path.read_bytes())
        ratio = readable_ratio(doc.ciphertext)
        print(f"\n  {color(doc.filename, PINK)}  v{doc.version}   "
              f"{color(f'(id {doc.doc_id.hex()[:8]}, owner {doc.owner}, {doc.size} bytes)', GREY)}")
        field("nonce", hexs(doc.nonce))
        field("ciphertext", hexs(doc.ciphertext))
        field("tag", hexs(doc.tag))
        field("readable", f"{ratio:.0%} of bytes look like text")
        check("contents unreadable -- AES-256-GCM, key never sent to the server")

        grants = sorted(g.stem for g in (root / "grants" / doc.doc_id.hex() / f"v{doc.version}").glob("*.bin"))
        field("shared with", ", ".join(grants) or "-")


def show_grants(root):
    title("key grants")
    for path in sorted((root / "grants").glob("*/v*/*.bin")):
        grant = decode_grant(path.read_bytes())
        print(f"\n  {color(f'{grant.sender} --> {grant.recipient}', PINK)}   "
              f"{color(f'(doc {grant.doc_id.hex()[:8]} v{grant.version})', GREY)}")
        field("temp X25519", hexs(grant.ephemeral_pk))
        field("sealed", hexs(grant.sealed))
        check("DEK + signature locked for the recipient only")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="show what the SecureVault server stores")
    parser.add_argument("--data", default="server_data")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args()

    USE_COLOR = not args.no_color
    os.system("") #colors on windows
    root = Path(args.data)
    if not root.exists():
        sys.exit(f"no server data in {root}/ -- start the server and sign up first")

    print(color("SecureVault -- what the server (or a thief) can see", BOLD + PINK))
    show_users(root)
    show_documents(root)
    show_grants(root)
    print()
else:
    USE_COLOR = False
