import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

import pytest
import keys
from client.client import VaultClient
from server.server import VaultServer
from tools import show_server_data as view

PASSWORD = "Layla@BirZeit2026"
SECRET = b"CHAPTER ONE: the secret results of my thesis"


@pytest.fixture(autouse=True)
def fast_argon2(monkeypatch):
    monkeypatch.setattr(keys, "ARGON2", dict(time_cost=1, memory_cost=64, parallelism=1))


def test_stolen_data_shows_no_password_and_no_text(tmp_path, capsys):
    server = VaultServer(tmp_path / "server")
    layla = VaultClient(server.handle, tmp_path / "layla_pc")
    omar = VaultClient(server.handle, tmp_path / "omar_pc")
    layla.signup("layla", PASSWORD)
    omar.signup("omar", "Omar@2026")

    thesis = tmp_path / "thesis.pdf"
    thesis.write_bytes(SECRET)
    doc_id = layla.upload(thesis)
    layla.contact("omar")
    layla.verify("omar")
    layla.share(doc_id, "omar")

    view.show_users(server.root)
    view.show_documents(server.root)
    view.show_grants(server.root)
    out = capsys.readouterr().out

    assert "layla" in out and "omar" in out and "thesis.pdf" in out
    #no password, no file text (not even hex)
    assert PASSWORD not in out and PASSWORD.encode().hex() not in out.replace(" ", "")
    assert b"CHAPTER" not in out.encode() and SECRET[:16].hex() not in out.replace(" ", "")

def test_ciphertext_does_not_look_like_text():
    assert view.readable_ratio(b"plain english text here") == 1.0
    assert view.readable_ratio(os.urandom(4096)) < 0.5
