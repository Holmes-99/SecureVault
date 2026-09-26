import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

import pytest
import keys
from client.client import VaultClient, Connection, ClientError
from secure_share import Rejected, MODIFIED, STALE
from server.server import VaultServer, TCPServer, REJECTED
from attacks.attacker import Attacker, Proxy

# real sockets: client --> attacker proxy --> server


@pytest.fixture(autouse=True)
def fast_argon2(monkeypatch):
    monkeypatch.setattr(keys, "ARGON2", dict(time_cost=1, memory_cost=64, parallelism=1))


@pytest.fixture
def net(tmp_path):
    server = TCPServer(("127.0.0.1", 0), VaultServer(tmp_path / "server"))
    attacker = Attacker(server.server_address, quiet=True)
    proxy = Proxy(("127.0.0.1", 0), attacker)
    for s in (server, proxy):
        threading.Thread(target=s.serve_forever, daemon=True).start()

    def client(name):
        c = VaultClient(Connection(*proxy.server_address).send, tmp_path / f"{name}_pc")
        c.signup(name, f"{name}-pass")
        return c

    thesis = tmp_path / "thesis-draft.pdf"
    thesis.write_bytes(b"%PDF-1.7 Layla's thesis " * 20)
    yield attacker, client, thesis, tmp_path
    for s in (server, proxy):
        s.shutdown()
        s.server_close()


def shared(client, thesis):
    layla, omar = client("layla"), client("omar")
    doc_id = layla.upload(thesis)
    layla.contact("omar"), omar.contact("layla")
    layla.verify("omar"), omar.verify("layla")
    layla.share(doc_id, "omar")
    return layla, omar, doc_id


def test_pass_mode_changes_nothing(net):
    attacker, client, thesis, tmp = net
    layla, omar, doc_id = shared(client, thesis)
    path, sender, _ = omar.download(doc_id, tmp / "out")
    assert path.read_bytes() == thesis.read_bytes() and sender == "layla"

def test_flip_is_detected(net):
    attacker, client, thesis, tmp = net
    layla, omar, doc_id = shared(client, thesis)
    attacker.mode = "flip"
    with pytest.raises(Rejected) as e:
        omar.download(doc_id, tmp / "out")
    assert str(e.value) == MODIFIED

def test_rename_is_detected(net):
    attacker, client, thesis, tmp = net
    layla, omar, doc_id = shared(client, thesis)
    attacker.mode = "rename"
    with pytest.raises(Rejected) as e:
        omar.download(doc_id, tmp / "out")
    assert str(e.value) == MODIFIED

def test_replay_is_stale(net):
    attacker, client, thesis, tmp = net
    layla, omar, doc_id = shared(client, thesis)
    omar.download(doc_id, tmp / "out")          #attacker records v1

    thesis.write_bytes(b"%PDF-1.7 fixed version")
    layla.update(doc_id, thesis)
    layla.share(doc_id, "omar")
    omar.download(doc_id, tmp / "out")          #omar sees v2

    attacker.mode = "replay"
    with pytest.raises(Rejected) as e:
        omar.download(doc_id, tmp / "out")
    assert str(e.value) == STALE

def test_swapped_key_shows_different_safety_number(net):
    attacker, client, thesis, tmp = net
    layla, omar = client("layla"), client("omar")
    real = omar.contact("layla")
    attacker.mode = "swapkey"
    assert layla.contact("omar") != real

def test_swapped_key_later_is_blocked(net):
    attacker, client, thesis, tmp = net
    layla, omar = client("layla"), client("omar")
    layla.contact("omar")                       #pinned the real key
    attacker.mode = "swapkey"
    with pytest.raises(ClientError):
        layla.contact("omar")

def test_resent_request_is_refused(net):
    attacker, client, thesis, tmp = net
    layla = client("layla")
    layla.list()                                #a signed request goes by
    assert attacker.resend() == REJECTED
