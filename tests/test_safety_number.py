import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

from crypto.safety_number import safety_number
from crypto import ed25519, x25519


def make_user(name):
    return (name,
            ed25519.public_key(ed25519.generate_private_key()),
            x25519.public_key(x25519.generate_private_key()))


def test_format_is_5_groups_of_4_digits():
    num = safety_number(make_user("layla"), make_user("omar"))
    groups = num.split(" ")
    assert len(groups) == 5
    assert all(len(g) == 4 and g.isdigit() for g in groups)

def test_same_number_on_both_sides():
    layla, omar = make_user("layla"), make_user("omar")
    assert safety_number(layla, omar) == safety_number(omar, layla)

def test_deterministic():
    layla, omar = make_user("layla"), make_user("omar")
    assert safety_number(layla, omar) == safety_number(layla, omar)

def test_swapped_key_changes_number():
    #the MITM case: the server hands Layla its own key instead of Omar's
    layla, omar = make_user("layla"), make_user("omar")
    fake_omar = ("omar",) + make_user("attacker")[1:]
    assert safety_number(layla, omar) != safety_number(layla, fake_omar)

def test_swapped_x25519_key_alone_changes_number():
    layla, omar = make_user("layla"), make_user("omar")
    fake_omar = (omar[0], omar[1], x25519.public_key(x25519.generate_private_key()))
    assert safety_number(layla, omar) != safety_number(layla, fake_omar)

def test_username_is_bound():
    #same keys under a different name must not give the same number
    layla, omar = make_user("layla"), make_user("omar")
    renamed = ("mallory",) + omar[1:]
    assert safety_number(layla, omar) != safety_number(layla, renamed)
