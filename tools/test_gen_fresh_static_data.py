from base64 import b64encode
from math import ceil
from pathlib import Path
from itertools import tee

import pytest

from stem.descriptor.microdescriptor import Microdescriptor
from stem.descriptor.networkstatus import NetworkStatusDocumentV3

from gen_fresh_static_data import (
    FLAG_EXIT,
    FLAG_GUARD,
    generate_consensus_dummy_signature,
    generate_microdescriptors_rust,
    select_routers
)

MICRODESCRIPTORS = [
"""onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAOi/yP3cE7ReZz2yYq3+uJVeF520qW7FEz8xNyyMEAGTeJe8gyhiJthd
fCQmRJ678rNvHTq4pl5gJqH/QvSEuGxm4+5Qz1tim2+tv9K0SZbKI0I1+Q8gg2gG
ShXO1W28ZBRSC+6MY29b8GFyyMs/vUTYSTyLpgFgW5kcFuR+BPNTAgMBAAE=
-----END RSA PUBLIC KEY-----
ntor-onion-key U7tjJtoAADZ79InM9GYvd+Rek7bHG4R4itrhkziIoxY
id ed25519 pur3uRuskkkHY48pKGG0CWQODAaeYhBXDBJqkcyI6Tk
""",
"""onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAJqu9AmsncF50qiHI3UpdYAYGS5NJyhaxo9n6lTJ31p/Ka7znok2cLU3
4yEjb5fJ/L2weAkXQpYcUuUkOqlxlX0oKmXFBPW8dJiwJwq0ACy6XGxrCBneWt0N
6QJx2xaFrDTYaZWFnOxAqKjIagxMiDofkSEjD5a3m92exo/EKKbBAgMBAAE=
-----END RSA PUBLIC KEY-----
ntor-onion-key hAw++P1jK6/O0EtIjdQs15VPcJ+AiC7j11BT0uDNcz8
id ed25519 RDfkoK10d6lI3Ar0H6ZHHL1lmqQzEgLqQl6l2nmzMm8
"""
]

def test_select_routers():
    """
    """
    consensus_path = Path("consensus.in")
    with consensus_path.open("rb") as consensus_fd:
        consensus_raw = consensus_fd.read()

    consensus = NetworkStatusDocumentV3(consensus_raw)

    routers = select_routers(consensus)

    # The correct number of routers are selected.
    assert len(routers) == 512

    # We have enough of guards and exits
    n_guards = sum(map(lambda r: 1 if FLAG_GUARD in r.flags else 0, routers))
    n_exits = sum(map(lambda r: 1 if FLAG_EXIT in r.flags else 0, routers))

    assert n_guards > ceil(512 * 0.5)
    assert n_exits > ceil(512 * 0.5)

    # The routers are ordered.
    a, b = tee(routers)
    next(b, None)
    for r1, r2 in zip(a, b):
        assert int(r1.fingerprint, 16) < int(r2.fingerprint, 16)


def test_generate_consensus_dummy_signature():
    consensus_path = Path("consensus.in")
    with consensus_path.open("rb") as consensus_fd:
        consensus_raw = consensus_fd.read()

    original_consensus = NetworkStatusDocumentV3(consensus_raw)

    routers = select_routers(original_consensus)
    consensus = generate_consensus_dummy_signature(routers)

    #print(consensus.decode("ASCII"))


def test_generate_microdescriptors_rust():
    microdescriptors = [Microdescriptor(m) for m in MICRODESCRIPTORS]

    code = generate_microdescriptors_rust(microdescriptors)
    print(code)

