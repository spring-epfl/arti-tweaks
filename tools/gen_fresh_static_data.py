#!/usr/bin/env python3

"""
Fetch a fresh consensus, select a subset of the routers, and generate code to use them in Arti.
"""

from base64 import b64encode
from hashlib import sha256
from heapq import nlargest
from math import ceil
from itertools import zip_longest
from pathlib import Path
from typing import List

from stem.descriptor import DocumentHandler
from stem.descriptor.microdescriptor import Microdescriptor
from stem.descriptor.networkstatus import NetworkStatusDocumentV3
from stem.descriptor.remote import (
    DescriptorDownloader,
    MAX_MICRODESCRIPTOR_HASHES
)
from stem.descriptor.router_status_entry import RouterStatusEntryMicroV3

PATH_CONSENSUS_OUT = Path("./consensus.in")
PATH_MICRODESCRIPTORS_OUT = Path("./microdescriptors.in")

FLAG_BAD_EXIT = "BadExit"
FLAG_EXIT = "Exit"
FLAG_FAST = "Fast"
FLAG_GUARD = "Guard"
FLAG_STABLE = "Stable"

# We only keep one authority vote.
CONSENSUS_HEADER = b"""network-status-version 3 microdesc
vote-status consensus
consensus-method 30
valid-after 2021-05-18 13:00:00
fresh-until 2022-05-18 14:00:00
valid-until 2023-05-18 16:00:00
voting-delay 300 300
client-versions 0.3.5.10,0.3.5.11,0.3.5.12,0.3.5.13,0.3.5.14,0.4.3.3-alpha,0.4.3.4-rc,0.4.3.5,0.4.3.6,0.4.3.7,0.4.3.8,0.4.4.1-alpha,0.4.4.2-alpha,0.4.4.3-alpha,0.4.4.4-rc,0.4.4.5,0.4.4.6,0.4.4.7,0.4.4.8,0.4.5.1-alpha,0.4.5.2-alpha,0.4.5.3-rc,0.4.5.4-rc,0.4.5.5-rc,0.4.5.6,0.4.5.7,0.4.5.8,0.4.6.1-alpha,0.4.6.2-alpha,0.4.6.3-rc
server-versions 0.3.5.10,0.3.5.11,0.3.5.12,0.3.5.13,0.3.5.14,0.4.3.3-alpha,0.4.3.4-rc,0.4.3.5,0.4.3.6,0.4.3.7,0.4.3.8,0.4.4.1-alpha,0.4.4.2-alpha,0.4.4.3-alpha,0.4.4.4-rc,0.4.4.5,0.4.4.6,0.4.4.7,0.4.4.8,0.4.5.1-alpha,0.4.5.2-alpha,0.4.5.3-rc,0.4.5.4-rc,0.4.5.5-rc,0.4.5.6,0.4.5.7,0.4.5.8,0.4.6.1-alpha,0.4.6.2-alpha,0.4.6.3-rc
known-flags Authority BadExit Exit Fast Guard HSDir NoEdConsensus Running Stable StaleDesc Sybil V2Dir Valid
recommended-client-protocols Cons=2 Desc=2 DirCache=2 HSDir=2 HSIntro=4 HSRend=2 Link=4-5 Microdesc=2 Relay=2
recommended-relay-protocols Cons=2 Desc=2 DirCache=2 HSDir=2 HSIntro=4 HSRend=2 Link=4-5 LinkAuth=3 Microdesc=2 Relay=2
required-client-protocols Cons=2 Desc=2 Link=4 Microdesc=2 Relay=2
required-relay-protocols Cons=2 Desc=2 DirCache=2 HSDir=2 HSIntro=4 HSRend=2 Link=4-5 LinkAuth=3 Microdesc=2 Relay=2
params CircuitPriorityHalflifeMsec=30000 DoSCircuitCreationEnabled=1 DoSConnectionEnabled=1 DoSConnectionMaxConcurrentCount=50 DoSRefuseSingleHopClientRendezvous=1 ExtendByEd25519ID=1 KISTSchedRunInterval=2 NumDirectoryGuards=3 NumEntryGuards=1 NumNTorsPerTAP=100 UseOptimisticData=1 bwauthpid=1 cbttestfreq=10 hs_service_max_rdv_failures=1 hsdir_spread_store=4 pb_disablepct=0 sendme_emit_min_version=1 usecreatefast=0
shared-rand-previous-value 9 xeS8VpGNclV8Fm2n2GDKKl3LnyX4dhmRLK+Fi7omlAw=
shared-rand-current-value 9 eV6ITJnqCRsV1+0fNgT/LcIfRi1tdGn3RXMqWsZOfNY=
dir-source dannenberg 0232AF901C31A04EE9848595AF9BB7620D4C5B2E dannenberg.torauth.de 193.23.244.244 80 443
contact Andreas Lehner
vote-digest 424791814A9186012FEEBDC346C28832986794B2
"""

# We only keep one authority signature.
CONSENSUS_FOOTER = b"""directory-footer
bandwidth-weights Wbd=0 Wbe=0 Wbg=4225 Wbm=10000 Wdb=10000 Web=10000 Wed=10000 Wee=10000 Weg=10000 Wem=10000 Wgb=10000 Wgd=0 Wgg=5775 Wgm=5775 Wmb=10000 Wmd=0 Wme=0 Wmg=4225 Wmm=10000
directory-signature sha256 0232AF901C31A04EE9848595AF9BB7620D4C5B2E 0AF48E6865839B2529BFB19DB8F97AFB3AAD2FFD
-----BEGIN SIGNATURE-----
i45HjZiUR+3ob02xro3P6rR9OgiqnNqOZhEIH93R8FnJpP3TryG5VAyaUpOVbMxq
ZW41k/LteyNlhVAbG2g6Xa1s7Bs9cwxKBvkJ7W1pz8njy0c9P0XHJ9QoLo6Wpg/l
oHsidfVhQhlRtQFfiL+U8gkWIPvsblOrWM7iLm0Rcf6hvBc7dV2B3NbO0DO90joo
qzAl9kmuAN5IpnvzKBToWjrUQNZZvDud2g4LCGtbXQXAymYMKfKfFAS5TVk1barz
Ha0wqt1qVTMufFyz8Fl4qBdTot/zFJtaPaQmdR0p33N/6nEmN5LszovinLt1B+5K
mHbEZDVZnHLMN9Qkm7jN1g==
-----END SIGNATURE-----
"""


def fetch_consensus() -> NetworkStatusDocumentV3:
    """
    Fetch the consensus, and validate it.
    """
    downloader = DescriptorDownloader()

    # TODO: Somehow the validation done by Stem fails...
    consensus = downloader.get_consensus(
        document_handler=DocumentHandler.DOCUMENT,
        microdescriptor=True,
        #validate=True
    ).run()[0]

    if not isinstance(consensus, NetworkStatusDocumentV3):
        raise TypeError(f"Not retrieved consensus but {type(consensus)}")

    return consensus


def fetch_microdescriptors(routers: List[RouterStatusEntryMicroV3]) -> List[Microdescriptor]:
    """
    Fetch the microdescriptors.
    """
    downloader = DescriptorDownloader()
    microdescriptors = list()
    buckets = [
        iter(r.microdescriptor_digest for r in routers)
    ] * MAX_MICRODESCRIPTOR_HASHES
    for bucket in zip_longest(*buckets):
        hashes = [h for h in bucket if h is not None]
        microdescriptors += downloader.get_microdescriptors(hashes=hashes, validate=True).run()

    for microdescriptor in microdescriptors:
        if not isinstance(microdescriptor, Microdescriptor):
            raise TypeError(f"Not retrieved microdescriptor but {type(microdescriptor)}")

    # TODO: Validate microdescriptor

    return microdescriptors



def select_routers(
        consensus: NetworkStatusDocumentV3,
        guard_ratio: float = 0.5,
        exit_ratio: float = 0.5,
        n_routers: int = 512
    ) -> List[RouterStatusEntryMicroV3]:
    """
    Select the routers with the highest available bandwidth matching the criteria.

    :param consensus: The consensus containing the routers descriptions
    :param guard_ratio: the minimal ratio of guards routers that we want
    :param exit_ratio: the minimal ratio of exit routers that we want
    :param n_routers: the final number of routers that we would like
    """
    if guard_ratio < 0 or guard_ratio > 1:
        raise ValueError("Invalid ratio")

    if exit_ratio < 0 or exit_ratio > 1:
        raise ValueError("Invalid ratio")

    if n_routers > len(consensus.routers):
        raise ValueError("Not enough routers in consensus")

    n_guards = ceil(n_routers * guard_ratio)
    n_exits = ceil(n_routers * exit_ratio)

    # Sort routers by type.
    potential_guards: List[RouterStatusEntryMicroV3] = list()
    potential_exits: List[RouterStatusEntryMicroV3] = list()
    potential_middles: List[RouterStatusEntryMicroV3] = list()

    for router in consensus.routers.values():
        flags = set(router.flags)
        # We only consider stable routers
        # Which also have the guard flag to ensure a higher stability.
        if FLAG_STABLE in flags and FLAG_FAST in flags and FLAG_GUARD in flags:
            if FLAG_GUARD in flags:
                potential_guards.append(router)
            if FLAG_EXIT in flags and FLAG_BAD_EXIT not in flags:
                potential_exits.append(router)

            # We try to avoid using exit routers as potential middle nodes.
            if FLAG_EXIT not in flags:
                potential_middles.append(router)

    # We select the guards with the largest measured bandwidth.
    # Note that they can also act as exit nodes.
    guards = nlargest(n_guards, potential_guards, key=lambda r: r.bandwidth)

    selected_set = {router.fingerprint for router in guards}

    # We select the exit nodes which we do not have yet with the largest available bandwidth.
    # Note that they can also act as guards.
    exits = nlargest(n_exits, potential_exits, key=lambda r: r.bandwidth)

    for router in exits:
        selected_set.add(router.fingerprint)

    # We select some other routers based on their available bandwidth and provided we didn't already select them.
    # Note that some might also act as guard or exit.
    n_middles = n_routers - len(selected_set)
    middles = nlargest(n_middles, potential_middles, key=lambda r: r.bandwidth if r.fingerprint not in selected_set else 0)

    for router in middles:
        selected_set.add(router.fingerprint)

    selected = sorted(selected_set, key=lambda fingerprint: int(fingerprint, 16))

    routers = [consensus.routers[fingerprint] for fingerprint in selected]

    return routers


def generate_consensus_dummy_signature(routers: List[RouterStatusEntryMicroV3]) -> bytes:
    """
    Genetate a consensus containing the routers with a wrong signature.
    """
    return CONSENSUS_HEADER + b"".join(r.get_bytes() for r in routers) + CONSENSUS_FOOTER


def generate_microdescriptors_rust(microdescriptors: List[Microdescriptor]) -> bytes:
    """
    Generate Rust code for static microdescriptors data.
    """
    code = list()

    for microdescriptor in microdescriptors:
        microdescriptor_raw = microdescriptor.get_bytes()
        hexdigest = sha256(microdescriptor_raw).hexdigest()
        escaped_digest = "".join(r"\x" + hexdigest[i:i + 2] for i in range(0, len(hexdigest), 2))

        code.append(f"StaticMicrodescriptor{{\ndigest: *b\"{escaped_digest}\",\ncontents: \"{microdescriptor}\"}}")

    return "[" + ",\n".join(code) + "]"


def main() -> None:
    """
    Entrypoint of the program.
    """
    original_consensus = fetch_consensus()
    routers = select_routers(original_consensus)

    consensus = generate_consensus_dummy_signature(routers)

    microdescriptors = fetch_microdescriptors(routers)
    microdescriptors_code = generate_microdescriptors_rust(microdescriptors)

    with PATH_CONSENSUS_OUT.open("wb") as consensus_fd:
        consensus_fd.write(consensus)

    with PATH_MICRODESCRIPTORS_OUT.open("w") as microdescriptors_fd:
        microdescriptors_fd.write(microdescriptors_code)


if __name__ == "__main__":
    main()
