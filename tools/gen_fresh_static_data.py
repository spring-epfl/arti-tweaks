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

PATH_CONSENSUS_OUT = Path("./consensus.txt")
PATH_MICRODESCRIPTORS_OUT = Path("./microdescriptors.txt")

FLAG_BAD_EXIT = "BadExit"
FLAG_EXIT = "Exit"
FLAG_FAST = "Fast"
FLAG_GUARD = "Guard"
FLAG_STABLE = "Stable"

# We only keep one authority vote.
CONSENSUS_HEADER = b"""network-status-version 3 microdesc
vote-status consensus
consensus-method 30
valid-after 2021-06-08 06:00:00
fresh-until 2022-06-08 07:00:00
valid-until 2023-06-08 09:00:00
voting-delay 300 300
client-versions 0.3.5.10,0.3.5.11,0.3.5.12,0.3.5.13,0.3.5.14,0.3.5.15,0.4.4.1-alpha,0.4.4.2-alpha,0.4.4.3-alpha,0.4.4.4-rc,0.4.4.5,0.4.4.6,0.4.4.7,0.4.4.8,0.4.4.9,0.4.5.1-alpha,0.4.5.2-alpha,0.4.5.3-rc,0.4.5.4-rc,0.4.5.5-rc,0.4.5.6,0.4.5.7,0.4.5.8,0.4.5.9,0.4.6.1-alpha,0.4.6.2-alpha,0.4.6.3-rc,0.4.6.4-rc,0.4.6.5
server-versions 0.3.5.10,0.3.5.11,0.3.5.12,0.3.5.13,0.3.5.14,0.3.5.15,0.4.4.1-alpha,0.4.4.2-alpha,0.4.4.3-alpha,0.4.4.4-rc,0.4.4.5,0.4.4.6,0.4.4.7,0.4.4.8,0.4.4.9,0.4.5.1-alpha,0.4.5.2-alpha,0.4.5.3-rc,0.4.5.4-rc,0.4.5.5-rc,0.4.5.6,0.4.5.7,0.4.5.8,0.4.5.9,0.4.6.1-alpha,0.4.6.2-alpha,0.4.6.3-rc,0.4.6.4-rc,0.4.6.5
known-flags Authority BadExit Exit Fast Guard HSDir NoEdConsensus Running Stable StaleDesc Sybil V2Dir Valid
recommended-client-protocols Cons=2 Desc=2 DirCache=2 HSDir=2 HSIntro=4 HSRend=2 Link=4-5 Microdesc=2 Relay=2
recommended-relay-protocols Cons=2 Desc=2 DirCache=2 HSDir=2 HSIntro=4 HSRend=2 Link=4-5 LinkAuth=3 Microdesc=2 Relay=2
required-client-protocols Cons=2 Desc=2 Link=4 Microdesc=2 Relay=2
required-relay-protocols Cons=2 Desc=2 DirCache=2 HSDir=2 HSIntro=4 HSRend=2 Link=4-5 LinkAuth=3 Microdesc=2 Relay=2
params CircuitPriorityHalflifeMsec=30000 DoSCircuitCreationEnabled=1 DoSConnectionEnabled=1 DoSConnectionMaxConcurrentCount=50 DoSRefuseSingleHopClientRendezvous=1 ExtendByEd25519ID=1 KISTSchedRunInterval=2 NumDirectoryGuards=3 NumEntryGuards=1 NumNTorsPerTAP=100 UseOptimisticData=1 bwauthpid=1 cbttestfreq=10 hs_service_max_rdv_failures=1 hsdir_spread_store=4 pb_disablepct=0 sendme_emit_min_version=1 usecreatefast=0
shared-rand-previous-value 9 pNuoMkYje+INHfh2V0B+SZCy+QRWLAJjTC1TRUkW18A=
shared-rand-current-value 9 sG4yOTssYKZmsKxby6H08zzcoFUcAIyUzfuv7WOIK2A=
dir-source dannenberg 0232AF901C31A04EE9848595AF9BB7620D4C5B2E dannenberg.torauth.de 193.23.244.244 80 443
contact Andreas Lehner
vote-digest 58B3AE3345A0C390F38AA3111CD3E89822FAEFB7
dir-source tor26 14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4 86.59.21.38 86.59.21.38 80 443
contact Peter Palfrader
vote-digest 66384959B777270D032A60FC1F4A5A0354BFFB23
dir-source longclaw 23D15D965BC35114467363C165C4F724B64B4F66 199.58.81.140 199.58.81.140 80 443
contact Riseup Networks <collective at riseup dot net> - 1nNzekuHGGzBYRzyjfjFEfeisNvxkn4RT
vote-digest 389F501BAA4D41893EAD0C6C6BD42663ED1DB78D
dir-source bastet 27102BC123E7AF1D4741AE047E160C91ADC76B21 204.13.164.118 204.13.164.118 80 443
contact stefani <nocat at readthefinemanual dot net> 4096/F4B863AD6642E7EE
vote-digest F398AC8FEE1200EDC215AA6B4F6FB40741FDBB06
dir-source maatuska 49015F787433103580E3B66A1707A00E60F2D15B 171.25.193.9 171.25.193.9 443 80
contact 4096R/1E8BF34923291265 Linus Nordberg <linus@nordberg.se>
vote-digest FE45F702A79F37CE9E579EE83F3BFB26651A957E
dir-source moria1 D586D18309DED4CD6D57C18FDB97EFA96D330566 128.31.0.34 128.31.0.34 9131 9101
contact 1024D/EB5A896A28988BF5 arma mit edu
vote-digest 84D014555ADB902E262B679F8A8E67D9C1C9BEB7
dir-source dizum E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58 45.66.33.45 45.66.33.45 80 443
contact FD790065EBBD5E7AE6D039620D7F81CD19147711 Alex de Joode <usura@sabotage.org>
vote-digest 33E472738FE473DC29E996C642DB2F40F15BF7F4
dir-source gabelmoo ED03BB616EB2F60BEC80151114BB25CEF515B226 131.188.40.189 131.188.40.189 80 443
contact 4096R/261C5FBE77285F88FB0C343266C8C2D7C5AA446D Sebastian Hahn <tor@sebastianhahn.net> - 12NbRAjAG5U3LLWETSF7fSTcdaz32Mu5CN
vote-digest 64237FB0E34DA0EC456DCF7C10B8F38C4C8EA4E2
dir-source Faravahar EFCBE720AB3A82B99F9E953CD5BF50F7EEFC7B97 154.35.175.225 154.35.175.225 80 443
contact 0x0B47D56D Sina Rabbani (inf0) <sina redteam net>
vote-digest 7EFBF41D678F2FBA602F0132D46E60B340536912
"""

# We only keep one authority signature.
CONSENSUS_FOOTER = b"""directory-footer
bandwidth-weights Wbd=0 Wbe=0 Wbg=4273 Wbm=10000 Wdb=10000 Web=10000 Wed=10000 Wee=10000 Weg=10000 Wem=10000 Wgb=10000 Wgd=0 Wgg=5727 Wgm=5727 Wmb=10000 Wmd=0 Wme=0 Wmg=4273 Wmm=10000
directory-signature sha256 0232AF901C31A04EE9848595AF9BB7620D4C5B2E 0AF48E6865839B2529BFB19DB8F97AFB3AAD2FFD
-----BEGIN SIGNATURE-----
NpVjPGNsGXTrrRmw7FXOj5mD0/SYo3CUAUFRA5DAr0rzF/BEL97rijNTzkivOfJi
eOUsPMnOuEXBE91a33Dv5KKDoL6UhQQ7WjM5nWu+PRvNnxkfG716ZvsU8S/3zkIH
tAzjeuT1kB/G2zPhXgEboPPphMA8L0ZwYLmgtAPKuTmcKqUXhsk4ZAI4eqbMgdh9
s4hS2+CSbXfQjHyUROpFJKJd4sKToUKZWumsQoTAizj2+F5RqJqBNo0T/OATKEvu
CLYwjaEfbVyn1juVtw9E8WHvGLGlAtxHkN+lIfWZtE3Vvdg3Kpx0CwslfQhGkTpB
xNTvfb1S8vKRH3y2qzkALA==
-----END SIGNATURE-----
directory-signature sha256 14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4 08C51820AE7A7457CD5C994E5D70F7153368520B
-----BEGIN SIGNATURE-----
KY6gZeqUUNbBVmE+GChfHnlPFWo2XN9148O6U/zFWsVSP3ea6kPtgghTtjdHRM0h
9h+jf1Lb4D1xFRPHRcda/J1yQxwxG4e1bEz98M38wWg63UKtEihGrT1zNj1Wm3aL
zU+xmFvRarRiHzdvWYdh7kLMRDkBodCiLu/aSg4NQaogWctqt2E4UH+IL9EWpMDO
s/xhqJNRSDLyIcmOZfp9Qw1uBqlmaGP4CEscZ4sLQ/CiEKiC582Xh87KkFUkhjvD
aWDpJ4Z6d+DuVnU0SNrwvk/hXspJJ1wHvhwBMLKlsXdfUljYf1Gja/ebWns9zS+j
n+ilIZk00wLcl7DY29UIq4n9jWo1NBKXcMxbDgCTY+b1uWunCmcDU5EUHF7g140Z
H/kVPUJFuMQpzxalIPGhhBt0ypRbHAB9FdPPdmhxRLc/DrDie1t5cYTZotlq2L+J
TkcwSd37nM2vr8R9GV0HnK5+oCAZqV/yedXIyLNfbo+OJSEhIV+w2OmM+FpONu5b
-----END SIGNATURE-----
directory-signature sha256 23D15D965BC35114467363C165C4F724B64B4F66 276FB81480D7A068340E71760935827BBF9E6513
-----BEGIN SIGNATURE-----
G0IpoPn4+0H/RSrxqQAO2wa8CkI3G9vV6FlHJM2pMBHyUjnfT4ROyWExDgQ5kZ3G
iMdQPD52nhOzNb4buM6XWeU9cci2YLg/PBXw78Qi978HyE0nKrZUnd1z0yGxTDf2
UM2jBhb7NAHA4kqa8SSdOg1iv1j+boA9BlcnJqDJLWyCed9xn5RTvno9+ovl9pSN
UbBw65/0O/DT7GPyPCwac/8VMM/86ofQEDjtV/1DMho4o+6O6+1PykA4KaZDu4zc
ncSbcLaYYYobe9gcqc2Kun6lGWbuHbODGaHhcQGSUfyjmqc1CkZGBFuORwfLfkAP
kwhM1tbWiEuFgff7HsN98Q==
-----END SIGNATURE-----
directory-signature sha256 27102BC123E7AF1D4741AE047E160C91ADC76B21 3FC8CFC044CB0B5030D421E5D201842020FA5683
-----BEGIN SIGNATURE-----
Eal7fIF+0tifP+h9WcAOA/LBFNYpbCPB0UVSOXDJbyJegdvJ86bz2nMSXGwjQovH
cT7AVHQv6pT7/SE3RaWhY9MKW3T/0XhkKiZpYjHZrMXiHvbVIJFVJdgPZAFSMHrz
/jtfmAYsjvAacmn+485bmKJXqHlbbNpwY2WomwbB8/+LP4Yg+dLH7YeZllbozvmd
ldlPFUJUxFhxd2zLKeSQsodoJ5aXubfjjxlSHoNY81VisxJ98qk0MF0KvCtWXzFM
4MP4Hv3BYMB+v5ZwhA9qhIh5HewALAuQx6j61ktuK+t/yb7U4wHcwCfliGBG1pdg
H21GEa8EFpssbmhJFnoHLg==
-----END SIGNATURE-----
directory-signature sha256 49015F787433103580E3B66A1707A00E60F2D15B A302F4C8FD6A48E5CC364C18B31949057D94D87D
-----BEGIN SIGNATURE-----
C6rJwdZSSjRpmOoBQ+wKzefhC7hopv8V6xMz6O/1jSzF/5lSHy8fgU7FW+tUQnii
zJGSzQ0kSqFDflWhKqIPJteXyTx69Pmvz/zWTC0jJunnEctrMmctpGofAPA2HrxD
YswgkGLOGyEE+/bTn8+I0s1Bxknylwx05nmGl8zL7QIMaFyIm9uCfzyV6QOgdHkT
bhsAepyoFfM4GP3c9wIZQodI9A6tC6IeCyp4nMrX0cg2tHKnglasbHj38Qk5ik8i
BY9aStbbzRI1prwwVBm6Cmbj9yDaOCOjEtiNeciDS/JRS8zmO9hEHT0x48geshHU
5Tk4BMToncSq/NK9q1RvMw==
-----END SIGNATURE-----
directory-signature sha256 D586D18309DED4CD6D57C18FDB97EFA96D330566 6D2D5D8A5AF3312B8A039F15B1B4471C23327C66
-----BEGIN SIGNATURE-----
Sa9ga9NoYWFSDpPHw6VmDsUyIdSDYnLJCZjuM7Bm9isvM+gwTTZjcJfx2i0Ah6cg
avp1DhDFvknDCbc1CZ7dXsC4U7LNfRskTeg/F+tZIeCaBeG21sBtC2xP7TriEHsd
Rhbouc1vvWNkAtbuXa6OH03Jtm8C0SqPcetRsxePpz5606RK04pXUnxo+sanGNsB
GDMovst8mkbGpC/U6JryfOnwE2SdotnsWGFkARSCwWZrfhgnh4MTx7SekzSlGzmB
El690c09l0l8MydHgJS8qOUEwB9SFWBljRsLs/gzKlEUEjaZ882RqHFeSZuhsgJn
BlJgeDgbvOmzn+aRwBStKA==
-----END SIGNATURE-----
directory-signature sha256 E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58 472B3A0BCDC5DBF1EB54A60FA32A2478D92C5D4E
-----BEGIN SIGNATURE-----
duMYaAuwpqe/ECMl7TVe3K8nFC2kfCcqQMrx7hpV8WGXMr6YmILLjMeAM2tX9sFs
hfDLJmC6z9vo73cakOVs8JaecbTTkIrLzvPxKef699tJb/f55+Hbv6UBa4GjnCPZ
KakyT5IBuQCx/zh3VWazbaFHxGtUHXsaJ0yyObox1t8sjl4dlA3uOssmSj5wx6Cz
WrGTYGV4EiYXEl4L3ZAQFKPulx2Nju/7gMn+pxC7OeJT4HjGFCLrFvAT/tQgHAGy
SGlkglxn6tt3GZSZWOs+TTbdXAE/re6frSGDaD1/jBipLZvv7Mc6Z+/mhkj7ym6K
Ltbfm3e6H+oC8PNebeLTig==
-----END SIGNATURE-----
directory-signature sha256 ED03BB616EB2F60BEC80151114BB25CEF515B226 C433D12EBDBA4E2644CAB7231A26035624278EE1
-----BEGIN SIGNATURE-----
Rm57nhQzYphZtAEmhFlkPMbzZ+vMtJ8q/8Jr4g872XoMqsU82+zKoIzCdQ7zrahW
9cRZhxbxXc6/jqYh0Y5VBDn96ihjmUM0XWbWIGWIe6RliKoKhPF8hBTWzJTOBsPZ
7PULPHadTzrBslBtFCBxsle+VwVZUdVRy0aDiB+k6vnwp+XGHdND+HN+ccq5NEUt
rlQeQtJKthXTcjbeyu12Wa7P/gWRrGwwe7GuG+FbMnwrZevEPzTdmNjfxwAImGuc
jFEs+JO+UDD87/EhusJ84OBitZf9EKt6OoJ6ayp1Hb6HlFUxvYrx9oAgHoMNgguB
YuWMdzYJAhhOgRB28RzSMg==
-----END SIGNATURE-----
directory-signature sha256 EFCBE720AB3A82B99F9E953CD5BF50F7EEFC7B97 21FB228258F9A729F88E86D83AB77F88C272C75D
-----BEGIN SIGNATURE-----
e669bEwHpFXPFIZLoTkF5pcyMcsTGGRnD9o9oyIcD4I37r74jPtxi4ITKfajvH0k
O4BQd6gU3his697edjr/s7gwwhf1WYNAKRYvpsI5Dcwt7tNokHisx8Z1PMwTir+s
iYJ+DXkD5XkbWsFIplpRqOGwUpTvlcHMRqA0t2EDdmWS2xEAlLc9eVD67fpkQZQ5
Bn8jFTB5Praj8XSDoMhnYTG/+EjSi0FX6Zn2ZuksNHHlXv/apKcBfOsLfe9yS/9r
bGBXLqM92OtYmdsrr4RS3yMrlXpy2lOFYRt5M9vDouEJWrVjgzuK9C8aRkyQMiO/
GM/pErtls3hbkULrup743A==
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


def generate_microdescriptors_rust(microdescriptors: List[Microdescriptor]) -> str:
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


def generate_microdescriptors(microdescriptors: List[Microdescriptor]) -> bytes:
    """
    Generate microdescriptors dcoument.
    """
    return b"".join(m.get_bytes() for m in microdescriptors)


def main() -> None:
    """
    Entrypoint of the program.
    """
    original_consensus = fetch_consensus()
    routers = select_routers(original_consensus)

    consensus = generate_consensus_dummy_signature(routers)

    microdescriptors = fetch_microdescriptors(routers)
    microdescriptors_code = generate_microdescriptors(microdescriptors)

    with PATH_CONSENSUS_OUT.open("wb") as consensus_fd:
        consensus_fd.write(consensus)

    with PATH_MICRODESCRIPTORS_OUT.open("wb") as microdescriptors_fd:
        microdescriptors_fd.write(microdescriptors_code)


if __name__ == "__main__":
    main()
