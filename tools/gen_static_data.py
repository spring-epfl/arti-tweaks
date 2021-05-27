#!/usr/bin/env python3

"""
Util to convert data cached by vanilla Arti into some code which is possible to side-load into Arti.
"""

import sqlite3
from pathlib import Path
from typing import List, Tuple

DATABASE_PATH = Path("dir.sqlite3")
CERTIFICATES_PATH = Path("certificates.in")
MICRODESCRIPTORS_PATH = Path("microdescriptors.in")


class BinStr:
    """
    Binary representation string.

    :param hex_str: binary string in hexadecimal format
    """

    def __init__(self, hex_str: str):
        self.hex_str = hex_str

    def rust(self) -> str:
        """
        Produce a binary string undesrstandable by the Rust programming language.

        :return: binary string in a format understandable by Rust
        """
        return "*b\"" + "".join(r"\x" + self.hex_str[i:i + 2] for i in range(0, len(self.hex_str), 2)) + "\""


class Certificate:
    """
    A certificate
    """

    def __init__(self, id_digest: str, sk_digest: str, contents: str):
        self.id_digest = BinStr(id_digest)
        self.sk_digest = BinStr(sk_digest)
        self.contents = contents

    def rust(self) -> str:
        """
        A representation of the certificate dependant on our static data structctures.
        """
        id_digest = self.id_digest.rust()
        sk_digest = self.sk_digest.rust()
        code = f"StaticCert{{id_fingerprint: { id_digest }, sk_fingerprint: { sk_digest }, contents: \"{ self.contents }\"}}"
        return code


class Microdescriptor:
    """
    A microdescriptor
    """

    def __init__(self, digest: str, contents: str):
        self.digest = BinStr(digest)
        self.contents = contents

    def rust(self) -> str:
        """
        A representation of the microdescriptor dependant on our static data structctures.
        """
        digest = self.digest.rust()
        code = f"StaticMicrodescriptor{{digest: { digest }, contents: \"{ self.contents }\"}}"
        return code


def fetch_from_db() -> Tuple[List[Certificate], List[Microdescriptor]]:
    """
    Retrieve all data from the DB.
    """
    con = sqlite3.connect(str(DATABASE_PATH))
    cur = con.cursor()
    certificates = list()
    microdescriptors = list()

    for row in cur.execute("SELECT id_digest, sk_digest, contents FROM Authcerts;"):
        certificate = Certificate(*row)
        certificates.append(certificate)

    for row in cur.execute("SELECT sha256_digest, contents FROM Microdescs;"):
        microdescriptor = Microdescriptor(*row)
        microdescriptors.append(microdescriptor)

    return certificates, microdescriptors


def usage():
    """
    Display usage info.
    """
    print(f"Please, run this script in the directory containing '{str(DATABASE_PATH)}'.")


def main():
    """
    Entrypoint of the program
    """

    if not DATABASE_PATH.is_file():
        usage()
        return

    certificates, microdescriptors = fetch_from_db()
    cert_code = [cert.rust() for cert in certificates]
    output = "[\n" + ",\n".join(cert_code) + "]"

    with CERTIFICATES_PATH.open("w") as certificates_fd:
        certificates_fd.write(output)

    microdesc_code = [micro.rust() for micro in microdescriptors]
    output = "[\n" + ",\n".join(microdesc_code) + "]"

    with MICRODESCRIPTORS_PATH.open("w") as microdescriptors_fd:
        microdescriptors_fd.write(output)


if __name__ == "__main__":
    main()
