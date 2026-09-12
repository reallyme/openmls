#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT

"""Seed unequal provider input lengths so bounded fuzz runs reach crypto parsing.

These public, synthetic zero-filled inputs are deliberately unauthenticated.
They are not conformance vectors or usable production key material.
"""

from pathlib import Path
import struct


def main() -> None:
    corpus = Path(__file__).resolve().parent / "corpus" / "reallyme_provider_boundaries"
    corpus.mkdir(parents=True, exist_ok=True)
    # Selector, encapsulation/ciphertext/private-key lengths for HPKE; or
    # message/public-key/signature lengths for signature verification.
    profiles = (
        ("xwing", 0, 1120, 16, 32),
        ("mlkem1024_p384", 2, 1568, 16, 64),
        ("mlkem1024_mldsa87", 4, 1568, 16, 64),
        ("mlkem1024p384", 6, 1665, 16, 32),
        ("ed25519", 1, 0, 32, 64),
        ("p384", 3, 0, 97, 104),
        ("mldsa87", 5, 0, 2592, 4627),
    )
    for name, selector, first_length, second_length, third_length in profiles:
        header = struct.pack("<BHH", selector, first_length, second_length)
        body = bytes(first_length + second_length + third_length)
        (corpus / name).write_bytes(header + body)
        # Keep truncated fields in the initial corpus as well as exact lengths.
        (corpus / f"{name}_truncated").write_bytes(header + body[:-1])


if __name__ == "__main__":
    main()
