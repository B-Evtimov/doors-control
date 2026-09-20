"""Generate an Ed25519 keypair for the signer or for a controller.

    python -m signer.keygen                 # signer keypair
    python -m signer.keygen --controller    # controller keypair plus a beacon key

Nothing is written to disk. Copy the private half into the environment of the
process that needs it and the public half into the database or the firmware
header, then close the terminal.
"""

from __future__ import annotations

import argparse
import base64
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def hex_c_array(raw: bytes, name: str) -> str:
    body = ", ".join(f"0x{b:02X}" for b in raw)
    return f"static const uint8_t {name}[{len(raw)}] = {{ {body} }};"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller", action="store_true",
                        help="also emit a beacon key and C arrays for the firmware")
    args = parser.parse_args()

    key = Ed25519PrivateKey.generate()
    private_raw = key.private_bytes_raw()
    public_raw = key.public_key().public_bytes_raw()

    if not args.controller:
        print("# signer keypair")
        print(f"ACS_SIGNER_PRIVATE_KEY={b64(private_raw)}")
        print(f"ACS_SIGNER_PUBLIC_KEY={b64(public_raw)}")
        print()
        print("# for firmware/esp32/include/config.h")
        print(hex_c_array(public_raw, "ACS_SIGNER_PUBLIC_KEY"))
        return

    beacon_key = os.urandom(32)
    print("# controller keypair - store the public key and beacon key in the database")
    print(f"public_key  (base64) = {b64(public_raw)}")
    print(f"beacon_key  (base64) = {b64(beacon_key)}")
    print()
    print("# for firmware/esp32/include/config.h - private key never leaves the board")
    print(hex_c_array(private_raw, "ACS_CONTROLLER_PRIVATE_KEY"))
    print(hex_c_array(public_raw, "ACS_CONTROLLER_PUBLIC_KEY"))
    print(hex_c_array(beacon_key, "ACS_BEACON_KEY"))


if __name__ == "__main__":
    main()
