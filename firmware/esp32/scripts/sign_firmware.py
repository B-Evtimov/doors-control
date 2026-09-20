"""Sign a firmware image so a controller will accept it.

    python sign_firmware.py --image .pio/build/esp32dev/firmware.bin \
                            --version 1.1.0 --key-file ota-private.key

Prints the manifest to stdout. The private key is read from a file that is not
in this repository and never committed; the matching public key is compiled
into config.h as ACS_OTA_PUBLIC_KEY.

The signature covers the version, the size and the hash together, not the hash
alone: signing only the hash would let someone keep a valid signature while
serving a different image under a different version string.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DOMAIN = "acs-ota:v1"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--url", default="https://updates.example.invalid/firmware.bin")
    parser.add_argument("--key-file", required=True, type=Path,
                        help="raw 32 byte Ed25519 private key, base64 on one line")
    args = parser.parse_args()

    if not args.image.is_file():
        sys.exit(f"no such image: {args.image}")

    image = args.image.read_bytes()
    digest = hashlib.sha256(image).digest()
    digest_b64 = base64.b64encode(digest).decode()

    private_raw = base64.b64decode(args.key_file.read_text().strip(), validate=True)
    if len(private_raw) != 32:
        sys.exit("the key file must contain exactly 32 base64 encoded bytes")

    signed_text = f"{DOMAIN}|{args.version}|{len(image)}|{digest_b64}"
    signature = Ed25519PrivateKey.from_private_bytes(private_raw).sign(
        signed_text.encode("utf-8")
    )

    print(json.dumps(
        {
            "version": args.version,
            "url": args.url,
            "size": len(image),
            "sha256": digest_b64,
            "signature": base64.b64encode(signature).decode(),
        },
        indent=2,
    ))


if __name__ == "__main__":
    main()
