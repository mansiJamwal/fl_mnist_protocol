import argparse
import os
from pathlib import Path

from openfhe import (
    BINARY,
    SerializeToFile,
    DeserializeCryptoContext,
    DeserializePrivateKey,
    DeserializeCiphertext,
)

ROOT = Path("runtime")


def load_object(loader, path):
    obj, ok = loader(str(path), BINARY)

    if not ok:
        raise RuntimeError(f"Could not deserialize {path}")

    return obj


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--party",
        type=int,
        required=True,
        choices=range(5),
    )
    args = parser.parse_args()

    party_id = args.party

    cc = load_object(
        DeserializeCryptoContext,
        ROOT / "public" / "context.bin",
    )

    secret_key = load_object(
        DeserializePrivateKey,
        ROOT / "private" / f"party_{party_id}" / "secret_key.bin",
    )

    ciphertext = load_object(
        DeserializeCiphertext,
        ROOT / "ciphertexts" / "test_ct.bin",
    )

    # Party 0 creates the lead partial decryption.
    # The remaining parties create main partial decryptions.
    if party_id == 0:
        partials = cc.MultipartyDecryptLead(
            [ciphertext],
            secret_key,
        )
    else:
        partials = cc.MultipartyDecryptMain(
            [ciphertext],
            secret_key,
        )

    output_path = (
        ROOT / "partials" / f"party_{party_id}.bin"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not SerializeToFile(
        str(output_path),
        partials[0],
        BINARY,
    ):
        raise RuntimeError(
            f"Could not save partial decryption for party {party_id}"
        )

    os.chmod(output_path, 0o600)

    print(f"Party {party_id}: partial decryption produced")


if __name__ == "__main__":
    main()
