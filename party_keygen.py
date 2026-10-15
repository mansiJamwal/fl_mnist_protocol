import argparse
import os
from pathlib import Path

from openfhe import (
    BINARY,
    SerializeToFile,
    DeserializeCryptoContext,
    DeserializePublicKey,
)

from threshold_bfv import create_crypto_context

ROOT = Path("runtime")


def save_object(path, obj):
    """Serialize an OpenFHE object and fail on errors."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if not SerializeToFile(str(path), obj, BINARY):
        raise RuntimeError(f"Could not serialize {path}")


def load_object(loader, path):
    """Deserialize an OpenFHE object and check success."""
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

    public_dir = ROOT / "public"
    private_dir = ROOT / "private" / f"party_{party_id}"

    public_dir.mkdir(parents=True, exist_ok=True)
    private_dir.mkdir(parents=True, exist_ok=True)

    # Only party 0 creates the initial context.
    context_path = public_dir / "context.bin"

    if party_id == 0:
        cc = create_crypto_context()
        save_object(context_path, cc)

        key_pair = cc.KeyGen()

        if not key_pair.good():
            raise RuntimeError("Initial key generation failed")

    else:
        # Load the same context and preceding joint public key.
        cc = load_object(
            DeserializeCryptoContext,
            context_path,
        )

        previous_public_key_path = (
            public_dir / f"joint_pk_{party_id - 1}.bin"
        )

        previous_public_key = load_object(
            DeserializePublicKey,
            previous_public_key_path,
        )

        # Generate this party's share and the updated joint key.
        key_pair = cc.MultipartyKeyGen(previous_public_key)

        if not key_pair.good():
            raise RuntimeError(
                f"Multiparty key generation failed for party {party_id}"
            )

    # Keep the secret share in this party's own directory.
    secret_key_path = private_dir / "secret_key.bin"
    save_object(secret_key_path, key_pair.secretKey)
    os.chmod(secret_key_path, 0o600)

    # Publish the current combined public key.
    public_key_path = public_dir / f"joint_pk_{party_id}.bin"
    save_object(public_key_path, key_pair.publicKey)

    print(f"Party {party_id}: key generation complete")
    print(f"Party {party_id}: secret share saved locally")
    print(f"Party {party_id}: joint public key published")


if __name__ == "__main__":
    main()

