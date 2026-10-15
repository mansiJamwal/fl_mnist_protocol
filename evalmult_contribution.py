import argparse
from pathlib import Path

from openfhe import (
    BINARY,
    ClearEvalMultKeys,
    DeserializeCryptoContext,
    DeserializePrivateKey,
    DeserializePublicKey,
)

ROOT = Path("runtime")
PUBLIC_DIR = ROOT / "public"
PRIVATE_DIR = ROOT / "private"


def load_object(loader, path):
    obj, ok = loader(str(path), BINARY)

    if not ok:
        raise RuntimeError(f"Could not load {path}")

    return obj


def load_eval_key(cc, key_path, tag_path):
    """Load one evaluation key and return its object."""

    ClearEvalMultKeys()

    if not cc.DeserializeEvalMultKey(
        str(key_path),
        BINARY,
    ):
        raise RuntimeError(
            f"Could not deserialize {key_path}"
        )

    tag = tag_path.read_text(
        encoding="utf-8"
    ).strip()

    keys = cc.GetEvalMultKeyVector(tag)

    if not keys:
        raise RuntimeError(
            f"No evaluation key found for tag {tag}"
        )

    key = keys[0]

    # Keep the Python reference to the key, but clear
    # the context cache before the next key operation.
    ClearEvalMultKeys()

    return key


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--party",
        type=int,
        choices=range(5),
        required=True,
    )
    args = parser.parse_args()

    party_id = args.party

    print(f"Party {party_id}: loading crypto context...")

    cc = load_object(
        DeserializeCryptoContext,
        PUBLIC_DIR / "context.bin",
    )

    print(f"Party {party_id}: loading its secret share...")

    secret_key = load_object(
        DeserializePrivateKey,
        PRIVATE_DIR
        / f"party_{party_id}"
        / "secret_key.bin",
    )

    joint_public_key = load_object(
        DeserializePublicKey,
        PUBLIC_DIR / "joint_pk_4.bin",
    )

    print("Loading the combined first-stage evaluation key...")

    combined_key = load_eval_key(
        cc,
        PUBLIC_DIR / "eval_mult_combined.bin",
        PUBLIC_DIR / "eval_mult_combined.tag",
    )

    print(
        f"Party {party_id}: computing MultiMultEvalKey..."
    )

    contribution = cc.MultiMultEvalKey(
        secret_key,
        combined_key,
        joint_public_key.GetKeyTag(),
    )

    contribution_tag = contribution.GetKeyTag()

    # Register only this party's new contribution.
    ClearEvalMultKeys()
    cc.InsertEvalMultKey([contribution])

    output_path = (
        PUBLIC_DIR
        / f"eval_mult_final_contrib_{party_id}.bin"
    )

    tag_path = (
        PUBLIC_DIR
        / f"eval_mult_final_contrib_{party_id}.tag"
    )

    if not cc.SerializeEvalMultKey(
        str(output_path),
        BINARY,
        contribution_tag,
    ):
        raise RuntimeError(
            f"Could not serialize Party {party_id}'s contribution"
        )

    tag_path.write_text(
        contribution_tag,
        encoding="utf-8",
    )

    print(f"Party {party_id}: contribution saved.")
    print(f"Artifact: {output_path}")


if __name__ == "__main__":
    main()
