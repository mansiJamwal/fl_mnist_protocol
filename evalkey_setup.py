import argparse
from pathlib import Path

from openfhe import (
    BINARY,
    DeserializeCryptoContext,
    DeserializePrivateKey,
)

ROOT = Path("runtime")
PUBLIC_DIR = ROOT / "public"
PRIVATE_DIR = ROOT / "private"


def load_object(loader, path):
    obj, ok = loader(str(path), BINARY)

    if not ok:
        raise RuntimeError(f"Could not load {path}")

    return obj


def create_base_key():
    """
    Server 0 creates the initial multiplication evaluation key.

    Only Server 0's secret share is loaded in this operation.
    """

    cc = load_object(
        DeserializeCryptoContext,
        PUBLIC_DIR / "context.bin",
    )

    sk0 = load_object(
        DeserializePrivateKey,
        PRIVATE_DIR / "party_0" / "secret_key.bin",
    )

    # Initial evaluation-key contribution from Server 0.
    eval_key = cc.KeySwitchGen(sk0, sk0)

    key_tag = eval_key.GetKeyTag()

    # Insert the key so OpenFHE can serialize it.
    cc.InsertEvalMultKey([eval_key], key_tag)

    output_path = PUBLIC_DIR / "eval_mult_base.bin"

    if not cc.SerializeEvalMultKey(
        str(output_path),
        BINARY,
        key_tag,
    ):
        raise RuntimeError(
            "Failed to serialize the initial evaluation key"
        )

    # The tag is metadata, not secret-key material.
    (PUBLIC_DIR / "eval_mult_base.tag").write_text(
        key_tag,
        encoding="utf-8",
    )

    print("Server 0: base evaluation key generated")
    print(f"Public artifact: {output_path}")
    print("Key tag saved")


def check_base_key():
    """
    Load the serialized evaluation key into a fresh process
    and verify that OpenFHE can retrieve it.
    """

    cc = load_object(
        DeserializeCryptoContext,
        PUBLIC_DIR / "context.bin",
    )

    key_tag = (
        PUBLIC_DIR / "eval_mult_base.tag"
    ).read_text(encoding="utf-8").strip()

    ok = cc.DeserializeEvalMultKey(
        str(PUBLIC_DIR / "eval_mult_base.bin"),
        BINARY,
    )

    if not ok:
        raise RuntimeError(
            "Failed to deserialize the base evaluation key"
        )

    keys = cc.GetEvalMultKeyVector(key_tag)

    if not keys:
        raise RuntimeError(
            "The evaluation key was loaded but not found by its tag"
        )

    print("PASS: evaluation key survived serialization")
    print(f"Retrieved evaluation-key entries: {len(keys)}")


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--stage",
        required=True,
        choices=["base", "check-base"],
    )

    args = parser.parse_args()

    PUBLIC_DIR.mkdir(parents=True, exist_ok=True)

    if args.stage == "base":
        create_base_key()
    else:
        check_base_key()


if __name__ == "__main__":
    main()
