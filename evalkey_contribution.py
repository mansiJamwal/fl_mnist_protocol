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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--party",
        type=int,
        choices=range(1, 5),
        required=True,
    )
    args = parser.parse_args()

    party_id = args.party

    print(f"Party {party_id}: loading public context...")

    cc = load_object(
        DeserializeCryptoContext,
        PUBLIC_DIR / "context.bin",
    )

    print(f"Party {party_id}: loading its secret share...")

    secret_key = load_object(
        DeserializePrivateKey,
        PRIVATE_DIR / f"party_{party_id}" / "secret_key.bin",
    )

    base_path = PUBLIC_DIR / "eval_mult_base.bin"
    base_tag_path = PUBLIC_DIR / "eval_mult_base.tag"

    if not base_path.exists() or not base_tag_path.exists():
        raise FileNotFoundError(
            "Run `python evalkey_setup.py --stage base` first."
        )

    base_tag = base_tag_path.read_text(
        encoding="utf-8"
    ).strip()

    print(f"Party {party_id}: loading the initial evaluation key...")

    if not cc.DeserializeEvalMultKey(
        str(base_path),
        BINARY,
    ):
        raise RuntimeError("Could not deserialize initial evaluation key")

    base_keys = cc.GetEvalMultKeyVector(base_tag)

    if not base_keys:
        raise RuntimeError(
            "Initial evaluation key not found under its recorded tag"
        )

    base_eval_key = base_keys[0]

    print(f"Party {party_id}: generating its contribution...")

    contribution = cc.MultiKeySwitchGen(
        secret_key,
        secret_key,
        base_eval_key,
    )

    contribution_tag = contribution.GetKeyTag()

    # Insert this contribution into the local evaluation-key cache.
    cc.InsertEvalMultKey(
        [contribution],
        contribution_tag,
    )

    output_path = (
        PUBLIC_DIR / f"eval_mult_contrib_{party_id}.bin"
    )
    tag_path = (
        PUBLIC_DIR / f"eval_mult_contrib_{party_id}.tag"
    )

    if not cc.SerializeEvalMultKey(
        str(output_path),
        BINARY,
        contribution_tag,
    ):
        raise RuntimeError(
            f"Could not serialize party {party_id}'s contribution"
        )

    tag_path.write_text(
        contribution_tag,
        encoding="utf-8",
    )

    print(f"Party {party_id}: contribution generated.")
    print(f"Public artifact: {output_path}")


if __name__ == "__main__":
    main()
