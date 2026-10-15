from pathlib import Path

from openfhe import (
    BINARY,
    ClearEvalMultKeys,
    DeserializeCryptoContext,
    DeserializePublicKey,
)

ROOT = Path("runtime")
PUBLIC_DIR = ROOT / "public"


def load_object(loader, path):
    obj, ok = loader(str(path), BINARY)

    if not ok:
        raise RuntimeError(f"Could not load {path}")

    return obj


def load_eval_key(cc, party_id):
    """
    Load one party's final evaluation-key contribution.

    The returned Python object is retained while we clear
    the context's evaluation-key cache.
    """

    ClearEvalMultKeys()

    key_path = (
        PUBLIC_DIR / f"eval_mult_final_contrib_{party_id}.bin"
    )
    tag_path = (
        PUBLIC_DIR / f"eval_mult_final_contrib_{party_id}.tag"
    )

    if not cc.DeserializeEvalMultKey(
        str(key_path),
        BINARY,
    ):
        raise RuntimeError(
            f"Could not deserialize contribution from Party {party_id}"
        )

    tag = tag_path.read_text(
        encoding="utf-8"
    ).strip()

    keys = cc.GetEvalMultKeyVector(tag)

    if not keys:
        raise RuntimeError(
            f"Could not retrieve Party {party_id}'s evaluation key"
        )

    key = keys[0]

    ClearEvalMultKeys()

    return key


def main():
    print("Loading BFV context...")

    cc = load_object(
        DeserializeCryptoContext,
        PUBLIC_DIR / "context.bin",
    )

    joint_public_key = load_object(
        DeserializePublicKey,
        PUBLIC_DIR / "joint_pk_4.bin",
    )

    # Load the five contributions.
    print("Loading five final contributions...")

    e0 = load_eval_key(cc, 0)
    e1 = load_eval_key(cc, 1)
    e2 = load_eval_key(cc, 2)
    e3 = load_eval_key(cc, 3)
    e4 = load_eval_key(cc, 4)

    # Follow OpenFHE's five-party combination order.
    print("Combining Parties 4 and 3...")
    e43 = cc.MultiAddEvalMultKeys(
        e4,
        e3,
        e4.GetKeyTag(),
    )

    print("Adding Party 2...")
    e243 = cc.MultiAddEvalMultKeys(
        e2,
        e43,
        e2.GetKeyTag(),
    )

    print("Adding Party 1...")
    e1243 = cc.MultiAddEvalMultKeys(
        e1,
        e243,
        e1.GetKeyTag(),
    )

    print("Adding Party 0...")
    final_key = cc.MultiAddEvalMultKeys(
        e0,
        e1243,
        joint_public_key.GetKeyTag(),
    )

    # Clear previously loaded contribution entries before
    # registering the final collective key.
    ClearEvalMultKeys()
    cc.InsertEvalMultKey([final_key])

    final_tag = final_key.GetKeyTag()

    output_path = (
        PUBLIC_DIR / "eval_mult_final.bin"
    )
    tag_path = (
        PUBLIC_DIR / "eval_mult_final.tag"
    )

    if not cc.SerializeEvalMultKey(
        str(output_path),
        BINARY,
        final_tag,
    ):
        raise RuntimeError(
            "Could not serialize final collective evaluation key"
        )

    tag_path.write_text(
        final_tag,
        encoding="utf-8",
    )

    print("\nPASS: final multiplication key generated.")
    print(f"Saved: {output_path}")
    print(f"Key tag: {final_tag}")


if __name__ == "__main__":
    main()

