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


def load_eval_key(cc, key_path, tag_path):
    """Load one serialized evaluation key and retrieve its entry."""

    if not cc.DeserializeEvalMultKey(
        str(key_path),
        BINARY,
    ):
        raise RuntimeError(
            f"Could not deserialize evaluation key: {key_path}"
        )

    tag = tag_path.read_text(encoding="utf-8").strip()
    keys = cc.GetEvalMultKeyVector(tag)

    if not keys:
        raise RuntimeError(
            f"No evaluation key found for tag {tag}"
        )

    return keys[0]


def main():
    print("Loading the public crypto context...")

    cc = load_object(
        DeserializeCryptoContext,
        PUBLIC_DIR / "context.bin",
    )

    # Party 0's initial KeySwitchGen contribution.
    combined = load_eval_key(
        cc,
        PUBLIC_DIR / "eval_mult_base.bin",
        PUBLIC_DIR / "eval_mult_base.tag",
    )

    print("Loaded Party 0's base evaluation key.")

    # Sequentially combine contributions from Parties 1-4.
    for party_id in range(1, 5):
        contribution = load_eval_key(
            cc,
            PUBLIC_DIR / f"eval_mult_contrib_{party_id}.bin",
            PUBLIC_DIR / f"eval_mult_contrib_{party_id}.tag",
        )

        # This is the cumulative joint public key through
        # the current party.
        joint_pk = load_object(
            DeserializePublicKey,
            PUBLIC_DIR / f"joint_pk_{party_id}.bin",
        )

        print(
            f"Combining Party {party_id}'s contribution..."
        )

        combined = cc.MultiAddEvalKeys(
            combined,
            contribution,
            joint_pk.GetKeyTag(),
        )

    # Install and serialize the resulting collective key.
    # The individual evaluation-key contributions were loaded
    # into OpenFHE's global evaluation-key cache.
    # Remove those cached entries before registering the final key.
    ClearEvalMultKeys()

    # Register only the final collective evaluation key.
    cc.InsertEvalMultKey([combined])

    final_tag = combined.GetKeyTag()

    output_path = PUBLIC_DIR / "eval_mult_combined.bin"
    tag_path = PUBLIC_DIR / "eval_mult_combined.tag"

    if not cc.SerializeEvalMultKey(
        str(output_path),
        BINARY,
        final_tag,
    ):
        raise RuntimeError(
            "Could not serialize the combined evaluation key"
        )

    tag_path.write_text(
        final_tag,
        encoding="utf-8",
    )

    print("\nPASS: five evaluation-key contributions combined.")
    print(f"Saved: {output_path}")
    print(f"Key tag: {final_tag}")


if __name__ == "__main__":
    main()

