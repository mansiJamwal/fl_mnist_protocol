
#!/usr/bin/env python3
"""Step A: generate independent, one-use BFV masks for a selected pilot scope."""

import argparse
import hashlib
import secrets

import numpy as np

from common import *


def main():
    parser = argparse.ArgumentParser(
        description="Generate and commit to one server's selected BFV masks."
    )
    parser.add_argument(
        "--server-id",
        type=int,
        required=True,
        choices=range(NUM_SERVERS),
    )
    parser.add_argument("--pair-i", type=int, required=True)
    parser.add_argument("--pair-j", type=int, required=True)
    parser.add_argument("--chunk-index", type=int, required=True)
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()

    # Validate the selected pair and chunk.
    if not (0 <= args.pair_i < args.pair_j < NUM_CLIENTS):
        parser.error(
            f"Require 0 <= pair-i < pair-j < {NUM_CLIENTS}."
        )

    if not (0 <= args.chunk_index < NUM_CHUNKS):
        parser.error(
            f"chunk-index must be between 0 and {NUM_CHUNKS - 1}."
        )

    i, j, k = args.pair_i, args.pair_j, args.chunk_index
    work = [(i, j, k)]

    # A partial pilot must not overwrite a full-round bundle or commitment.
    mask_file = masks_path(args.server_id)
    commitment_file = commitment_path(args.server_id)

    if (mask_file.exists() or commitment_file.exists()) and not args.overwrite:
        raise FileExistsError(
            "A mask bundle or commitment already exists. "
            "Use --overwrite only when intentionally restarting this "
            "server's mask generation."
        )

    # Load the BFV context and public key.
    cc, pk, load, serialize, BINARY = load_openfhe()

    # Generate a fresh independent mask for this server and selected scope.
    selected_masks = []
    coverage = []

    for pair_i, pair_j, chunk_index in work:
        values = np.array(
            [secrets.randbelow(Q) for _ in range(CHUNK_SIZE)],
            dtype=np.int64,
        )
        selected_masks.append(values)

        plaintext = cc.MakePackedPlaintext(
            [int(value) for value in values]
        )
        ciphertext = cc.Encrypt(pk, plaintext)

        output_file = mask_ct_path(
            args.server_id, pair_i, pair_j, chunk_index
        )
        output_file.parent.mkdir(parents=True, exist_ok=True)

        if output_file.exists() and not args.overwrite:
            raise FileExistsError(
                f"{output_file} already exists. "
                "Use --overwrite only when intentionally regenerating it."
            )

        if not serialize(str(output_file), ciphertext, BINARY):
            raise RuntimeError(
                f"Failed to serialize encrypted mask: {output_file}"
            )

        coverage.append(
            {
                "pair_i": pair_i,
                "pair_j": pair_j,
                "chunk_index": chunk_index,
                "chunk_owner": chunk_owner(chunk_index),
            }
        )

    # Commit to the selected mask values using a fresh secret salt.
    mask_array = np.asarray(selected_masks, dtype=np.int64)
    salt = secrets.token_bytes(32)

    digest = hashlib.sha256(
        salt + mask_array.tobytes(order="C")
    ).hexdigest()

    mask_file.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(
        mask_file,
        masks=mask_array,
        salt=np.frombuffer(salt, dtype=np.uint8),
        coverage=np.asarray(work, dtype=np.int64),
    )

    save_json(
        commitment_file,
        {
            "server_id": args.server_id,
            "scheme": (
                "SHA256(salt || C-order int64 selected mask array)"
            ),
            "commitment_sha256": digest,
            "shape": list(mask_array.shape),
            "q": Q,
            "coverage": coverage,
            "complete_coverage": False,
            "note": (
                "Selected pilot scope only. Keep masks.npz and its salt "
                "private; publish only the commitment."
            ),
        },
    )

    print(f"Server: {args.server_id}")
    print(f"Selected pair: ({i}, {j})")
    print(f"Selected chunk: {k}")
    print(f"Chunk owner: {chunk_owner(k)}")
    print(f"Encrypted mask: {mask_ct_path(args.server_id, i, j, k)}")
    print(f"Private mask bundle: {mask_file}")
    print(f"Commitment: {commitment_file}")
    print(f"SHA-256 commitment: {digest}")
    print("Pilot mask generation completed.")


if __name__ == "__main__":
    main()
