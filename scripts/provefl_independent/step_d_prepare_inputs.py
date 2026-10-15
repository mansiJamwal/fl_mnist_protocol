
#!/usr/bin/env python3
"""Step D1: prepare party-local MP-SPDZ inputs for one pilot chunk."""

import argparse
import numpy as np
from common import *


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--server-id", type=int, required=True,
                   choices=range(NUM_SERVERS))
    p.add_argument("--pair-i", type=int, required=True)
    p.add_argument("--pair-j", type=int, required=True)
    p.add_argument("--chunk-index", type=int, required=True)
    p.add_argument("--mp-spdz",
                   default=str(Path.home() / "MP-SPDZ"))
    a = p.parse_args()

    if a.pair_i >= a.pair_j:
        raise ValueError("Require pair-i < pair-j.")

    if not 0 <= a.chunk_index < NUM_CHUNKS:
        raise ValueError("Invalid chunk index.")

    mask_file = masks_path(a.server_id)
    commit = read_json(commitment_path(a.server_id))

    # Pilot Step A stores exactly one mask vector with shape (1, CHUNK_SIZE).
    with np.load(mask_file) as bundle:
        masks = bundle["masks"].copy()

    coverage = commit.get("coverage", [])
    covered = {
        (x["pair_i"], x["pair_j"], x["chunk_index"])
        for x in coverage
    }
    key = (a.pair_i, a.pair_j, a.chunk_index)

    if key not in covered:
        raise RuntimeError(
            f"Server {a.server_id} has no mask for {key}."
        )

    if masks.shape != (1, CHUNK_SIZE):
        raise RuntimeError(
            f"Expected pilot mask shape (1, {CHUNK_SIZE}), "
            f"got {masks.shape}."
        )

    if len(coverage) != 1:
        raise RuntimeError(
            "This script supports only the one-pair, one-chunk pilot."
        )

    data = read_json(masked_value_path(
        a.pair_i, a.pair_j, a.chunk_index
    ))
    ys = [int(v) for v in data["values"]]
    bs = [int(v) for v in masks[0]]

    if len(ys) != CHUNK_SIZE or len(bs) != CHUNK_SIZE:
        raise RuntimeError("Expected exactly CHUNK_SIZE values.")

    if not all(0 <= v < Q for v in ys + bs):
        raise RuntimeError("Input outside the expected modular range.")

    # The current MPC program consumes y from P0, then beta_s from
    # each party in each coordinate iteration.
    if a.server_id == 0:
        ordered = [
            v
            for y, b in zip(ys, bs)
            for v in (y, b)
        ]
    else:
        ordered = bs

    player_data = Path(a.mp_spdz) / "Player-Data"
    player_data.mkdir(parents=True, exist_ok=True)
    out = player_data / f"Input-P{a.server_id}-0"
    out.write_text(
        "\n".join(map(str, ordered)) + "\n",
        encoding="utf-8"
    )

    print(f"Wrote {len(ordered)} values to {out}")
    print(f"Party: {a.server_id}; pair: {a.pair_i},{a.pair_j}; "
          f"chunk: {a.chunk_index}")


if __name__ == "__main__":
    main()
