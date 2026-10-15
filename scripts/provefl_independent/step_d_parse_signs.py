
#!/usr/bin/env python3
"""Parse the MPC signs for one pilot client pair and chunk."""

import argparse
import json
from pathlib import Path


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True,
                   help="File containing MPC output lines")
    p.add_argument("--output", default="pilot_signs.json")
    p.add_argument("--pair-i", type=int, default=0)
    p.add_argument("--pair-j", type=int, default=1)
    p.add_argument("--coordinates", type=int, default=64)
    a = p.parse_args()

    signs = {}
    with open(a.input, encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) != 5 or parts[0] != "SIGN":
                continue

            i, j, coordinate, sign = map(int, parts[1:])
            if (i, j) != (a.pair_i, a.pair_j):
                continue
            if sign not in (-1, 0, 1):
                raise ValueError(f"Invalid sign: {sign}")
            if coordinate in signs:
                raise ValueError(f"Duplicate coordinate: {coordinate}")

            signs[coordinate] = sign

    expected = set(range(a.coordinates))
    if set(signs) != expected:
        raise RuntimeError(
            f"Expected {a.coordinates} unique signs; got {len(signs)}."
        )

    result = {
        "pair_i": a.pair_i,
        "pair_j": a.pair_j,
        "signs": [signs[k] for k in range(a.coordinates)],
        "meaning": "sign(u_i - u_j), under the pilot's signed modular encoding"
    }

    out = Path(a.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Saved {len(signs)} signs to {out}")


if __name__ == "__main__":
    main()
