import secrets
import shutil
import subprocess
import sys
from pathlib import Path

from openfhe import (
    BINARY,
    SerializeToFile,
    DeserializeCryptoContext,
    DeserializePublicKey,
    DeserializeCiphertext,
)

from config import (
    NUM_SERVERS,
    BFV_PLAINTEXT_MODULUS,
)

PROJECT_DIR = Path(__file__).resolve().parent
ROOT = PROJECT_DIR / "runtime"
PUBLIC_DIR = ROOT / "public"
CIPHERTEXT_DIR = ROOT / "ciphertexts"
PARTIAL_DIR = ROOT / "partials"

MP_SPDZ_DIR = Path.home() / "MP-SPDZ"
Q = BFV_PLAINTEXT_MODULUS

# Synthetic test only: these contributions sum to -12.
# They will later be replaced with actual client-update differences.
D_SHARES = [3, -8, -6, -1, 0]


def load_object(loader, path):
    obj, ok = loader(str(path), BINARY)

    if not ok:
        raise RuntimeError(f"Could not load {path}")

    return obj


def mod_q(value):
    """Convert an integer to its canonical BFV plaintext residue."""
    return int(value) % Q


def decrypt_masked_ciphertext(cc, ciphertext, index):
    """
    Save one masked ciphertext, request a partial decryption
    from each of five server processes, and fuse the results.

    This test uses the existing party_decrypt.py interface.
    """

    CIPHERTEXT_DIR.mkdir(parents=True, exist_ok=True)

    ciphertext_path = CIPHERTEXT_DIR / "test_ct.bin"

    if not SerializeToFile(
        str(ciphertext_path),
        ciphertext,
        BINARY,
    ):
        raise RuntimeError(
            f"Could not serialize masked ciphertext {index}"
        )

    if PARTIAL_DIR.exists():
        shutil.rmtree(PARTIAL_DIR)

    PARTIAL_DIR.mkdir(parents=True, exist_ok=True)

    # Generate all five partial decryptions.
    # These operations are sequential; they do not require
    # concurrent MPC communication.
    for party_id in range(NUM_SERVERS):
        subprocess.run(
            [
                sys.executable,
                "party_decrypt.py",
                "--party",
                str(party_id),
            ],
            cwd=PROJECT_DIR,
            check=True,
        )

    partials = []

    for party_id in range(NUM_SERVERS):
        partial_path = (
            PARTIAL_DIR / f"party_{party_id}.bin"
        )

        partials.append(
            load_object(
                DeserializeCiphertext,
                partial_path,
            )
        )

    result = cc.MultipartyDecryptFusion(partials)
    result.SetLength(1)

    values = result.GetPackedValue()

    return mod_q(values[0])


def prepare_mpc_inputs(mask_shares, public_y):
    """
    Write the temporary local MP-SPDZ inputs.

    In this integration test, the same machine holds every share.
    A real deployment must deliver each share directly to its owner.
    """

    player_dir = MP_SPDZ_DIR / "Player-Data"
    public_input_dir = MP_SPDZ_DIR / "Programs" / "Public-Input"

    player_dir.mkdir(parents=True, exist_ok=True)
    public_input_dir.mkdir(parents=True, exist_ok=True)

    for party_id, mask in enumerate(mask_shares):
        input_path = player_dir / f"Input-P{party_id}-0"

        input_path.write_text(
            f"{mask}\n",
            encoding="utf-8",
        )

    public_input_path = public_input_dir / "sign_masked"

    public_input_path.write_text(
        f"{public_y}\n",
        encoding="utf-8",
    )


def run_mpc():
    """
    Launch the five MASCOT parties concurrently.
    Each party produces a separate log.
    """

    executable = MP_SPDZ_DIR / "mascot-party.x"

    if not executable.exists():
        raise FileNotFoundError(
            f"MASCOT executable not found: {executable}"
        )

    log_paths = [
        Path(f"/tmp/mpc-bridge-party{party_id}.log")
        for party_id in range(NUM_SERVERS)
    ]

    processes = []
    log_handles = []

    try:
        for party_id in range(NUM_SERVERS):
            handle = open(
                log_paths[party_id],
                "w",
                encoding="utf-8",
            )

            log_handles.append(handle)

            process = subprocess.Popen(
                [
                    str(executable),
                    "-N",
                    str(NUM_SERVERS),
                    "-p",
                    str(party_id),
                    "sign_masked",
                ],
                cwd=MP_SPDZ_DIR,
                stdout=handle,
                stderr=subprocess.STDOUT,
            )

            processes.append(process)

        statuses = [
            process.wait()
            for process in processes
        ]

    finally:
        for handle in log_handles:
            handle.close()

    if any(status != 0 for status in statuses):
        for party_id, log_path in enumerate(log_paths):
            print(f"\n--- Party {party_id} log ---")
            print(
                log_path.read_text(
                    encoding="utf-8",
                    errors="replace",
                )
            )

        raise RuntimeError(
            f"MPC failed; process exit codes: {statuses}"
        )

    print("All five MPC parties completed.")

    # The sign classification should appear in party 0's log.
    print("\n--- MPC result ---")
    print(
        log_paths[0].read_text(
            encoding="utf-8",
            errors="replace",
        )
    )


def main():
    if NUM_SERVERS != 5:
        raise ValueError(
            "This test expects exactly five server parties."
        )

    if len(D_SHARES) != NUM_SERVERS:
        raise ValueError("One difference contribution is required per server.")

    print("1. Loading the BFV context and joint public key...")

    cc = load_object(
        DeserializeCryptoContext,
        PUBLIC_DIR / "context.bin",
    )

    public_key = load_object(
        DeserializePublicKey,
        PUBLIC_DIR / "joint_pk_4.bin",
    )

    print("2. Generating fresh additive mask shares...")

    # These shares are independent and uniform modulo Q.
    # This centralized generation is only for the local test.
    mask_shares = [
        secrets.randbelow(Q)
        for _ in range(NUM_SERVERS)
    ]

    opened_masked_values = []

    for party_id in range(NUM_SERVERS):
        d_k = D_SHARES[party_id]
        b_k = mask_shares[party_id]

        print(
            f"3. Encrypting and opening masked contribution "
            f"for server {party_id}..."
        )

        # BFV plaintexts are encoded as residues modulo Q.
        plaintext_d = cc.MakePackedPlaintext([mod_q(d_k)])
        plaintext_b = cc.MakePackedPlaintext([b_k])

        ciphertext_d = cc.Encrypt(
            public_key,
            plaintext_d,
        )

        ciphertext_b = cc.Encrypt(
            public_key,
            plaintext_b,
        )

        # Enc(d_k + B_k) without decrypting either input.
        ciphertext_y = cc.EvalAdd(
            ciphertext_d,
            ciphertext_b,
        )

        # Threshold-decrypt only the masked contribution.
        y_k = decrypt_masked_ciphertext(
            cc,
            ciphertext_y,
            party_id,
        )

        opened_masked_values.append(y_k)

    print("4. Aggregating the publicly opened masked values...")

    public_y = mod_q(sum(opened_masked_values))

    print(f"Public masked aggregate Y = {public_y}")

    # Test-only invariant. This coordinator knows the shares,
    # so do not use this check to claim privacy.
    expected_d = sum(D_SHARES)
    check_d = mod_q(
        public_y - sum(mask_shares)
    )

    if check_d != mod_q(expected_d):
        raise AssertionError(
            "BFV masked aggregation failed its arithmetic check."
        )

    print("5. Preparing the MPC public and private inputs...")

    prepare_mpc_inputs(mask_shares, public_y)

    print("6. Running five-party MASCOT...")

    run_mpc()

    print("\nBFV-to-MPC integration test completed.")


if __name__ == "__main__":
    main()
