from config import NUM_SERVERS
from threshold_bfv import (
    create_crypto_context,
    generate_server_keys,
    threshold_decrypt,
)


def generate_multiparty_eval_mult_key(cc, key_pairs):
    """
    Generate the collective BFV evaluation multiplication key.

    Each party contributes using its own secret-key share.
    This function is for the current single-process API test:
    all key shares are temporarily present in this process.
    """

    # Party 0 generates its initial evaluation-key contribution.
    first = key_pairs[0]

    eval_mult_key = cc.KeySwitchGen(
        first.secretKey,
        first.secretKey,
    )

    contributions = [eval_mult_key]

    # Each remaining party contributes its own evaluation key.
    for key_pair in key_pairs[1:]:
        contribution = cc.MultiKeySwitchGen(
            key_pair.secretKey,
            key_pair.secretKey,
            eval_mult_key,
        )
        contributions.append(contribution)

    # Combine the contributions sequentially.
    joint_eval_key = contributions[0]

    for i in range(1, len(key_pairs)):
        joint_eval_key = cc.MultiAddEvalKeys(
            joint_eval_key,
            contributions[i],
            key_pairs[i].publicKey.GetKeyTag(),
        )

    # Each party contributes to the cross terms required
    # for multiplication under the collective secret key.
    joint_public_key_tag = key_pairs[-1].publicKey.GetKeyTag()

    cross_terms = []

    for key_pair in key_pairs:
        term = cc.MultiMultEvalKey(
            key_pair.secretKey,
            joint_eval_key,
            joint_public_key_tag,
        )
        cross_terms.append(term)

    # Combine all cross-term contributions.
    final_eval_key = cross_terms[0]

    for term in cross_terms[1:]:
        final_eval_key = cc.MultiAddEvalMultKeys(
            final_eval_key,
            term,
            joint_eval_key.GetKeyTag(),
        )

    # Install the collective evaluation key in the context.
    cc.InsertEvalMultKey([final_eval_key])


def decrypt_and_check(cc, ciphertext, key_pairs, expected):
    """Threshold-decrypt a ciphertext and check its result."""

    actual = threshold_decrypt(
        cc,
        ciphertext,
        key_pairs,
        len(expected),
    )

    print("Expected:", expected)
    print("Actual:  ", actual)

    if actual != expected:
        raise AssertionError("BFV arithmetic result is incorrect")


def main():
    print("1. Creating BFV context...")
    cc = create_crypto_context()

    print("2. Generating five-party key...")
    key_pairs, joint_public_key = generate_server_keys(cc)

    print("3. Generating multiplication evaluation key...")
    generate_multiparty_eval_mult_key(cc, key_pairs)

    # Use small, nonnegative integers to avoid ambiguity
    # from modular wraparound in this test.
    a = [12, 15, 19, 23]
    b = [2, 3, 4, 5]

    plaintext_a = cc.MakePackedPlaintext(a)
    plaintext_b = cc.MakePackedPlaintext(b)

    print("4. Encrypting both vectors...")
    ciphertext_a = cc.Encrypt(joint_public_key, plaintext_a)
    ciphertext_b = cc.Encrypt(joint_public_key, plaintext_b)

    print("\nTesting homomorphic addition...")
    ciphertext_sum = cc.EvalAdd(ciphertext_a, ciphertext_b)
    decrypt_and_check(
        cc,
        ciphertext_sum,
        key_pairs,
        [14, 18, 23, 28],
    )

    print("\nTesting homomorphic subtraction...")
    ciphertext_diff = cc.EvalSub(ciphertext_a, ciphertext_b)
    decrypt_and_check(
        cc,
        ciphertext_diff,
        key_pairs,
        [10, 12, 15, 18],
    )

    print("\nTesting homomorphic multiplication...")
    ciphertext_product = cc.EvalMult(ciphertext_a, ciphertext_b)
    decrypt_and_check(
        cc,
        ciphertext_product,
        key_pairs,
        [24, 45, 76, 115],
    )

    print("\nPASS: BFV arithmetic and multiparty decryption work.")


if __name__ == "__main__":
    main()

