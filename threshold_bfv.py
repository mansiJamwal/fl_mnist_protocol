from openfhe import (
    CCParamsBFVRNS,
    GenCryptoContext,
    PKE,
    KEYSWITCH,
    LEVELEDSHE,
    ADVANCEDSHE,
    MULTIPARTY,
    NOISE_FLOODING_MULTIPARTY,
)


from config import (
    NUM_SERVERS,
    BFV_PLAINTEXT_MODULUS,
    BFV_BATCH_SIZE,
    BFV_MULTIPLICATIVE_DEPTH,
    TEST_VALUES,
)


def create_crypto_context():
    """Create a BFV context supporting multiparty decryption."""

    params = CCParamsBFVRNS()

    params.SetPlaintextModulus(BFV_PLAINTEXT_MODULUS)
    params.SetBatchSize(BFV_BATCH_SIZE)
    params.SetMultiplicativeDepth(BFV_MULTIPLICATIVE_DEPTH)

    # Enable noise flooding for multiparty decryption.
    params.SetMultipartyMode(NOISE_FLOODING_MULTIPARTY)

    cc = GenCryptoContext(params)

    cc.Enable(PKE)
    cc.Enable(KEYSWITCH)
    cc.Enable(LEVELEDSHE)
    cc.Enable(ADVANCEDSHE)
    cc.Enable(MULTIPARTY)

    return cc


def generate_server_keys(cc):
    """
    Exercise OpenFHE's multiparty key-generation API.

    The first party creates the initial key.
    Each additional party contributes to the joint public key.
    Each KeyPair's secretKey is retained as that party's share.
    """

    key_pairs = []

    first_key_pair = cc.KeyGen()

    if not first_key_pair.good():
        raise RuntimeError("Initial key generation failed")

    key_pairs.append(first_key_pair)

    for server_id in range(1, NUM_SERVERS):
        key_pair = cc.MultipartyKeyGen(
            key_pairs[-1].publicKey
        )

        if not key_pair.good():
            raise RuntimeError(
                f"Key generation failed for server {server_id}"
            )

        key_pairs.append(key_pair)

    joint_public_key = key_pairs[-1].publicKey

    return key_pairs, joint_public_key


def encrypt_test_vector(cc, public_key, values):
    """Encrypt a small vector using the joint public key."""

    plaintext = cc.MakePackedPlaintext(values)
    ciphertext = cc.Encrypt(public_key, plaintext)

    return ciphertext


def threshold_decrypt(cc, ciphertext, key_pairs, length):
    """
    Obtain five partial decryptions and fuse them.

    This exercises the actual OpenFHE multiparty-decryption
    operations. It is not yet a distributed deployment:
    this test process temporarily holds every share.
    """

    partials = []

    # The lead party uses MultipartyDecryptLead.
    lead_partials = cc.MultipartyDecryptLead(
        [ciphertext],
        key_pairs[0].secretKey,
    )

    partials.append(lead_partials[0])

    # The remaining parties provide their partial decryptions.
    for server_id in range(1, NUM_SERVERS):
        server_partials = cc.MultipartyDecryptMain(
            [ciphertext],
            key_pairs[server_id].secretKey,
        )

        partials.append(server_partials[0])

    # Combine all five partial decryptions.
    result = cc.MultipartyDecryptFusion(partials)
    result.SetLength(length)

    return [int(x) for x in result.GetPackedValue()[:length]]


def main():
    print("Creating BFV context...")
    cc = create_crypto_context()

    print("Generating five-party joint key...")
    key_pairs, joint_public_key = generate_server_keys(cc)

    print("Encrypting the test vector...")
    ciphertext = encrypt_test_vector(
        cc,
        joint_public_key,
        TEST_VALUES,
    )

    print("Combining five partial decryptions...")
    recovered = threshold_decrypt(
        cc,
        ciphertext,
        key_pairs,
        len(TEST_VALUES),
    )

    print("Expected: ", TEST_VALUES)
    print("Recovered:", recovered)

    if recovered != TEST_VALUES:
        raise AssertionError(
            "Threshold BFV decryption returned an incorrect result"
        )

    print("PASS: five-party BFV decryption works")


if __name__ == "__main__":
    main()

