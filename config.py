# Experiment configuration

NUM_CLIENTS = 20
NUM_MALICIOUS_CLIENTS = 2

NUM_SERVERS = 5
HONEST_SERVER_ID = 4

# Coordinate-wise Trimmed Mean
TRIM_PER_SIDE = 2

# MNIST linear model
INPUT_DIM = 784
NUM_CLASSES = 10
MODEL_PARAMETER_COUNT = INPUT_DIM * NUM_CLASSES + NUM_CLASSES

# BFV smoke-test settings only.
# These are NOT final production parameters.
BFV_PLAINTEXT_MODULUS = 65537
BFV_BATCH_SIZE = 16
BFV_MULTIPLICATIVE_DEPTH = 2

# Fixed-point encoding, to be validated against bounds.
FIXED_POINT_SCALE = 100

# Initial test vector for verifying collective decryption.
TEST_VALUES = [7, 11, 13, 17]
