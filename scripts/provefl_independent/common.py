from __future__ import annotations
import itertools, json, os
from pathlib import Path
NUM_CLIENTS=20
NUM_SERVERS=5
PARAM_COUNT=320
CHUNK_SIZE=64
NUM_CHUNKS=(PARAM_COUNT+CHUNK_SIZE-1)//CHUNK_SIZE
Q=65537
TRIM_PER_SIDE=2
SCALE=10000
PROJECT_ROOT=Path(os.environ.get('PROVEFL_ROOT',str(Path.home()/'fl_mnist_protocol'))).expanduser()
RUNTIME=PROJECT_ROOT/'runtime'
MNIST_DIR=RUNTIME/'mnist'/'bfv_round1'
PUBLIC_DIR=RUNTIME/'public'
PRIVATE_DIR=RUNTIME/'private'
FLOW_DIR=RUNTIME/'provefl_independent'
MASK_PRIVATE_DIR=FLOW_DIR/'private'
COMMITMENT_DIR=FLOW_DIR/'commitments'
ENCRYPTED_MASK_DIR=FLOW_DIR/'encrypted_masks'
MASKED_CT_DIR=FLOW_DIR/'masked_ciphertexts'
PARTIAL_DIR=FLOW_DIR/'partials'
MASKED_VALUE_DIR=FLOW_DIR/'masked_values'
SIGN_DIR=FLOW_DIR/'signs'
RETAINED_DIR=FLOW_DIR/'retained'
AGGREGATE_CT_DIR=FLOW_DIR/'aggregate_ciphertexts'
CONTEXT_PATH=PUBLIC_DIR/'context.bin'
JOINT_PK_PATH=PUBLIC_DIR/'joint_pk_4.bin'

def chunk_owner(chunk_index:int)->int:
    if not 0 <= chunk_index < NUM_CHUNKS: raise ValueError(f'Invalid chunk index: {chunk_index}')
    return chunk_index % NUM_SERVERS

def pairs(): return list(itertools.combinations(range(NUM_CLIENTS),2))
def pair_index(i,j):
    if not (0<=i<j<NUM_CLIENTS): raise ValueError('Require 0 <= pair-i < pair-j < NUM_CLIENTS')
    return pairs().index((i,j))
def pair_tag(i,j): return f'pair_{i:02d}_{j:02d}'
def chunk_tag(k): return f'chunk_{k:04d}'
def client_chunk_path(c,k): return MNIST_DIR/f'client_{c:02d}'/f'{chunk_tag(k)}.bin'
def mask_ct_path(s,i,j,k): return ENCRYPTED_MASK_DIR/f'server_{s}'/pair_tag(i,j)/f'{chunk_tag(k)}.bin'
def masked_ct_path(i,j,k): return MASKED_CT_DIR/pair_tag(i,j)/f'{chunk_tag(k)}.bin'
def partial_path(s,i,j,k): return PARTIAL_DIR/f'server_{s}'/pair_tag(i,j)/f'{chunk_tag(k)}.bin'
def masked_value_path(i,j,k): return MASKED_VALUE_DIR/pair_tag(i,j)/f'{chunk_tag(k)}.json'
def masks_path(s): return MASK_PRIVATE_DIR/f'server_{s}'/'masks.npz'
def commitment_path(s): return COMMITMENT_DIR/f'server_{s}.json'
def load_openfhe():
    try:
        from openfhe import BINARY, DeserializeCryptoContext, DeserializePublicKey, SerializeToFile
    except Exception as e: raise RuntimeError('OpenFHE Python bindings are unavailable in this Python environment') from e
    def load(loader,path):
        obj,ok=loader(str(path),BINARY)
        if not ok: raise RuntimeError(f'OpenFHE deserialization failed: {path}')
        return obj
    return load(DeserializeCryptoContext,CONTEXT_PATH),load(DeserializePublicKey,JOINT_PK_PATH),load,SerializeToFile,BINARY

def save_json(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(obj,indent=2,sort_keys=True)+'\n',encoding='utf-8')
def read_json(path): return json.loads(path.read_text(encoding='utf-8'))
def all_work(): return [(i,j,k) for i,j in pairs() for k in range(NUM_CHUNKS)]
def add_scope_args(p):
    p.add_argument('--pair-i',type=int); p.add_argument('--pair-j',type=int); p.add_argument('--chunk-index',type=int)
def selected_work(a):
    if a.pair_i is None and a.pair_j is None and a.chunk_index is None: return all_work()
    if a.pair_i is None or a.pair_j is None: raise ValueError('Specify both --pair-i and --pair-j for a partial run')
    pair_index(a.pair_i,a.pair_j)
    if a.chunk_index is None: return [(a.pair_i,a.pair_j,k) for k in range(NUM_CHUNKS)]
    if not 0<=a.chunk_index<NUM_CHUNKS: raise ValueError(f'chunk-index must be in [0,{NUM_CHUNKS-1}]')
    return [(a.pair_i,a.pair_j,a.chunk_index)]
