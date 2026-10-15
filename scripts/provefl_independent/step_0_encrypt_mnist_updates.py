#!/usr/bin/env python3
"""Encrypt a round of client deltas into fixed 64-slot BFV chunks."""
import argparse, json
import numpy as np
from common import *

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--round-key',default='round_01',help='NPZ key, e.g. round_01')
    p.add_argument('--scale',type=float,default=SCALE)
    p.add_argument('--overwrite',action='store_true')
    p.add_argument('--input',default=str(RUNTIME/'mnist'/'colab_export'/'all_client_deltas.npz'))
    a=p.parse_args()
    source=Path(a.input)
    if not source.exists(): raise FileNotFoundError(source)
    cc,pk,load,serialize,BINARY=load_openfhe()
    with np.load(source) as data:
        if a.round_key not in data.files: raise KeyError(f'{a.round_key} not in {source}; keys={data.files}')
        deltas=np.asarray(data[a.round_key],dtype=np.float64)
    if deltas.ndim != 2 or deltas.shape[0] != NUM_CLIENTS:
        raise ValueError(
            f"Expected {NUM_CLIENTS} clients, got shape {deltas.shape}"
        )

    if deltas.shape[1] < PARAM_COUNT:
        raise ValueError(
            f"Need at least {PARAM_COUNT} coordinates, got {deltas.shape[1]}"
        )

    # Pilot uses the first 320 coordinates from each client's update.
    deltas = deltas[:, :PARAM_COUNT]

    assert deltas.shape == (NUM_CLIENTS, PARAM_COUNT)
    quantized=np.rint(deltas*a.scale).astype(np.int64)
    # Require signed values to be unambiguous under Q for pairwise differences.
    max_abs=int(np.max(np.abs(quantized)))
    if 2*max_abs >= Q//2:
        raise ValueError(f'Quantized coordinate magnitude {max_abs} is too large for safe pairwise signed differences with Q={Q}; clip/re-quantize or use a larger plaintext modulus.')
    manifest={'round_key':a.round_key,'source':str(source),'scale':a.scale,'q':Q,'shape':list(deltas.shape),'chunk_size':CHUNK_SIZE,'num_chunks':NUM_CHUNKS,'max_abs_quantized_client_coordinate':max_abs,'padding':'zero to 64 slots'}
    for client in range(NUM_CLIENTS):
        for k in range(NUM_CHUNKS):
            out=client_chunk_path(client,k)
            if out.exists() and not a.overwrite: raise FileExistsError(f'{out} exists; pass --overwrite to replace existing encrypted updates')
    for client in range(NUM_CLIENTS):
        for k in range(NUM_CHUNKS):
            lo=k*CHUNK_SIZE; hi=min(PARAM_COUNT,lo+CHUNK_SIZE)
            slots=[int(v)%Q for v in quantized[client,lo:hi]]
            slots += [0]*(CHUNK_SIZE-len(slots))
            ct=cc.Encrypt(pk,cc.MakePackedPlaintext(slots))
            out=client_chunk_path(client,k); out.parent.mkdir(parents=True,exist_ok=True)
            if not serialize(str(out),ct,BINARY): raise RuntimeError(f'Failed to serialize {out}')
        print(f'Encrypted client {client+1}/{NUM_CLIENTS}')
    save_json(MNIST_DIR/'manifest_round1.json',manifest)
    print(f'Wrote {NUM_CLIENTS*NUM_CHUNKS} ciphertext chunks; manifest: {MNIST_DIR/"manifest_round1.json"}')

if __name__=='__main__': main()
