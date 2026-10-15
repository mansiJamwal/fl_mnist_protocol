#!/usr/bin/env python3
"""Step C2: fuse partial decryptions; plaintext output remains masked Y only."""
import argparse
from common import *
def main():
    p=argparse.ArgumentParser(); p.add_argument('--all',action='store_true'); add_scope_args(p); a=p.parse_args(); work=all_work() if a.all else selected_work(a)
    from openfhe import DeserializeCiphertext
    cc,pk,load,serialize,BINARY=load_openfhe()
    for n,(i,j,k) in enumerate(work,1):
        partials=[load(DeserializeCiphertext,partial_path(s,i,j,k)) for s in range(NUM_SERVERS)]
        pt=cc.MultipartyDecryptFusion(partials); pt.SetLength(CHUNK_SIZE)
        vals=[int(x)%Q for x in pt.GetPackedValue()[:CHUNK_SIZE]]
        save_json(masked_value_path(i,j,k),{'pair_i':i,'pair_j':j,'chunk_index':k,'q':Q,'values':vals,'meaning':'u_i-u_j + sum of five masks (mod q)'})
        if n%100==0: print(f'fused {n}/{len(work)}')
    print(f'Fused {len(work)} masked plaintext chunks. No unmasked differences were written.')
if __name__=='__main__': main()
